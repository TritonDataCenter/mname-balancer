


#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <inttypes.h>
#include <unistd.h>
#include <strings.h>
#include <err.h>
#include <errno.h>
#include <port.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/un.h>

#include <sys/debug.h>
#include <sys/list.h>
#include <sys/avl.h>

#include <libcbuf.h>
#include <libcloop.h>
#include <bunyan.h>

#include "bbal.h"

uint32_t g_tcp_conn_count = 0;
uint32_t g_active = 0;

typedef struct {
	uint32_t prx_id;
	uint32_t prx_backend;
	bunyan_logger_t *prx_log;
	cconn_t *prx_front;
	cconn_t *prx_back;
	boolean_t prx_flowing;
} proxy_t;

static void
bbal_tcp_teardown(proxy_t *prx)
{
	bunyan_debug(prx->prx_log, "TCP teardown", BUNYAN_T_END);

	if (prx->prx_front != NULL) {
		cconn_abort(prx->prx_front);
	}
	if (prx->prx_back != NULL) {
		cconn_abort(prx->prx_back);
	}
}

static void
bbal_tcp_front_data(cconn_t *ccn, int event)
{
	proxy_t *prx = cconn_data(ccn);

	bunyan_trace(prx->prx_log, "TCP frontend data", BUNYAN_T_END);

	if (!prx->prx_flowing) {
		/*
		 * Still waiting for the backend connection to be established.
		 */
		bunyan_trace(prx->prx_log, "TCP data arrived from remote, but "
		    "backend not yet connected", BUNYAN_T_END);
		return;
	}

	/*
	 * Push all of the data we have into the backend.
	 */
	cbufq_t *q = cconn_recvq(prx->prx_front);
	cbuf_t *b;
	while ((b = cbufq_deq(q)) != NULL) {
		if (cbuf_available(b) == 0) {
			cbuf_free(b);
			continue;
		}

		bunyan_trace(prx->prx_log, "forwarded bytes from front to back",
		    BUNYAN_T_UINT32, "count", cbuf_available(b),
		    BUNYAN_T_END);

		cbuf_resume(b);
		if (cconn_send(prx->prx_back, b) != 0) {
			bunyan_warn(prx->prx_log, "forward to backend failed",
			    BUNYAN_T_UINT32, "count", cbuf_available(b),
			    BUNYAN_T_INT32, "errno", (int32_t)errno,
			    BUNYAN_T_STRING, "strerror", strerror(errno),
			    BUNYAN_T_END);
			cbuf_free(b);
			bbal_tcp_teardown(prx);
			return;
		}
	}

	cconn_more_data(prx->prx_front);
}

static void
bbal_tcp_back_connect(cconn_t *ccn, int event)
{
	proxy_t *prx = cconn_data(ccn);

	bunyan_debug(prx->prx_log, "connected to backend", BUNYAN_T_END);

	backend_t *be = backend_lookup(prx->prx_backend);
	if (be != NULL) {
		be->be_stat_tcp++;
	}

	/*
	 * Connected to backend.  First send our preamble frame which identifies
	 * the remote peer to the backend, then start the flow of data.
	 */
	cbuf_t *buf;
	if (cbuf_alloc(&buf, 2048) != 0) {
		err(1, "cbuf_alloc backend connect");
	}
	cbuf_byteorder_set(buf, CBUF_ORDER_LITTLE_ENDIAN);

	const struct sockaddr_in *sin = cconn_sockaddr_in(prx->prx_front);
	VERIFY0(cbuf_put_u32(buf, FRAME_TYPE_INBOUND_TCP)); /* FRAME TYPE */
	VERIFY0(cbuf_put_u32(buf, ntohl(sin->sin_addr.s_addr))); /* IP */
	VERIFY0(cbuf_put_u32(buf, ntohs(sin->sin_port))); /* PORT */

	if (cconn_send(ccn, buf) != 0) {
		err(1, "cconn_send backend hello frame");
	}
}

static void
bbal_tcp_back_data(cconn_t *ccn, int event)
{
	proxy_t *prx = cconn_data(ccn);
	cbufq_t *q = cconn_recvq(ccn);
	cbuf_t *b;

	bunyan_trace(prx->prx_log, "TCP frontend data", BUNYAN_T_END);

	if (!prx->prx_flowing) {
		/*
		 * Wait for the server to send it's acknowledgement of this
		 * TCP connection before sending data.
		 */
		if (cbufq_pullup(q, sizeof (uint32_t)) != 0) {
			if (errno == EIO) {
				/*
				 * Wait for the entire frame type value.
				 */
				goto done;
			}

			err(1, "cbufq_pullup");
			return;
		}

		b = cbufq_peek(q);
		uint32_t frame_type;
		VERIFY0(cbuf_get_u32(b, &frame_type));

		if (frame_type != FRAME_TYPE_INBOUND_TCP_OK) {
			bunyan_warn(prx->prx_log, "backend invalid TCP OK",
			    BUNYAN_T_UINT32, "frame_type", frame_type,
			    BUNYAN_T_END);
			bbal_tcp_teardown(prx);
			return;
		}

		bunyan_trace(prx->prx_log, "backend reports TCP OK");

		/*
		 * Start the flow of data from the frontend.
		 */
		prx->prx_flowing = B_TRUE;
		bbal_tcp_front_data(prx->prx_front, CCONN_CB_DATA_AVAILABLE);
	}

	/*
	 * Push all of the data we have into the frontend.
	 */
	while ((b = cbufq_deq(q)) != NULL) {
		if (cbuf_available(b) == 0) {
			cbuf_free(b);
			continue;
		}

		bunyan_trace(prx->prx_log, "forwarded bytes from back to front",
		    BUNYAN_T_UINT32, "count", cbuf_available(b),
		    BUNYAN_T_END);

		cbuf_resume(b);
		if (cconn_send(prx->prx_front, b) != 0) {
			bunyan_warn(prx->prx_log, "forward to frontend failed",
			    BUNYAN_T_UINT32, "count", cbuf_available(b),
			    BUNYAN_T_INT32, "errno", (int32_t)errno,
			    BUNYAN_T_STRING, "strerror", strerror(errno),
			    BUNYAN_T_END);
			cbuf_free(b);
			bbal_tcp_teardown(prx);
			return;
		}
	}

done:
	cconn_more_data(prx->prx_back);
}

static void
bbal_tcp_end(cconn_t *ccn, int event)
{
	proxy_t *prx = cconn_data(ccn);
	cconn_t *other = ccn == prx->prx_front ? prx->prx_back : prx->prx_front;

	bunyan_trace(prx->prx_log, "TCP stream EOF",
	    BUNYAN_T_STRING, "which", ccn == prx->prx_front ? "front" :
	    "back",
	    BUNYAN_T_END);

	if (other != NULL && cconn_fin(other) != 0) {
		bunyan_error(prx->prx_log, "FIN send failed", BUNYAN_T_END);
	}
}

static void
bbal_tcp_error(cconn_t *ccn, int event)
{
	proxy_t *prx = cconn_data(ccn);

	bunyan_error(prx->prx_log, "TCP error",
	    BUNYAN_T_STRING, "which", ccn == prx->prx_front ? "front" :
	    "back",
	    BUNYAN_T_END);

	bbal_tcp_teardown(prx);
}

static void
bbal_tcp_close(cconn_t *ccn, int event)
{
	proxy_t *prx = cconn_data(ccn);

	VERIFY3S(event, ==, CCONN_CB_CLOSE);

	if (ccn == prx->prx_front) {
		bunyan_debug(prx->prx_log, "frontend connection closed",
		    BUNYAN_T_END);
		prx->prx_front = NULL;
	}
	if (ccn == prx->prx_back) {
		bunyan_debug(prx->prx_log, "backend connection closed",
		    BUNYAN_T_END);
		prx->prx_back = NULL;
	}

	if (prx->prx_front != NULL || prx->prx_back != NULL) {
		/*
		 * Connections still remain to be torn down.
		 */
		return;
	}

	bunyan_debug(prx->prx_log, "proxy connection finished", BUNYAN_T_END);
	bunyan_fini(prx->prx_log);
	free(prx);

	VERIFY3U(g_active, >, 0);
	g_active--;
}

void
bbal_tcp_incoming(cserver_t *cserver, int event)
{
	VERIFY3S(event, ==, CSERVER_CB_INCOMING);

	proxy_t *prx;
	if ((prx = calloc(1, sizeof (*prx))) == NULL) {
		/*
		 * Abort here.  We could instead wait for more memory, but we'd
		 * need to remember to call "cserver_accept()" later or this
		 * incoming callback won't rearm.
		 */
		bunyan_fatal(g_log, "incoming TCP calloc", BUNYAN_T_END);
		abort();
	}
	prx->prx_id = ++g_tcp_conn_count;

	if (cserver_accept(cserver, &prx->prx_front) != 0) {
		if (errno != EAGAIN) {
			bunyan_warn(g_log, "incoming TCP accept failure",
			    BUNYAN_T_INT32, "errno", (int32_t)errno,
			    BUNYAN_T_STRING, "strerror", strerror(errno),
			    BUNYAN_T_END);
		}
		free(prx);
		return;
	}

	g_active++;

	const struct sockaddr_in *sin = cconn_sockaddr_in(prx->prx_front);
	bunyan_debug(g_log, "inbound TCP connection",
	    BUNYAN_T_UINT32, "conn_id", prx->prx_id,
	    BUNYAN_T_IP, "remote_ip", &sin->sin_addr,
	    BUNYAN_T_UINT32, "remote_port", (uint32_t)ntohs(sin->sin_port),
	    BUNYAN_T_END);

	/*
	 * Select a backend for the remote peer.
	 */
	remote_t *rem = remote_lookup(&sin->sin_addr);
	if (rem == NULL) {
		bunyan_error(g_log, "could not lookup remote (dropping)",
		    BUNYAN_T_IP, "remote_ip", &sin->sin_addr,
		    BUNYAN_T_UINT32, "remote_port",
		    (uint32_t)ntohs(sin->sin_port),
		    BUNYAN_T_END);
		goto fail;
	}

	backend_t *be = remote_backend(rem);
	if (be == NULL) {
		bunyan_trace(rem->rem_log, "could not find backend for remote",
		    BUNYAN_T_END);
		goto fail;
	}
	prx->prx_backend = be->be_id;

	if (bunyan_child(g_log, &prx->prx_log,
	    BUNYAN_T_UINT32, "backend", be->be_id,
	    BUNYAN_T_UINT32, "conn_id", prx->prx_id,
	    BUNYAN_T_IP, "remote_ip", &sin->sin_addr,
	    BUNYAN_T_UINT32, "remote_port", (uint32_t)ntohs(sin->sin_port),
	    BUNYAN_T_END) != 0) {
		err(1, "bunyan_child");
	}

	bunyan_trace(prx->prx_log, "connecting to backend", BUNYAN_T_END);

	/*
	 * Begin connecting to the backend.
	 */
	if (bbal_connect_uds_tcp(be, &prx->prx_back) != 0) {
		goto fail;
	}

	rem->rem_stat_tcp++;

	cconn_data_set(prx->prx_front, prx);
	cconn_on(prx->prx_front, CCONN_CB_DATA_AVAILABLE, bbal_tcp_front_data);
	cconn_on(prx->prx_front, CCONN_CB_END, bbal_tcp_end);
	cconn_on(prx->prx_front, CCONN_CB_ERROR, bbal_tcp_error);
	cconn_on(prx->prx_front, CCONN_CB_CLOSE, bbal_tcp_close);

	cconn_data_set(prx->prx_back, prx);
	cconn_on(prx->prx_back, CCONN_CB_CONNECTED, bbal_tcp_back_connect);
	cconn_on(prx->prx_back, CCONN_CB_DATA_AVAILABLE, bbal_tcp_back_data);
	cconn_on(prx->prx_back, CCONN_CB_END, bbal_tcp_end);
	cconn_on(prx->prx_back, CCONN_CB_ERROR, bbal_tcp_error);
	cconn_on(prx->prx_back, CCONN_CB_CLOSE, bbal_tcp_close);

	return;

fail:
	if (rem != NULL) {
		rem->rem_stat_tcp_drop++;
	}
	bbal_tcp_teardown(prx);
	free(prx);
}
