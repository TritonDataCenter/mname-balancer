


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


typedef struct {
	cconn_t *prx_front;
	cconn_t *prx_back;
	boolean_t prx_flowing;
} proxy_t;

static void
bbal_tcp_teardown(proxy_t *prx)
{
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

	fprintf(stdout, "\tTCP FRONT DATA\n");

	if (!prx->prx_flowing) {
		/*
		 * Still waiting for the backend connection to be established.
		 */
		fprintf(stdout, "\t\tnot yet flowing\n");
		return;
	}

	/*
	 * Push all of the data we have into the backend.
	 */
	cbufq_t *q = cconn_recvq(prx->prx_front);
	cbuf_t *b;
	while ((b = cbufq_deq(q)) != NULL) {
		fprintf(stdout, "\t\tforward %d bytes\n", cbuf_available(b));
		cbuf_resume(b);
		if (cconn_send(prx->prx_back, b) != 0) {
			cbuf_free(b);
			warn("cconn_send to backend");
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

	fprintf(stdout, "\tTCP BACK CONNECT\n");

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
	VERIFY0(cbuf_put_u32(buf, 3)); /* FRAME TYPE */
	VERIFY0(cbuf_put_u32(buf, ntohl(sin->sin_addr.s_addr))); /* IP */
	VERIFY0(cbuf_put_u32(buf, ntohs(sin->sin_port))); /* PORT */

	if (cconn_send(ccn, buf) != 0) {
		err(1, "cconn_send backend hello frame");
	}

	prx->prx_flowing = B_TRUE;
	bbal_tcp_front_data(prx->prx_front, CCONN_CB_DATA_AVAILABLE);
}

static void
bbal_tcp_back_data(cconn_t *ccn, int event)
{
	proxy_t *prx = cconn_data(ccn);

	fprintf(stdout, "\tTCP BACK DATA\n");

	/*
	 * Push all of the data we have into the frontend.
	 */
	cbufq_t *q = cconn_recvq(prx->prx_back);
	cbuf_t *b;
	while ((b = cbufq_deq(q)) != NULL) {
		fprintf(stdout, "\t\tforward %d bytes\n", cbuf_available(b));
		cbuf_resume(b);
		if (cconn_send(prx->prx_front, b) != 0) {
			cbuf_free(b);
			warn("cconn_send to frontend");
			bbal_tcp_teardown(prx);
			return;
		}
	}

	cconn_more_data(prx->prx_back);
}

static void
bbal_tcp_front_end(cconn_t *ccn, int event)
{
	proxy_t *prx = cconn_data(ccn);

	fprintf(stdout, "\tTCP FRONT END\n");

	if (cconn_fin(prx->prx_back) != 0) {
		warn("cconn_fin");
	}
}

static void
bbal_tcp_back_end(cconn_t *ccn, int event)
{
	proxy_t *prx = cconn_data(ccn);

	fprintf(stdout, "\tTCP BACK END\n");

	if (cconn_fin(prx->prx_front) != 0) {
		warn("cconn_fin");
	}
}

static void
bbal_tcp_error(cconn_t *ccn, int event)
{
	proxy_t *prx = cconn_data(ccn);

	fprintf(stdout, "\tTCP ERROR (%s)\n", ccn == prx->prx_front ? "front" :
	    "back");

	bbal_tcp_teardown(prx);
}

void
bbal_tcp_incoming(cserver_t *cserver, int event)
{
	VERIFY3S(event, ==, CSERVER_CB_INCOMING);

	proxy_t *prx;
	if ((prx = calloc(1, sizeof (*prx))) == NULL) {
		/*
		 * XXX Exit now.  We could instead wait for more memory, but
		 * we'd need to remember to call "cserver_accept()" later or
		 * this incoming callback won't rearm.
		 */
		err(1, "incoming tcp calloc");
	}

	if (cserver_accept(cserver, &prx->prx_front) != 0) {
		if (errno != EAGAIN) {
			warn("cserver_accept");
		}
		return;
	}

	bunyan_debug(g_log, "inbound TCP connection",
	    BUNYAN_T_STRING, "address", cconn_remote_addr_str(prx->prx_front),
	    BUNYAN_T_END);

	/*
	 * Select a backend for the remote peer.
	 */
	remote_t *rem = remote_lookup(
	    &cconn_sockaddr_in(prx->prx_front)->sin_addr);
	if (rem == NULL) {
		warn("remote_lookup");
		goto fail;
	}
	backend_t *be = backend_lookup(rem->rem_backend);
	if (be == NULL) {
		warn("backend_lookup");
		goto fail;
	}

	fprintf(stdout, "\t\tbackend -> %d\n", be->be_id);

	/*
	 * Begin connecting to the backend.
	 */
	if (bbal_connect_uds_tcp(be, &prx->prx_back) != 0) {
		goto fail;
	}

	cconn_data_set(prx->prx_front, prx);
	cconn_on(prx->prx_front, CCONN_CB_DATA_AVAILABLE, bbal_tcp_front_data);
	cconn_on(prx->prx_front, CCONN_CB_END, bbal_tcp_front_end);
	cconn_on(prx->prx_front, CCONN_CB_ERROR, bbal_tcp_error);

	cconn_data_set(prx->prx_back, prx);
	cconn_on(prx->prx_back, CCONN_CB_CONNECTED, bbal_tcp_back_connect);
	cconn_on(prx->prx_back, CCONN_CB_DATA_AVAILABLE, bbal_tcp_back_data);
	cconn_on(prx->prx_back, CCONN_CB_END, bbal_tcp_back_end);
	cconn_on(prx->prx_back, CCONN_CB_ERROR, bbal_tcp_error);

	return;

fail:
	bbal_tcp_teardown(prx);
	free(prx);
}
