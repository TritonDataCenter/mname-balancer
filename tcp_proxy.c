/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright (c) 2018, Joyent, Inc.
 */

/*
 * TCP PROXY
 *
 * In addition to the classical use of UDP packets for DNS requests and
 * responses, modern DNS servers will also answer queries via TCP connections.
 * This file is responsible for forwarding those TCP connections to the backend
 * DNS processes.
 *
 * A TCP listen port is established at program startup; see
 * "bbal_tcp_listen()".  For each connection received on this port, a new local
 * session is established to the appropriate backend.  After an initial header
 * which informs the backend process of the source IP and port for the incoming
 * connection, data is forwarded verbatim without additional framing.  The same
 * backend association (see "backend.c" and "remotes.c") that is used for UDP
 * packets is also used for incoming TCP connections.
 */

#include "bbal.h"

/*
 * It's not really clear that there's a universally excellent value for listen
 * backlog, so we'll simply try not to set it too small to be useful.
 */
#define	BBAL_TCP_BACKLOG	1000

uint32_t g_tcp_conn_count = 0;

/*
 * This object tracks the lifecycle of a single connection from a remote peer
 * to a backend DNS process through a local socket.
 */
typedef struct {
	uint32_t prx_id;
	uint32_t prx_backend;
	bunyan_logger_t *prx_log;
	cconn_t *prx_front;
	cconn_t *prx_back;
	boolean_t prx_flowing;
	timeout_t *prx_connect_timeout;
} proxy_t;

/*
 * Abort all connections for this proxy object.
 */
static void
bbal_tcp_teardown(proxy_t *prx)
{
	bunyan_debug(prx->prx_log, "TCP teardown", BUNYAN_T_END);

	if (prx->prx_front == NULL && prx->prx_back == NULL) {
		/*
		 * No connections have been established, so there will not be
		 * a subsequent CLOSE event.  Free the remaining resources now.
		 */
		if (prx->prx_log != NULL) {
			bunyan_fini(prx->prx_log);
		}
		timeout_free(prx->prx_connect_timeout);
		free(prx);
		return;
	}

	timeout_clear(prx->prx_connect_timeout);

	if (prx->prx_front != NULL) {
		cconn_abort(prx->prx_front);
	}
	if (prx->prx_back != NULL) {
		cconn_abort(prx->prx_back);
	}
}

/*
 * Called when data arrives from the remote peer.
 */
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

/*
 * Called when a connection to the backend is established.
 */
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
	 * Send the preamble frame which identifies the remote peer to the
	 * backend.  Once the appropriate response is received, the flow of
	 * data will begin.
	 *
	 * Note that we do not cancel the connection timeout until that
	 * response arrives.
	 */
	cbuf_t *buf;
	if (cbuf_alloc(&buf, 2048) != 0) {
		bunyan_warn(prx->prx_log, "backend hello frame alloc failed",
		    BUNYAN_T_INT32, "errno", (int32_t)errno,
		    BUNYAN_T_STRING, "strerror", strerror(errno),
		    BUNYAN_T_END);
		bbal_tcp_teardown(prx);
		return;
	}
	cbuf_byteorder_set(buf, CBUF_ORDER_LITTLE_ENDIAN);

	const struct sockaddr_in *sin = cconn_sockaddr_in(prx->prx_front);
	VERIFY0(cbuf_put_u32(buf, FRAME_TYPE_INBOUND_TCP));
	VERIFY0(cbuf_put_u32(buf, ntohl(sin->sin_addr.s_addr)));
	VERIFY0(cbuf_put_u32(buf, ntohs(sin->sin_port)));

	if (cconn_send(ccn, buf) != 0) {
		bunyan_warn(prx->prx_log, "backend hello frame send failed",
		    BUNYAN_T_INT32, "errno", (int32_t)errno,
		    BUNYAN_T_STRING, "strerror", strerror(errno),
		    BUNYAN_T_END);
		cbuf_free(buf);
		bbal_tcp_teardown(prx);
		return;
	}
}

/*
 * Called when data arrives from the backend server process via the local
 * socket session.
 */
static void
bbal_tcp_back_data(cconn_t *ccn, int event)
{
	proxy_t *prx = cconn_data(ccn);
	cbufq_t *q = cconn_recvq(ccn);
	cbuf_t *b;

	bunyan_trace(prx->prx_log, "TCP backend data", BUNYAN_T_END);

	if (!prx->prx_flowing) {
		/*
		 * Wait for the server to send it's acknowledgement of this
		 * TCP connection before sending data.
		 */
		if (cbufq_pullup(q, sizeof (uint32_t)) != 0) {
			if (errno == ENODATA) {
				/*
				 * Wait for the entire frame type value.
				 */
				goto done;
			}

			bunyan_fatal(prx->prx_log, "could not pullup",
			    BUNYAN_T_INT32, "errno", (int32_t)errno,
			    BUNYAN_T_STRING, "strerror", strerror(errno),
			    BUNYAN_T_END);
			exit(1);
			return;
		}

		/*
		 * Read the frame type from the head of the buffer queue.
		 */
		uint32_t frame_type;
		VERIFY0(cbuf_get_u32(cbufq_peek(q), &frame_type));

		if (frame_type != FRAME_TYPE_INBOUND_TCP_OK) {
			bunyan_warn(prx->prx_log, "backend invalid TCP OK",
			    BUNYAN_T_UINT32, "frame_type", frame_type,
			    BUNYAN_T_END);
			bbal_tcp_teardown(prx);
			return;
		}

		bunyan_trace(prx->prx_log, "backend reports TCP OK");
		timeout_clear(prx->prx_connect_timeout);

		/*
		 * Start the flow of data from the frontend.  From this point
		 * on, data is passed verbatim without framing.
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

/*
 * Called when either the frontend or backend connection has finished sending
 * data.  The stream EOF is propagated to the other connection.
 */
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

/*
 * Called when either the frontend or backend connection has experienced an
 * error.
 */
static void
bbal_tcp_error(cconn_t *ccn, int event)
{
	proxy_t *prx = cconn_data(ccn);
	int32_t e = cconn_error_errno(ccn);

	bunyan_error(prx->prx_log, "TCP error",
	    BUNYAN_T_STRING, "which", ccn == prx->prx_front ? "front" :
	    "back",
	    BUNYAN_T_STRING, "cause", cconn_error_string(ccn),
	    BUNYAN_T_INT32, "errno", e,
	    BUNYAN_T_STRING, "strerror", strerror(e),
	    BUNYAN_T_END);

	bbal_tcp_teardown(prx);
}

/*
 * Called when either the frontend or backend connection has been completely
 * torn down for whatever reason.  Once both have been torn down, free the
 * remaining
 */
static void
bbal_tcp_close(cconn_t *ccn, int event)
{
	proxy_t *prx = cconn_data(ccn);

	VERIFY3S(event, ==, CCONN_CB_CLOSE);

	/*
	 * Determine which connection was closed this time around.
	 */
	if (ccn == prx->prx_front) {
		bunyan_debug(prx->prx_log, "frontend connection closed",
		    BUNYAN_T_END);
		prx->prx_front = NULL;
	} else if (ccn == prx->prx_back) {
		bunyan_debug(prx->prx_log, "backend connection closed",
		    BUNYAN_T_END);
		prx->prx_back = NULL;
	} else {
		/*
		 * What connection is this?!
		 */
		abort();
	}

	if (prx->prx_front != NULL || prx->prx_back != NULL) {
		/*
		 * Connections still remain to be torn down.
		 */
		return;
	}

	bunyan_debug(prx->prx_log, "proxy connection finished", BUNYAN_T_END);
	bunyan_fini(prx->prx_log);
	timeout_free(prx->prx_connect_timeout);
	free(prx);
}

/*
 * This timeout callback is scheduled when we begin the process of connecting
 * to the backend to forward a new TCP connection.  The timeout is cleared
 * once the session is established and forwarding has begun; if the timeout
 * executes, we have waited too long and we abandon the attempt.
 */
static void
bbal_tcp_connect_timeout(timeout_t *to, void *arg)
{
	proxy_t *prx = arg;

	bunyan_error(prx->prx_log, "timed out connecting to backend",
	    BUNYAN_T_END);

	backend_t *be;
	if ((be = backend_lookup(prx->prx_backend)) != NULL) {
		bbal_backend_fault(be);
	}

	bbal_tcp_teardown(prx);
}

/*
 * This callback is triggered when an incoming connection has arrived on the
 * TCP listen port.  The connection is accepted and the process of establishing
 * a session to the appropriate backend is initiated.
 */
static void
bbal_tcp_incoming(cserver_t *cserver, int event)
{
	VERIFY3S(event, ==, CSERVER_CB_INCOMING);

	proxy_t *prx;
	if ((prx = calloc(1, sizeof (*prx))) == NULL ||
	    timeout_alloc(&prx->prx_connect_timeout) != 0) {
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
		bunyan_warn(g_log, "incoming TCP failure (bunyan child)",
		    BUNYAN_T_INT32, "errno", (int32_t)errno,
		    BUNYAN_T_STRING, "strerror", strerror(errno),
		    BUNYAN_T_END);
		goto fail;
	}

	bunyan_trace(prx->prx_log, "connecting to backend", BUNYAN_T_END);

	/*
	 * Begin connecting to the backend.
	 */
	if (bbal_connect_uds_common(be, &prx->prx_back) != 0) {
		goto fail;
	}

	/*
	 * If the connection has not been established in 10 seconds, we'll tear
	 * it down.  This connection happens in line with request processing,
	 * so a longer timeout would be visible to clients when a backend is
	 * failing.
	 */
	timeout_set(prx->prx_connect_timeout, 10, bbal_tcp_connect_timeout,
	    prx);

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
}

/*
 * Called at program startup to establish the front end TCP listen socket.
 */
int
bbal_tcp_listen(cserver_t *tcp, cloop_t *loop, const char *listen_ip,
    const char *listen_port)
{
	cserver_on(tcp, CSERVER_CB_INCOMING, bbal_tcp_incoming);
	if (cserver_listen_tcp(tcp, loop, listen_ip, listen_port,
	    BBAL_TCP_BACKLOG) != 0) {
		bunyan_fatal(g_log, "failed to create TCP listen socket",
		    BUNYAN_T_STRING, "address", listen_ip,
		    BUNYAN_T_STRING, "port", listen_port,
		    BUNYAN_T_INT32, "errno", (int32_t)errno,
		    BUNYAN_T_STRING, "strerror", strerror(errno),
		    BUNYAN_T_END);
		return (-1);
	}

	bunyan_info(g_log, "listening for TCP packets",
	    BUNYAN_T_STRING, "address", listen_ip,
	    BUNYAN_T_STRING, "port", listen_port,
	    BUNYAN_T_END);

	return (0);
}
