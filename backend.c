


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


static void
bbal_uds_data(cconn_t *ccn, int event)
{
	backend_t *be = cconn_data(ccn);

	VERIFY(event == CCONN_CB_DATA_AVAILABLE);

	for (;;) {
		cbufq_t *q = cconn_recvq(ccn);

		/*
		 * Remove any truly empty buffers from the front of the queue.
		 */
		while (cbufq_peek(q) != NULL &&
		    cbuf_available(cbufq_peek(q)) == 0) {
			cbuf_free(cbufq_deq(q));
		}

		if (cbufq_available(q) < sizeof (uint32_t)) {
			/*
			 * We need at least four bytes in order to read the
			 * frame type.
			 */
			cconn_more_data(ccn);
			return;
		}

		if (cbufq_pullup(q, sizeof (uint32_t)) != 0) {
			err(1, "cbufq_pullup");
			return;
		}

		/*
		 * Look at the first buffer in the queue, and stash the position
		 * in a marker in case there isn't enough data and we need to
		 * rewind.
		 */
		cbuf_t *cbuf = cbufq_peek(q);
		size_t marker = cbuf_position(cbuf);

		uint32_t frame_type;
		VERIFY0(cbuf_get_u32(cbuf, &frame_type));

		bunyan_trace(be->be_log, "inbound frame",
		    BUNYAN_T_UINT32, "frame_type", frame_type,
		    BUNYAN_T_END);

		if (frame_type == 1001) {
			/*
			 * SERVER_HELLO.  Just the frame type; nothing else.
			 */
			be->be_ok = B_TRUE;
			continue;
		}

		if (frame_type != 1002) {
			bunyan_error(be->be_log, "invalid frame type",
			    BUNYAN_T_UINT32, "frame_type", frame_type,
			    BUNYAN_T_END);
			cconn_abort(ccn);
			return;
		}

		if (cbufq_available(q) < 3 * sizeof (uint32_t)) {
			/*
			 * This frame has three uint32_t values after the
			 * frame type, but they have not yet arrived.
			 */
			VERIFY0(cbuf_position_set(cbuf, marker));
			break;
		}

		if (cbufq_pullup(q, 3 * sizeof (uint32_t)) != 0) {
			err(1, "cbufq_pullup");
			return;
		}

		/*
		 * Read the IP address, the port, and the frame data length
		 * value from the header.
		 */
		uint32_t ipaddr, port, datalen;
		VERIFY0(cbuf_get_u32(cbuf, &ipaddr));
		VERIFY0(cbuf_get_u32(cbuf, &port));
		VERIFY0(cbuf_get_u32(cbuf, &datalen));

		if (cbufq_pullup(q, datalen) != 0) {
			/*
			 * The data has not yet arrived.
			 */
			VERIFY0(cbuf_position_set(cbuf, marker));
			break;
		}

		struct sockaddr_in sin;
		bzero(&sin, sizeof (sin));

		sin.sin_family = AF_INET;
		sin.sin_addr.s_addr = htonl(ipaddr);
		sin.sin_port = htons(port);

		bunyan_trace(be->be_log, "outbound UDP packet",
		    BUNYAN_T_IP, "dest_ip", &sin.sin_addr,
		    BUNYAN_T_UINT32, "dest_port", port,
		    BUNYAN_T_UINT32, "data_len", datalen,
		    BUNYAN_T_END);

		size_t actual;
again:
		if (cbuf_sys_sendto(cbuf, g_sock, datalen, &actual,
		    MSG_NOSIGNAL, (struct sockaddr *)&sin, sizeof (sin)) != 0) {
			if (errno == EINTR) {
				goto again;
			}

			bunyan_error(be->be_log, "outbound UDP packet error",
			    BUNYAN_T_IP, "dest_ip", &sin.sin_addr,
			    BUNYAN_T_UINT32, "dest_port", port,
			    BUNYAN_T_UINT32, "data_len", datalen,
			    BUNYAN_T_INT32, "errno", (int32_t)errno,
			    BUNYAN_T_STRING, "strerror", strerror(errno),
			    BUNYAN_T_END);

			/*
			 * These are UDP packets; treat this one as if it were
			 * dropped.
			 */
			VERIFY0(cbuf_skip(cbuf, datalen));
		}
		VERIFY3U(actual, ==, datalen);
	}

	cconn_more_data(ccn);
}

static void
bbal_uds_connected(cconn_t *ccn, int event)
{
	backend_t *be = cconn_data(ccn);

	VERIFY(!be->be_ok);

	bunyan_info(be->be_log, "backend socket connected", BUNYAN_T_END);

	cbuf_t *buf;
	if (cbuf_alloc(&buf, 4) != 0) {
		err(1, "cbuf_alloc");
	}
	cbuf_byteorder_set(buf, CBUF_ORDER_LITTLE_ENDIAN);
	VERIFY0(cbuf_put_u32(buf, 1));

	if (cconn_send(ccn, buf) != 0) {
		bunyan_error(be->be_log, "sending hello frame",
		    BUNYAN_T_INT32, "errno", (int32_t)errno,
		    BUNYAN_T_STRING, "strerror", strerror(errno),
		    BUNYAN_T_END);
		goto close_be;
	}

	return;

close_be:
	be->be_ok = B_FALSE;
	cconn_abort(ccn);
}

static void
bbal_uds_end(cconn_t *ccn, int event)
{
	backend_t *be = cconn_data(ccn);

	bunyan_info(be->be_log, "backend socket EOF", BUNYAN_T_END);

	be->be_ok = B_FALSE;
	cconn_fin(ccn);
}

static void
bbal_uds_error(cconn_t *ccn, int event)
{
	backend_t *be = cconn_data(ccn);

	bunyan_error(be->be_log, "backend socket error", BUNYAN_T_END);
	be->be_stat_conn_error++;

	be->be_ok = B_FALSE;
}

static void
bbal_uds_close(cconn_t *ccn, int event)
{
	backend_t *be = cconn_data(ccn);

	bunyan_info(be->be_log, "backend socket closed", BUNYAN_T_END);

	be->be_ok = B_FALSE;
	be->be_reconnect = B_TRUE;

	/*
	 * XXX the CLOSE event currently calls destroy on the socket...
	 */
	be->be_conn = NULL;
}

static int
bbal_connect_uds_common(backend_t *be, int *sockp)
{
	int e;
	int sock = -1;
	struct sockaddr_un sun;

	if ((sock = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC,
	    0)) < 0) {
		e = errno;
		bunyan_error(be->be_log, "socket(2) failed",
		    BUNYAN_T_INT32, "errno", e,
		    BUNYAN_T_STRING, "strerror", strerror(e),
		    BUNYAN_T_END);
		goto fail;
	}

	bzero(&sun, sizeof (sun));
	sun.sun_family = AF_UNIX;
	snprintf(sun.sun_path, sizeof (sun.sun_path), "%s", be->be_path);

	be->be_stat_conn_start++;

	if (connect(sock, (struct sockaddr *)&sun, sizeof (sun)) != 0 &&
	    errno != EINPROGRESS) {
		e = errno;
		bunyan_error(be->be_log, "connect(3SOCKET) failed",
		    BUNYAN_T_STRING, "socket_path", be->be_path,
		    BUNYAN_T_INT32, "errno", e,
		    BUNYAN_T_STRING, "strerror", strerror(e),
		    BUNYAN_T_END);
		goto fail;
	}

	*sockp = sock;
	return (0);

fail:
	be->be_stat_conn_error++;
	if (sock != -1) {
		VERIFY0(close(sock));
	}
	errno = e;
	return (-1);
}

/*
 * Make a new connection to this backend for use in proxying a TCP connection.
 */
int
bbal_connect_uds_tcp(backend_t *be, cconn_t **ccnp)
{
	cconn_t *ccn;

	if (cconn_alloc(&ccn) != 0) {
		bunyan_error(be->be_log, "cconn_alloc for TCP failed",
		    BUNYAN_T_INT32, "errno", errno,
		    BUNYAN_T_STRING, "strerror", strerror(errno),
		    BUNYAN_T_END);
		return (-1);
	}
	cconn_byteorder_set(ccn, CBUF_ORDER_LITTLE_ENDIAN);

	int sock;
	if (bbal_connect_uds_common(be, &sock) != 0) {
		cconn_destroy(ccn);
		return (-1);
	}

	cconn_attach(be->be_loop, ccn, sock);

	*ccnp = ccn;
	return (0);
}

/*
 * Establish the standing connection to this backend that we use to forward
 * UDP packets to and from remote peers.
 */
int
bbal_connect_uds(backend_t *be)
{
	int e;
	int sock = -1;

	if (bbal_connect_uds_common(be, &sock) != 0) {
		return (-1);
	}

	cconn_destroy(be->be_conn);
	if (cconn_alloc(&be->be_conn) != 0) {
		e = errno;
		bunyan_error(be->be_log, "cconn_alloc for UDP failed",
		    BUNYAN_T_INT32, "errno", e,
		    BUNYAN_T_STRING, "strerror", strerror(e),
		    BUNYAN_T_END);
		goto fail;
	}
	cconn_byteorder_set(be->be_conn, CBUF_ORDER_LITTLE_ENDIAN);
	cconn_data_set(be->be_conn, be);

	cconn_on(be->be_conn, CCONN_CB_CONNECTED, bbal_uds_connected);
	cconn_on(be->be_conn, CCONN_CB_END, bbal_uds_end);
	cconn_on(be->be_conn, CCONN_CB_ERROR, bbal_uds_error);
	cconn_on(be->be_conn, CCONN_CB_CLOSE, bbal_uds_close);
	cconn_on(be->be_conn, CCONN_CB_DATA_AVAILABLE, bbal_uds_data);

	cconn_attach(be->be_loop, be->be_conn, sock);

	return (0);

fail:
	if (sock != -1) {
		VERIFY0(close(sock));
	}
	errno = e;
	return (-1);
}
