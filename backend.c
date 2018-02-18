/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright (c) 2018, Joyent, Inc.
 */

/*
 * BACKENDS
 *
 * DNS service is provided by a set of backend processes.  Each process listens
 * on a local socket (AF_UNIX) bound within a particular directory.  A special
 * protocol is defined for use on connections to these sockets, forming an
 * interface between the load balancer and backend processes.
 *
 * A particular backend is tracked by a "backend_t" object, indexed both by
 * backend ID and backend path in a pair of AVLs.
 *
 * PROTOCOL
 *
 * A simple protocol with framed messages allows the load balancer to forward
 * UDP packets between backend processes and remote peers, while providing
 * enough information for the backend to know the source of packets for logging
 * and instrumentation.  The protocol also allows a session to be converted
 * to a TCP proxy session, at which point data will be passed verbatim from
 * clients to the backend and vice versa.
 *
 * All integers are little-endian.  Every frame begins with a 32-bit unsigned
 * integer denoting the frame type.  Most frames are of a fixed length
 * determined by the frame type.  The following frames can be sent from the
 * load balancer to the backend server:
 *
 * 	CLIENT_HELLO		(type 1; frame type only)
 *
 * 	The first frame sent by the load balancer to the backend to establish
 * 	a session for health checks and forwarded UDP packets.  This frame
 * 	has no data other than the frame type.
 *
 * 	INBOUND_UDP		(type 2; header + data)
 *
 * 	Each inbound UDP packet is wrapped in a frame which includes the
 * 	source IPv4 address and port number for the packet, followed by
 * 	the length of the packet data and then the packet data itself.  The
 * 	frame layout is as follows:
 *
 * 		OFFSET	LENGTH	DESCRIPTION
 * 		0	4	[u32] frame type
 * 		4	4	[u32] source IPv4 address
 * 		8	4	[u32] source port number
 * 		12	4	[u32] packet data length
 * 		16	N	packet data
 *
 *	INBOUND_TCP		(type 3; header only)
 *
 *	Each inbound TCP connection is proxied through a separate local
 *	session to the backend.  This frame negotiates such a session, including
 *	details about the source of the connection.  The frame is fixed length,
 *	with the following layout:
 *
 *		OFFSET	LENGTH	DESCRIPTION
 *		0	4	[u32] frame type
 *		4	4	[u32] source IPv4 address
 *		8	4	[u32] source port number
 *
 *	The backend process is expected to respond with an INBOUND_TCP_OK
 *	frame, after which data will be forwarded between the remote peer
 *	and the backend without any additional framing.
 *
 *	CLIENT_HEARTBEAT	(type 4; frame type only)
 *
 *	This packet is sent by the load balancer to the backend periodically to
 *	ensure the backend is at least somewhat responsive.  The backend must
 *	respond promptly with a SERVER_HEARTBEAT frame.  This frame has no data
 *	other than the frame type.
 *
 * The backend server responds to requests from the load balancer with the
 * following frame types:
 *
 *	SERVER_HELLO		(type 1001; frame type only)
 *
 *	Sent in response to a CLIENT_HELLO frame, signalling readiness by the
 *	backend to process UDP packets and heartbeats on this connection.
 *	This frame has no data other than the frame type.
 *
 *	OUTBOUND_UDP		(type 1002; header + data)
 *
 *	This frame is the outbound analogue of INBOUND_UDP.  The backend
 *	uses it to instruct the load balancer to send an outbound UDP packet
 *	as a response to a particular DNS query.  The frame layout is as
 *	follows:
 *
 * 		OFFSET	LENGTH	DESCRIPTION
 * 		0	4	[u32] frame type
 * 		4	4	[u32] destination IPv4 address
 * 		8	4	[u32] destination port number
 * 		12	4	[u32] packet data length
 * 		16	N	packet data
 *
 *	INBOUND_TCP_OK		(type 1003; frame type only)
 *
 *	Sent in response to an INBOUND_TCP frame, this frame informs the
 *	load balancer that the backend will now treat this connection as
 *	if it were a TCP connection from the designated remote peer.
 *	The frame has no data other than the frame type, and is the last
 *	frame the backend will send on this connection.
 *
 *	SERVER_HEARTBEAT	(type 1004; frame type only)
 *
 *	Sent in response to a CLIENT_HEARTBEAT message.  The frame has no
 *	data other than the frame type.
 */

#include "bbal.h"

static avl_tree_t g_backends;
static avl_tree_t g_backends_by_path;

static uint32_t g_backend_last_assigned = 0;

static char *g_backends_path = NULL;
static cloop_t *g_backends_loop = NULL;

/*
 * Track the last time a "no backends available" error was emitted, so that we
 * can avoid filling the disk with these log messages.
 */
static hrtime_t g_backend_last_error = 0;

static int bbal_connect_uds(backend_t *be);


static int
backends_compar(const void *first, const void *second)
{
	const backend_t *bf = first;
	const backend_t *bs = second;

	return (compare_u32(bf->be_id, bs->be_id));
}

static int
backends_compar_by_path(const void *first, const void *second)
{
	const backend_t *bf = first;
	const backend_t *bs = second;

	return (compare_str(bf->be_path, bs->be_path));
}

backend_t *
backend_lookup(uint32_t id)
{
	backend_t search;
	search.be_id = id;

	if (id == 0) {
		/*
		 * Backend ID zero is reserved to mean a backend is not
		 * assigned.
		 */
		return (NULL);
	}

	return (avl_find(&g_backends, &search, NULL));
}

backend_t *
backend_lookup_by_path(const char *path)
{
	VERIFY3P(path, !=, NULL);

	backend_t search;
	search.be_path = (char *)path;

	return (avl_find(&g_backends_by_path, &search, NULL));
}

/*
 * Select a backend.  Cycles through backends in order of their ID, skipping
 * any that are not currently healthy.  This is, in effect, a simple
 * round-robin assignment policy.
 */
backend_t *
backends_select(void)
{
	ulong_t nnodes = avl_numnodes(&g_backends);

	/*
	 * Start at the backend we have most recently assigned.  If no backend
	 * has ever been assigned, we'll get NULL here and move to the start
	 * of the list within the loop body.
	 */
	backend_t *be = backend_lookup(g_backend_last_assigned);

	for (unsigned n = 0; n < nnodes; n++) {
		if (be != NULL) {
			/*
			 * Move to the next backend in the list.
			 */
			be = AVL_NEXT(&g_backends, be);
		}

		if (be == NULL) {
			/*
			 * If there is no backend, move to the start of the
			 * list.
			 */
			be = avl_first(&g_backends);
		}

		if (be->be_ok) {
			/*
			 * We believe this backend is alive and can be used
			 * for new remotes.
			 */
			g_backend_last_assigned = be->be_id;
			return (be);
		}
	}

	/*
	 * No backends were available.  Log a message to report this condition,
	 * but only if we haven't already reported it recently.
	 */
	hrtime_t now = gethrtime();
	if (g_backend_last_error == 0 || (now - g_backend_last_error) >
	    SECONDS_IN_NS(5)) {
		bunyan_error(g_log, "no backends available", BUNYAN_T_END);
		g_backend_last_error = now;
	}
	return (NULL);
}

/*
 * Allocate a new backend object for the process bound to this socket path.
 */
static int
backend_create(cloop_t *loop, const char *path, backend_t **bep)
{
	int e;

	VERIFY3P(loop, !=, NULL);

	backend_t *be;
	if ((be = calloc(1, sizeof (*be))) == NULL) {
		return (-1);
	}

	if ((be->be_path = strdup(path)) == NULL) {
		goto fail;
	}

	if (cbufq_alloc(&be->be_input) != 0) {
		e = errno;
		goto fail;
	}

	if (timeout_alloc(&be->be_connect_timeout) != 0 ||
	    timeout_alloc(&be->be_reconnect_timeout) != 0 ||
	    timeout_alloc(&be->be_heartbeat_timeout) != 0) {
		e = errno;
		goto fail;
	}

	be->be_loop = loop;
	be->be_ok = B_FALSE;
	be->be_reconnect = B_FALSE;

	const char *bn = strrchr(path, '/');
	if (bn != NULL) {
		int pathid = atoi(bn + 1);

		/*
		 * By convention, binder will be creating socket names that
		 * match the high numbered port on which the instance will
		 * listen for direct DNS queries.  If this socket has a name
		 * that appears to fit in the expected range, use that number
		 * as the backend ID to make the logs easier to reason about.
		 */
		if (pathid >= 5300 && pathid <= 5399) {
			if (backend_lookup(pathid) == NULL) {
				be->be_id = pathid;
			}
		}
	}

	if (be->be_id == 0) {
		/*
		 * Determine the next available backend ID.
		 */
		backend_t *be_max = avl_last(&g_backends);
		be->be_id = be_max != NULL ? be_max->be_id + 1 : 1;
	}

	/*
	 * We reserve ID 0 to mean no backend is assigned.
	 */
	VERIFY3U(be->be_id, !=, 0);

	if (bunyan_child(g_log, &be->be_log,
	    BUNYAN_T_INT32, "be_id", be->be_id,
	    BUNYAN_T_STRING, "be_path", be->be_path,
	    BUNYAN_T_END) != 0) {
		e = errno;
		goto fail;
	}

	bunyan_info(be->be_log, "new backend", BUNYAN_T_END);

	avl_add(&g_backends, be);
	avl_add(&g_backends_by_path, be);

	if (bep != NULL) {
		*bep = be;
	}
	return (0);

fail:
	if (be->be_log != NULL) {
		bunyan_fini(be->be_log);
	}
	cbufq_free(be->be_input);
	free(be->be_path);
	timeout_free(be->be_connect_timeout);
	timeout_free(be->be_reconnect_timeout);
	timeout_free(be->be_heartbeat_timeout);
	free(be);
	errno = e;
	return (-1);
}


/*
 * Timeout callback triggered by "bbal_backend_reconnect()" for a delayed
 * reconnection.
 */
static void
bbal_backend_reconnect_cb(timeout_t *to, void *arg)
{
	backend_t *be = arg;

	VERIFY(be->be_reconnect == B_TRUE);
	VERIFY(be->be_ok == B_FALSE);

	bunyan_info(be->be_log, "connecting to backend", BUNYAN_T_END);

	if (bbal_connect_uds(be) != 0) {
		bunyan_error(be->be_log, "failed to connect",
		    BUNYAN_T_INT32, "errno", (int32_t)errno,
		    BUNYAN_T_STRING, "strerror", strerror(errno),
		    BUNYAN_T_END);

		/*
		 * This attempt at a connection failed.  Try again shortly.
		 */
		be->be_reconnect = B_FALSE;
		bbal_backend_reconnect(be);
		return;
	}

	be->be_reconnect = B_FALSE;
}

/*
 * Called to trigger a reconnection for a backend that is already connected,
 * or the initial connection for a newly created backend.
 */
void
bbal_backend_reconnect(backend_t *be)
{
	if (be->be_reconnect) {
		VERIFY(!be->be_ok);

		/*
		 * Reconnection already triggered.
		 */
		return;
	}

	/*
	 * Do not use this backend for any more proxied traffic until the
	 * reconnect cycle is complete.
	 */
	be->be_ok = B_FALSE;

	if (be->be_conn != NULL) {
		/*
		 * The existing socket has not yet been closed so we need to
		 * force it closed.
		 */
		VERIFY0(cconn_abort(be->be_conn));
		return;
	}

	be->be_reconnect = B_TRUE;

	bunyan_debug(be->be_log, "reconnect triggered for backend",
	    BUNYAN_T_UINT32, "delay_secs", be->be_reconnect_delay,
	    BUNYAN_T_END);

	timeout_set(be->be_reconnect_timeout, be->be_reconnect_delay,
	    bbal_backend_reconnect_cb, be);

	if (be->be_reconnect_delay == 0) {
		be->be_reconnect_delay = MIN_RECONNECT_DELAY_SECS;
	} else if (be->be_reconnect_delay < MAX_RECONNECT_DELAY_SECS) {
		/*
		 * Increase the reconnect delay for subsequent attempts, as
		 * a basic form of back-off.  This delay will be reset
		 * after the next successful connection.
		 */
		be->be_reconnect_delay += 2;
	}
}

/*
 * Mark a backend as faulted.  Newly arrived UDP packets or TCP connections
 * will be directed to another backend, if one is available.  The existing
 * connection to this backend will be torn down and reestablished.
 */
void
bbal_backend_fault(backend_t *be)
{
	if (be->be_ok) {
		bunyan_error(be->be_log, "backend faulted (reset and "
		    "reconnect)", BUNYAN_T_END);
	}
	be->be_ok = B_FALSE;

	/*
	 * Trigger a reconnection.
	 */
	bbal_backend_reconnect(be);
}

/*
 * When a heartbeat has been sent by the "backend_send_heartbeat" function,
 * this timeout is scheduled to make sure it arrives within the expected
 * interval.  If the heartbeat response arrives on time, this timeout will
 * be cleared and the callback will not fire.
 */
static void
backend_no_heartbeat(timeout_t *to, void *arg)
{
	backend_t *be = arg;

	if (!be->be_ok) {
		/*
		 * The timeout will be rearmed the next time we are connected
		 * to the backend.
		 */
		return;
	}

	/*
	 * We have an outstanding heartbeat for which we have not received a
	 * reply in a reasonable time frame.  Terminate this connection.
	 */
	bunyan_error(be->be_log, "no heartbeat from backend (aborting "
	    "connection)", BUNYAN_T_END);
	be->be_ok = B_FALSE;
	cconn_abort(be->be_conn);
}

/*
 * Scheduled for each successfully established session to a backend, this
 * callback fires when it is time to send a periodic heartbeat to check backend
 * session health.
 */
static void
backend_send_heartbeat(timeout_t *to, void *arg)
{
	backend_t *be = arg;

	if (!be->be_ok) {
		/*
		 * The timeout will be rearmed the next time we are connected
		 * to the backend.
		 */
		return;
	}

	/*
	 * Send a heartbeat message to the remote peer.
	 */
	cbuf_t *buf;
	if (cbuf_alloc(&buf, 4) != 0) {
		goto rearm;
	}
	cbuf_byteorder_set(buf, CBUF_ORDER_LITTLE_ENDIAN);
	VERIFY0(cbuf_put_u32(buf, FRAME_TYPE_CLIENT_HEARTBEAT));
	if (cconn_send(be->be_conn, buf) != 0) {
		cbuf_free(buf);
		goto rearm;
	}

	bunyan_trace(be->be_log, "heartbeat sent", BUNYAN_T_END);

	/*
	 * Use our existing heartbeat timeout object to wait for up to 15
	 * seconds for a response to our heartbeat frame.  This timeout
	 * will be cleared if the response arrives before it expires.
	 */
	timeout_set(be->be_heartbeat_timeout, 15, backend_no_heartbeat, be);
	return;

rearm:
	/*
	 * We couldn't send a heartbeat frame.  Try again soon.
	 */
	timeout_set(be->be_heartbeat_timeout, 1, backend_send_heartbeat, be);
}

/*
 * Callback triggered when new data is available for a particular backend
 * session.
 */
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

		if (cbufq_pullup(q, sizeof (uint32_t)) != 0) {
			if (errno == EIO) {
				/*
				 * We need at least four bytes in order to read
				 * the frame type.
				 */
				cconn_more_data(ccn);
				return;
			}

			bunyan_fatal(be->be_log, "could not pullup",
			    BUNYAN_T_INT32, "errno", (int32_t)errno,
			    BUNYAN_T_STRING, "strerror", strerror(errno),
			    BUNYAN_T_END);
			exit(1);
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

		switch (frame_type) {
		case FRAME_TYPE_SERVER_HELLO:
			/*
			 * SERVER_HELLO.  Just the frame type; nothing else.
			 */
			bunyan_info(be->be_log, "backend socket established",
			    BUNYAN_T_END);
			timeout_clear(be->be_connect_timeout);
			timeout_set(be->be_heartbeat_timeout, 5,
			    backend_send_heartbeat, be);
			be->be_ok = B_TRUE;

			/*
			 * Reset the reconnect delay back-off time to the
			 * minimum value.
			 */
			be->be_reconnect_delay = MIN_RECONNECT_DELAY_SECS;
			continue;

		case FRAME_TYPE_SERVER_HEARTBEAT:
			/*
			 * The server is responding to our periodic heartbeat
			 * request.
			 */
			bunyan_trace(be->be_log, "received heartbeat reply",
			    BUNYAN_T_END);
			timeout_set(be->be_heartbeat_timeout, 5,
			    backend_send_heartbeat, be);
			continue;

		case FRAME_TYPE_OUTBOUND_UDP:
			break;

		default:
			bunyan_error(be->be_log, "invalid frame type",
			    BUNYAN_T_UINT32, "frame_type", frame_type,
			    BUNYAN_T_END);
			bbal_backend_fault(be);
			return;
		}

		/*
		 * An OUTBOUND_UDP frame has three uint32_t values after the
		 * frame type.
		 */
		if (cbufq_pullup(q, 3 * sizeof (uint32_t)) != 0) {
			if (errno == EIO) {
				/*
				 * Wait for the entire frame header to arrive.
				 */
				VERIFY0(cbuf_position_set(cbuf, marker));
				break;
			}

			bunyan_fatal(be->be_log, "could not pullup",
			    BUNYAN_T_INT32, "errno", (int32_t)errno,
			    BUNYAN_T_STRING, "strerror", strerror(errno),
			    BUNYAN_T_END);
			exit(1);
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

		if (datalen > 1500) {
			bunyan_warn(be->be_log, "backend sent oversized UDP "
			    "packet",
			    BUNYAN_T_UINT32, "len", datalen,
			    BUNYAN_T_END);
			bbal_backend_fault(be);
			return;
		}

		/*
		 * Make sure all of the data that we expect in the frame has
		 * arrived, and that it is contiguous in memory so we can pass
		 * it to sendto(3SOCKET).
		 */
		if (cbufq_pullup(q, datalen) != 0) {
			if (errno == EIO) {
				/*
				 * The data has not yet arrived.
				 */
				VERIFY0(cbuf_position_set(cbuf, marker));
				break;
			}

			bunyan_fatal(be->be_log, "could not pullup",
			    BUNYAN_T_INT32, "errno", (int32_t)errno,
			    BUNYAN_T_STRING, "strerror", strerror(errno),
			    BUNYAN_T_END);
			exit(1);
			return;
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

/*
 * Callback triggered when a local connection to the backend has been
 * established.
 */
static void
bbal_uds_connected(cconn_t *ccn, int event)
{
	backend_t *be = cconn_data(ccn);

	VERIFY(!be->be_ok);

	bunyan_info(be->be_log, "backend socket connected", BUNYAN_T_END);

	/*
	 * Send a CLIENT_HELLO frame.  This frame consists entirely of the
	 * frame type number.
	 */
	cbuf_t *buf;
	if (cbuf_alloc(&buf, sizeof (uint32_t)) != 0) {
		bunyan_error(be->be_log, "could not allocate buffer",
		    BUNYAN_T_INT32, "errno", (int32_t)errno,
		    BUNYAN_T_STRING, "strerror", strerror(errno),
		    BUNYAN_T_END);
		bbal_backend_fault(be);
		return;
	}
	cbuf_byteorder_set(buf, CBUF_ORDER_LITTLE_ENDIAN);
	VERIFY0(cbuf_put_u32(buf, FRAME_TYPE_CLIENT_HELLO));

	if (cconn_send(ccn, buf) != 0) {
		bunyan_error(be->be_log, "sending hello frame",
		    BUNYAN_T_INT32, "errno", (int32_t)errno,
		    BUNYAN_T_STRING, "strerror", strerror(errno),
		    BUNYAN_T_END);
		bbal_backend_fault(be);
		return;
	}
}

/*
 * Callback triggered if the backend shuts the local socket for write.  This
 * should not happen during normal operation, but may happen if the backend is
 * being restarted for some reason.
 */
static void
bbal_uds_end(cconn_t *ccn, int event)
{
	backend_t *be = cconn_data(ccn);

	bunyan_warn(be->be_log, "backend socket EOF", BUNYAN_T_END);

	bbal_backend_fault(be);
}

/*
 * Callback triggered if the backend socket experiences an error condition.
 */
static void
bbal_uds_error(cconn_t *ccn, int event)
{
	backend_t *be = cconn_data(ccn);

	bunyan_error(be->be_log, "backend socket error", BUNYAN_T_END);
	be->be_stat_conn_error++;

	bbal_backend_fault(be);
}

/*
 * Callback triggered once the backend socket connection is fully torn down by
 * the server framework, and all resources have been released.  We use this
 * opportunity to initiate a reconnection attempt.
 */
static void
bbal_uds_close(cconn_t *ccn, int event)
{
	backend_t *be = cconn_data(ccn);

	bunyan_info(be->be_log, "backend socket closed", BUNYAN_T_END);

	be->be_ok = B_FALSE;

	timeout_clear(be->be_connect_timeout);
	timeout_clear(be->be_heartbeat_timeout);

	/*
	 * Note that the CLOSE event will free the connection object, so we
	 * need to forget about it here.
	 */
	be->be_conn = NULL;

	/*
	 * Trigger a reconnection.
	 */
	bbal_backend_reconnect(be);
}

/*
 * Make a connection to the local socket for this backend.  This connection
 * can be used for either the standing control and UDP packet session for
 * a backend, or a TCP proxy session.
 */
int
bbal_connect_uds_common(backend_t *be, cconn_t **ccnp)
{
	int e;
	int sock = -1;
	struct sockaddr_un sun;
	cconn_t *ccn = NULL;

	if (cconn_alloc(&ccn) != 0) {
		e = errno;
		bunyan_error(be->be_log, "backend cconn_alloc failed",
		    BUNYAN_T_INT32, "errno", errno,
		    BUNYAN_T_STRING, "strerror", strerror(errno),
		    BUNYAN_T_END);
		goto fail;
	}
	cconn_byteorder_set(ccn, CBUF_ORDER_LITTLE_ENDIAN);

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

	cconn_attach(be->be_loop, ccn, sock);

	*ccnp = ccn;
	return (0);

fail:
	be->be_stat_conn_error++;
	cconn_destroy(ccn);
	if (sock != -1) {
		VERIFY0(close(sock));
	}
	errno = e;
	return (-1);
}

/*
 * Callback triggered when a connection to a local backend has been outstanding
 * without completing and receiving a SERVER_HELLO frame.
 */
static void
bbal_connect_timeout(timeout_t *to, void *arg)
{
	backend_t *be = arg;

	VERIFY3P(be->be_conn, !=, NULL);

	bunyan_warn(be->be_log, "timed out connecting to backend",
	    BUNYAN_T_END);

	bbal_backend_fault(be);
}

/*
 * Establish the standing connection to this backend that we use to forward
 * UDP packets to and from remote peers.
 */
static int
bbal_connect_uds(backend_t *be)
{
	int e;

	VERIFY3P(be->be_conn, ==, NULL);
	if (bbal_connect_uds_common(be, &be->be_conn) != 0) {
		e = errno;
		goto fail;
	}

	cconn_data_set(be->be_conn, be);
	cconn_on(be->be_conn, CCONN_CB_CONNECTED, bbal_uds_connected);
	cconn_on(be->be_conn, CCONN_CB_END, bbal_uds_end);
	cconn_on(be->be_conn, CCONN_CB_ERROR, bbal_uds_error);
	cconn_on(be->be_conn, CCONN_CB_CLOSE, bbal_uds_close);
	cconn_on(be->be_conn, CCONN_CB_DATA_AVAILABLE, bbal_uds_data);

	/*
	 * If the connection has not been completely established in 30 seconds,
	 * we'll tear it down and try again.
	 */
	timeout_set(be->be_connect_timeout, 30, bbal_connect_timeout, be);

	return (0);

fail:
	cconn_destroy(be->be_conn);
	be->be_conn = NULL;
	errno = e;
	return (-1);
}

/*
 * Check the backend socket directory to see if any new backends have become
 * available.  This function is called once at startup, and then periodically
 * from a timer.
 */
void
backends_refresh()
{
	const char *path = g_backends_path;
	DIR *sockdir;

	VERIFY3P(g_backends_loop, !=, NULL);

	if ((sockdir = opendir(path)) == NULL) {
		bunyan_error(g_log, "error opening socket directory",
		    BUNYAN_T_STRING, "socket_dir", path,
		    BUNYAN_T_INT32, "errno", (int32_t)errno,
		    BUNYAN_T_STRING, "error", strerror(errno),
		    BUNYAN_T_END);
		return;
	}

	for (;;) {
		struct dirent *de;

		errno = 0;
		if ((de = readdir(sockdir)) == NULL) {
			if (errno != 0) {
				bunyan_error(g_log, "error reading socket "
				    "directory",
				    BUNYAN_T_STRING, "socket_dir", path,
				    BUNYAN_T_INT32, "errno", (int32_t)errno,
				    BUNYAN_T_STRING, "error", strerror(errno),
				    BUNYAN_T_END);
			}
			break;
		}

		if (strcmp(de->d_name, ".") == 0 ||
		    strcmp(de->d_name, "..") == 0) {
			continue;
		}

		/*
		 * The backend path name needs to fit in the 108 characters
		 * available in the "sun_path" member of "struct sockaddr_un".
		 */
		char sockpath[108];
		VERIFY3S(snprintf(sockpath, sizeof (sockpath), "%s/%s",
		    path, de->d_name), <, sizeof (sockpath));

		backend_t *be;
		if ((be = backend_lookup_by_path(sockpath)) != NULL) {
			/*
			 * There is already a backend for this path.
			 */
			continue;
		}

		if (backend_create(g_backends_loop, sockpath, &be) != 0) {
			bunyan_fatal(g_log, "backend_create failed",
			    BUNYAN_T_STRING, "socket_path", sockpath,
			    BUNYAN_T_INT32, "errno", (int32_t)errno,
			    BUNYAN_T_STRING, "error", strerror(errno),
			    BUNYAN_T_END);
			exit(1);
		}

		/*
		 * For newly discovered backends, we want to trigger an
		 * immediate connection attempt.
		 */
		be->be_reconnect_delay = 0;
		bbal_backend_reconnect(be);
	}

	VERIFY0(closedir(sockdir));
}

/*
 * Checks to make sure that remotes are reasonably balanced across the set of
 * currently active backends.  If this is not the case, reset the association
 * of some number of remotes that are presently assigned to the backend with
 * the most remotes assigned.  This function is run periodically from a timer.
 */
void
backends_rebalance(void)
{
	/*
	 * Determine the minimum and the maximum count of remotes per backend
	 * for all backends.
	 */
	int32_t max_count = -1;
	uint32_t max_backend_id = 0;
	int32_t min_count = -1;

	for (backend_t *be = avl_first(&g_backends); be != NULL;
	    be = AVL_NEXT(&g_backends, be)) {
		if (!be->be_ok) {
			/*
			 * If a backend is not online, do not consider it
			 * in the rebalancing process.
			 */
			continue;
		}

		if (max_count == -1 || be->be_remotes > (uint32_t)max_count) {
			max_backend_id = be->be_id;
			max_count = be->be_remotes;
		}
		if (min_count == -1 || be->be_remotes < (uint32_t)min_count) {
			min_count = be->be_remotes;
		}
	}

	/*
	 * Check to see what the spread is.
	 */
	uint32_t spread = max_count - min_count;
	bunyan_trace(g_log, "balancer spread statistics",
	    BUNYAN_T_INT32, "max_count", max_count,
	    BUNYAN_T_INT32, "min_count", min_count,
	    BUNYAN_T_UINT32, "max_be_id", max_backend_id,
	    BUNYAN_T_UINT32, "spread", spread,
	    BUNYAN_T_END);

	if (min_count == -1 || max_count == -1) {
		/*
		 * There are no working backends.  Skip rebalancing completely.
		 */
		return;
	}

	ulong_t nbe = avl_numnodes(&g_backends);
	if (spread > nbe) {
		remotes_rebalance(max_backend_id, spread - nbe);
	}
}

int
backends_init(cloop_t *loop, const char *path)
{
	VERIFY3P(g_backends_loop, ==, NULL);
	g_backends_loop = loop;

	VERIFY3P(g_backends_path, ==, NULL);
	if ((g_backends_path = strdup(path)) == NULL) {
		return (-1);
	}

	avl_create(&g_backends, backends_compar, sizeof (backend_t),
	    offsetof(backend_t, be_node));

	avl_create(&g_backends_by_path, backends_compar_by_path,
	    sizeof (backend_t), offsetof(backend_t, be_node_by_path));

	return (0);
}
