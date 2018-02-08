


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

bunyan_logger_t *g_log;

int g_sock = -1;

typedef struct {
	int be_id;
	char *be_path;

	cloop_t *be_loop;
	cconn_t *be_conn;

	boolean_t be_ok;
	boolean_t be_reconnect;

	list_node_t be_link;

	cbufq_t *be_input;

	bunyan_logger_t *be_log;
} backend_t;

list_t g_backends;

static backend_t *
backend_lookup(int id)
{
	for (backend_t *be = list_head(&g_backends); be != NULL;
	    be = list_next(&g_backends, be)) {
		if (be->be_id == id) {
			return (be);
		}
	}

	return (NULL);
}

static int
backends_init(cloop_t *loop)
{
	list_create(&g_backends, sizeof (backend_t), offsetof(backend_t,
	    be_link));

	backend_t *be;
	if ((be = calloc(1, sizeof (*be))) == NULL) {
		return (-1);
	}

	if (cbufq_alloc(&be->be_input) != 0) {
		free(be);
		return (-1);
	}

	be->be_loop = loop;
	be->be_id = 1;
	be->be_path = strdup("/tmp/bbal.0");
	be->be_ok = B_FALSE;
	be->be_reconnect = B_TRUE;

	if (bunyan_child(g_log, &be->be_log,
	    BUNYAN_T_INT32, "be_id", be->be_id,
	    BUNYAN_T_STRING, "be_path", be->be_path,
	    BUNYAN_T_END) != 0) {
		cbufq_free(be->be_input);
		free(be);
		return (-1);
	}

	list_insert_tail(&g_backends, be);

	return (0);
}

typedef struct {
	struct in_addr rem_addr;
	int rem_backend;
	avl_node_t rem_node;
} remote_t;

avl_tree_t g_remotes;

static int
remotes_compar(const void *first, const void *second)
{
	const remote_t *rf = first;
	const remote_t *rs = second;

	if (rf->rem_addr.s_addr < rs->rem_addr.s_addr) {
		return (-1);
	} else if (rf->rem_addr.s_addr > rs->rem_addr.s_addr) {
		return (1);
	} else {
		return (0);
	}
}

static int
remotes_init(void)
{
	avl_create(&g_remotes, remotes_compar, sizeof (remote_t),
	    offsetof(remote_t, rem_node));

	return (0);
}

static remote_t *
remote_lookup(const struct in_addr *addr)
{
	remote_t search;
	search.rem_addr = *addr;

	avl_index_t where;
	remote_t *rem;
	if ((rem = avl_find(&g_remotes, &search, &where)) != NULL) {
		return (rem);
	}

	/*
	 * XXX need backend selection
	 */
	backend_t *be = backend_lookup(1);
	if (be == NULL) {
		errno = ENXIO;
		return (NULL);
	}

	/*
	 * The remote does not exist; create it.
	 */
	if ((rem = calloc(1, sizeof (*rem))) == NULL) {
		return (NULL);
	}

	rem->rem_addr = *addr;
	rem->rem_backend = be->be_id;

	avl_insert(&g_remotes, rem, where);

	return (rem);
}


static int
bbal_parse_ipv4addr(const char *ipaddr, const char *port,
    struct sockaddr_in *addr)
{
	bzero(addr, sizeof (*addr));

	addr->sin_family = AF_INET;
	addr->sin_port = htons(atoi(port));

	switch (inet_pton(AF_INET, ipaddr, &addr->sin_addr)) {
	case 1:
		return (0);

	case 0:
		warnx("inet_pton (%s) invalid address", ipaddr);
		errno = EPROTO;
		return (-1);

	default:
		warn("inet_pton (%s) failure", ipaddr);
		return (-1);
	}
}

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

		size_t avail = cbufq_available(q);
		if (avail < sizeof (uint32_t)) {
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
	if (sock != -1) {
		VERIFY0(close(sock));
	}
	errno = e;
	return (-1);
}

/*
 * Make a new connection to this backend for use in proxying a TCP connection.
 */
static int
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
static int
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

static int
bbal_listen_udp(const char *ipaddr, const char *port, int *sockp)
{
	int e;
	int sock = -1;
	struct sockaddr_in addr;

	/*
	 * Create UDP listen socket.
	 */
	if ((sock = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC,
	    0)) < 0) {
		e = errno;
		warn("socket failed");
		goto fail;
	}

	/*
	 * Set socket options.
	 */
	int opt_on = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt_on,
	    sizeof (opt_on)) != 0) {
		e = errno;
		warn("could not set SO_REUSEADDR");
		goto fail;
	}

	if (bbal_parse_ipv4addr(ipaddr != NULL ? ipaddr : "0.0.0.0", port,
	    &addr) != 0) {
		e = errno;
		warn("bbal_parse_ipv4addr failed");
		goto fail;
	}

	/*
	 * Bind to the socket.
	 */
	if (bind(sock, (struct sockaddr *)&addr, sizeof (addr)) != 0) {
		e = errno;
		warn("bind failed");
		goto fail;
	}

	bunyan_info(g_log, "listening for UDP packets",
	    BUNYAN_T_STRING, "address", ipaddr,
	    BUNYAN_T_STRING, "port", port,
	    BUNYAN_T_END);

	*sockp = sock;
	return (0);

fail:
	if (sock != -1) {
		VERIFY0(close(sock));
	}
	errno = e;
	return (-1);
}

static void
run_timer(cloop_ent_t *ent, int event)
{
	VERIFY3S(event, ==, CLOOP_CB_TIMER);

	for (backend_t *be = list_head(&g_backends); be != NULL;
	    be = list_next(&g_backends, be)) {
		/*
		 * Do we need to initiate a connection?
		 */
		if (be->be_reconnect) {
			VERIFY(!be->be_ok);

			bunyan_debug(be->be_log, "reconnecting to backend",
			    BUNYAN_T_END);

			if (bbal_connect_uds(be) == -1) {
				warn("bbal_connect_uds from run_timer");
				continue;
			}

			be->be_reconnect = B_FALSE;
			continue;
		}
	}
}

static void
bbal_udp_read(cloop_ent_t *ent, int event)
{
	cbuf_t *buf;

	if (cbuf_alloc(&buf, 8192) != 0) {
		warn("cbuf_alloc");
		return;
	}
	cbuf_byteorder_set(buf, CBUF_ORDER_LITTLE_ENDIAN);
	size_t hdrsz = 4 * sizeof (uint32_t);
	VERIFY0(cbuf_position_set(buf, hdrsz));

	/*
	 * XXX Read a packet from the file descriptor.
	 */
	struct sockaddr_storage from;
	socklen_t fromlen = sizeof (from);
	size_t rsz;
	if (cbuf_sys_recvfrom(buf, cloop_ent_fd(ent),
	    CBUF_SYSREAD_ENTIRE, &rsz, 0, (struct sockaddr *)&from,
	    &fromlen) != 0) {
		warn("recvfrom failure");
		goto bail;
	}

	struct sockaddr_in *sin = (struct sockaddr_in *)&from;
	char remote[INET6_ADDRSTRLEN];
	const char *a = inet_ntop(sin->sin_family,
	    &sin->sin_addr, remote, sizeof (remote));

	fprintf(stdout, "[%s:%d] recvfrom %d bytes\n", a,
	    (int)ntohs(sin->sin_port), rsz);

	remote_t *rem = remote_lookup(&sin->sin_addr);
	if (rem == NULL) {
		fprintf(stdout, "\tno remote; drop\n");
		goto bail;
	}

	backend_t *be = backend_lookup(rem->rem_backend);
	if (be == NULL) {
		fprintf(stdout, "\tno backend; drop\n");
		goto bail;
	}

	if (!be->be_ok) {
		fprintf(stdout, "\tbackend not ok; drop\n");
		goto bail;
	}

	/*
	 * Preserve the final position so that we can go back and add the
	 * header.
	 */
	size_t p = cbuf_position(buf);
	cbuf_rewind(buf);

	VERIFY0(cbuf_put_u32(buf, 2)); /* FRAME TYPE */
	VERIFY0(cbuf_put_u32(buf, ntohl(sin->sin_addr.s_addr))); /* IP */
	VERIFY0(cbuf_put_u32(buf, ntohs(sin->sin_port))); /* PORT */
	VERIFY0(cbuf_put_u32(buf, (uint32_t)rsz)); /* FRAME DATA LENGTH */

	VERIFY0(cbuf_position_set(buf, p));

	fprintf(stdout, "\tbackend ok; sending\n");
	if (cconn_send(be->be_conn, buf) != 0) {
		warn("send backend %d", be->be_id);

		cconn_abort(be->be_conn);
	}

	cloop_ent_want(ent, CLOOP_CB_READ);
	return;

bail:
	cbuf_free(buf);
	cloop_ent_want(ent, CLOOP_CB_READ);
}

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

static void
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

int
main(int argc, char *argv[])
{
	cloop_t *loop = NULL;
	cloop_ent_t *timer = NULL;
	cloop_ent_t *udp = NULL;
	cserver_t *tcp = NULL;
	const char *listen_ip = "0.0.0.0";
	const char *listen_port = "10053";

	if (bunyan_init("bbal", &g_log) != 0) {
		err(1, "bunyan_init");
	}
	if (bunyan_stream_add(g_log, "stdout", BUNYAN_L_TRACE,
	    bunyan_stream_fd, (void *)STDOUT_FILENO) != 0) {
		err(1, "bunyan_stream_add");
	}

	(void) bunyan_info(g_log, "starting up", BUNYAN_T_END);

	if (cloop_alloc(&loop) != 0 || cloop_ent_alloc(&udp) != 0 ||
	    cloop_ent_alloc(&timer) != 0 || cserver_alloc(&tcp) != 0) {
		err(1, "cloop init");
	}

	if (backends_init(loop) != 0 || remotes_init() != 0) {
		err(1, "data init");
	}

	if (cloop_attach_ent_timer(loop, timer, 1) != 0) {
		err(1, "timer init");
	}
	cloop_ent_on(timer, CLOOP_CB_TIMER, run_timer);

	/*
	 * Listen on the UDP DNS port.
	 */
	if (bbal_listen_udp(listen_ip, listen_port, &g_sock) != 0) {
		err(1, "bbal_listen_udp");
	}

	cloop_attach_ent(loop, udp, g_sock);

	cloop_ent_on(udp, CLOOP_CB_READ, bbal_udp_read);
	cloop_ent_want(udp, CLOOP_CB_READ);

	/*
	 * Listen on the TCP DNS port.
	 */
	cserver_on(tcp, CSERVER_CB_INCOMING, bbal_tcp_incoming);
	if (cserver_listen_tcp(tcp, loop, listen_ip, listen_port) != 0) {
		err(1, "cserver_listen");
	}

	bunyan_info(g_log, "listening for TCP packets",
	    BUNYAN_T_STRING, "address", listen_ip,
	    BUNYAN_T_STRING, "port", listen_port,
	    BUNYAN_T_END);

	int loopc = 0;
	for (;;) {
		unsigned int again = 0;

		bunyan_trace(g_log, "event loop",
		    BUNYAN_T_INT32, "count", ++loopc,
		    BUNYAN_T_END);
		if (cloop_run(loop, &again) != 0) {
			err(1, "cloop_run");
		}

		/*
		 * The event loop should always have work to do, as we have
		 * registered a persistent timer and have a persistent open
		 * listen socket.
		 */
		VERIFY3U(again, !=, 0);
	}

	abort();
}
