


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
		if (avail < 4) {
			/*
			 * We need at least four bytes in order to read the
			 * frame type.
			 */
			cconn_more_data(ccn);
			return;
		}

		if (cbufq_pullup(q, 4) != 0) {
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

		fprintf(stdout, "\tframe type %u\n", frame_type);

		if (frame_type == 1001) {
			/*
			 * SERVER_HELLO.  Just the frame type; nothing else.
			 */
			be->be_ok = B_TRUE;
			continue;
		}

		if (frame_type != 1002) {
			cconn_abort(ccn);
			return;
		}

		fprintf(stdout, "\tavail %d\n", cbufq_available(q));

		if (cbufq_available(q) < 3 * 4) {
			/*
			 * This frame has three uint32_t values after the
			 * frame type, but they have not yet arrived.
			 */
			VERIFY0(cbuf_position_set(cbuf, marker));
			break;
		}

		if (cbufq_pullup(q, 3 * 4) != 0) {
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

		fprintf(stdout, "\t\tipaddr %x port %d datalen %d\n",
		    ipaddr, port, datalen);

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

		size_t actual;
		if (cbuf_sys_sendto(cbuf, g_sock, datalen, &actual,
		    MSG_NOSIGNAL, (struct sockaddr *)&sin, sizeof (sin)) != 0) {
			err(1, "cbuf_sys_sendto");
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

	fprintf(stdout, "[BE %d] connected!\n", be->be_id);

	fprintf(stdout, "\tsending HELLO frame\n");

	cbuf_t *buf;
	if (cbuf_alloc(&buf, 4) != 0) {
		err(1, "cbuf_alloc");
	}
	cbuf_byteorder_set(buf, CBUF_ORDER_LITTLE_ENDIAN);
	VERIFY0(cbuf_put_u32(buf, 1));

	cbuf_dump(buf, stdout);

	if (cconn_send(ccn, buf) != 0) {
		warn("send backend %d", be->be_id);
		goto close_be;
	}

	return;

close_be:
	be->be_ok = B_FALSE;
	cconn_abort(ccn);
}

static void
bbal_uds_error(cconn_t *ccn, int event)
{
	backend_t *be = cconn_data(ccn);

	fprintf(stdout, "[BE %d] error!\n", be->be_id);
	be->be_ok = B_FALSE;
}

static void
bbal_uds_close(cconn_t *ccn, int event)
{
	backend_t *be = cconn_data(ccn);

	fprintf(stdout, "[BE %d] closed!\n", be->be_id);
	be->be_ok = B_FALSE;
	be->be_reconnect = B_TRUE;

	/*
	 * XXX the CLOSE event currently calls destroy on the socket...
	 */
	be->be_conn = NULL;
}

static int
bbal_connect_uds(backend_t *be)
{
	int e;
	struct sockaddr_un sun;
	int sock;

	if ((sock = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC,
	    0)) < 0) {
		e = errno;
		warn("socket failed");
		goto fail;
	}

	bzero(&sun, sizeof (sun));
	sun.sun_family = AF_UNIX;
	snprintf(sun.sun_path, sizeof (sun.sun_path), "%s", be->be_path);

	if (connect(sock, (struct sockaddr *)&sun, sizeof (sun)) != 0 &&
	    errno != EINPROGRESS) {
		e = errno;
		warn("connect failed");
		goto fail;
	}

	cconn_destroy(be->be_conn);
	if (cconn_alloc(&be->be_conn) != 0) {
		e = errno;
		warn("cconn_alloc");
		goto fail;
	}
	cconn_byteorder_set(be->be_conn, CBUF_ORDER_LITTLE_ENDIAN);
	cconn_data_set(be->be_conn, be);

	cconn_on(be->be_conn, CCONN_CB_CONNECTED, bbal_uds_connected);
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

	fprintf(stdout, "UDP listen socket bound (%s:%s) -> %d\n", ipaddr, port,
	    sock);

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
	size_t hdrsz = 4 * 4;
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
	VERIFY0(cbuf_position_set(buf, 0));

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

int
main(int argc, char *argv[])
{
	int port = -1;
	cloop_t *loop = NULL;
	cloop_ent_t *timer = NULL;
	cloop_ent_t *udp = NULL;

	if (cloop_alloc(&loop) != 0 || cloop_ent_alloc(&udp) != 0 ||
	    cloop_ent_alloc(&timer) != 0) {
		warn("cloop init");
		goto fail;
	}

	if (backends_init(loop) != 0 || remotes_init() != 0) {
		warn("data init");
		goto fail;
	}

	if (cloop_attach_ent_timer(loop, timer, 1) != 0) {
		warn("bbal_timer_init");
		goto fail;
	}
	cloop_ent_on(timer, CLOOP_CB_TIMER, run_timer);

	if (bbal_listen_udp("0.0.0.0", "10053", &g_sock) != 0) {
		warn("bbal_listen_udp");
		goto fail;
	}

	cloop_attach_ent(loop, udp, g_sock);

	cloop_ent_on(udp, CLOOP_CB_READ, bbal_udp_read);
	cloop_ent_want(udp, CLOOP_CB_READ);

	for (;;) {
		unsigned int again = 0;

		if (cloop_run(loop, &again) != 0) {
			warn("cloop_run");
			goto fail;
		}

		if (!again) {
			warnx("LOOP ENDED?");
			goto fail;
		}
	}

	return (0);

fail:
	if (port != -1) {
		VERIFY0(close(port));
	}
	if (g_sock != -1) {
		VERIFY0(close(g_sock));
	}
	return (1);
}


