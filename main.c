


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


bunyan_logger_t *g_log;

int g_sock = -1;

list_t g_backends;

backend_t *
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

remote_t *
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
	if (bbal_udp_listen(listen_ip, listen_port, &g_sock) != 0) {
		err(1, "bbal_udp_listen");
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
