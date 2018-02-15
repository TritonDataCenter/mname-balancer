


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
#include <sys/time.h>
#include <dirent.h>

#include <sys/debug.h>
#include <sys/list.h>
#include <sys/avl.h>

#include <libcbuf.h>
#include <libcloop.h>
#include <bunyan.h>

#include "bbal.h"


bunyan_logger_t *g_log;

int g_sock = -1;

static avl_tree_t g_backends;
static avl_tree_t g_backends_by_path;
static backend_t *g_backend_last_assigned = NULL;
hrtime_t g_backend_last_error = 0;
hrtime_t g_loop_time = 0;

static int
compare_u32(uint32_t first, uint32_t second)
{
	return (first < second ? -1 : first > second ? 1 : 0);
}

static int
compare_str(const char *first, const char *second)
{
	int ret = strcmp(first, second);

	return (ret > 0 ? 1 : ret < 0 ? -1 : 0);
}

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

	return (avl_find(&g_backends, &search, NULL));
}

backend_t *
backend_lookup_by_path(const char *path)
{
	backend_t search;
	search.be_path = (char *)path;

	return (avl_find(&g_backends_by_path, &search, NULL));
}

backend_t *
backend_select(void)
{
	ulong_t nnodes = avl_numnodes(&g_backends);
	backend_t *be = g_backend_last_assigned;

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
			g_backend_last_assigned = be;
			return (be);
		}
	}

	/*
	 * No backends were available.
	 */
	hrtime_t now = gethrtime();
	if (g_backend_last_error == 0 || (now - g_backend_last_error) >
	    SECONDS_IN_NS(5)) {
		bunyan_error(g_log, "no backends available", BUNYAN_T_END);
		g_backend_last_error = now;
	}
	return (NULL);
}

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

	be->be_loop = loop;
	be->be_ok = B_FALSE;
	be->be_reconnect = B_TRUE;

	/*
	 * Determine the next available backend ID.
	 */
	backend_t *be_max = avl_last(&g_backends);
	be->be_id = be_max != NULL ? be_max->be_id + 1 : 1;

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
	free(be);
	errno = e;
	return (-1);
}

static void
backends_refresh(cloop_t *loop)
{
	DIR *sockdir;
	const char *path = "/tmp/bbal_sockets";

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

		if (backend_create(loop, sockpath, &be) != 0) {
			bunyan_fatal(g_log, "backend_create failed",
			    BUNYAN_T_STRING, "socket_path", sockpath,
			    BUNYAN_T_INT32, "errno", (int32_t)errno,
			    BUNYAN_T_STRING, "error", strerror(errno),
			    BUNYAN_T_END);
			exit(1);
		}
	}

	VERIFY0(closedir(sockdir));
}

static int
backends_init(cloop_t *loop)
{
	avl_create(&g_backends, backends_compar, sizeof (backend_t),
	    offsetof(backend_t, be_node));

	avl_create(&g_backends_by_path, backends_compar_by_path,
	    sizeof (backend_t), offsetof(backend_t, be_node_by_path));

	return (0);
}

avl_tree_t g_remotes;

static int
remotes_compar(const void *first, const void *second)
{
	const remote_t *rf = first;
	const remote_t *rs = second;

	return (compare_u32(rf->rem_addr.s_addr, rs->rem_addr.s_addr));
}

static int
remotes_init(void)
{
	avl_create(&g_remotes, remotes_compar, sizeof (remote_t),
	    offsetof(remote_t, rem_node));

	return (0);
}

/*
 * Given a remote, determine which backend we should try to use.  This routine
 * needs to account for backends that are temporarily offline, etc.
 */
backend_t *
remote_backend(remote_t *rem)
{
	backend_t *be = NULL;

top:
	if (rem->rem_backend == 0) {
		/*
		 * No primary backend is currently assigned.  Assign one now.
		 */
		if ((be = backend_select()) == NULL) {
			/*
			 * No backend could be assigned at this time.
			 */
			rem->rem_backend_backup = rem->rem_backend = 0;
			return (NULL);
		}

		/*
		 * A newly selected backend must be working at the time of
		 * assignment.
		 */
		bunyan_info(rem->rem_log,
		    "remote assigned to new primary backend",
		    BUNYAN_T_UINT32, "be_id", be->be_id,
		    BUNYAN_T_END);
		rem->rem_backend = be->be_id;
		rem->rem_backend_backup = 0;
		return (be);
	}

	if ((be = backend_lookup(rem->rem_backend)) == NULL) {
		/*
		 * Our existing backend could not be found!  Reset everything.
		 */
		rem->rem_backend_backup = rem->rem_backend = 0;
		goto top;
	}

	if (be->be_ok) {
		/*
		 * Our primary backend is online.
		 */
		if (rem->rem_backend_backup != 0) {
			bunyan_info(rem->rem_log,
			    "remote assigned to original primary backend",
			    BUNYAN_T_UINT32, "be_id", be->be_id,
			    BUNYAN_T_END);
			rem->rem_backend_backup = 0;
		}
		return (be);
	}

backup_again:
	if (rem->rem_backend_backup == 0) {
		/*
		 * The primary backend is offline and we have not yet assigned
		 * a backup.
		 */
		if ((be = backend_select()) == NULL) {
			/*
			 * No backup backend could be assigned at this time.
			 */
			return (NULL);
		}

		bunyan_info(rem->rem_log,
		    "remote assigned to new backup backend",
		    BUNYAN_T_UINT32, "be_id", be->be_id,
		    BUNYAN_T_END);
		rem->rem_backend_backup = be->be_id;
		return (be);
	}

	if ((be = backend_lookup(rem->rem_backend_backup)) == NULL ||
	    !be->be_ok) {
		/*
		 * Our existing backup backend could not be found or is
		 * offline.  Reset just the backup and try again.
		 */
		rem->rem_backend_backup = 0;
		goto backup_again;
	}

	/*
	 * Our backup backend is online.
	 */
	return (be);
}

remote_t *
remote_lookup(const struct in_addr *addr)
{
	remote_t search;
	search.rem_addr = *addr;

	avl_index_t where;
	remote_t *rem;
	if ((rem = avl_find(&g_remotes, &search, &where)) != NULL) {
		rem->rem_last_seen = g_loop_time;
		return (rem);
	}

	/*
	 * The remote does not exist; create it.
	 */
	if ((rem = calloc(1, sizeof (*rem))) == NULL) {
		return (NULL);
	}

	rem->rem_addr = *addr;
	rem->rem_first_seen = g_loop_time;
	rem->rem_last_seen = g_loop_time;

	if (bunyan_child(g_log, &rem->rem_log,
	    BUNYAN_T_IP, "remote_ip", &rem->rem_addr,
	    BUNYAN_T_END) != 0) {
		free(rem);
		return (NULL);
	}

	bunyan_info(rem->rem_log, "new remote peer", BUNYAN_T_END);

	avl_insert(&g_remotes, rem, where);

	return (rem);
}

static void
remote_destroy(remote_t *rem)
{
	if (rem == NULL) {
		return;
	}

	if (rem->rem_log != NULL) {
		bunyan_fini(rem->rem_log);
	}

	avl_remove(&g_remotes, rem);

	free(rem);
}

static void
run_timer(cloop_ent_t *ent, int event)
{
	VERIFY3S(event, ==, CLOOP_CB_TIMER);

	backends_refresh(cloop_ent_loop(ent));

#if 0
	/*
	 * Keep track of the minimum and the maximum count of remotes per
	 * backend.  If there is a spread of more than 2 remotes per backend
	 * between the minimum and maximum, then unassign one of the remotes
	 * for the maximum backend.
	 * XXX Reword this comment.
	 */
	int32_t max_count = -1;
	int32_t max_backend = 0;
	int32_t min_count = -1;
#endif

	for (backend_t *be = avl_first(&g_backends); be != NULL;
	    be = AVL_NEXT(&g_backends, be)) {
#if 0
		if (max_count == -1) {
			max_backend = be->be_id;
			max_count = be->be_remotes;
		}
		if (min_count == -1) {
			min_count = be->be_remotes;
		}
#endif

		/*
		 * Do we need to initiate a connection?
		 */
		if (be->be_reconnect) {
			VERIFY(!be->be_ok);

			bunyan_debug(be->be_log, "reconnecting to backend",
			    BUNYAN_T_END);

			if (bbal_connect_uds(be) != 0) {
				bunyan_error(be->be_log, "failed to connect",
				    BUNYAN_T_INT32, "errno", (int32_t)errno,
				    BUNYAN_T_STRING, "strerror",
				    strerror(errno),
				    BUNYAN_T_END);
				continue;
			}

			be->be_reconnect = B_FALSE;
			continue;
		}
	}

	/*
	 * Look for backends to which we should send a heartbeat message.
	 */
	for (backend_t *be = avl_first(&g_backends); be != NULL;
	    be = AVL_NEXT(&g_backends, be)) {
		if (!be->be_ok) {
			continue;
		}

		if (be->be_heartbeat_sent == 0) {
			/*
			 * We do not have an outstanding heartbeat.
			 */
			if (be->be_heartbeat_seen == 0 ||
			    (g_loop_time - be->be_heartbeat_seen) >
			    SECONDS_IN_NS(30)) {
				/*
				 * Either we have never sent a heartbeat, or it
				 * has been at least 30 seconds since we have
				 * seen a reply from the server.  Send one now.
				 */
				cbuf_t *buf;
				if (cbuf_alloc(&buf, 4) != 0) {
					continue;
				}
				cbuf_byteorder_set(buf,
				    CBUF_ORDER_LITTLE_ENDIAN);
				VERIFY0(cbuf_put_u32(buf,
				    FRAME_TYPE_CLIENT_HEARTBEAT));
				if (cconn_send(be->be_conn, buf) != 0) {
					cbuf_free(buf);
					continue;
				}

				bunyan_trace(be->be_log, "heartbeat sent",
				    BUNYAN_T_END);

				be->be_heartbeat_sent = g_loop_time;
				be->be_heartbeat_seen = 0;
				continue;
			}
			continue;
		}

		if (be->be_heartbeat_sent != 0 &&
		    be->be_heartbeat_seen == 0 &&
		    (g_loop_time - be->be_heartbeat_sent) > SECONDS_IN_NS(30)) {
			/*
			 * We have an outstanding heartbeat for which we have
			 * not received a reply in 30 seconds.  Terminate this
			 * connection.
			 */
			bunyan_error(be->be_log, "no heartbeat from backend "
			    "(aborting connection)", BUNYAN_T_END);
			be->be_ok = B_FALSE;
			cconn_abort(be->be_conn);
			continue;
		}
	}

	/*
	 * Look for stale remote entries.
	 */
	hrtime_t now = gethrtime();
	remote_t *rem_next;
	for (remote_t *rem = avl_first(&g_remotes); rem != NULL;
	    rem = rem_next) {
		hrtime_t age = now - rem->rem_last_seen;
		rem_next = AVL_NEXT(&g_remotes, rem);

		/*
		 * XXX make this 120 seconds?
		 */
		if (age > SECONDS_IN_NS(5)) {
			bunyan_debug(rem->rem_log, "expiring remote entry",
			    BUNYAN_T_END);
			remote_destroy(rem);
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
	int level = BUNYAN_L_INFO;

	if (getenv("LOG_LEVEL") != NULL) {
		if (bunyan_parse_level(getenv("LOG_LEVEL"), &level) != 0) {
			err(1, "invalid LOG_LEVEL \"%s\"", getenv("LOG_LEVEL"));
		}
	}

	if (bunyan_init("bbal", &g_log) != 0) {
		err(1, "bunyan_init");
	}
	if (bunyan_stream_add(g_log, "stdout", level, bunyan_stream_fd,
	    (void *)STDOUT_FILENO) != 0) {
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
		exit(1);
	}

	cloop_attach_ent(loop, udp, g_sock);

	cloop_ent_on(udp, CLOOP_CB_READ, bbal_udp_read);
	cloop_ent_want(udp, CLOOP_CB_READ);

	/*
	 * Listen on the TCP DNS port.
	 */
	cserver_on(tcp, CSERVER_CB_INCOMING, bbal_tcp_incoming);
	if (cserver_listen_tcp(tcp, loop, listen_ip, listen_port) != 0) {
		bunyan_fatal(g_log, "failed to create TCP listen socket",
		    BUNYAN_T_STRING, "address", listen_ip,
		    BUNYAN_T_STRING, "port", listen_port,
		    BUNYAN_T_INT32, "errno", (int32_t)errno,
		    BUNYAN_T_STRING, "strerror", strerror(errno),
		    BUNYAN_T_END);
		exit(1);
	}

	bunyan_info(g_log, "listening for TCP packets",
	    BUNYAN_T_STRING, "address", listen_ip,
	    BUNYAN_T_STRING, "port", listen_port,
	    BUNYAN_T_END);

	/*
	 * Run the event loop.
	 */
	int loopc = 0;
	for (;;) {
		unsigned int again = 0;

		/*
		 * Get the time once per loop turn.  We'll use this to update
		 * the last seen timestamp on each remote.
		 */
		g_loop_time = gethrtime();

		bunyan_trace(g_log, "event loop",
		    BUNYAN_T_INT32, "count", ++loopc,
		    BUNYAN_T_END);

		if (cloop_run(loop, &again) != 0) {
			err(1, "cloop_run");
		}

		/*
		 * The event loop should always have work to do as we have
		 * registered a persistent timer and have a persistent open
		 * listen socket.
		 */
		VERIFY3U(again, !=, 0);
	}

	abort();
}
