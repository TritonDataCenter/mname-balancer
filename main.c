/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright (c) 2018, Joyent, Inc.
 */

/*
 * BINDER LOAD BALANCER
 *
 * This program is a simple DNS load balancer built to work with the Node-based
 * "node-mname" DNS server library, as used in the "binder" service discovery
 * server.  A listen socket is established for both TCP and UDP on the
 * nominated DNS server port to receive requests from remote peers.  A pool of
 * connections to backend server processes are maintained via local sockets
 * (AF_UNIX).
 *
 * The program is broken up into different subsystems.  Each file has a comment
 * which describes the particular subsystem.  Of particular note is the
 * description of the protocol that forms an interface between this program
 * and "node-mname", which appears in "backends.c".
 */

#include "bbal.h"

/*
 * This is the root bunyan logger.  It should only be used when a more specific
 * child logger is not available; e.g., each backend object has a child logger
 * which includes the identity of the backend.
 */
bunyan_logger_t *g_log;

/*
 * The UDP listen socket.  This is used by "backend.c" to send outbound packets
 * at the request of backends.
 */
int g_sock = -1;

/*
 * This time value is updated once per turn of the event loop.  This avoids
 * the need to call gethrtime(3C) frequently when our timing needs are generally
 * quite coarse.
 */
hrtime_t g_loop_time = 0;

static void
run_timer_rebalance(cloop_ent_t *ent, int event)
{
	VERIFY3S(event, ==, CLOOP_CB_TIMER);

	backends_rebalance();
}

static void
run_timer_expire_remotes(cloop_ent_t *ent, int event)
{
	VERIFY3S(event, ==, CLOOP_CB_TIMER);

	remotes_expire();
}

static void
run_timer_timeouts(cloop_ent_t *ent, int event)
{
	VERIFY3S(event, ==, CLOOP_CB_TIMER);

	timeout_run();
}

static void
run_timer_backends(cloop_ent_t *ent, int event)
{
	VERIFY3S(event, ==, CLOOP_CB_TIMER);

	backends_refresh();
}

int
main(int argc, char *argv[])
{
	cloop_t *loop = NULL;
	cloop_ent_t *udp = NULL;
	cserver_t *tcp = NULL;
	const char *listen_ip = "0.0.0.0";
	const char *listen_port = "53";
	const char *backends_path;
	int level = BUNYAN_L_INFO;

	int c;
	while ((c = getopt(argc, argv, ":b:p:s:l:")) != -1) {
		switch (c) {
		case 'b':
			listen_ip = optarg;
			break;

		case 'p':
			listen_port = optarg;
			break;

		case 's':
			backends_path = optarg;
			break;

		case 'l':
			if (bunyan_parse_level(optarg, &level) != 0) {
				err(1, "invalid log level for -l: %s", optarg);
			}
			break;

		case ':':
			errx(1, "argument -%c requires an option value",
			    optopt);
			break;

		case '?':
			errx(1, "unknown argument -%c", optopt);
			break;

		default:
			abort();
		}
	}

	if (backends_path == NULL) {
		errx(1, "must specify socket directory (-s)");
	}

	/*
	 * Allow the environment to override the bunyan log level.
	 */
	const char *llenv = getenv("LOG_LEVEL");
	if (llenv != NULL) {
		if (bunyan_parse_level(llenv, &level) != 0) {
			err(1, "invalid LOG_LEVEL \"%s\"", llenv);
		}
	}

	if (bunyan_init("mname-balancer", &g_log) != 0) {
		err(1, "bunyan_init");
	}
	if (bunyan_stream_add(g_log, "stdout", level, bunyan_stream_fd,
	    (void *)STDOUT_FILENO) != 0) {
		err(1, "bunyan_stream_add");
	}

	(void) bunyan_info(g_log, "starting up", BUNYAN_T_END);

	if (cloop_alloc(&loop) != 0 || cloop_ent_alloc(&udp) != 0 ||
	    cserver_alloc(&tcp) != 0) {
		bunyan_fatal(g_log, "cloop init failure",
		    BUNYAN_T_INT32, "errno", (int32_t)errno,
		    BUNYAN_T_STRING, "strerror", strerror(errno),
		    BUNYAN_T_END);
		exit(1);
	}

	if (backends_init(loop, backends_path) != 0 || remotes_init() != 0 ||
	    timeout_init() != 0) {
		bunyan_fatal(g_log, "data structure failure",
		    BUNYAN_T_INT32, "errno", (int32_t)errno,
		    BUNYAN_T_STRING, "strerror", strerror(errno),
		    BUNYAN_T_END);
		exit(1);
	}

	/*
	 * Start the periodic maintenance routines.  Intervals are specified
	 * in seconds.  Note that these functions are run by the event loop,
	 * so scheduling them now does not cause them to run until the loop
	 * starts.
	 */
	struct timer_def {
		cloop_ent_cb_t *tde_func;
		int tde_interval;
		cloop_ent_t *tde_ent;
	} timer_defs[] = {
		{ .tde_func = run_timer_timeouts,	.tde_interval = 1 },
		{ .tde_func = run_timer_backends,	.tde_interval = 5 },
		{ .tde_func = run_timer_rebalance,	.tde_interval = 15 },
		{ .tde_func = run_timer_expire_remotes,	.tde_interval = 30 },
		{ NULL }
	};
	for (unsigned i = 0; timer_defs[i].tde_func != NULL; i++) {
		if (cloop_ent_alloc(&timer_defs[i].tde_ent) != 0 ||
		    cloop_attach_ent_timer(loop, timer_defs[i].tde_ent,
		    timer_defs[i].tde_interval) != 0) {
			bunyan_fatal(g_log, "timer init failure",
			    BUNYAN_T_INT32, "errno", (int32_t)errno,
			    BUNYAN_T_STRING, "strerror", strerror(errno),
			    BUNYAN_T_END);
			exit(1);
		}
		cloop_ent_on(timer_defs[i].tde_ent, CLOOP_CB_TIMER,
		    timer_defs[i].tde_func);
	}

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
	if (bbal_tcp_listen(tcp, loop, listen_ip, listen_port) != 0) {
		exit(1);
	}

	/*
	 * Before we kick off the event loop, do an initial sweep for backends.
	 */
	backends_refresh();

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
			bunyan_fatal(g_log, "cloop run failure",
			    BUNYAN_T_INT32, "errno", (int32_t)errno,
			    BUNYAN_T_STRING, "strerror", strerror(errno),
			    BUNYAN_T_END);
			exit(1);
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
