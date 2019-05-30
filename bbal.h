/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright (c) 2018, Joyent, Inc.
 */

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

#ifndef	_BBAL_H
#define	_BBAL_H

#define	_UNUSED	__attribute__((unused))
#define	_INLINE	inline __attribute__((always_inline))

/*
 * These base functions are used in the various subsystems to construct more
 * specific AVL comparators.  See also: avl_create(3AVL).
 */
static _INLINE int _UNUSED
compare_u32(uint32_t first, uint32_t second)
{
	return (first < second ? -1 : first > second ? 1 : 0);
}

static _INLINE int _UNUSED
compare_hrtime(hrtime_t first, hrtime_t second)
{
	return (first < second ? -1 : first > second ? 1 : 0);
}

static _INLINE int _UNUSED
compare_str(const char *first, const char *second)
{
	int ret = strcmp(first, second);

	return (ret > 0 ? 1 : ret < 0 ? -1 : 0);
}

/*
 * When reconnecting to faulted backends, we back off for each subsequent
 * failure.  The delay starts at 1 second and grows to a maximum of 32.
 * Increasing this any further could mean a protracted delay in returning a
 * newly healthy backend to service.
 */
#define	MIN_RECONNECT_DELAY_SECS	1
#define	MAX_RECONNECT_DELAY_SECS	32

/*
 * Frame type numbers for use in the backend protocol.  See comments in
 * "backend.c" for more details about frame layouts, etc.
 */
#define	FRAME_TYPE_CLIENT_HELLO		1
#define	FRAME_TYPE_INBOUND_UDP		2
#define	FRAME_TYPE_INBOUND_TCP		3
#define	FRAME_TYPE_CLIENT_HEARTBEAT	4
#define	FRAME_TYPE_SERVER_HELLO		1001
#define	FRAME_TYPE_OUTBOUND_UDP		1002
#define	FRAME_TYPE_INBOUND_TCP_OK	1003
#define	FRAME_TYPE_SERVER_HEARTBEAT	1004

extern bunyan_logger_t *g_log;
extern int g_sock;
extern hrtime_t g_loop_time;

typedef struct bbal_timeout timeout_t;

typedef void timeout_func_t(timeout_t *, void *);

struct bbal_timeout {
	avl_node_t to_node;
	uint32_t to_id;
	hrtime_t to_scheduled_at;
	hrtime_t to_run_at;
	hrtime_t to_expiry;
	timeout_func_t *to_func;
	void *to_arg;
	boolean_t to_active;
};

typedef struct {
	avl_node_t be_node;
	avl_node_t be_node_by_path;

	uint32_t be_id;
	char *be_path;

	cloop_t *be_loop;
	cconn_t *be_conn;

	boolean_t be_ok;
	boolean_t be_reconnect;
	boolean_t be_heartbeat_outstanding;
	boolean_t be_removed;
	uint32_t be_remotes;

	timeout_t *be_connect_timeout;
	timeout_t *be_heartbeat_timeout;

	timeout_t *be_reconnect_timeout;
	unsigned be_reconnect_delay;

	bunyan_logger_t *be_log;

	uint64_t be_stat_conn_start;
	uint64_t be_stat_conn_error;
	uint64_t be_stat_udp;
	uint64_t be_stat_tcp;
	uint64_t be_stat_stuck;
} backend_t;

typedef struct {
	struct in_addr rem_addr;
	uint32_t rem_backend;
	uint32_t rem_backend_backup;
	avl_node_t rem_node;

	bunyan_logger_t *rem_log;

	uint64_t rem_stat_udp;
	uint64_t rem_stat_udp_drop;
	uint64_t rem_stat_tcp;
	uint64_t rem_stat_tcp_drop;

	hrtime_t rem_first_seen;
	hrtime_t rem_last_seen;
} remote_t;

extern int timeout_alloc(timeout_t **);
extern void timeout_free(timeout_t *);
extern void timeout_set(timeout_t *, unsigned, timeout_func_t *, void *);
extern void timeout_clear(timeout_t *);
extern void timeout_run(void);
extern int timeout_init(void);

extern int bbal_tcp_listen(cserver_t *, cloop_t *, const char *, const char *);

extern int bbal_connect_uds_common(backend_t *, cconn_t **);

extern void bbal_backend_reconnect(backend_t *);
extern void bbal_backend_fault(backend_t *);

extern void bbal_udp_read(cloop_ent_t *, int);
extern int bbal_udp_listen(const char *, const char *, int *);

extern int backends_init(cloop_t *, const char *);
extern void backends_refresh(void);
extern void backends_rebalance(void);
extern backend_t *backends_select(void);
extern backend_t *backend_lookup(uint32_t);

extern remote_t *remote_lookup(const struct in_addr *);
extern backend_t *remote_backend(remote_t *);
extern void remotes_expire(void);
extern void remotes_rebalance(uint32_t, uint32_t);
extern int remotes_init(void);

#define	SECONDS_IN_NS(s)	(s * NANOSEC)

#endif	/* _BBAL_H_ */
