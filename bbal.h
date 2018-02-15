#ifndef	_BBAL_H
#define	_BBAL_H

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

typedef struct {
	avl_node_t be_node;
	avl_node_t be_node_by_path;

	uint32_t be_id;
	char *be_path;

	cloop_t *be_loop;
	cconn_t *be_conn;

	boolean_t be_ok;
	boolean_t be_reconnect;
	hrtime_t be_heartbeat_sent;
	hrtime_t be_heartbeat_seen;
	uint32_t be_remotes;

	cbufq_t *be_input;

	bunyan_logger_t *be_log;

	uint64_t be_stat_conn_start;
	uint64_t be_stat_conn_error;
	uint64_t be_stat_udp;
	uint64_t be_stat_tcp;
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

extern void bbal_tcp_incoming(cserver_t *, int);
extern int bbal_connect_uds_tcp(backend_t *, cconn_t **);
extern int bbal_connect_uds(backend_t *);

extern void bbal_udp_read(cloop_ent_t *, int);
extern int bbal_udp_listen(const char *, const char *, int *);

extern remote_t *remote_lookup(const struct in_addr *);
extern backend_t *backend_lookup(uint32_t);
extern backend_t *remote_backend(remote_t *);

#define	SECONDS_IN_NS(s)	(s * 1000000000LL)

#endif	/* _BBAL_H_ */
