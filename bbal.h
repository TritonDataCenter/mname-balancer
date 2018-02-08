#ifndef	_BBAL_H
#define	_BBAL_H

extern bunyan_logger_t *g_log;
extern int g_sock;

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

typedef struct {
	struct in_addr rem_addr;
	int rem_backend;
	avl_node_t rem_node;
} remote_t;

extern void bbal_tcp_incoming(cserver_t *, int);
extern int bbal_connect_uds_tcp(backend_t *, cconn_t **);
extern int bbal_connect_uds(backend_t *);

extern void bbal_udp_read(cloop_ent_t *, int);
extern int bbal_udp_listen(const char *, const char *, int *);

extern remote_t *remote_lookup(const struct in_addr *);
extern backend_t * backend_lookup(int);

#endif	/* _BBAL_H_ */
