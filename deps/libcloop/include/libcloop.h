#ifndef	_LIBCLOOP_H
#define	_LIBCLOOP_H

typedef enum cloop_ent_cb_type {
	CLOOP_CB_READ = 1,
	CLOOP_CB_WRITE = 2,
	CLOOP_CB_HANGUP = 3,
	CLOOP_CB_ERROR = 4,
	CLOOP_CB_TIMER
} cloop_ent_cb_type_t;

typedef enum cloop_ent_type {
	CLOOP_ENT_TYPE_NONE = 0,
	CLOOP_ENT_TYPE_FD = 1,
	CLOOP_ENT_TYPE_TIMER
} cloop_ent_type_t;

typedef enum cserver_type {
	CSERVER_TYPE_NONE = 0,
	CSERVER_TYPE_TCP = 1,
} cserver_type_t;

typedef enum cserver_cb_type {
	CSERVER_CB_INCOMING = 1,
} cserver_cb_type_t;

typedef enum cconn_cb_type {
	CCONN_CB_CONNECTED = 1,
	CCONN_CB_DATA_AVAILABLE,
	CCONN_CB_ERROR,
	CCONN_CB_END,
	CCONN_CB_CLOSE,
} cconn_cb_type_t;

typedef struct cloop cloop_t;
typedef struct cloop_ent cloop_ent_t;

typedef struct cserver cserver_t;
typedef struct cconn cconn_t;

typedef void cloop_ent_cb_t(cloop_ent_t *, int);

extern int cloop_alloc(cloop_t **cloopp);
extern void cloop_free(cloop_t *cloop);

extern int cloop_run(cloop_t *cloop, unsigned int *again);

extern int cloop_ent_alloc(cloop_ent_t **clent);
extern void cloop_ent_free(cloop_ent_t *clent);

extern void *cloop_ent_data(cloop_ent_t *clent);
extern void cloop_ent_data_set(cloop_ent_t *clent, void *data);
extern cloop_t *cloop_ent_loop(cloop_ent_t *clent);

extern void cloop_ent_on(cloop_ent_t *clent, int event, cloop_ent_cb_t *func);

extern void cloop_ent_want(cloop_ent_t *clent, int event);

extern void cloop_attach_ent(cloop_t *cloop, cloop_ent_t *clent, int fd);
extern int cloop_attach_ent_timer(cloop_t *cloop, cloop_ent_t *clent, int interval);

extern int cloop_ent_fd(cloop_ent_t *clent);

typedef void cserver_cb_t(cserver_t *, int);

extern int cserver_alloc(cserver_t **csrvp);
extern void cserver_free(cserver_t *csrv);

/*
 * Close the listen socket so as to stop accepting incoming connections.
 */
extern void cserver_close(cserver_t *);

extern int cserver_listen_tcp(cserver_t *, cloop_t *, const char *ipaddr,
    const char *port);

extern void cserver_destroy(cserver_t *);
extern void cserver_abort(cserver_t *);

extern int cserver_accept(cserver_t *, cconn_t **);

extern void cserver_on(cserver_t *, int, cserver_cb_t *);

extern int cconn_alloc(cconn_t **);
extern void cconn_destroy(cconn_t *);

extern void cconn_byteorder_set(cconn_t *, unsigned int);

/*
 * Attach this cconn_t to a socket for which connect(3SOCKET) has been called.
 * Will poll for asynchronous completion of the connection.
 */
extern void cconn_attach(cloop_t *, cconn_t *, int);

typedef void cconn_cb_t(cconn_t *, int);

extern void cconn_on(cconn_t *, int, cconn_cb_t *);

extern void cconn_set_recvq_max(cconn_t *ccn, size_t);
extern cbufq_t *cconn_recvq(cconn_t *ccn);
extern void cconn_more_data(cconn_t *ccn);
extern int cconn_send(cconn_t *ccn, cbuf_t *);
extern int cconn_fin(cconn_t *ccn);
extern int cconn_abort(cconn_t *ccn);

extern void *cconn_data(cconn_t *ccn);
extern void cconn_data_set(cconn_t *ccn, void *data);

extern const struct sockaddr_in *cconn_sockaddr_in(cconn_t *ccn);
extern const char *cconn_remote_addr_str(cconn_t *ccn);

#endif	/* !_LIBCLOOP_H */
