#ifndef	_LIBCLOOP_IMPL_H
#define	_LIBCLOOP_IMPL_H

#include <sys/list.h>
#include "libcloop.h"

struct cloop {
	list_t cloop_ents;
	int cloop_port;
};

struct cloop_ent {
	cloop_ent_type_t clent_type;

	int clent_fd;
	int clent_events;
	int clent_reassoc;
	int clent_destroy;
	int clent_active;
	timer_t clent_timer;

	cloop_ent_cb_t *clent_on_in;
	cloop_ent_cb_t *clent_on_out;
	cloop_ent_cb_t *clent_on_hup;
	cloop_ent_cb_t *clent_on_err;
	cloop_ent_cb_t *clent_on_timer;

	void *clent_data;

	cloop_t *clent_loop;
	list_node_t clent_link;
};

#if 0
#define	CLOOP_ENT_FIELDS						\
	cloop_ent_type_t clent_type;					\
	int clent_fd;							\
	int clent_events;						\
	list_node_t clent_link

struct cloop_ent {
	CLOOP_ENT_FIELDS;
};

typedef struct cloop_ent_tcp {
	CLOOP_ENT_FIELDS;

	cbufq_t *clent_sendq;
	cbufq_t *clent_recvq;
} cloop_ent_tcp_t;
#endif

#endif	/* !_LIBCLOOP_IMPL_H */
