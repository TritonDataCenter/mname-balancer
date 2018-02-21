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
	clockid_t clent_timer_clock;

	cloop_ent_cb_t *clent_on_in;
	cloop_ent_cb_t *clent_on_out;
	cloop_ent_cb_t *clent_on_hup;
	cloop_ent_cb_t *clent_on_err;
	cloop_ent_cb_t *clent_on_timer;

	void *clent_data;

	cloop_t *clent_loop;
	list_node_t clent_link;

	const char *clent_error_info;
	int clent_error_errno;
};

#endif	/* !_LIBCLOOP_IMPL_H */
