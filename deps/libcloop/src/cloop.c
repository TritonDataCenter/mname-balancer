
#include <stdio.h>
#include <stddef.h>
#include <unistd.h>
#include <poll.h>
#include <port.h>
#include <err.h>
#include <sys/debug.h>
#include <strings.h>
#include <errno.h>

#include <sys/list.h>

#include "libcbuf.h"
#include "libcloop.h"
#include "libcloop_impl.h"

static void cloop_ent_free_impl(cloop_ent_t *clent);
static void cloop_run_one_event(cloop_t *cloop, port_event_t *pe);

int
cloop_alloc(cloop_t **cloopp)
{
	cloop_t *cloop;
	int port = -1;

	*cloopp = NULL;

	if ((cloop = calloc(1, sizeof (*cloop))) == NULL) {
		return (-1);
	}

	if ((port = port_create()) < 0) {
		free(cloop);
		return (-1);
	}
	cloop->cloop_port = port;

	list_create(&cloop->cloop_ents, sizeof (cloop_ent_t),
	    offsetof(cloop_ent_t, clent_link));

	*cloopp = cloop;
	return (0);
}

void
cloop_free(cloop_t *cloop)
{
	if (cloop == NULL) {
		return;
	}

	free(cloop);
}

int
cloop_run(cloop_t *cloop, unsigned int *again)
{
	int port = cloop->cloop_port;

	if (list_is_empty(&cloop->cloop_ents)) {
		*again = 0;
		return (0);
	} else {
		*again = 1;
	}

	for (cloop_ent_t *clent = list_head(&cloop->cloop_ents); clent != NULL;
	    clent = list_next(&cloop->cloop_ents, clent)) {
		uintptr_t o;

		if (!clent->clent_reassoc) {
			continue;
		}
		clent->clent_reassoc = 0;

		o = (uintptr_t)clent->clent_fd;

		if (clent->clent_events == 0) {
			VERIFY0(port_dissociate(port, PORT_SOURCE_FD, o));
			continue;
		}

		if (port_associate(port, PORT_SOURCE_FD, o,
		    clent->clent_events, clent) != 0) {
			err(1, "port_assocate");
		}
	}

	port_event_t pe[32];
	uint_t nget;
again:
	nget = 1;
	if (port_getn(port, pe, 32, &nget, NULL) != 0) {
		if (errno == EINTR || errno == EAGAIN) {
			goto again;
		}

		err(1, "port_getn failure");
	}
	VERIFY3U(nget, >, 0);

	for (uint_t i = 0; i < nget; i++) {
		cloop_run_one_event(cloop, &pe[i]);
	}

	return (0);
}

static void
cloop_run_one_event(cloop_t *cloop, port_event_t *pe)
{
	switch (pe->portev_source) {
	case PORT_SOURCE_FD: {
		cloop_ent_t *clent = pe->portev_user;
		VERIFY(clent->clent_type == CLOOP_ENT_TYPE_FD);
		VERIFY(clent->clent_fd == (int)pe->portev_object);
		clent->clent_reassoc = 1;

		/*
		 * We mark this entity as processing to defer destroys until
		 * an opportune moment.
		 */
		clent->clent_active = 1;

		int handle_events = pe->portev_events & (POLLIN | POLLOUT);
		pe->portev_events &= ~handle_events;

		if (pe->portev_events & (POLLHUP | POLLERR)) {
			/*
			 * If there is an error or a hangup, fire both the
			 * read and write callbacks so that those functions
			 * may check for errors.
			 */
			handle_events |= POLLIN | POLLOUT;
			pe->portev_events &= ~(POLLHUP | POLLERR);
		}

		if (!clent->clent_destroy && (handle_events & POLLIN)) {
			clent->clent_events &= ~(POLLIN);
			if (clent->clent_on_in != NULL) {
				clent->clent_on_in(clent, CLOOP_CB_READ);
			}
		}
		if (!clent->clent_destroy && (handle_events & POLLOUT)) {
			clent->clent_events &= ~(POLLOUT);
			if (clent->clent_on_out != NULL) {
				clent->clent_on_out(clent, CLOOP_CB_WRITE);
			}
		}

		/*
		 * Check if this entity was destroyed by one of the callbacks.
		 */
		clent->clent_active = 0;
		if (clent->clent_destroy) {
			cloop_ent_free_impl(clent);
			break;
		}

		if (pe->portev_events != 0) {
			warnx("unknown events %x", pe->portev_events);
			abort();
		}

		if (clent->clent_events == 0) {
			clent->clent_reassoc = 0;
		}
	} break;

	case PORT_SOURCE_TIMER: {
		cloop_ent_t *clent = pe->portev_user;
		VERIFY(clent->clent_type == CLOOP_ENT_TYPE_TIMER);

		clent->clent_active = 1;

		if (!clent->clent_destroy) {
			if (clent->clent_on_timer != NULL) {
				clent->clent_on_timer(clent, CLOOP_CB_TIMER);
			}
		}

		clent->clent_active = 0;
		if (clent->clent_destroy) {
			cloop_ent_free_impl(clent);
			break;
		}
	} break;
	}
}

void
cloop_ent_on(cloop_ent_t *clent, int event, cloop_ent_cb_t *func)
{
	switch (event) {
	case CLOOP_CB_READ:
		clent->clent_on_in = func;
		break;
	case CLOOP_CB_WRITE:
		clent->clent_on_out = func;
		break;
	case CLOOP_CB_HANGUP:
		clent->clent_on_hup = func;
		break;
	case CLOOP_CB_ERROR:
		clent->clent_on_err = func;
		break;
	case CLOOP_CB_TIMER:
		clent->clent_on_timer = func;
		break;
	default:
		abort();
		break;
	}
}

int
cloop_ent_alloc(cloop_ent_t **clentp)
{
	cloop_ent_t *clent;

	*clentp = NULL;

	if ((clent = calloc(1, sizeof (*clent))) == NULL) {
		return (-1);
	}

	clent->clent_fd = -1;

	*clentp = clent;
	return (0);
}

static void
cloop_ent_free_impl(cloop_ent_t *clent)
{
	if (clent == NULL) {
		return;
	}

	if (clent->clent_loop != NULL) {
		list_remove(&clent->clent_loop->cloop_ents, clent);
		clent->clent_loop = NULL;
	}

	if (clent->clent_timer != 0) {
		VERIFY0(timer_delete(clent->clent_timer));
		clent->clent_timer = 0;
	}

	if (clent->clent_fd != -1) {
		VERIFY0(close(clent->clent_fd));
		clent->clent_fd = -1;
	}

	free(clent);
}

void
cloop_ent_free(cloop_ent_t *clent)
{
	if (clent == NULL) {
		return;
	}

	if (clent->clent_active) {
		clent->clent_destroy = 1;
		return;
	}

	cloop_ent_free_impl(clent);
}

void *
cloop_ent_data(cloop_ent_t *clent)
{
	return (clent->clent_data);
}

void
cloop_ent_data_set(cloop_ent_t *clent, void *data)
{
	clent->clent_data = data;
}

cloop_t *
cloop_ent_loop(cloop_ent_t *clent)
{
	return (clent->clent_loop);
}

void
cloop_attach_ent(cloop_t *cloop, cloop_ent_t *clent, int fd)
{
	VERIFY(clent->clent_type == CLOOP_ENT_TYPE_NONE);
	VERIFY(!list_link_active(&clent->clent_link));
	VERIFY(fd >= 0);
	VERIFY(clent->clent_fd == -1);

	clent->clent_type = CLOOP_ENT_TYPE_FD;
	clent->clent_fd = fd;
	clent->clent_loop = cloop;
	list_insert_tail(&cloop->cloop_ents, clent);
}

int
cloop_attach_ent_timer(cloop_t *cloop, cloop_ent_t *clent, int interval)
{
	VERIFY(clent->clent_type == CLOOP_ENT_TYPE_NONE);
	VERIFY(!list_link_active(&clent->clent_link));

	timer_t timer = 0;
	struct sigevent sigev = { 0 };
	port_notify_t pn = { 0 };

	pn.portnfy_port = cloop->cloop_port;
	pn.portnfy_user = clent;
	sigev.sigev_notify = SIGEV_PORT;
	sigev.sigev_value.sival_ptr = &pn;
	if (timer_create(CLOCK_REALTIME, &sigev, &timer) != 0) {
		err(1, "timer_create failure");
	}

	struct itimerspec itsp;
	bzero(&itsp, sizeof (itsp));
	itsp.it_interval.tv_sec = interval;
	itsp.it_value = itsp.it_interval;
	if (timer_settime(timer, 0, &itsp, NULL) != 0) {
		err(1, "timer_settime failure");
	}

	clent->clent_type = CLOOP_ENT_TYPE_TIMER;
	clent->clent_timer = timer;
	clent->clent_loop = cloop;

	return (0);
}

void
cloop_ent_want(cloop_ent_t *clent, int event)
{
	int e = 0;

	switch (event) {
	case CLOOP_CB_READ:
		e = POLLIN;
		break;
	case CLOOP_CB_WRITE:
		e = POLLOUT;
		break;
	default:
		fprintf(stderr, "cloop_ent_want: invalid event %x\n", event);
		abort();
	}

	if ((clent->clent_events & e) != e) {
		clent->clent_events |= e;
		clent->clent_reassoc = 1;
	}
}

int
cloop_ent_fd(cloop_ent_t *clent)
{
	return (clent->clent_fd);
}
