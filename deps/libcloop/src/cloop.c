
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

/*
 * This function is used when no callback is registered for a particular
 * event.
 */
static void
cloop_noop(cloop_ent_t *loop, int event)
{
}

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
		/*
		 * There are no entities registered with this loop.  Report to
		 * the caller that we have no work left to do.
		 */
		*again = 0;
		return (0);
	} else {
		*again = 1;
	}

	for (cloop_ent_t *clent = list_head(&cloop->cloop_ents); clent != NULL;
	    clent = list_next(&cloop->cloop_ents, clent)) {
		if (!clent->clent_reassoc) {
			continue;
		}
		clent->clent_reassoc = 0;

		uintptr_t o = (uintptr_t)clent->clent_fd;

		if (clent->clent_events == 0) {
			VERIFY0(port_dissociate(port, PORT_SOURCE_FD, o));
			continue;
		}

		VERIFY0(port_associate(port, PORT_SOURCE_FD, o,
		    clent->clent_events, clent));
	}

	port_event_t pe[32];
	uint_t nget;
again:
	nget = 1;
	if (port_getn(port, pe, 32, &nget, NULL) != 0) {
		if (errno == EINTR || errno == EAGAIN) {
			goto again;
		}

		abort();
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
		VERIFY3S(clent->clent_type, ==, CLOOP_ENT_TYPE_FD);
		VERIFY3S(clent->clent_fd, ==, (int)pe->portev_object);
		clent->clent_reassoc = 1;

		/*
		 * We mark this entity as processing to defer destroys until
		 * an opportune moment.
		 */
		clent->clent_active = 1;

		/*
		 * Call handler functions for each reported event.  If any
		 * handler calls destroy on the loop entity, we won't call any
		 * further handlers.
		 */
		int ev = pe->portev_events;
		if (!clent->clent_destroy && (ev & POLLERR)) {
			ev &= ~POLLERR;
			clent->clent_on_err(clent, CLOOP_CB_ERROR);
		}
		if (!clent->clent_destroy && (ev & POLLHUP)) {
			ev &= ~POLLHUP;
			clent->clent_on_hup(clent, CLOOP_CB_HANGUP);
		}
		if (!clent->clent_destroy && (ev & POLLIN)) {
			ev &= ~POLLIN;
			clent->clent_events &= ~POLLIN;
			clent->clent_on_in(clent, CLOOP_CB_READ);
		}
		if (!clent->clent_destroy && (ev & POLLOUT)) {
			ev &= ~POLLOUT;
			clent->clent_events &= ~POLLOUT;
			clent->clent_on_out(clent, CLOOP_CB_WRITE);
		}

		clent->clent_active = 0;

		/*
		 * Check if this entity was destroyed by one of the callbacks.
		 */
		if (clent->clent_destroy) {
			cloop_ent_free_impl(clent);
			break;
		}

		/*
		 * Confirm that we processed all triggered events.
		 */
		VERIFY3S(ev, ==, 0);

		if (clent->clent_events == 0) {
			clent->clent_reassoc = 0;
		}
		break;
	}

	case PORT_SOURCE_TIMER: {
		cloop_ent_t *clent = pe->portev_user;
		VERIFY3S(clent->clent_type, ==, CLOOP_ENT_TYPE_TIMER);

		clent->clent_active = 1;

		if (!clent->clent_destroy) {
			clent->clent_on_timer(clent, CLOOP_CB_TIMER);
		}

		clent->clent_active = 0;

		if (clent->clent_destroy) {
			cloop_ent_free_impl(clent);
		}
		break;
	}

	default:
		abort();
		break;
	}
}

void
cloop_ent_on(cloop_ent_t *clent, int event, cloop_ent_cb_t *func)
{
	if (func == NULL) {
		func = cloop_noop;
	}

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

	clent->clent_on_in = cloop_noop;
	clent->clent_on_out = cloop_noop;
	clent->clent_on_hup = cloop_noop;
	clent->clent_on_err = cloop_noop;
	clent->clent_on_timer = cloop_noop;

	*clentp = clent;
	return (0);
}

const char *
cloop_ent_error_info(cloop_ent_t *clent)
{
	return (clent->clent_error_info);
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
	VERIFY3S(clent->clent_type, ==, CLOOP_ENT_TYPE_NONE);
	VERIFY(!list_link_active(&clent->clent_link));
	VERIFY3S(fd, >=, 0);
	VERIFY3S(clent->clent_fd, ==, -1);

	clent->clent_type = CLOOP_ENT_TYPE_FD;
	clent->clent_fd = fd;
	clent->clent_loop = cloop;
	list_insert_tail(&cloop->cloop_ents, clent);
}

int
cloop_attach_ent_timer(cloop_t *cloop, cloop_ent_t *clent, int interval)
{
	VERIFY3S(clent->clent_type, ==, CLOOP_ENT_TYPE_NONE);
	VERIFY(!list_link_active(&clent->clent_link));

	port_notify_t pn = { 0 };
	pn.portnfy_port = cloop->cloop_port;
	pn.portnfy_user = clent;

	struct sigevent sigev = { 0 };
	sigev.sigev_notify = SIGEV_PORT;
	sigev.sigev_value.sival_ptr = &pn;

	/*
	 * Try, first, to create a timer based on the non-adjustable clock.  It
	 * hasn't always been possible for unprivileged users to use this clock
	 * as a timing base, so if that fails we'll try one last time with the
	 * wall clock.
	 */
	timer_t timer = 0;
	if (timer_create(CLOCK_HIGHRES, &sigev, &timer) == 0) {
		clent->clent_timer_clock = CLOCK_HIGHRES;
		goto ok;
	} else if (errno != EPERM) {
		clent->clent_error_errno = errno;
		clent->clent_error_info = "timer_create failure (HIGHRES)";
		return (-1);
	}

	if (timer_create(CLOCK_REALTIME, &sigev, &timer) == 0) {
		clent->clent_timer_clock = CLOCK_REALTIME;
		goto ok;
	} else {
		clent->clent_error_errno = errno;
		clent->clent_error_info = "timer_create failure (REALTIME)";
		return (-1);
	}

	struct itimerspec itsp = { { 0 }, { 0 } };
ok:
	itsp.it_interval.tv_sec = interval;
	itsp.it_value = itsp.it_interval;
	if (timer_settime(timer, 0, &itsp, NULL) != 0) {
		clent->clent_error_errno = errno;
		clent->clent_error_info = "timer_settime failure";
		return (-1);
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
