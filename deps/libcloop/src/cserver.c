

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <err.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <signal.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <netdb.h>
#include <port.h>
#include <sys/debug.h>
#include <errno.h>
#include <limits.h>

#include <sys/list.h>

#include <libcbuf.h>
#include "libcloop.h"

#ifdef	MSG_NOSIGNAL
#define	CSERVER_MSG_NOSIGNAL	MSG_NOSIGNAL
#else
/*
 * See the comment in "cserver_signal_setup()" that describes the workaround
 * for a missing MSG_NOSIGNAL.
 */
#define	CSERVER_MSG_NOSIGNAL	0
#endif

boolean_t cserver_debug = B_FALSE;

/*
 * EVENT ORDERING:
 *
 * 	Creation
 * 	  |
 * 	  +-->---------------------------------------\
 * 	  |                                          |
 * 	  V                                          |
 *	CCONN_CB_DATA_AVAILABLE <-\                  |
 *	  |                       |                  |
 *	  +-->--------------------/                  |
 *	  |                                          |
 *	  +-->------------------------------------:. |
 *	  |                                         \|
 *	  V                                          V
 *	CCONN_CB_END (end of inbound data stream)    |
 *	  |                                          |
 *	  +----> CCONN_CB_ERROR <--------------------/
 *	  |        |
 *	  V        V
 *	CCONN_CB_CLOSE (socket closed)
 */

typedef enum cconn_state {
	CCONN_ST_PRE_CONNECTION = 1,
	CCONN_ST_WAITING_FOR_CONNECT,
	CCONN_ST_WAITING_FOR_DATA,
	CCONN_ST_DATA_AVAILABLE,
	CCONN_ST_READ_EOF,
	CCONN_ST_ERROR,
	CCONN_ST_CLOSED,
} cconn_state_t;

struct cconn {
	cserver_t *ccn_server;
	cconn_state_t ccn_state;
	int ccn_callback_depth;

	cloop_ent_t *ccn_clent;
	struct sockaddr_storage ccn_remote_addr;
	char *ccn_remote_addr_str;

	unsigned int ccn_order;
	size_t ccn_recvq_buffer_size;
	size_t ccn_recvq_max;
	cbufq_t *ccn_recvq;
	boolean_t ccn_recvq_end;
	cbufq_t *ccn_sendq;
	boolean_t ccn_sendq_end;
	boolean_t ccn_sendq_flushed;

	cconn_cb_t *ccn_on_data_available;
	cconn_cb_t *ccn_on_end;
	cconn_cb_t *ccn_on_error;
	cconn_cb_t *ccn_on_close;
	cconn_cb_t *ccn_on_connected;

	list_node_t ccn_link;			/* cserver linkage */

	const char *ccn_error_message;
	int ccn_error_errno;

	void *ccn_data;
};

struct cserver {
	cserver_type_t csrv_type;

	cloop_t *csrv_loop;
	cloop_ent_t *csrv_listen;

	struct sockaddr_storage csrv_addr;

	list_t csrv_connections;		/* list of cconn_t */

	/*
	 * Callbacks:
	 */
	cserver_cb_t *csrv_on_incoming;
};

static void ccn_handle_incoming_data(cconn_t *ccn, int notify);
static boolean_t ccn_sendq_finalised(cconn_t *ccn);

static char *
cconn_state_name(cconn_state_t s)
{
	return (s == CCONN_ST_PRE_CONNECTION ? "PRE_CONNECTION" :
	    s == CCONN_ST_WAITING_FOR_CONNECT ? "WAITING_FOR_CONNECT" :
	    s == CCONN_ST_WAITING_FOR_DATA ? "WAITING_FOR_DATA" :
	    s == CCONN_ST_DATA_AVAILABLE ? "DATA_AVAILABLE" :
	    s == CCONN_ST_READ_EOF ? "READ_EOF" :
	    s == CCONN_ST_ERROR ? "ERROR" :
	    s == CCONN_ST_CLOSED ? "CLOSED" :
	    "?UNKNOWN");
}

void *
cconn_data(cconn_t *ccn)
{
	return (ccn->ccn_data);
}

void
cconn_data_set(cconn_t *ccn, void *data)
{
	ccn->ccn_data = data;
}

static struct sockaddr_in *
cserver_sockaddr_in(cserver_t *csrv)
{
	VERIFY(csrv->csrv_type == CSERVER_TYPE_TCP);

	return ((struct sockaddr_in *)&csrv->csrv_addr);
}

const struct sockaddr_in *
cconn_sockaddr_in(cconn_t *ccn)
{
	return ((struct sockaddr_in *)&ccn->ccn_remote_addr);
}

static void
cconn_callback_enter(cconn_t *ccn)
{
	/*
	 * Callbacks may themselves trigger forward state transitions.  In
	 * order to avoid freeing the object until we are finished, we track
	 * recursive execution.
	 */
	ccn->ccn_callback_depth++;
}

static void
cconn_callback_exit(cconn_t *ccn)
{
	VERIFY3S(ccn->ccn_callback_depth, >, 0);
	if (--ccn->ccn_callback_depth == 0) {
		/*
		 * This is the last nested callback.  If the connection has
		 * reached the closed state, free it now.
		 */
		if (ccn->ccn_state == CCONN_ST_CLOSED) {
			cconn_destroy(ccn);
		}
	}
}

void
cconn_advance_state(cconn_t *ccn, cconn_state_t nstate)
{
	cconn_state_t ostate;

	cconn_callback_enter(ccn);

top:
	if (ccn->ccn_state == CCONN_ST_CLOSED) {
		/*
		 * Nothing left to do.
		 */
		goto release;
	}

	if (ccn->ccn_state == nstate) {
		/*
		 * This is not a transition.
		 */
		goto release;
	}

	ostate = ccn->ccn_state;
	ccn->ccn_state = nstate;
	if (cserver_debug) {
		fprintf(stderr, "CCONN[%p] STATE: %s -> %s\n", ccn,
		    cconn_state_name(ostate),
		    cconn_state_name(nstate));
	}

	switch (nstate) {
	case CCONN_ST_ERROR:
		VERIFY(ostate != CCONN_ST_CLOSED);
		if (ccn->ccn_on_error != NULL) {
			ccn->ccn_on_error(ccn, CCONN_CB_ERROR);
		}
		nstate = CCONN_ST_CLOSED;
		goto top;

	case CCONN_ST_CLOSED:
		cloop_ent_free(ccn->ccn_clent);
		ccn->ccn_clent = NULL;
		if (ccn->ccn_on_close != NULL) {
			ccn->ccn_on_close(ccn, CCONN_CB_CLOSE);
		}
		goto release;

	case CCONN_ST_DATA_AVAILABLE:
		VERIFY(ostate == CCONN_ST_WAITING_FOR_DATA);
		if (ccn->ccn_on_data_available != NULL) {
			ccn->ccn_on_data_available(ccn,
			    CCONN_CB_DATA_AVAILABLE);
		}
		goto release;

	case CCONN_ST_WAITING_FOR_DATA:
		VERIFY(ostate == CCONN_ST_PRE_CONNECTION ||
		    ostate == CCONN_ST_WAITING_FOR_CONNECT ||
		    ostate == CCONN_ST_DATA_AVAILABLE);

		if (ostate == CCONN_ST_WAITING_FOR_CONNECT) {
			/*
			 * This is an outbound connection.  Notify the consumer
			 * that the connection has completed.
			 */
			if (ccn->ccn_on_connected != NULL) {
				ccn->ccn_on_connected(ccn, CCONN_CB_CONNECTED);
			}
		}

		/*
		 * Trigger the incoming data routine.  This routine
		 * will mark the socket for read if needed.
		 */
		ccn_handle_incoming_data(ccn, 0);
		goto release;


	case CCONN_ST_WAITING_FOR_CONNECT:
		VERIFY(ostate == CCONN_ST_PRE_CONNECTION);

		/*
		 * We need to wait for POLLOUT so that we can check the
		 * asynchronous completion status of this connection.
		 * See also: connect(3SOCKET).
		 */
		cloop_ent_want(ccn->ccn_clent, CLOOP_CB_WRITE);
		goto release;

	case CCONN_ST_READ_EOF:
		VERIFY(ostate == CCONN_ST_WAITING_FOR_DATA);
		if (ccn->ccn_on_end != NULL) {
			ccn->ccn_on_end(ccn, CCONN_CB_END);
		}
		if (ccn->ccn_sendq_flushed) {
			/*
			 * Both the inbound and outbound data streams have
			 * come to an end.  Close down the socket.
			 */
			nstate = CCONN_ST_CLOSED;
			goto top;
		}
		goto release;

	case CCONN_ST_PRE_CONNECTION:
		abort();
		return;
	}

	abort();

release:
	cconn_callback_exit(ccn);
}

const char *
cconn_error_string(cconn_t *ccn)
{
	return (ccn->ccn_error_message);
}

int
cconn_error_errno(cconn_t *ccn)
{
	return (ccn->ccn_error_errno);
}

/*
 * Record some basic detail about the error condition we hit, and then move to
 * the error state.
 */
static void
cconn_raise_error(cconn_t *ccn, const char *err_msg, int err_errno)
{
	if (ccn->ccn_error_message != NULL) {
		/*
		 * Only record the first error we hit.  A subsequent error
		 * during teardown is regrettable, but should not mask the
		 * original fault.
		 */
		ccn->ccn_error_message = err_msg;
		ccn->ccn_error_errno = err_errno;
	}

	cconn_advance_state(ccn, CCONN_ST_ERROR);
}

/*
 * XXX
 */
void
cconn_more_data(cconn_t *ccn)
{
	if (ccn->ccn_state == CCONN_ST_DATA_AVAILABLE) {
		cconn_advance_state(ccn, CCONN_ST_WAITING_FOR_DATA);
	}
}

/*
 * XXX
 */
void
cconn_set_recvq_max(cconn_t *ccn, size_t max)
{
	ccn->ccn_recvq_max = max;
}


/*
 * XXX
 */
cbufq_t *
cconn_recvq(cconn_t *ccn)
{
	switch (ccn->ccn_state) {
	case CCONN_ST_DATA_AVAILABLE:
	case CCONN_ST_WAITING_FOR_DATA:
		break;

	default:
		errno = EINVAL;
		return (NULL);
	}

	return (ccn->ccn_recvq);
}

int
cconn_fin(cconn_t *ccn)
{
	switch (ccn->ccn_state) {
	case CCONN_ST_DATA_AVAILABLE:
	case CCONN_ST_WAITING_FOR_DATA:
	case CCONN_ST_READ_EOF:
		break;

	default:
		errno = EINVAL;
		return (-1);
	}

	ccn->ccn_sendq_end = B_TRUE;
	if (!ccn_sendq_finalised(ccn)) {
		/*
		 * If the sendq hasn't been completely flushed, we still
		 * need to wait for POLLOUT.
		 */
		cloop_ent_want(ccn->ccn_clent, CLOOP_CB_WRITE);
	}
	return (0);
}

int
cconn_abort(cconn_t *ccn)
{
	switch (ccn->ccn_state) {
	case CCONN_ST_DATA_AVAILABLE:
	case CCONN_ST_WAITING_FOR_DATA:
	case CCONN_ST_READ_EOF:
		break;

	default:
		errno = EINVAL;
		return (-1);
	}

	/*
	 * Enable an immediate close of the connection by setting SO_LINGER
	 * with a timeout of zero.
	 */
	struct linger l;
	l.l_onoff = 1;
	l.l_linger = 0;
	if (setsockopt(cloop_ent_fd(ccn->ccn_clent), SOL_SOCKET, SO_LINGER,
	    &l, sizeof (l)) != 0) {
		/*
		 * It's possible that the socket is not in a valid state for
		 * this option to be set.  If the error is not obviously a
		 * logic error, we'll let it slide.
		 */
		VERIFY(errno != EBADF && errno != ENOTSOCK && errno != EFAULT);
	}

	cconn_advance_state(ccn, CCONN_ST_CLOSED);
	return (0);
}

int
cconn_send(cconn_t *ccn, cbuf_t *cbuf)
{
	switch (ccn->ccn_state) {
	case CCONN_ST_DATA_AVAILABLE:
	case CCONN_ST_WAITING_FOR_DATA:
	case CCONN_ST_READ_EOF:
		break;

	default:
		errno = EINVAL;
		return (-1);
	}

	if (ccn->ccn_sendq_end) {
		errno = EPIPE;
		return (-1);
	}

	cbuf_flip(cbuf);
	cbufq_enq(ccn->ccn_sendq, cbuf);
	cloop_ent_want(ccn->ccn_clent, CLOOP_CB_WRITE);
	return (0);
}

/*
 * XXX
 */
static void
ccn_handle_incoming_data(cconn_t *ccn, int notify)
{
	size_t avail = cbufq_available(ccn->ccn_recvq);

	if (avail == 0 && ccn->ccn_recvq_end) {
		/*
		 * We have run out of buffers and hit EOF on the read side of
		 * the socket.  Inform our consumer that there will be no more
		 * data.
		 */
		cconn_advance_state(ccn, CCONN_ST_READ_EOF);
		return;
	}

	if (avail < ccn->ccn_recvq_max && !ccn->ccn_recvq_end) {
		/*
		 * As far as we know, there is more data to come.  Request
		 * additional reads.
		 */
		cloop_ent_want(ccn->ccn_clent, CLOOP_CB_READ);
	}

	if (notify && avail > 0) {
		/*
		 * Inform the consumer that there remains data in the recvq.
		 */
		cconn_advance_state(ccn, CCONN_ST_DATA_AVAILABLE);
	}
}

static boolean_t
ccn_sendq_finalised(cconn_t *ccn)
{
	if (cbufq_peek(ccn->ccn_sendq) != NULL || !ccn->ccn_sendq_end) {
		/*
		 * Either the sendq is not empty, or if it is empty it is not
		 * marked as ended.
		 */
		return (B_FALSE);
	}

	/*
	 * The outbound queue is empty _and_ we have no more data to send.
	 * Proceed with a FIN.
	 */
	if (cserver_debug) {
		fprintf(stderr, "CCONN[%p] SHUTDOWN WRITES\n", ccn);
	}
	if (shutdown(cloop_ent_fd(ccn->ccn_clent), SHUT_WR) != 0) {
		if (cserver_debug) {
			warn("shutdown(SHUT_WR)");
		}
		cconn_advance_state(ccn, CCONN_ST_ERROR);
		return (B_TRUE);
	}
	ccn->ccn_sendq_flushed = B_TRUE;

	if (ccn->ccn_state == CCONN_ST_READ_EOF) {
		/*
		 * If the read side has already shut down, we can close the
		 * whole connection now.
		 */
		cconn_advance_state(ccn, CCONN_ST_CLOSED);
	}
	return (B_TRUE);
}

static void
cconn_on_write(cloop_ent_t *clent, int ev)
{
	cconn_t *ccn = cloop_ent_data(clent);

	VERIFY(ev == CLOOP_CB_WRITE);

	if (ccn->ccn_state == CCONN_ST_WAITING_FOR_CONNECT) {
		/*
		 * Check for an asynchronous connect(3SOCKET) error.
		 */
		int err;
		size_t errsz = sizeof (err);
		if (getsockopt(cloop_ent_fd(clent), SOL_SOCKET, SO_ERROR,
		    &err, &errsz) != 0) {
			cconn_raise_error(ccn, "getsockopt() for async "
			    "connect() status", errno);
			return;
		}

		if (err != 0) {
			cconn_raise_error(ccn, "connect failed", err);
			return;
		}

		/*
		 * Connection was successful!  Start reading from the
		 * connection.
		 */
		cconn_advance_state(ccn, CCONN_ST_WAITING_FOR_DATA);
	}

	if (cserver_debug) {
		fprintf(stderr, "CCONN[%p] WRITE DATA\n", ccn);
	}

	if (ccn_sendq_finalised(ccn)) {
		/*
		 * The sendq has been completely flushed and we have
		 * shut down the socket for writes.
		 */
		return;
	}

	cbuf_t *head;
	while ((head = cbufq_peek(ccn->ccn_sendq)) != NULL) {
		size_t actual = 0;
		size_t want;

		if (cserver_debug) {
			cbufq_dump(ccn->ccn_sendq, stderr);
		}

		if ((want = cbuf_available(head)) < 1) {
			cbuf_free(cbufq_deq(ccn->ccn_sendq));
			continue;
		}
		if (cserver_debug) {
			fprintf(stderr, "CCONN[%p] WRITE DATA: HAVE %d; "
			    "Q %d\n", ccn, want,
			    cbufq_available(ccn->ccn_sendq));
		}

retry:
		if (cbuf_sys_send(head, cloop_ent_fd(clent),
		    CBUF_SYSREAD_ENTIRE, &actual, CSERVER_MSG_NOSIGNAL) != 0) {
			switch (errno) {
			case EINTR:
				goto retry;

			case EAGAIN:
				cloop_ent_want(clent, CLOOP_CB_WRITE);
				return;

			case EFAULT:
			case EBADF:
			case ENOTSOCK:
				abort();
				return;

			default:
				cconn_raise_error(ccn, "send() to socket",
				    errno);
				return;
			}
		}
	}

	if (cbufq_peek(ccn->ccn_sendq) != NULL) {
		/*
		 * The sendq is not empty, so we must poll for writes.
		 */
		cloop_ent_want(clent, CLOOP_CB_WRITE);
	}
}

static void
cconn_on_read(cloop_ent_t *clent, int ev)
{
	cconn_t *ccn = cloop_ent_data(clent);
	cbuf_t *cbuf = NULL;
	size_t actual = 0;
	boolean_t new_cbuf = B_FALSE;

	VERIFY(ev == CLOOP_CB_READ);

	if (cserver_debug) {
		fprintf(stderr, "CCONN[%p] READ DATA\n", ccn);
	}

	size_t av;
	if ((av = cbufq_available(ccn->ccn_recvq)) >= ccn->ccn_recvq_max) {
		/*
		 * We were woken to read, but the receive queue is already
		 * above the high water mark.  Assume this was a spurious
		 * wakeup and go back to sleep without rearming.
		 */
		if (cserver_debug) {
			fprintf(stderr, "CCONN[%p] READ TOO MUCH (%d)\n", ccn,
			    av);
		}
		return;
	}

	/*
	 * Check to see if we have space in the tail of the buffer queue:
	 */
	if ((cbuf = cbufq_peek_tail(ccn->ccn_recvq)) != NULL &&
	    cbuf_unused(cbuf) > 8) {
		cbuf_resume(cbuf);
		VERIFY(cbuf_available(cbuf) > 8);
		if (cserver_debug) {
			fprintf(stderr, "CCONN[%p] REUSE BUF %p (UNUSED %u)\n",
			    ccn, cbuf, cbuf_available(cbuf));
		}
	} else {
		/*
		 * Allocate a new buffer:
		 */
		new_cbuf = B_TRUE;
		if (cbuf_alloc(&cbuf, ccn->ccn_recvq_buffer_size) != 0) {
			err(1, "cbuf_alloc");
		}
		cbuf_byteorder_set(cbuf, ccn->ccn_order);
		if (cserver_debug) {
			fprintf(stderr, "CCONN[%p] ALLOC BUF %p (UNUSED %u)\n",
			    ccn, cbuf, cbuf_available(cbuf));
		}
	}

retry:
	if (cbuf_sys_read(cbuf, cloop_ent_fd(clent), CBUF_SYSREAD_ENTIRE,
	    &actual) != 0) {
		switch (errno) {
		case EINTR:
			goto retry;

		case EAGAIN:
			cloop_ent_want(clent, CLOOP_CB_READ);
			goto out;

		case EFAULT:
		case EBADF:
		case ENOTSOCK:
			abort();
			return;

		default:
			cconn_raise_error(ccn, "read() from socket", errno);
			goto out;
		}
	} else if (actual == 0) {
		/*
		 * Mark the receive queue as finished.  We will transition
		 * to EOF once the recvq has been completely emptied.
		 */
		ccn->ccn_recvq_end = B_TRUE;
		if (cserver_debug) {
			fprintf(stderr, "CCONN[%p] READ EOF\n", ccn);
		}
	} else if (cserver_debug) {
		fprintf(stderr, "CCONN[%p] READ %u BYTES\n", ccn, actual);
	}

	cbuf_flip(cbuf);
	if (new_cbuf) {
		if (actual == 0) {
			cbuf_free(cbuf);
		} else {
			cbufq_enq(ccn->ccn_recvq, cbuf);
		}
	}

	/*
	 * Handle any new data that has arrived:
	 */
	ccn_handle_incoming_data(ccn, actual > 0);
	return;

out:
	if (new_cbuf) {
		cbuf_free(cbuf);
	} else {
		cbuf_flip(cbuf);
	}
}

static void
cconn_on_other(cloop_ent_t *clent, int ev)
{
	cconn_t *ccn = cloop_ent_data(clent);

	if (cserver_debug) {
		fprintf(stderr, "CCONN[%p] OTHER (%d)\n", ccn, ev);
	}

	switch (ev) {
	case CLOOP_CB_HANGUP:
	case CLOOP_CB_ERROR:
		/*
		 * The POLLERR and POLLHUP events aren't particularly useful
		 * on their own, at least for AF_UNIX and probably TCP sockets.
		 * We use these events to trigger a read and a write from the
		 * descriptor, in order to try and catch any material errors.
		 * If the connection is already closed, don't run any more
		 * callbacks.
		 */
		cconn_callback_enter(ccn);
		if (ccn->ccn_state != CCONN_ST_CLOSED) {
			cconn_on_read(clent, CLOOP_CB_READ);
		}
		if (ccn->ccn_state != CCONN_ST_CLOSED) {
			cconn_on_write(clent, CLOOP_CB_WRITE);
		}
		cconn_callback_exit(ccn);
		return;

	default:
		abort();
	}
}

void
cconn_destroy(cconn_t *ccn)
{
	int e = errno;

	if (ccn == NULL)
		return;

	if (ccn->ccn_server != NULL) {
		list_remove(&ccn->ccn_server->csrv_connections, ccn);
	}

	cloop_ent_free(ccn->ccn_clent);
	cbufq_free(ccn->ccn_recvq);
	cbufq_free(ccn->ccn_sendq);
	free(ccn->ccn_remote_addr_str);

	free(ccn);

	errno = e;
}

int
cconn_alloc(cconn_t **ccnp)
{
	cconn_t *ccn = NULL;

	if ((ccn = calloc(1, sizeof (*ccn))) == NULL) {
		return (-1);
	}

	if (cloop_ent_alloc(&ccn->ccn_clent) != 0 ||
	    cbufq_alloc(&ccn->ccn_recvq) != 0 ||
	    cbufq_alloc(&ccn->ccn_sendq) != 0) {
		cconn_destroy(ccn);
		return (-1);
	}

	/*
	 * Link the cloop entity and the connection object.
	 */
	cloop_ent_data_set(ccn->ccn_clent, ccn);

	/*
	 * Install the appropriate cloop entity event callbacks.
	 */
	cloop_ent_on(ccn->ccn_clent, CLOOP_CB_HANGUP, cconn_on_other);
	cloop_ent_on(ccn->ccn_clent, CLOOP_CB_READ, cconn_on_read);
	cloop_ent_on(ccn->ccn_clent, CLOOP_CB_WRITE, cconn_on_write);
	cloop_ent_on(ccn->ccn_clent, CLOOP_CB_ERROR, cconn_on_other);

	/*
	 * Set the connection to the pre-connection state:
	 */
	ccn->ccn_state = CCONN_ST_PRE_CONNECTION;

	/*
	 * XXX Set default recvq size of 8KB.
	 */
	ccn->ccn_recvq_max = 8 * 1024;

	/*
	 * XXX Set default buffer size to 2KB.
	 */
	ccn->ccn_recvq_buffer_size = 2 * 1024;

	/*
	 * Use "network" byte order by default.
	 */
	ccn->ccn_order = CBUF_ORDER_BIG_ENDIAN;

	*ccnp = ccn;
	return (0);
}

void
cconn_byteorder_set(cconn_t *ccn, unsigned int order)
{
	switch (order) {
	case CBUF_ORDER_BIG_ENDIAN:
	case CBUF_ORDER_LITTLE_ENDIAN:
		ccn->ccn_order = order;
		break;

	default:
		abort();
		break;
	}
}

void
cconn_attach(cloop_t *cloop, cconn_t *ccn, int sock)
{
	/*
	 * Attach our cloop entity to the event loop:
	 */
	cloop_attach_ent(cloop, ccn->ccn_clent, sock);

	cconn_advance_state(ccn, CCONN_ST_WAITING_FOR_CONNECT);
}

int
cserver_signal_setup(void)
{
#ifndef	MSG_NOSIGNAL
	/*
	 * Writing to a SOCK_STREAM socket that has been shut down for writing
	 * will result not only in the desired EPIPE error, but an entirely
	 * unhelpful thread-directed SIGPIPE signal.  Prior to the introduction
	 * of the MSG_NOSIGNAL option for send(3SOCKET), etc, the only way to
	 * avoid this signal is to ignore it completely.
	 *
	 * In order to avoid silently inflicting this regrettable porcine face
	 * paint on every consumer, we provide this entry point to make the
	 * change if it is required for this system.
	 */
	struct sigaction sa;
	sa.sa_handler = SIG_IGN;
	sa.sa_flags = 0;
	VERIFY0(sigemptyset(&sa.sa_mask));

	if (sigaction(SIGPIPE, &sa, NULL) != 0) {
		return (-1);
	}
#endif

	return (0);
}

static int
cserver_setsockopt_int(int s, int level, int optname, int optval)
{
	return (setsockopt(s, level, optname, &optval, sizeof (optval)));
}

int
cserver_accept(cserver_t *csrv, cconn_t **ccnp)
{
	cconn_t *ccn = NULL;
	size_t sz;
	int e;
	int fd;

	if (cconn_alloc(&ccn) != 0) {
		*ccnp = NULL;
		return (-1);
	}

	sz = sizeof (ccn->ccn_remote_addr);
retry:
	if ((fd = accept4(cloop_ent_fd(csrv->csrv_listen),
	    (struct sockaddr *)&ccn->ccn_remote_addr, &sz,
	    SOCK_CLOEXEC | SOCK_NONBLOCK)) < 0) {
		switch (errno) {
		case EINTR:
			goto retry;

		case ECONNABORTED:
		case EWOULDBLOCK:
			/*
			 * Not actionable.  Back to sleep.
			 */
			e = EWOULDBLOCK;
			cloop_ent_want(csrv->csrv_listen, CLOOP_CB_READ);
			goto fail;

		default:
			VERIFY3S(errno, ==, 0);
		}
	}

	/*
	 * Enable keep-alive probes for this socket, such that if the remote
	 * peer goes away we will eventually notice.
	 */
	if (cserver_setsockopt_int(fd, SOL_SOCKET, SO_KEEPALIVE, 1) != 0) {
		e = errno;
		if (cserver_debug) {
			warn("could not set SO_KEEPALIVE");
		}
		goto fail;
	}

	/*
	 * Further tune the keep-alive mechanism to be more responsive.  The
	 * IDLE and INTVL interval (in seconds) specify how long to wait before
	 * sending the first and subsequent probes, respectively.  The CNT is
	 * the number of failed probes before we will abort the connection.
	 * See tcp(7P) for more information.
	 */
	(void) cserver_setsockopt_int(fd, IPPROTO_TCP, TCP_KEEPIDLE, 1);
	(void) cserver_setsockopt_int(fd, IPPROTO_TCP, TCP_KEEPCNT, 15);
	(void) cserver_setsockopt_int(fd, IPPROTO_TCP, TCP_KEEPINTVL, 1);

	/*
	 * We want to be notified when there are more incoming connections.
	 */
	cloop_ent_want(csrv->csrv_listen, CLOOP_CB_READ);

	/*
	 * Link this connection into the server connection list:
	 */
	ccn->ccn_server = csrv;
	list_insert_tail(&csrv->csrv_connections, ccn);

	/*
	 * Attach our cloop entity to the event loop:
	 */
	cloop_attach_ent(csrv->csrv_loop, ccn->ccn_clent, fd);

	/*
	 * Mark this connection as waiting for incoming data.
	 */
	cconn_advance_state(ccn, CCONN_ST_WAITING_FOR_DATA);

	ccn->ccn_remote_addr_str = strdup(inet_ntoa(cconn_sockaddr_in(
	    ccn)->sin_addr));
	if (cserver_debug) {
		fprintf(stderr, "ACCEPTED (%s)\n", ccn->ccn_remote_addr_str);
	}

	*ccnp = ccn;
	return (0);

fail:
	cconn_destroy(ccn);
	errno = e;
	return (-1);
}

static void
cserver_on_incoming(cloop_ent_t *clent, int event)
{
	cserver_t *csrv = cloop_ent_data(clent);

	VERIFY(event == CLOOP_CB_READ);


	if (csrv->csrv_on_incoming != NULL) {
		/*
		 * Report a possible incoming connection to our consumer.
		 * Note that we do not rearm for read events; this happens
		 * in cserver_accept().
		 */
		csrv->csrv_on_incoming(csrv, CSERVER_CB_INCOMING);
	} else {
		/*
		 * XXX Should we abort here?
		 */
		fprintf(stderr, "CSERVER[%p]: INCOMING WITH NO HANDLER!\n",
		    csrv);
		abort();
		cloop_ent_want(clent, CLOOP_CB_READ);
	}
}

const char *
cconn_remote_addr_str(cconn_t *ccn)
{
	return (ccn->ccn_remote_addr_str);
}

void
cconn_on(cconn_t *ccn, int event, cconn_cb_t *func)
{
	switch ((cconn_cb_type_t) event) {
	case CCONN_CB_DATA_AVAILABLE:
		ccn->ccn_on_data_available = func;
		return;

	case CCONN_CB_ERROR:
		ccn->ccn_on_error = func;
		return;

	case CCONN_CB_END:
		ccn->ccn_on_end = func;
		return;

	case CCONN_CB_CLOSE:
		ccn->ccn_on_close = func;
		return;

	case CCONN_CB_CONNECTED:
		ccn->ccn_on_connected = func;
		return;
	}

	warnx("unknown cconn cb %d\n", event);
	abort();
}

void
cserver_on(cserver_t *csrv, int event, cserver_cb_t *func)
{
	switch ((cserver_cb_type_t) event) {
	case CSERVER_CB_INCOMING:
		csrv->csrv_on_incoming = func;
		return;
	}

	warnx("unknown cserver cb %d\n", event);
	abort();
}

static void
cserver_on_error(cloop_ent_t *clent, int event)
{
	cserver_t *csrv = cloop_ent_data(clent);

	VERIFY(event == CLOOP_CB_ERROR);

	/*
	 * It's not clear why this would happen to us on a listen socket.
	 */
	fprintf(stderr, "CSERVER[%p]: ERROR!\n", csrv);
	abort();
}

static void
cserver_on_hangup(cloop_ent_t *clent, int event)
{
	cserver_t *csrv = cloop_ent_data(clent);

	VERIFY(event == CLOOP_CB_HANGUP);

	/*
	 * It's not clear why this would happen to us on a listen socket.
	 */
	fprintf(stderr, "CSERVER[%p]: HANGUP!\n", csrv);
	abort();
}

void
cserver_free(cserver_t *csrv)
{
	if (csrv == NULL) {
		return;
	}

	cserver_close(csrv);

	/*
	 * Destroy all connections.
	 */
	while (!list_is_empty(&csrv->csrv_connections)) {
		cconn_destroy(list_head(&csrv->csrv_connections));
	}

	free(csrv);
}

int
cserver_alloc(cserver_t **csrvp)
{
	cserver_t *csrv = NULL;
	cloop_ent_t *clent = NULL;

	if (getenv("CSERVER_DEBUG") != NULL) {
		cserver_debug = B_TRUE;
	}

	if ((csrv = calloc(1, sizeof (*csrv))) == NULL) {
		return (-1);
	}
	csrv->csrv_type = CSERVER_TYPE_NONE;

	if (cloop_ent_alloc(&clent) != 0) {
		free(csrv);
		return (-1);
	}

	/*
	 * Create list of connection objects for this server:
	 */
	list_create(&csrv->csrv_connections, sizeof (cconn_t),
	    offsetof(cconn_t, ccn_link));

	/*
	 * Link the listen server to the cloop entity:
	 */
	csrv->csrv_listen = clent;
	cloop_ent_data_set(clent, csrv);

	*csrvp = csrv;
	return (0);
}

static int
cserver_parse_long(const char *input, long *output, int base)
{
	char *endp;
	long ret;

	errno = 0;
	ret = strtol(input, &endp, base);

	if (ret == 0 && errno == EINVAL) {
		return (-1);
	} else if ((ret == LONG_MAX || ret == LONG_MIN) && errno == ERANGE) {
		return (-1);
	}

	/*
	 * Any other error would appear to be a programmer error.
	 */
	VERIFY3S(errno, ==, 0);

	if (*endp != '\0') {
		/*
		 * The string contained trailing detritus after the numeric
		 * portion.
		 */
		errno = EINVAL;
		return (-1);
	}

	*output = ret;
	return (0);
}


int
cserver_parse_ipv4addr(const char *ipaddr, const char *port,
    struct sockaddr_in *addr)
{
	long portn;

	if (cserver_parse_long(port, &portn, 10) != 0 ||
	    portn < 1 || portn > 65535) {
		if (cserver_debug) {
			warnx("invalid port %s", port);
		}
		errno = EPROTO;
		return (-1);
	}

	bzero(addr, sizeof (*addr));
	addr->sin_family = AF_INET;
	addr->sin_port = htons((in_port_t)portn);

	switch (inet_pton(AF_INET, ipaddr, &addr->sin_addr)) {
	case 1:
		return (0);
	case 0:
		if (cserver_debug) {
			warnx("inet_pton (%s) invalid address", ipaddr);
		}
		errno = EPROTO;
		return (-1);
	default:
		if (cserver_debug) {
			warn("inet_pton (%s) failure", ipaddr);
		}
		return (-1);
	}
}

int
cserver_listen_tcp(cserver_t *csrv, cloop_t *cloop, const char *ipaddr,
    const char *port, int backlog)
{
	int e;
	int sock = -1;
	struct sockaddr_in addr;

	if (csrv->csrv_type != CSERVER_TYPE_NONE) {
		/*
		 * This server is already listening.
		 */
		errno = EINVAL;
		return (-1);
	}

	/*
	 * Create TCP listen socket.
	 */
	if ((sock = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC,
	    0)) < 0) {
		e = errno;
		if (cserver_debug) {
			warn("socket failed");
		}
		goto fail;
	}

	/*
	 * Set socket options.
	 */
	int opt_on = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt_on,
	    sizeof (opt_on)) != 0) {
		e = errno;
		if (cserver_debug) {
			warn("could not set SO_REUSEADDR");
		}
		goto fail;
	}

	/*
	 * Set TCP Listen Address.
	 */
	if (cserver_parse_ipv4addr(ipaddr != NULL ? ipaddr : "0.0.0.0", port,
	    &addr) != 0) {
		e = errno;
		if (cserver_debug) {
			warn("cserver_parse_ipv4addr failed");
		}
		goto fail;
	}

	/*
	 * Bind to the Listen Address.
	 */
	if (bind(sock, (struct sockaddr *)&addr, sizeof (addr)) != 0) {
		e = errno;
		if (cserver_debug) {
			warn("bind failed");
		}
		goto fail;
	}

	/*
	 * Listen.
	 */
	if (listen(sock, backlog) != 0) {
		e = errno;
		if (cserver_debug) {
			warn("listen failed");
		}
		goto fail;
	}

	/*
	 * We were successful in establishing the listen socket.  Copy
	 * the relevant data into the server object:
	 */
	csrv->csrv_type = CSERVER_TYPE_TCP;
	*cserver_sockaddr_in(csrv) = addr;

	/*
	 * Register our callbacks:
	 */
	cloop_ent_t *clent = csrv->csrv_listen;
	cloop_ent_on(clent, CLOOP_CB_READ, cserver_on_incoming);
	cloop_ent_on(clent, CLOOP_CB_HANGUP, cserver_on_hangup);
	cloop_ent_on(clent, CLOOP_CB_ERROR, cserver_on_error);

	/*
	 * We want to be notified of incoming connections:
	 */
	cloop_ent_want(clent, CLOOP_CB_READ);

	/*
	 * Attach the cloop entity to the loop:
	 */
	csrv->csrv_loop = cloop;
	cloop_attach_ent(cloop, clent, sock);
	return (0);

fail:
	if (sock != -1) {
		VERIFY0(close(sock));
	}
	errno = e;
	return (-1);
}

/*
 * Close the listen socket so as to stop accepting incoming connections.
 */
void
cserver_close(cserver_t *csrv)
{
	if (csrv->csrv_listen == NULL)
		return;

	cloop_ent_free(csrv->csrv_listen);
	csrv->csrv_listen = NULL;
}

void
cserver_abort(cserver_t *csrv)
{
	/*
	 * Abort all connections.
	 */
	while (!list_is_empty(&csrv->csrv_connections)) {
		cconn_abort(list_head(&csrv->csrv_connections));
	}
}
