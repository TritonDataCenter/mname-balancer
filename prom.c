
#include "bbal.h"

cloop_t *g_loop;
cserver_t *g_prom;

#define	CRLF	"\r\n"

uint64_t g_metric_reset = 0;
uint64_t g_reqs = 0;

static uint32_t g_prom_conn_count = 0;

typedef struct prom_conn {
	uint32_t pc_id;
	cconn_t *pc_conn;

	http_inc_t *pc_req;
} prom_conn_t;


static int
bbal_prom_respond(prom_conn_t *pc)
{
	warnx("bbal_prom_respond(id %u)", pc->pc_id);

	g_reqs++;

	cbuf_t *buf = NULL;
	custr_t *body = NULL;
	custr_t *head = NULL;
	if (custr_alloc(&body) != 0 || custr_alloc(&head) != 0) {
		custr_free(body);
		custr_free(head);
		return (-1);
	}

	warnx(" method = %s", http_inc_method(pc->pc_req));
	warnx(" url = %s", http_inc_url(pc->pc_req));
	const strmap_ent_t *e = NULL;
	while ((e = strmap_next(http_inc_headers(pc->pc_req), e)) != NULL) {
		warnx("   header: \"%s\" = %s", strmap_ent_key(e),
		    strmap_ent_value(e));
	}

	const char *ctype = NULL;
	const char *status = NULL;
	if (strcmp(http_inc_method(pc->pc_req), "GET") != 0) {
		ctype = "text/plain";
		status = "405 Method Not Allowed";
		if (custr_append(body, "Only GET is allowed.\n") != 0) {
			goto done;
		}
	} else if (strcmp(http_inc_url(pc->pc_req), "/metrics") != 0) {
		ctype = "text/plain";
		status = "404 Not Found";
		if (custr_append(body, "URL not found; try /metrics\n") != 0) {
			goto done;
		}
	} else {
		/*
		 * Construct a reply for this "GET /metrics" request:
		 */
		ctype = "text/plain; version=0.0.4"; /* XXX */
		status = "200 OK";
		if (custr_append_printf(body,
		    "# HELP metric_requests_total Total number of metric "
		    "requests.\n"
		    "# TYPE metric_requests_total counter\n"
		    "metric_requests_total %llu %llu\n",
		    (long long unsigned)g_reqs,
		    (long long unsigned)g_metric_reset) != 0) {
			goto done;
		}
	}

	/*
	 * Construct our reply:
	 */
	if (custr_append_printf(head,
	    "HTTP/1.0 %s" CRLF
	    "Server: blah" CRLF
	    "Connection: close" CRLF
	    "Content-Type: %s" CRLF
	    "Content-Length: %u" CRLF
	    CRLF,
	    status, ctype, (unsigned)custr_len(body)) != 0) {
		goto done;
	}

	if (cbuf_alloc(&buf, custr_len(head) + custr_len(body)) != 0) {
		goto done;
	}

	/*
	 * XXX sigh.
	 */
	for (size_t n = 0; n < custr_len(head); n++) {
		cbuf_put_char(buf, custr_cstr(head)[n]);
	}
	for (size_t n = 0; n < custr_len(body); n++) {
		cbuf_put_char(buf, custr_cstr(body)[n]);
	}

	if (cconn_send(pc->pc_conn, buf) != 0) {
		cconn_abort(pc->pc_conn);
		goto done;
	}
	buf = NULL;

	if (cconn_fin(pc->pc_conn) != 0) {
		cconn_abort(pc->pc_conn);
		goto done;
	}

done:
	cbuf_free(buf);
	custr_free(head);
	custr_free(body);
	return (0);
}

static void
bbal_prom_data(cconn_t *ccn, int event)
{
	prom_conn_t *pc = cconn_data(ccn);

	warnx("bbal_prom_data(id %u)", pc->pc_id);

	cbufq_t *q = cconn_recvq(ccn);
	while (cbufq_peek(q) != NULL) {
		cbuf_t *b = cbufq_peek(q);

		if (cbuf_available(b) == 0) {
			/*
			 * The head of the queue is an empty buffer.  Discard
			 * it.
			 */
			cbuf_free(cbufq_deq(q));
			continue;
		}

		if (http_inc_complete(pc->pc_req)) {
			warnx("bbal_prom_data(id %u) DATA AFTER REQUEST",
			    pc->pc_id);
			cconn_abort(pc->pc_conn);
			return;
		}

		if (http_inc_input_cbuf(pc->pc_req, b) != 0) {
			warnx("bbal_prom_data(id %u) failed: %s", pc->pc_id,
			    http_inc_error(pc->pc_req));
			cconn_abort(pc->pc_conn);
			return;
		}

		if (http_inc_complete(pc->pc_req)) {
			warnx("bbal_prom_data(id %u) complete; url: %s",
			    pc->pc_id, http_inc_url(pc->pc_req));
			(void) bbal_prom_respond(pc);
			return;
		}
	}

	cconn_more_data(ccn);
}

static void
bbal_prom_end(cconn_t *ccn, int event)
{
	prom_conn_t *pc = cconn_data(ccn);

	warnx("bbal_prom_end(id %u)", pc->pc_id);

	cconn_abort(ccn);
}

static void
bbal_prom_close(cconn_t *ccn, int event)
{
	prom_conn_t *pc = cconn_data(ccn);

	warnx("bbal_prom_close(id %u)", pc->pc_id);

	http_inc_free(pc->pc_req);
	free(pc);
}

static void
bbal_prom_error(cconn_t *ccn, int event)
{
	prom_conn_t *pc = cconn_data(ccn);

	warnx("bbal_prom_error(id %u)", pc->pc_id);
}

static void
bbal_prom_incoming(cserver_t *cserver, int event)
{
	prom_conn_t *pc;
	if ((pc = calloc(1, sizeof (*pc))) == NULL ||
	    http_inc_alloc(&pc->pc_req) != 0) {
		/*
		 * XXX
		 */
		abort();
	}
	pc->pc_id = ++g_prom_conn_count;

	if (cserver_accept(cserver, &pc->pc_conn) != 0) {
		if (errno != EAGAIN) {
			warnx("incoming TCP accept failure");
		}
		free(pc);
		return;
	}

	cconn_data_set(pc->pc_conn, pc);
	cconn_on(pc->pc_conn, CCONN_CB_DATA_AVAILABLE, bbal_prom_data);
	cconn_on(pc->pc_conn, CCONN_CB_END, bbal_prom_end);
	cconn_on(pc->pc_conn, CCONN_CB_ERROR, bbal_prom_error);
	cconn_on(pc->pc_conn, CCONN_CB_CLOSE, bbal_prom_close);

	// cconn_abort(pc->pc_conn); /* XXX */
}

static int
bbal_prom_listen(cserver_t *tcp, cloop_t *loop, const char *listen_ip,
    const char *listen_port)
{
	cserver_on(tcp, CSERVER_CB_INCOMING, bbal_prom_incoming);
	if (cserver_listen_tcp(tcp, loop, listen_ip, listen_port,
	    1000 /* XXX */) != 0) {
		warn("cserver_listen_tcp");
		return (-1);
	}

	warnx("cserver_listen_tcp ok");
	return (0);
}


int
main(int argc, char *argv[])
{
	const char *listen_ip = "0.0.0.0";
	const char *listen_port = "9900";

	g_metric_reset = time(NULL) * 1000; /* XXX sigh */

	int c;
	while ((c = getopt(argc, argv, ":b:p:")) != -1) {
		switch (c) {
		case 'b':
			listen_ip = optarg;
			break;

		case 'p':
			listen_port = optarg;
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

	if (cserver_signal_setup() != 0) {
		err(1, "cserver_signal_setup");
	}

	if (cloop_alloc(&g_loop) != 0 || cserver_alloc(&g_prom) != 0) {
		err(1, "cloop init failure");
		exit(1);
	}

	if (bbal_prom_listen(g_prom, g_loop, listen_ip, listen_port) != 0) {
		exit(1);
	}

	for (;;) {
		unsigned int again = 0;

		if (cloop_run(g_loop, &again) != 0) {
			err(1, "cloop run failure");
		}

		VERIFY3U(again, !=, 0);
	}

	abort();
}
