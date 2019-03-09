


#include "bbal.h"
#include <strmap.h>
#include <http_parser.h>


typedef enum {
	HPWH_NONE = 0,
	HPWH_URL,
	HPWH_HEADER_NAME,
	HPWH_HEADER_VALUE,
	HPWH_BODY
} hpwrap_what_t;

typedef struct hpwrap {
	const char *hpwr_error;

	custr_t *hpwr_buf;
	char *hpwr_header_name;
	hpwrap_what_t hpwr_what;
	http_parser hpwr_parser;

	char *hpwr_url;
	strmap_t *hpwr_headers;

	bool hpwr_finished;
} hpwrap_t;

static int
hpwrap_init(hpwrap_t *hpwr)
{
	hpwr->hpwr_error = NULL;
	hpwr->hpwr_what = HPWH_NONE;
	hpwr->hpwr_url = NULL;
	hpwr->hpwr_finished = false;

	hpwr->hpwr_parser.data = hpwr;
	http_parser_init(&hpwr->hpwr_parser, HTTP_REQUEST);

	if (custr_alloc(&hpwr->hpwr_buf) != 0) {
		return (-1);
	}

	if (strmap_alloc(&hpwr->hpwr_headers,
	    STRMAP_F_UNIQUE_NAMES | STRMAP_F_CASE_INSENSITIVE) != 0) {
		custr_free(hpwr->hpwr_buf);
		return (-1);
	}

	return (0);
}

static void
hpwrap_clear(hpwrap_t *hpwr)
{
	free(hpwr->hpwr_url);
	custr_free(hpwr->hpwr_buf);
	strmap_free(hpwr->hpwr_headers);
}

static int
commit_string(hpwrap_t *hpwr, char **target)
{
	char *t;

	if ((t = strndup(custr_cstr(hpwr->hpwr_buf),
	    custr_len(hpwr->hpwr_buf))) == NULL) {
		hpwr->hpwr_error = "commit_string";
		return (-1);
	}

	free(*target);
	*target = t;
	return (0);
}

static int
hpwrap_common(hpwrap_t *hpwr, hpwrap_what_t what, const char *input,
    size_t length)
{
	if (hpwr->hpwr_error != NULL) {
		/*
		 * Things have already failed; exit without doing any more
		 * work.
		 */
		return (-1);
	}

#if 0
	warnx("hpwrap_common(%u, %c)", what, input[0] == '\0' ? '*' : input[0]);
#endif

	/*
	 * If this event type is the same as the previous type, just append the
	 * new string chunk to the existing value.
	 */
	if (what == hpwr->hpwr_what) {
		goto append;
	}

#if 0
	warnx("hpwrap_common(%u -> %u)", hpwr->hpwr_what, what);
#endif

	/*
	 * The event type has changed.  Commit the existing value and clear.
	 */
	switch (hpwr->hpwr_what) {
	case HPWH_NONE:
		break;

	case HPWH_URL:
		if (commit_string(hpwr, &hpwr->hpwr_url) != 0) {
			return (-1);
		}
		break;

	case HPWH_HEADER_NAME:
		if (commit_string(hpwr, &hpwr->hpwr_header_name) != 0) {
			return (-1);
		}
		break;

	case HPWH_HEADER_VALUE:
		if (strmap_add(hpwr->hpwr_headers, hpwr->hpwr_header_name,
		    custr_cstr(hpwr->hpwr_buf)) != 0) {
			hpwr->hpwr_error = "strmap_add";
			return (-1);
		}
		break;

	default:
		break;
	}

	/*
	 * Clear out the accumulating buffer before starting to collect for the
	 * new event type.
	 */
	custr_reset(hpwr->hpwr_buf);
	hpwr->hpwr_what = what;

append:
	if (what != HPWH_BODY) {
		for (size_t i = 0; i < length; i++) {
			if (input[i] == '\0') {
				/*
				 * XXX
				 */
				hpwr->hpwr_error = "embedded NUL byte";
				return (-1);
			}

			if (custr_appendc(hpwr->hpwr_buf, input[i]) != 0) {
				hpwr->hpwr_error = "custr_appendc";
				return (-1);
			}
		}
	}

	return (0);
}

static int
hpwrap_on_message_begin(http_parser *hp)
{
	return (hpwrap_common(hp->data, HPWH_NONE, "", 0));
}

static int
hpwrap_on_message_complete(http_parser *hp)
{
	int ret = hpwrap_common(hp->data, HPWH_NONE, "", 0);

	if (ret == 0) {
		hpwrap_t *hpwr = hp->data;

		hpwr->hpwr_finished = true;
	}

	return (ret);
}

static int
hpwrap_on_headers_complete(http_parser *hp)
{
	return (hpwrap_common(hp->data, HPWH_NONE, "", 0));
}

static int
hpwrap_on_header_field(http_parser *hp, const char *input, size_t len)
{
	return (hpwrap_common(hp->data, HPWH_HEADER_NAME, input, len));
}

static int
hpwrap_on_header_value(http_parser *hp, const char *input, size_t len)
{
	return (hpwrap_common(hp->data, HPWH_HEADER_VALUE, input, len));
}

static int
hpwrap_on_url(http_parser *hp, const char *input, size_t len)
{
	return (hpwrap_common(hp->data, HPWH_URL, input, len));
}

static http_parser_settings hpwrap_settings = {
	.on_message_begin = hpwrap_on_message_begin,
	.on_message_complete = hpwrap_on_message_complete,
	.on_url = hpwrap_on_url,
	.on_headers_complete = hpwrap_on_headers_complete,
	.on_header_field = hpwrap_on_header_field,
	.on_header_value = hpwrap_on_header_value,
};



struct http_inc {
	hpwrap_t him_hpwrap;

	/*
	 * Track the current inbound byte count for this request, as well as
	 * the maximum number of bytes we're willing to read in one request.
	 */
	size_t him_len;
	size_t him_max_len;
};

/*
 * Allocate an incoming HTTP request structure.
 */
int
http_inc_alloc(http_inc_t **himp)
{
	http_inc_t *him;

	if ((him = calloc(1, sizeof (*him))) == NULL) {
		return (-1);
	}

	hpwrap_init(&him->him_hpwrap);

	him->him_len = 0;
	him->him_max_len = 128 * 1024; /* XXX 128KB */

	*himp = him;
	return (0);
}

void
http_inc_free(http_inc_t *him)
{
	if (him == NULL) {
		return;
	}

	hpwrap_clear(&him->him_hpwrap);
	free(him);
}

/*
 * Read bytes from a cbuf_t and pass them through the parser.  The caller is
 * responsible for freeing the buffer.
 */
int
http_inc_input_cbuf(http_inc_t *him, cbuf_t *b)
{
	if (him->him_hpwrap.hpwr_error != NULL) {
		return (-1);
	}

	while (cbuf_available(b) > 0) {
		char c[2];

		if (http_inc_complete(him)) {
			/*
			 * We have read an entire request, so stop.
			 */
			return (0);
		}

		if (him->him_len >= him->him_max_len) {
			him->him_hpwrap.hpwr_error = "client overrun";
			return (-1);
		}
		him->him_len++;

		/*
		 * XXX sigh.
		 */
		VERIFY0(cbuf_get_char(b, &c[0]));
		c[1] = '\0';

		if (http_parser_execute(&him->him_hpwrap.hpwr_parser,
		    &hpwrap_settings, c, 1) != 1) {
			him->him_hpwrap.hpwr_error = "HTTP parser";
			return (-1);
		}
	}

	return (0);
}

/*
 * Returns true when a request has been completely ingested.
 */
bool
http_inc_complete(http_inc_t *him)
{
	if (him->him_hpwrap.hpwr_error != NULL) {
		return (false);
	}

	return (him->him_hpwrap.hpwr_finished);
}

const char *
http_inc_url(http_inc_t *him)
{
	if (!http_inc_complete(him)) {
		return (NULL);
	}

	return (him->him_hpwrap.hpwr_url);

}

const char *
http_inc_method(http_inc_t *him)
{
	if (!http_inc_complete(him)) {
		return (NULL);
	}

	return (http_method_str(him->him_hpwrap.hpwr_parser.method));
}

const char *
http_inc_error(http_inc_t *him)
{
	return (him->him_hpwrap.hpwr_error);
}

const strmap_t *
http_inc_headers(http_inc_t *him)
{
	if (!http_inc_complete(him)) {
		return (NULL);
	}

	return (him->him_hpwrap.hpwr_headers);
}
