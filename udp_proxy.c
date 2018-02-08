


#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <inttypes.h>
#include <unistd.h>
#include <strings.h>
#include <err.h>
#include <errno.h>
#include <port.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/un.h>

#include <sys/debug.h>
#include <sys/list.h>
#include <sys/avl.h>

#include <libcbuf.h>
#include <libcloop.h>
#include <bunyan.h>

#include "bbal.h"


static int
bbal_parse_ipv4addr(const char *ipaddr, const char *port,
    struct sockaddr_in *addr)
{
	bzero(addr, sizeof (*addr));

	addr->sin_family = AF_INET;
	addr->sin_port = htons(atoi(port));

	switch (inet_pton(AF_INET, ipaddr, &addr->sin_addr)) {
	case 1:
		return (0);

	case 0:
		warnx("inet_pton (%s) invalid address", ipaddr);
		errno = EPROTO;
		return (-1);

	default:
		warn("inet_pton (%s) failure", ipaddr);
		return (-1);
	}
}

int
bbal_udp_listen(const char *ipaddr, const char *port, int *sockp)
{
	int e;
	int sock = -1;
	struct sockaddr_in addr;

	/*
	 * Create UDP listen socket.
	 */
	if ((sock = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC,
	    0)) < 0) {
		e = errno;
		warn("socket failed");
		goto fail;
	}

	/*
	 * Set socket options.
	 */
	int opt_on = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt_on,
	    sizeof (opt_on)) != 0) {
		e = errno;
		warn("could not set SO_REUSEADDR");
		goto fail;
	}

	if (bbal_parse_ipv4addr(ipaddr != NULL ? ipaddr : "0.0.0.0", port,
	    &addr) != 0) {
		e = errno;
		warn("bbal_parse_ipv4addr failed");
		goto fail;
	}

	/*
	 * Bind to the socket.
	 */
	if (bind(sock, (struct sockaddr *)&addr, sizeof (addr)) != 0) {
		e = errno;
		warn("bind failed");
		goto fail;
	}

	bunyan_info(g_log, "listening for UDP packets",
	    BUNYAN_T_STRING, "address", ipaddr,
	    BUNYAN_T_STRING, "port", port,
	    BUNYAN_T_END);

	*sockp = sock;
	return (0);

fail:
	if (sock != -1) {
		VERIFY0(close(sock));
	}
	errno = e;
	return (-1);
}

void
bbal_udp_read(cloop_ent_t *ent, int event)
{
	cbuf_t *buf;

	if (cbuf_alloc(&buf, 8192) != 0) {
		warn("cbuf_alloc");
		return;
	}
	cbuf_byteorder_set(buf, CBUF_ORDER_LITTLE_ENDIAN);
	size_t hdrsz = 4 * sizeof (uint32_t);
	VERIFY0(cbuf_position_set(buf, hdrsz));

	/*
	 * XXX Read a packet from the file descriptor.
	 */
	struct sockaddr_storage from;
	socklen_t fromlen = sizeof (from);
	size_t rsz;
	if (cbuf_sys_recvfrom(buf, cloop_ent_fd(ent),
	    CBUF_SYSREAD_ENTIRE, &rsz, 0, (struct sockaddr *)&from,
	    &fromlen) != 0) {
		warn("recvfrom failure");
		goto bail;
	}

	struct sockaddr_in *sin = (struct sockaddr_in *)&from;
	char remote[INET6_ADDRSTRLEN];
	const char *a = inet_ntop(sin->sin_family,
	    &sin->sin_addr, remote, sizeof (remote));

	fprintf(stdout, "[%s:%d] recvfrom %d bytes\n", a,
	    (int)ntohs(sin->sin_port), rsz);

	remote_t *rem = remote_lookup(&sin->sin_addr);
	if (rem == NULL) {
		fprintf(stdout, "\tno remote; drop\n");
		goto bail;
	}

	backend_t *be = backend_lookup(rem->rem_backend);
	if (be == NULL) {
		fprintf(stdout, "\tno backend; drop\n");
		goto bail;
	}

	if (!be->be_ok) {
		fprintf(stdout, "\tbackend not ok; drop\n");
		goto bail;
	}

	/*
	 * Preserve the final position so that we can go back and add the
	 * header.
	 */
	size_t p = cbuf_position(buf);
	cbuf_rewind(buf);

	VERIFY0(cbuf_put_u32(buf, 2)); /* FRAME TYPE */
	VERIFY0(cbuf_put_u32(buf, ntohl(sin->sin_addr.s_addr))); /* IP */
	VERIFY0(cbuf_put_u32(buf, ntohs(sin->sin_port))); /* PORT */
	VERIFY0(cbuf_put_u32(buf, (uint32_t)rsz)); /* FRAME DATA LENGTH */

	VERIFY0(cbuf_position_set(buf, p));

	fprintf(stdout, "\tbackend ok; sending\n");
	if (cconn_send(be->be_conn, buf) != 0) {
		warn("send backend %d", be->be_id);

		cconn_abort(be->be_conn);
	}

	cloop_ent_want(ent, CLOOP_CB_READ);
	return;

bail:
	cbuf_free(buf);
	cloop_ent_want(ent, CLOOP_CB_READ);
}
