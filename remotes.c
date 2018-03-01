/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright (c) 2018, Joyent, Inc.
 */

/*
 * REMOTES
 *
 * The load balancer maintains an association between a remote host (identified
 * by its IP address) and a particular backend DNS server process.  This
 * association is tracked via a "remote_t" object, indexed by remote IP address
 * in an AVL.
 *
 * The tracking object for a remote peer will be discarded if that peer does
 * not interact with the DNS server for some time (see the "remotes_expire"
 * function).
 *
 * Backend selection is "sticky" so that requests from a particular remote host
 * will be serviced by the same DNS server process as long as that process
 * remains available.  This should result in more consistent and debuggable
 * service when possible; i.e., if you run "dig" on a remote peer, your request
 * should be serviced by the same backend as other requests made from that
 * peer.  See the "remote_backend" function for more details about backend
 * selection.
 */

#include "bbal.h"

/*
 * Map from remote IP address to remote object.
 */
static avl_tree_t g_remotes;

static int
remotes_compar(const void *first, const void *second)
{
	const remote_t *rf = first;
	const remote_t *rs = second;

	return (compare_u32(rf->rem_addr.s_addr, rs->rem_addr.s_addr));
}

typedef enum {
	REMBE_PRIMARY = 1234,
	REMBE_BACKUP,
	REMBE_BOTH
} backend_which_t;

/*
 * Set the backend for a particular remote object.
 *
 * This function, and its sister function "remote_backend_reset", are
 * responsible for keeping the count of remotes assigned to a particular
 * backend up to date.
 */
static void
remote_backend_set(remote_t *rem, backend_which_t w, backend_t *be)
{
	VERIFY(w == REMBE_PRIMARY || w == REMBE_BACKUP);

	if (w == REMBE_PRIMARY) {
		VERIFY3U(rem->rem_backend, ==, 0);

		rem->rem_backend = be->be_id;
		be->be_remotes++;
	}

	if (w == REMBE_BACKUP) {
		VERIFY3U(rem->rem_backend_backup, ==, 0);

		rem->rem_backend_backup = be->be_id;
	}
}

/*
 * Clear the backend assignment for this remote, so that a new selection will
 * be made the next time a backend is required.
 */
static void
remote_backend_reset(remote_t *rem, backend_which_t w)
{
	VERIFY(w == REMBE_PRIMARY || w == REMBE_BACKUP || w == REMBE_BOTH);

	if (w == REMBE_PRIMARY || w == REMBE_BOTH) {
		if (rem->rem_backend != 0) {
			/*
			 * Update the count for this backend.
			 */
			backend_t *be = backend_lookup(rem->rem_backend);

			VERIFY3U(be->be_remotes, >, 0);
			be->be_remotes--;
		}
		rem->rem_backend = 0;
	}

	if (w == REMBE_BACKUP || w == REMBE_BOTH) {
		rem->rem_backend_backup = 0;
	}
}

/*
 * Given a remote, determine which backend we should try to use.  This routine
 * needs to account for backends that are temporarily offline, etc.
 *
 * A remote peer may be assigned up to two backends at any time: a primary, and
 * a backup.  The primary allocation is generally "sticky"; if the primary
 * backend becomes unavailable, we switch temporarily to a backup.  If the
 * primary comes back online, the remote will revert to its primary backend.
 * If the backup is in use and itself becomes unavailable, we just select a new
 * backup.
 *
 * If no backend is currently online, this function will return NULL.
 */
backend_t *
remote_backend(remote_t *rem)
{
	backend_t *be = NULL;

top:
	if (rem->rem_backend == 0) {
		/*
		 * No primary backend is currently assigned.  Assign one now.
		 */
		if ((be = backends_select()) == NULL) {
			/*
			 * No backend could be assigned at this time.
			 */
			remote_backend_reset(rem, REMBE_BOTH);
			return (NULL);
		}

		/*
		 * A newly selected backend must be working at the time of
		 * assignment.
		 */
		bunyan_info(rem->rem_log,
		    "remote assigned to new primary backend",
		    BUNYAN_T_UINT32, "be_id", be->be_id,
		    BUNYAN_T_END);
		remote_backend_set(rem, REMBE_PRIMARY, be);
		remote_backend_reset(rem, REMBE_BACKUP);
		return (be);
	}

	if ((be = backend_lookup(rem->rem_backend)) == NULL) {
		/*
		 * Our existing backend could not be found!  Reset everything.
		 */
		remote_backend_reset(rem, REMBE_BOTH);
		goto top;
	}

	if (be->be_removed) {
		/*
		 * The socket for our primary backend has been removed from
		 * the file system.  Reset everything.
		 */
		remote_backend_reset(rem, REMBE_BOTH);
		goto top;
	}

	if (be->be_ok) {
		/*
		 * Our primary backend is online.
		 */
		if (rem->rem_backend_backup != 0) {
			bunyan_info(rem->rem_log,
			    "remote assigned to original primary backend",
			    BUNYAN_T_UINT32, "be_id", be->be_id,
			    BUNYAN_T_END);
			remote_backend_reset(rem, REMBE_BACKUP);
		}
		return (be);
	}

backup_again:
	if (rem->rem_backend_backup == 0) {
		/*
		 * The primary backend is offline and we have not yet assigned
		 * a backup.
		 */
		if ((be = backends_select()) == NULL) {
			/*
			 * No backup backend could be assigned at this time.
			 */
			return (NULL);
		}

		bunyan_info(rem->rem_log,
		    "remote assigned to new backup backend",
		    BUNYAN_T_UINT32, "be_id", be->be_id,
		    BUNYAN_T_END);
		remote_backend_set(rem, REMBE_BACKUP, be);
		return (be);
	}

	if ((be = backend_lookup(rem->rem_backend_backup)) == NULL ||
	    !be->be_ok) {
		/*
		 * Our existing backup backend could not be found or is
		 * offline.  Reset just the backup and try again.
		 */
		remote_backend_reset(rem, REMBE_BACKUP);
		goto backup_again;
	}

	/*
	 * Our backup backend is online.
	 */
	return (be);
}

/*
 * Lookup the remote object for this remote peer IP address.  If this remote
 * peer has not been seen before, a new remote object will be allocated.
 */
remote_t *
remote_lookup(const struct in_addr *addr)
{
	remote_t search;
	search.rem_addr = *addr;

	avl_index_t where;
	remote_t *rem;
	if ((rem = avl_find(&g_remotes, &search, &where)) != NULL) {
		rem->rem_last_seen = g_loop_time;
		return (rem);
	}

	/*
	 * The remote does not exist; create it.
	 */
	if ((rem = calloc(1, sizeof (*rem))) == NULL) {
		return (NULL);
	}

	rem->rem_addr = *addr;
	rem->rem_first_seen = g_loop_time;
	rem->rem_last_seen = g_loop_time;

	if (bunyan_child(g_log, &rem->rem_log,
	    BUNYAN_T_IP, "remote_ip", &rem->rem_addr,
	    BUNYAN_T_END) != 0) {
		free(rem);
		return (NULL);
	}

	bunyan_info(rem->rem_log, "new remote peer", BUNYAN_T_END);

	avl_insert(&g_remotes, rem, where);

	return (rem);
}

static void
remote_destroy(remote_t *rem)
{
	if (rem == NULL) {
		return;
	}

	if (rem->rem_log != NULL) {
		bunyan_fini(rem->rem_log);
	}

	remote_backend_reset(rem, REMBE_BOTH);

	avl_remove(&g_remotes, rem);

	free(rem);
}

/*
 * Timer service routine to look for remote objects which have not been used
 * in some time and free them.
 */
void
remotes_expire(void)
{
	/*
	 * Look for stale remote entries.
	 */
	remote_t *rem_next;
	for (remote_t *rem = avl_first(&g_remotes); rem != NULL;
	    rem = rem_next) {
		hrtime_t age = g_loop_time - rem->rem_last_seen;
		rem_next = AVL_NEXT(&g_remotes, rem);

		/*
		 * If we have not heard from a particular host in two minutes,
		 * expire its remote entry.
		 */
		if (age > SECONDS_IN_NS(120)) {
			bunyan_info(rem->rem_log, "expiring remote entry",
			    BUNYAN_T_END);
			remote_destroy(rem);
			continue;
		}
	}
}

/*
 * Clear the backend association for a number (count) of remote peers in an
 * attempt to rebalance the association of remotes to backends.
 */
void
remotes_rebalance(uint32_t backend_id, uint32_t count)
{
	/*
	 * Look for remotes which match the backend with the most remotes
	 * assigned and cause them to select a new primary backend.
	 */
	for (remote_t *rem = avl_first(&g_remotes); rem != NULL;
	    rem = AVL_NEXT(&g_remotes, rem)) {
		if (count == 0) {
			return;
		}

		if (rem->rem_backend == backend_id) {
			VERIFY3S(count, >, 0);
			count--;

			bunyan_info(rem->rem_log, "rebalancing to reduce "
			    "spread", BUNYAN_T_END);
			remote_backend_reset(rem, REMBE_BOTH);
		}
	}
}

int
remotes_init(void)
{
	avl_create(&g_remotes, remotes_compar, sizeof (remote_t),
	    offsetof(remote_t, rem_node));

	return (0);
}
