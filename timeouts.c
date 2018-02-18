/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright (c) 2018, Joyent, Inc.
 */

/*
 * TIMEOUTS
 *
 * This subsystem allows for the one-shot scheduling of a function at some time
 * in the future.  Execution time is specified as an interval (in seconds)
 * relative to the current time.  Future executions are arranged in an AVL
 * sorted by execution time.  Precise timing is not available; the only
 * guarantee is that timeout callbacks will be called at some point after their
 * scheduled execution time.
 */

#include "bbal.h"

static avl_tree_t g_timeouts;
static uint32_t g_timeout_last_id = 1;

static int
timeouts_compar(const void *first, const void *second)
{
	const timeout_t *fto = first;
	const timeout_t *sto = second;

	if (fto->to_expiry == sto->to_expiry) {
		return (compare_u32(fto->to_id, sto->to_id));
	}

	return (compare_hrtime(fto->to_expiry, sto->to_expiry));
}


/*
 * Create a timeout object to schedule the future execution of a callback
 * function.  A single timeout object can be reused many times, via the
 * "timeout_set" and "timeout_clear" functions.
 */
int
timeout_alloc(timeout_t **pto)
{
	timeout_t *to;

	if ((to = calloc(1, sizeof (*to))) == NULL) {
		return (-1);
	}

	to->to_id = g_timeout_last_id++;

	*pto = to;
	return (0);
}

void
timeout_free(timeout_t *to)
{
	if (to == NULL) {
		return;
	}

	timeout_clear(to);
	free(to);
}

/*
 * Schedule a callback to run after a specified interval (seconds).  Takes two
 * a data pointer (arg) and the callback function (tof).
 *
 * If the timeout has been scheduled already but the callback has not yet
 * run, this function will cancel that execution in favour of the new
 * future execution.
 */
void
timeout_set(timeout_t *to, unsigned seconds, timeout_func_t *tof, void *arg)
{
	VERIFY3P(to, !=, NULL);

	if (to->to_active) {
		/*
		 * The timeout is already scheduled.  Remove it from the tree
		 * so that we can update the expiry time and re-add it in the
		 * correct execution order.
		 */
		avl_remove(&g_timeouts, to);
		to->to_active = B_FALSE;
	}

	to->to_expiry = g_loop_time + SECONDS_IN_NS(seconds);
	to->to_scheduled_at = g_loop_time;
	to->to_run_at = 0;
	to->to_func = tof;
	to->to_arg = arg;

	to->to_active = B_TRUE;
	avl_add(&g_timeouts, to);
}

/*
 * Cancel any pending execution of this timeout if one has been scheduled.
 */
void
timeout_clear(timeout_t *to)
{
	VERIFY3P(to, !=, NULL);

	if (to->to_active) {
		avl_remove(&g_timeouts, to);
		to->to_active = B_FALSE;
	}
}

/*
 * This function is invoked periodically (by a timer) to execute the callback
 * for any timeout which is due to run.
 */
void
timeout_run(void)
{
	/*
	 * Run timeouts.
	 */
	for (;;) {
		timeout_t *to = avl_first(&g_timeouts);
		if (to == NULL || to->to_expiry > g_loop_time) {
			/*
			 * Timeouts are sorted in the AVL by expiry time, so if
			 * the first timeout expires in the future there is no
			 * more work to do.
			 */
			break;
		}

		VERIFY(to->to_active == B_TRUE);
		avl_remove(&g_timeouts, to);
		to->to_active = B_FALSE;

		/*
		 * Note that the callback might rearm or free the timeout
		 * object itself.  Do not reference it after calling the
		 * callback.
		 */
		to->to_run_at = g_loop_time;
		to->to_func(to, to->to_arg);
	}
}

/*
 * Initialise the timeout subsystem.
 */
int
timeout_init(void)
{
	avl_create(&g_timeouts, timeouts_compar, sizeof (timeout_t),
	    offsetof(timeout_t, to_node));

	return (0);
}
