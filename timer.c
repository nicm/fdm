/* $Id$ */

/*
 * Copyright (c) 2007 Nicholas Marriott <nicm@users.sourceforge.net>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF MIND, USE, DATA OR PROFITS, WHETHER
 * IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/types.h>
#include <sys/time.h>

#include <signal.h>
#include <string.h>

#include "fdm.h"

volatile sig_atomic_t	timer_value;

void			timer_handler(int);

/* Signal handler for SIGALRM setitimer timeout. */
void
timer_handler(unused int sig)
{
	timer_value = 1;
}

/* Return timer state. */
int
timer_expired(void)
{
	return (timer_value);
}

/* Set timer with setitimer. */
void
timer_set(int seconds)
{
	struct itimerval itv;
	struct sigaction act;

	if (seconds == 0)
		fatalx("zero timeout");
	timer_value = 0;

	memset(&act, 0, sizeof act);
	sigemptyset(&act.sa_mask);
	act.sa_handler = timer_handler;
	if (sigaction(SIGALRM, &act, NULL) != 0)
		fatal("sigaction failed");

	memset(&itv, 0, sizeof itv);
	itv.it_value.tv_sec = seconds;
	while (setitimer(ITIMER_REAL, &itv, NULL) != 0) {
		/*
		 * If the timeout is too large (EINVAL), keep trying it until
		 * it reaches a minimum of 30 seconds.
		 */
		if (errno != EINVAL || itv.it_value.tv_sec < 30)
			fatal("setitimer failed");
		itv.it_value.tv_sec /= 2;
	}
}

/* Unset timer. */
void
timer_cancel(void)
{
	struct itimerval itv;
	struct sigaction act;

	memset(&itv, 0, sizeof itv);
	if (setitimer(ITIMER_REAL, &itv, NULL) != 0)
		fatal("setitimer failed");

	memset(&act, 0, sizeof act);
	sigemptyset(&act.sa_mask);
	act.sa_handler = SIG_DFL;
	if (sigaction(SIGALRM, &act, NULL) != 0)
		fatal("sigaction failed");
}
