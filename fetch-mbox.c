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
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/uio.h>

#include <errno.h>
#include <fcntl.h>
#include <glob.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "fdm.h"
#include "fetch.h"

int	fetch_mbox_connect(struct account *);
int	fetch_mbox_completed(struct account *);
int	fetch_mbox_fetch(struct account *, struct fetch_ctx *);
int	fetch_mbox_disconnect(struct account *, int);
void	fetch_mbox_desc(struct account *, char *, size_t);

void	fetch_mbox_free(void *);

int	fetch_mbox_make(struct account *);
int	fetch_mbox_commit(struct account *, struct fetch_mbox_mbox *);
void	fetch_mbox_dequeue(struct account *, struct fetch_ctx *);

int	fetch_mbox_next(struct account *, struct fetch_ctx *);
int	fetch_mbox_open(struct account *, struct fetch_ctx *);
int	fetch_mbox_mail(struct account *, struct fetch_ctx *);

struct fetch fetch_mbox = {
	"mbox",
	fetch_mbox_connect,
	NULL,
	NULL,
	fetch_mbox_completed,
	NULL,
	fetch_mbox_fetch,
	NULL,
	NULL,
	NULL,
	fetch_mbox_disconnect,
	fetch_mbox_desc
};

void
fetch_mbox_free(void *ptr)
{
	struct fetch_mbox_mail	*aux = ptr;

	if (aux->fmbox->reference == 0)
		fatalx("zero reference count");
	aux->fmbox->reference--;

	xfree(aux);
}

/* Make an array of all the mboxes to visit. */
int
fetch_mbox_make(struct account *a)
{
	struct fetch_mbox_data	*data = a->data;
	struct fetch_mbox_mbox	*fmbox;
	char			*path;
	u_int			 i, j;
	glob_t			 g;

	ARRAY_INIT(&data->fmboxes);

	for (i = 0; i < ARRAY_LENGTH(data->mboxes); i++) {
		path = ARRAY_ITEM(data->mboxes, i);
		if (glob(path, GLOB_BRACE|GLOB_NOCHECK, NULL, &g) != 0) {
			log_warn("%s: glob(\"%s\")", a->name, path);
			goto error;
		}

		if (g.gl_pathc < 1)
			fatalx("glob returned garbage");
		for (j = 0; j < (u_int) g.gl_pathc; j++) {
			fmbox = xcalloc(1, sizeof *fmbox);
			fmbox->path = xstrdup(g.gl_pathv[j]);
			fmbox->fd = -1;
			fmbox->base = NULL;
			ARRAY_ADD(&data->fmboxes, fmbox);
		}

		globfree(&g);
	}

	return (0);

error:
	for (i = 0; i < ARRAY_LENGTH(&data->fmboxes); i++) {
		fmbox = ARRAY_ITEM(&data->fmboxes, i);

		xfree(fmbox->path);
		xfree(fmbox);
	}
	ARRAY_FREE(&data->fmboxes);

	return (-1);
}

/* Set initial state. */
int
fetch_mbox_connect(struct account *a)
{
	struct fetch_mbox_data	*data = a->data;
	
	if (fetch_mbox_make(a) != 0)
		return (-1);
	data->index = 0;

	if (ARRAY_EMPTY(&data->fmboxes)) {
		log_warnx("%s: no mboxes found", a->name);
		return (-1);
	}

	TAILQ_INIT(&data->kept);

	data->state = fetch_mbox_open;
	return (0);
}

/* Check if all mboxes completed. */
int
fetch_mbox_completed(struct account *a)
{
	struct fetch_mbox_data	*data = a->data;

	return (data->index >= ARRAY_LENGTH(&data->fmboxes));
}

/* Clean up and free data. */
int
fetch_mbox_disconnect(struct account *a, int aborted)
{
	struct fetch_mbox_data	*data = a->data;
	struct fetch_mbox_mbox	*fmbox;
	u_int			 i;

	for (i = 0; i < ARRAY_LENGTH(&data->fmboxes); i++) {
		fmbox = ARRAY_ITEM(&data->fmboxes, i);

		/* Commit changes if not aborted. */
		if (!aborted && fetch_mbox_commit(a, fmbox) != 0)
			aborted = 1;

		if (fmbox->base != NULL)
			munmap(fmbox->base, fmbox->size);
		if (fmbox->fd != -1)
			closelock(fmbox->fd, fmbox->path, conf.lock_types);

		xfree(fmbox->path);
		xfree(fmbox);
	}
	ARRAY_FREE(&data->fmboxes);

	return (0);
}

/* Commit mbox changes. */
int
fetch_mbox_commit(struct account *a, struct fetch_mbox_mbox *fmbox)
{
	struct fetch_mbox_data	*data = a->data;
	struct fetch_mbox_mail	*aux, *this;
	char			 path[MAXPATHLEN], saved[MAXPATHLEN], c;
	int			 fd;
	ssize_t			 n;
	struct iovec		 iov[2];

	log_debug2("%s: %s: committing mbox: %u kept, %u total",
	    a->name, fmbox->path, fmbox->reference, fmbox->total);
	fd = -1;

	/*
	 * If the reference count is 0, no mails were kept, so the mbox can
	 * just be truncated.
	 */
	if (fmbox->reference == 0) {
		if (fmbox->total != 0 && ftruncate(fmbox->fd, 0) != 0)
			goto error;
		goto free_all;
	}

	/* If all the mails were kept, do nothing. */
	if (fmbox->reference == fmbox->total)
		goto free_all;

	/*
	 * Otherwise, things get complicated. data->kept is a list of all the
	 * mails (struct fetch_mbox_mail) which were kept for ALL mailboxes.
	 * There is no guarantee it is ordered by offset. Rather than try to be
	 * clever and save disk space, just create a new mbox and copy all the
	 * kept mails into it.
	 */
	if (mkpath(path, sizeof path, "%s.XXXXXXXXXX", fmbox->path) != 0)
		goto error;
	if (mkpath(saved, sizeof saved, "%s.XXXXXXXXXX", fmbox->path) != 0)
		goto error;
	if ((fd = mkstemp(path)) == -1)
		goto error;

	aux = TAILQ_FIRST(&data->kept);
	while (aux != NULL) {
		this = aux;
		aux = TAILQ_NEXT(aux, entry);

		if (this->fmbox != fmbox)
			continue;

		log_debug2("%s: writing message from %zu, size %zu",
		    a->name, this->off, this->size);
		c = '\n';
		iov[0].iov_base = fmbox->base + this->off;
		iov[0].iov_len = this->size;
		iov[1].iov_base = &c;
		iov[1].iov_len = 1;
		if ((n = writev(fd, iov, 2)) < 0)
			goto error;
		if ((size_t) n != this->size + 1) {
			errno = EIO;
			goto error;
		}

		fetch_mbox_free(this);
		TAILQ_REMOVE(&data->kept, this, entry);
	}

	if (fsync(fd) != 0)
		goto error;
	close(fd);

	/*
	 * Do the replacement dance: create a backup copy of the mbox, remove
	 * the mbox, link in the temporary file, unlink the temporary file,
	 * then unlink the backup mbox. We don't try to recover if anything
	 * fails on the grounds that it could just make things worse, just
	 * die and let the user sort it out.
	 */
	if (link(fmbox->path, saved) != 0)
		goto error;
	if (unlink(fmbox->path) != 0)
		goto error;
	if (link(path, fmbox->path) != 0)
		goto error;
	if (unlink(path) != 0)
		goto error;
	if (unlink(saved) != 0)
		goto error;

free_all:
	aux = TAILQ_FIRST(&data->kept);
	while (aux != NULL) {
		this = aux;
		aux = TAILQ_NEXT(aux, entry);

		if (this->fmbox == fmbox)
			fetch_mbox_free(this);
	}

	if (fmbox->reference != 0)
		fatalx("dangling reference");

	return (0);

error:
	if (fd != -1) {
		close(fd);
		unlink(path);
	}
	log_warn("%s: %s", a->name, fmbox->path);
	return (-1);
}

/* Handle done queue. */
void
fetch_mbox_dequeue(struct account *a, struct fetch_ctx *fctx)
{
	struct fetch_mbox_data	*data = a->data;
	struct fetch_mbox_mail	*aux;
	struct mail	       	*m;

	/* Delete mail if any. */
	while ((m = done_mail(a, fctx)) != NULL) {
		if (m->decision != DECISION_DROP) {
			aux = m->auxdata;

			/*
			 * Add to kept list and reset callback to prevent free.
			 * Kept entries are used when committing changes to
			 * mboxes.
			 */
			TAILQ_INSERT_TAIL(&data->kept, aux, entry);
			m->auxfree = NULL;
		}
		dequeue_mail(a, fctx);
	}
}

/* Fetch mail. */
int
fetch_mbox_fetch(struct account *a, struct fetch_ctx *fctx)
{
	struct fetch_mbox_data	*data = a->data;

	return (data->state(a, fctx));
}

/* Next state. Move to next mbox. */
int
fetch_mbox_next(struct account *a, struct fetch_ctx *fctx)
{
	struct fetch_mbox_data	*data = a->data;

	fetch_mbox_dequeue(a, fctx);

	if (!fetch_mbox_completed(a))
		data->index++;
	if (fetch_mbox_completed(a))
		return (FETCH_HOLD);

	data->state = fetch_mbox_open;
	return (FETCH_AGAIN);
}

/* Open state. */
int
fetch_mbox_open(struct account *a, unused struct fetch_ctx *fctx)
{
	struct fetch_mbox_data	*data = a->data;
	struct fetch_mbox_mbox	*fmbox;
	char			*ptr;
	struct stat	         sb;
	uintmax_t		 size;
	long long		 used;

	fmbox = ARRAY_ITEM(&data->fmboxes, data->index);

	log_debug2("%s: trying path: %s", a->name, fmbox->path);
	if (stat(fmbox->path, &sb) != 0)
		goto error;
	if (S_ISDIR(sb.st_mode)) {
		errno = EISDIR;
		goto error;
	}
	if (sb.st_size == 0) {
		data->state = fetch_mbox_next;
		return (FETCH_AGAIN);
	}
	if (sb.st_size < 5) {
		log_warnx("%s: %s: mbox too small", a->name, fmbox->path);
		return (FETCH_ERROR);
	}
	size = sb.st_size;
	if (size > SIZE_MAX) {
		log_warnx("%s: %s: mbox too big", a->name, fmbox->path);
		return (FETCH_ERROR);
	}
	fmbox->size = size;
	
	log_debug3("%s: opening mbox, size %ju", a->name, size);
	used = 0;
	do {
		fmbox->fd = openlock(fmbox->path, O_RDWR, conf.lock_types);
		if (fmbox->fd == -1) {
			if (errno == EAGAIN) {
				if (locksleep(a->name, fmbox->path, &used) != 0)
					return (FETCH_ERROR);
				continue;
			}
			goto error;
		}
	} while (fmbox->fd < 0);
		
	/* mmap the file. */
	fmbox->base = mmap(
	    NULL, fmbox->size, PROT_READ|PROT_WRITE, MAP_SHARED, fmbox->fd, 0);
	if (fmbox->base == MAP_FAILED) {
		fmbox->base = NULL;
		goto error;
	}
	data->off = 0;

	ptr = memchr(fmbox->base, '\n', fmbox->size);
	if (strncmp(fmbox->base, "From ", 5) != 0) {
		log_warnx("%s: %s: not an mbox", a->name, fmbox->path);
		return (FETCH_ERROR);
	}

	data->state = fetch_mbox_mail;
	return (FETCH_AGAIN);

error:
	if (fmbox->base != NULL) {
		munmap(fmbox->base, fmbox->size);
		fmbox->base = NULL;
	}
	if (fmbox->fd != -1) {
		closelock(fmbox->fd, fmbox->path, conf.lock_types);
		fmbox->fd = -1;
	}
	log_warn("%s: %s", a->name, fmbox->path);
	return (FETCH_ERROR);
}

/* Mail state. Find and read mail file. */
int
fetch_mbox_mail(struct account *a, struct fetch_ctx *fctx)
{
	struct fetch_mbox_data		*data = a->data;
	struct fetch_mbox_mbox		*fmbox;
	struct fetch_mbox_mail		*aux;
	struct mail			*m;
	char				*line, *ptr, *lptr;
	size_t				 llen;
	int				 flushing;

	/* 
	 * Dequeue mail, if not done here likely to run out of file handles
	 * before opening the next mbox.
	 */	   
	fetch_mbox_dequeue(a, fctx);

	/* Find current mbox and check for EOF. */
	fmbox = ARRAY_ITEM(&data->fmboxes, data->index);
	if (data->off == fmbox->size) {
		data->state = fetch_mbox_next;
		return (FETCH_AGAIN);
	}

	/* Create a new mail. */
	m = xcalloc(1, sizeof *m);
	m->shm.fd = -1;

	/* Open the mail. */
	if (mail_open(m, IO_BLOCKSIZE) != 0) {
		log_warn("%s: failed to create mail", a->name);
		mail_destroy(m);
		return (FETCH_ERROR);
	}

	/* Create aux data. */
	aux = xmalloc(sizeof *aux);
	aux->off = data->off;
	aux->size = 0;
	aux->fmbox = fmbox;
	if (++fmbox->reference == 0)
		fatalx("reference count overflow");
	m->auxdata = aux;
	m->auxfree = fetch_mbox_free;

	/*
	 * We start at a "From " line and include it in the mail (it can be
	 * trimmed later with minimal penalty).
	 */
	flushing = 0;
	for (;;) {
		/* Check for EOF. */
		if (data->off == fmbox->size) {
			aux->size = data->off - aux->off;
			break;
		}

		/* Locate the EOL. */
		line = fmbox->base + data->off;
		ptr = memchr(line, '\n', fmbox->size - data->off);
		if (ptr == NULL) {
			ptr = fmbox->base + fmbox->size;
			data->off = fmbox->size;
		} else
			data->off += ptr - line + 1;
		
		/* Check if the line is "From ". */
		if (line > fmbox->base &&
		    ptr - line >= 5 && strncmp(line, "From ", 5) == 0) {
			/* End of mail. */
			aux->size = (line - fmbox->base) - aux->off;
			break;
		}

		/* Trim >s from From. */
		if (*line == '>') {
			lptr = line;
			llen = ptr - line;
			while (*lptr == '>' && llen > 0) {
				lptr++;
				llen--;
			}
			
			if (llen >= 5 && strncmp(lptr, "From ", 5) == 0)
				line++;
		}

		if (flushing)
			continue;
		if (append_line(m, line, ptr - line) != 0) {
			log_warn("%s: failed to resize mail", a->name);
			mail_destroy(m);
			return (FETCH_ERROR);
		}
		if (m->size > conf.max_size)
			flushing = 1;
	}
	fmbox->total++;

	/*
	 * Check if there was a blank line between the mails and remove it if
	 * so.
	 */
	if (aux->size >= 2 &&
	    fmbox->base[aux->off + aux->size - 1] == '\n' &&
	    fmbox->base[aux->off + aux->size - 2] == '\n') {
		aux->size -= 2;
		m->size -= 2;
	}
	
	/* Tag mail. */
	default_tags(&m->tags, NULL);

	if (enqueue_mail(a, fctx, m) != 0)
		return (FETCH_ERROR);

	return (FETCH_AGAIN);
}

void
fetch_mbox_desc(struct account *a, char *buf, size_t len)
{
	struct fetch_mbox_data	*data = a->data;
	char			*mboxes;

	mboxes = fmt_strings("mboxes ", data->mboxes);
	strlcpy(buf, mboxes, len);
	xfree(mboxes);
}
