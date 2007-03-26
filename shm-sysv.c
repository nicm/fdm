/* $Id$ */

/*
 * Copyright (c) 2006 Nicholas Marriott <nicm@users.sourceforge.net>
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
#include <sys/ipc.h>                                                        
#include <sys/shm.h>  
#include <sys/stat.h>

#include <string.h>

#include "fdm.h"

void *
shm_create(struct shm *shm, size_t size)
{
        if (size == 0)
                fatalx("shm_malloc: zero size");

	shm->key = 0xff;

restart:
	shm->id = shmget(shm->key, size, IPC_CREAT|IPC_EXCL|S_IRWXU);
	if (shm->id == -1) {
		if (errno == EEXIST || errno == EINVAL) {
			shm->key++;
			goto restart;
		}
		return (NULL);
	}

	shm->size = size;
	shm->data = shmat(shm->id, NULL, 0);
	if (shm->data == (void *) -1) {
		if (shmctl(shm->id, IPC_RMID, NULL) != 0)
			fatal("shmctl");
		return (NULL);
	}

	return (shm->data);
} 

void
shm_destroy(struct shm *shm)
{
	shm_close(shm);
	
	if (shmctl(shm->id, IPC_RMID, NULL) != 0)
		fatal("shmctl");
	shm->id = 0;
}

void
shm_close(struct shm *shm)
{
	if (shmdt(shm->data) != 0)
		fatal("shmdt");
	shm->data = NULL;
}

void *
shm_reopen(struct shm *shm)
{
	if ((shm->id = shmget(shm->key, shm->size, 0)) == -1)
		return (NULL);

	shm->data = shmat(shm->id, NULL, 0);
	if (shm->data == NULL || shm->data == (void *) -1) {
		if (shmctl(shm->id, IPC_RMID, NULL) != 0)
			fatal("shmctl");
		return (NULL);
	}
	return (shm->data);
}

int
shm_owner(struct shm *shm, uid_t uid, gid_t gid)
{
	struct shmid_ds	ds;

	if (shmctl(shm->id, IPC_STAT, &ds) != 0)
		return (1);

	ds.shm_perm.uid = uid;
	ds.shm_perm.gid = gid;

	if (shmctl(shm->id, IPC_SET, &ds) != 0)
		return (1);

	return (0);
}

void *
shm_resize(struct shm *shm, size_t nmemb, size_t size)
{
	size_t	 	newsize = nmemb * size;
	struct shm	saved;

	if (size == 0)
                fatalx("shm_realloc: zero size");
        if (SIZE_MAX / nmemb < size)
                fatalx("shm_realloc: nmemb * size > SIZE_MAX");

	if (newsize <= shm->size) {
		shm->size = newsize;
		return (shm->data);
	}

	memcpy(&saved, shm, sizeof saved);
	if (shm_create(shm, newsize) == NULL) {
		memcpy(shm, &saved, sizeof *shm);
		return (NULL);
	}

	memcpy(shm->data, saved.data, saved.size);
	if (shmdt(saved.data) != 0)
		fatal("shmdt");
	if (shmctl(saved.id, IPC_RMID, NULL) != 0)
		fatal("shmctl");

	return (shm->data);
}

