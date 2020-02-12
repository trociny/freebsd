/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2020  Mykola Golub <trociny@FreeBSD.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#ifndef _BLOCK_EMUL_H_
#define _BLOCK_EMUL_H_

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/linker_set.h>

struct iovec *iov;

struct block_devemu {
	char		*bd_emu;
	int		(*bd_open)(const char *optstr, void **bd,
			    int *candelete, int *rdonly, off_t *size,
			    int *sectsz, int *psectsz, int *psectoff);
	int		(*bd_close)(void *bd);
	ssize_t		(*bd_read)(void *bd, const struct iovec *iov,
			    int iovcnt, size_t nbytes, off_t offset);
	ssize_t		(*bd_write)(void *bd, const struct iovec *iov,
			    int iovcnt, size_t nbytes, off_t offset);
	ssize_t		(*bd_delete)(void *bd, size_t nbytes, off_t offset);
	int		(*bd_flush)(void *bd);
};

#define BLOCK_EMUL_SET(x)   DATA_SET(block_devemu_set, x);

struct block_devemu	*block_emul_finddev(char *name);

#endif /* _BLOCK_EMUL_H_ */
