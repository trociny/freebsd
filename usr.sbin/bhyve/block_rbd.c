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

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <rbd/librbd.h>

#include "block_emul.h"
#include "debug.h"

struct block_rbd_inst {
	rados_t ri_rados;
	rados_ioctx_t ri_ioctx;
	rbd_image_t ri_image;
};

static int
block_rbd_open(const char *optstr, void **bd,
    int *candelete_p, int *rdonly_p, off_t *size_p, int *sectsz_p,
    int *psectsz_p, int *psectoff_p)
{
	char *nopt, *xopts, *cp;
        char *pool_name, *image_name, *snap_name;
	struct block_rbd_inst *ri;
	rbd_image_info_t info;
	uint64_t features, stripe_unit;
	int r, ro;

	nopt = xopts = strdup(optstr);
	ri = calloc(1, sizeof(struct block_rbd_inst));
	if (ri == NULL) {
		perror("calloc");
		goto err_free;
	}

	ro = 0;

	while (xopts != NULL) {
		cp = strsep(&xopts, ",");
		if (cp == nopt)		/* image spec */
			continue;
		else if (!strcmp(cp, "ro"))
			ro = 1;
		else {
			EPRINTLN("Invalid device option \"%s\"", cp);
                        errno = EINVAL;
			goto err_free;
		}
	}

        xopts = nopt;
        pool_name = strsep(&xopts, "/");
        if (xopts == NULL) {
                EPRINTLN("Invalid device spec \"%s\"", pool_name);
                errno = EINVAL;
                goto err_free;
        }
        image_name = strsep(&xopts, "@");
        snap_name = xopts;
        if (snap_name != NULL) {
                ro = 1;
        }

	r = rados_create(&ri->ri_rados, NULL);
	if (r < 0) {
		errno = -r;
		perror("rados_create");
		goto err_free;
	}

	r = rados_conf_read_file(ri->ri_rados, NULL);
	if (r < 0) {
		errno = -r;
		perror("rados_conf_read_file");
		goto err_rados_shutdown;
	}

	rados_conf_parse_env(ri->ri_rados, NULL);

	r = rados_connect(ri->ri_rados);
	if (r < 0) {
		errno = -r;
		perror("rados_connect");
		goto err_rados_shutdown;
	}

	r = rados_ioctx_create(ri->ri_rados, pool_name, &ri->ri_ioctx);
	if (r < 0) {
		errno = -r;
		perror("rados_ioctx_create");
		goto err_rados_shutdown;
	}

	r = rbd_open(ri->ri_ioctx, image_name, &ri->ri_image, snap_name);
	if (r < 0) {
		errno = -r;
		perror("rbd_open");
		goto err_ioctx_destroy;
	}

	r = rbd_stat(ri->ri_image, &info, sizeof(info));
	if (r < 0) {
		errno = -r;
		perror("rbd_stat");
		goto err;
	}

	r = rbd_get_features(ri->ri_image, &features);
	if (r < 0) {
		errno = -r;
		perror("rbd_get_features");
		goto err;
	}

	if ((features & RBD_FEATURE_STRIPINGV2) != 0) {
		r = rbd_get_stripe_unit(ri->ri_image, &stripe_unit);
		if (r < 0) {
			errno = -r;
			perror("rbd_get_stripe_unit");
			goto err;
		}
	} else {
		stripe_unit = (1 << info.order);
	}

	*bd = ri;
	*candelete_p = 1;
	*rdonly_p = ro;
	*size_p = info.size;
	*sectsz_p = DEV_BSIZE;
	*psectsz_p = stripe_unit;
	*psectoff_p = 0;

        free(nopt);

	return (0);

err:
	rbd_close(ri->ri_image);
err_ioctx_destroy:
	rados_ioctx_destroy(ri->ri_ioctx);
err_rados_shutdown:
	rados_shutdown(ri->ri_rados);
err_free:
	free(ri);
        free(nopt);

	return (-1);
}

static int
block_rbd_close(void *bd)
{
	struct block_rbd_inst *ri = bd;

	rbd_close(ri->ri_image);
	rados_ioctx_destroy(ri->ri_ioctx);
	rados_shutdown(ri->ri_rados);

	return (0);
}

static ssize_t
block_rbd_read(void *bd, const struct iovec *iov, int iovcnt, size_t nbytes,
    off_t offset) {
	struct block_rbd_inst *ri = bd;
        rbd_completion_t comp;
        int r;

        r = rbd_aio_create_completion(NULL, NULL, &comp);
	if (r < 0) {
		errno = -r;
		perror("rbd_aio_create_completion");
                return (-1);
	}

        r = rbd_aio_readv(ri->ri_image, iov, iovcnt, offset, comp);
	if (r < 0) {
		errno = -r;
		perror("rbd_aio_readv");
                return (-1);
	}

        r = rbd_aio_wait_for_complete(comp);
	if (r < 0) {
		errno = -r;
		perror("rbd_aio_wait_for_complete");
                rbd_aio_release(comp);
                return (-1);
	}

        r = rbd_aio_get_return_value(comp);
        rbd_aio_release(comp);
	if (r < 0) {
		errno = -r;
		perror("rbd_aio_get_return_value");
                return (-1);
	}

        return (nbytes);
}

static ssize_t
block_rbd_write(void *bd, const struct iovec *iov, int iovcnt, size_t nbytes,
    off_t offset) {
	struct block_rbd_inst *ri = bd;
        rbd_completion_t comp;
        int r;

        r = rbd_aio_create_completion(NULL, NULL, &comp);
	if (r < 0) {
		errno = -r;
		perror("rbd_aio_create_completion");
                return (-1);
	}

        r = rbd_aio_writev(ri->ri_image, iov, iovcnt, offset, comp);
	if (r < 0) {
		errno = -r;
		perror("rbd_aio_writev");
                return (-1);
	}

        r = rbd_aio_wait_for_complete(comp);
	if (r < 0) {
		errno = -r;
		perror("rbd_aio_wait_for_complete");
                rbd_aio_release(comp);
                return (-1);
	}

        r = rbd_aio_get_return_value(comp);
        rbd_aio_release(comp);
	if (r < 0) {
		errno = -r;
		perror("rbd_aio_get_return_value");
                return (-1);
	}

        return (nbytes);
}

static ssize_t
block_rbd_delete(void *bd, size_t nbytes, off_t offset)
{
	struct block_rbd_inst *ri = bd;
        rbd_completion_t comp;
        int r;

        r = rbd_aio_create_completion(NULL, NULL, &comp);
	if (r < 0) {
		errno = -r;
		perror("rbd_aio_create_completion");
                return (-1);
	}

        r = rbd_aio_discard(ri->ri_image, offset, nbytes, comp);
	if (r < 0) {
		errno = -r;
		perror("rbd_aio_discard");
                return (-1);
	}

        r = rbd_aio_wait_for_complete(comp);
	if (r < 0) {
		errno = -r;
		perror("rbd_aio_wait_for_complete");
                rbd_aio_release(comp);
                return (-1);
	}

        r = rbd_aio_get_return_value(comp);
        rbd_aio_release(comp);
	if (r < 0) {
		errno = -r;
		perror("rbd_aio_get_return_value");
                return (-1);
	}

        return (nbytes);
}

static int
block_rbd_flush(void *bd)
{
	struct block_rbd_inst *ri = bd;
        rbd_completion_t comp;
        int r;

        r = rbd_aio_create_completion(NULL, NULL, &comp);
	if (r < 0) {
		errno = -r;
		perror("rbd_aio_create_completion");
                return (-1);
	}

        r = rbd_aio_flush(ri->ri_image, comp);
	if (r < 0) {
		errno = -r;
		perror("rbd_aio_flush");
                return (-1);
	}

        r = rbd_aio_wait_for_complete(comp);
	if (r < 0) {
		errno = -r;
		perror("rbd_aio_wait_for_complete");
                rbd_aio_release(comp);
                return (-1);
	}

        r = rbd_aio_get_return_value(comp);
        rbd_aio_release(comp);
	if (r < 0) {
		errno = -r;
		perror("rbd_aio_get_return_value");
                return (-1);
	}

        return (0);
}

struct block_devemu block_de_rbd = {
	.bd_emu =	"rbd",
	.bd_open =	block_rbd_open,
	.bd_close =	block_rbd_close,
	.bd_read =	block_rbd_read,
	.bd_write =	block_rbd_write,
	.bd_delete =	block_rbd_delete,
	.bd_flush =	block_rbd_flush
};
BLOCK_EMUL_SET(block_de_rbd);
