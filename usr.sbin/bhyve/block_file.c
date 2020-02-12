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
#ifndef WITHOUT_CAPSICUM
#include <sys/capsicum.h>
#endif
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/disk.h>
#include <sys/uio.h>

#include <assert.h>
#ifndef WITHOUT_CAPSICUM
#include <capsicum_helpers.h>
#endif
#include <err.h>
#include <fcntl.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include "block_emul.h"
#include "debug.h"

struct block_file_inst {
	int	fi_fd;
	int	fi_ischr;
	uint8_t	*fi_buf;
};

static int
block_file_open(const char *optstr, void **bd,
    int *candelete_p, int *rdonly_p, off_t *size_p, int *sectsz_p,
    int *psectsz_p, int *psectoff_p)
{
	char name[MAXPATHLEN];
	char *nopt, *xopts, *cp;
	struct block_file_inst *fi;
	struct stat sbuf;
	struct diocgattr_arg arg;
	off_t size, psectsz, psectoff;
	int extra, fd, sectsz;
	int nocache, sync, ro, candelete, geom, ssopt, pssopt;
#ifndef WITHOUT_CAPSICUM
	cap_rights_t rights;
	cap_ioctl_t cmds[] = { DIOCGFLUSH, DIOCGDELETE };
#endif

	fd = -1;
	ssopt = 0;
	nocache = 0;
	sync = 0;
	ro = 0;

	/*
	 * The first element in the optstring is always a pathname.
	 * Optional elements follow
	 */
	nopt = xopts = strdup(optstr);
	while (xopts != NULL) {
		cp = strsep(&xopts, ",");
		if (cp == nopt)		/* file or device pathname */
			continue;
		else if (!strcmp(cp, "nocache"))
			nocache = 1;
		else if (!strcmp(cp, "sync") || !strcmp(cp, "direct"))
			sync = 1;
		else if (!strcmp(cp, "ro"))
			ro = 1;
		else if (sscanf(cp, "sectorsize=%d/%d", &ssopt, &pssopt) == 2)
			;
		else if (sscanf(cp, "sectorsize=%d", &ssopt) == 1)
			pssopt = ssopt;
		else {
			EPRINTLN("Invalid device option \"%s\"", cp);
			goto err;
		}
	}

	extra = 0;
	if (nocache)
		extra |= O_DIRECT;
	if (sync)
		extra |= O_SYNC;

	fd = open(nopt, (ro ? O_RDONLY : O_RDWR) | extra);
	if (fd < 0 && !ro) {
		/* Attempt a r/w fail with a r/o open */
		fd = open(nopt, O_RDONLY | extra);
		ro = 1;
	}

	if (fd < 0) {
		warn("Could not open backing file: %s", nopt);
		goto err;
	}

	if (fstat(fd, &sbuf) < 0) {
		warn("Could not stat backing file %s", nopt);
		goto err;
	}

#ifndef WITHOUT_CAPSICUM
	cap_rights_init(&rights, CAP_FSYNC, CAP_IOCTL, CAP_READ, CAP_SEEK,
	    CAP_WRITE);
	if (ro)
		cap_rights_clear(&rights, CAP_FSYNC, CAP_WRITE);

	if (caph_rights_limit(fd, &rights) == -1)
		errx(EX_OSERR, "Unable to apply rights for sandbox");
#endif

	/*
	 * Deal with raw devices
	 */
	size = sbuf.st_size;
	sectsz = DEV_BSIZE;
	psectsz = psectoff = 0;
	candelete = geom = 0;
	if (S_ISCHR(sbuf.st_mode)) {
		if (ioctl(fd, DIOCGMEDIASIZE, &size) < 0 ||
		    ioctl(fd, DIOCGSECTORSIZE, &sectsz)) {
			perror("Could not fetch dev blk/sector size");
			goto err;
		}
		assert(size != 0);
		assert(sectsz != 0);
		if (ioctl(fd, DIOCGSTRIPESIZE, &psectsz) == 0 && psectsz > 0)
			ioctl(fd, DIOCGSTRIPEOFFSET, &psectoff);
		strlcpy(arg.name, "GEOM::candelete", sizeof(arg.name));
		arg.len = sizeof(arg.value.i);
		if (ioctl(fd, DIOCGATTR, &arg) == 0)
			candelete = arg.value.i;
		if (ioctl(fd, DIOCGPROVIDERNAME, name) == 0)
			geom = 1;
	} else
		psectsz = sbuf.st_blksize;

#ifndef WITHOUT_CAPSICUM
	if (caph_ioctls_limit(fd, cmds, nitems(cmds)) == -1)
		errx(EX_OSERR, "Unable to apply rights for sandbox");
#endif

	if (ssopt != 0) {
		if (!powerof2(ssopt) || !powerof2(pssopt) || ssopt < 512 ||
		    ssopt > pssopt) {
			EPRINTLN("Invalid sector size %d/%d",
			    ssopt, pssopt);
			goto err;
		}

		/*
		 * Some backend drivers (e.g. cd0, ada0) require that the I/O
		 * size be a multiple of the device's sector size.
		 *
		 * Validate that the emulated sector size complies with this
		 * requirement.
		 */
		if (S_ISCHR(sbuf.st_mode)) {
			if (ssopt < sectsz || (ssopt % sectsz) != 0) {
				EPRINTLN("Sector size %d incompatible "
				    "with underlying device sector size %d",
				    ssopt, sectsz);
				goto err;
			}
		}

		sectsz = ssopt;
		psectsz = pssopt;
		psectoff = 0;
	}

	fi = calloc(1, sizeof(struct block_file_inst));
	if (fi == NULL) {
		perror("calloc");
		goto err;
	}
	fi->fi_fd = fd;
	fi->fi_ischr = S_ISCHR(sbuf.st_mode);
	fi->fi_buf = geom ? malloc(MAXPHYS) : NULL;

	*bd = fi;
	*candelete_p = candelete;
	*rdonly_p = ro;
	*size_p = size;
	*sectsz_p = sectsz;
	*psectsz_p = psectsz;
	*psectoff_p = psectoff;

        free(nopt);

	return (0);
err:
	if (fd >= 0)
		close(fd);
	free(nopt);
	errno = EINVAL;
	return (-1);
}

static int
block_file_close(void *bd)
{
	struct block_file_inst *fi = bd;

	close(fi->fi_fd);
	free(fi->fi_buf);
	free(fi);

	return (0);
}

static ssize_t
block_file_read(void *bd, const struct iovec *iov, int iovcnt, size_t nbytes,
    off_t offset) {
	struct block_file_inst *fi = bd;
	uint8_t	*buf;
	ssize_t clen, len, off, boff, voff, resid;
	int i;

	buf = iovcnt > 1 ? fi->fi_buf : NULL;

	if (buf == NULL) {
		return (preadv(fi->fi_fd, iov, iovcnt, offset));
	}

	i = 0;
	off = voff = 0;
	resid = nbytes;
	while (resid > 0) {
		len = MIN(resid, MAXPHYS);
		if (pread(fi->fi_fd, buf, len, offset + off) < 0) {
			return (-1);
		}
		boff = 0;
		do {
			clen = MIN(len - boff, iov[i].iov_len - voff);
			memcpy(iov[i].iov_base + voff, buf + boff, clen);
			if (clen < iov[i].iov_len - voff) {
				voff += clen;
			} else {
				i++;
				voff = 0;
			}
			boff += clen;
		} while (boff < len);
		off += len;
		resid -= len;
	}

	return (nbytes);
}

static ssize_t
block_file_write(void *bd, const struct iovec *iov, int iovcnt, size_t nbytes,
    off_t offset) {
	struct block_file_inst *fi = bd;
	uint8_t	*buf;
	ssize_t clen, len, off, boff, voff, resid;
	int i;

	buf = iovcnt > 1 ? fi->fi_buf : NULL;

	if (buf == NULL) {
		return (pwritev(fi->fi_fd, iov, iovcnt, offset));
	}

	i = 0;
	off = voff = 0;
	resid = nbytes;
	while (resid > 0) {
		len = MIN(resid, MAXPHYS);
		boff = 0;
		do {
			clen = MIN(len - boff, iov[i].iov_len - voff);
			memcpy(buf + boff, iov[i].iov_base + voff, clen);
			if (clen < iov[i].iov_len - voff) {
				voff += clen;
			} else {
				i++;
				voff = 0;
			}
			boff += clen;
		} while (boff < len);
		if (pwrite(fi->fi_fd, buf, len, offset + off) < 0) {
			return (-1);
		}
		off += len;
		resid -= len;
	}

	return (nbytes);
}

static ssize_t
block_file_delete(void *bd, size_t nbytes, off_t offset)
{
	struct block_file_inst *fi = bd;
	off_t arg[2];

	if (fi->fi_ischr) {
		arg[0] = offset;
		arg[1] = nbytes;
		return (ioctl(fi->fi_fd, DIOCGDELETE, arg));
	} else {
		errno = EOPNOTSUPP;
		return (-1);
	}
}

static int
block_file_flush(void *bd)
{
	struct block_file_inst *fi = bd;
	if (fi->fi_ischr)
		return (ioctl(fi->fi_fd, DIOCGFLUSH));
	else
		return (fsync(fi->fi_fd));
}

struct block_devemu block_de_file = {
	.bd_emu =	"file",
	.bd_open =	block_file_open,
	.bd_close =	block_file_close,
	.bd_read =	block_file_read,
	.bd_write =	block_file_write,
	.bd_delete =	block_file_delete,
	.bd_flush =	block_file_flush
};
BLOCK_EMUL_SET(block_de_file);
