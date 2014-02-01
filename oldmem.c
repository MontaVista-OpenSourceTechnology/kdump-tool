/*
 * oldmem.c
 *
 * Handling for reading /dev/oldmem and /proc/vmcore into an elf format
 *
 * Author: MontaVista Software, Inc.
 *         Corey Minyard <minyard@mvista.com>
 *         source@mvista.com
 *
 * Copyright 2014 MontaVista Software Inc.
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public License
 *  as published by the Free Software Foundation; either version 2 of
 *  the License, or (at your option) any later version.
 *
 *
 *  THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 *  WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 *  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 *  INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 *  BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 *  OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 *  ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
 *  TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 *  USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this program; if not, write to the Free
 *  Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include "kdumptool.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

#include "list.h"
#include "elfhnd.h"

struct mementry {
	struct link link;
	GElf_Addr vaddr;
	GElf_Addr paddr;
	GElf_Addr size;
};

static struct mementry *
newmems(GElf_Addr vaddr, GElf_Addr paddr, GElf_Addr size)
{
	struct mementry *e = malloc(sizeof(*e));
	if (!e) {
		fprintf(stderr, "Out of memory allocating mems\n");
		return NULL;
	}
	e->vaddr = vaddr;
	e->paddr = paddr;
	e->size = size;
	return e;
}

struct fdio_data {
	int fd;
};

static int
fdio_do_write(struct elfc *e, int fd, GElf_Phdr *phdr,
	      void *data, void *userdata)
{
	struct fdio_data *d = userdata;
	int rv;

	rv = lseek(d->fd, phdr->p_paddr, SEEK_SET);
	if (rv == -1)
		return -1;
	return elfc_copy_fd_range(fd, d->fd, phdr->p_filesz);
}

static int
fdio_get_data(struct elfc *e, GElf_Phdr *phdr, void *data,
	      GElf_Off off, void *odata, size_t len,
	      void *userdata)
{
	struct fdio_data *d = userdata;
	int rv;

	if ((off > phdr->p_filesz) || ((off + len) > phdr->p_filesz)) {
		errno = EINVAL;
		return -1;
	}

	rv = lseek(d->fd, phdr->p_paddr + off, SEEK_SET);
	if (rv == -1)
		return -1;

	rv = read(d->fd, odata, len);
	if (rv == -1)
		return -1;
	return 0;
}

static int
fdio_set_data(struct elfc *e, GElf_Phdr *phdr, void *data,
	      GElf_Off off, const void *idata, size_t len,
	      void *userdata)
{
	struct fdio_data *d = userdata;
	int rv;

	if ((off > phdr->p_filesz) || ((off + len) > phdr->p_filesz)) {
		errno = EINVAL;
		return -1;
	}

	rv = lseek(d->fd, phdr->p_paddr + off, SEEK_SET);
	if (rv == -1)
		return -1;

	rv = write(d->fd, idata, len);
	if (rv == -1)
		return -1;
	return 0;
}

struct elfc *
read_oldmem(char *oldmem, char *vmcore)
{
	struct list mems;
	struct mementry *e;
	struct link *tmpe;
	int nr_phdr = 0;
	unsigned char *buf = NULL;
	struct elfc *velf = NULL, *elf = NULL;
	int vfd = -1, mfd = -1;
	int rv = 0;
	off_t start = 0;
	off_t pos = 0;
	struct fdio_data *fdio_data;
	struct vmcoreinfo_data vmci[] = {
		{ "PAGESIZE=", 10 },
		{ NULL }
	};
	int page_size;

	list_init(&mems);

	vfd = open(vmcore, O_RDONLY);
	if (vfd == -1) {
		fprintf(stderr, "Unable to open %s: %s\n", vmcore,
			strerror(errno));
		goto out_err;
	}

	velf = elfc_alloc();
	if (!velf) {
		fprintf(stderr, "Out of memory allocating velf\n");
		goto out_err;
	}
	rv = elfc_open(velf, vfd);
	if (rv) {
		fprintf(stderr, "Unable to elfc open %s: %s\n", vmcore,
			strerror(elfc_get_errno(velf)));
		goto out_err;
	}

	handle_vminfo_notes(velf, vmci);
	if (vmci[0].found) {
		page_size = vmci[0].val;
	} else {
		page_size = 4096;
		fprintf(stderr, "Warning: Page size in vmcore, assuming %d\n",
			page_size);
	}

	elf = elfc_alloc();
	if (!elf) {
		fprintf(stderr, "Out of memory allocating elfc\n");
		goto out_err;
	}
	rv = elfc_setup(elf, ET_CORE);
	if (rv == -1) {
		fprintf(stderr, "Error setting up elfc: %s\n",
			strerror(elfc_get_errno(elf)));
		goto out_err;
	}
	elfc_setmachine(elf, elfc_getmachine(velf));
	elfc_setclass(elf, elfc_getclass(velf));
	elfc_setencoding(elf, elfc_getencoding(velf));
	copy_elf_notes(elf, velf);

	elfc_free(velf);
	velf = NULL;
	close(vfd);
	vfd = -1;

	mfd = open(oldmem, O_RDONLY);
	if (mfd == -1) {
		fprintf(stderr, "Unable to open %s: %s\n", oldmem,
			strerror(errno));
		rv = -1;
		goto out_err;
	}

	buf = malloc(page_size);
	if (!buf) {
		fprintf(stderr, "Out of memory allocating page\n");
		goto out_err;
	}

	for (;;) {
		rv = read(mfd, buf, page_size);
		if (rv == -1) {
			if (errno == ENOMEM) {
				if (start != pos) {
					e = newmems(0, start, pos - start);
					if (!e)
						goto out_err;
					list_add_last(&mems, &e->link);
					nr_phdr++;
				}
				start = pos + page_size;
				rv = lseek(mfd, pos + page_size, SEEK_SET);
				if (rv == -1) {
					fprintf(stderr, "Error seek %s: %s\n",
						oldmem, strerror(errno));
					goto out_err;
				}
			} else {
				fprintf(stderr, "Unable to read %s: %s\n",
					oldmem, strerror(errno));
				goto out_err;
			}
		} else if (rv == 0)
			break;
		pos += page_size;
		if (((Elf32_Word) ((pos - start) + page_size)) < page_size) {
			/* Next page will not fit in phdr */
			e = newmems(start, start, pos - start);
			if (!e)
				goto out_err;
			list_add_last(&mems, &e->link);
			nr_phdr++;
			start = pos;
		}
	}
	if (start != pos) {
		e = newmems(0, start, pos - start);
		if (!e)
			goto out_err;
		list_add_last(&mems, &e->link);
		nr_phdr++;
	}

	free(buf);
	buf = NULL;

	if (nr_phdr == 0) {
		fprintf(stderr, "No data in file %s\n", oldmem);
		goto out_err;
	}
	rv = lseek(mfd, 0, SEEK_SET);
	if (rv == -1) {
		fprintf(stderr, "Error seek %s: %s\n",
			oldmem, strerror(errno));
		goto out_err;
	}
	list_for_each_item_safe(&mems, e, tmpe, struct mementry, link) {
		rv = elfc_add_phdr(elf, PT_LOAD, e->vaddr, e->paddr,
				   e->size, e->size, PF_R | PF_W | PF_X,
				   page_size);
		if (rv == -1) {
			fprintf(stderr, "Error adding elfc phdr: %s\n",
				strerror(elfc_get_errno(elf)));
			goto out_err;
		}

		fdio_data = malloc(sizeof(*fdio_data));
		if (!fdio_data) {
			fprintf(stderr, "Error allocation fdio data\n");
			goto out_err;
		}
		fdio_data->fd = mfd;
		
		rv = elfc_set_phdr_data(elf, rv, NULL, elfc_gen_phdr_free,
					NULL, fdio_do_write, NULL,
					fdio_get_data, fdio_set_data,
					fdio_data);
		if (rv == -1) {
			free(fdio_data);
			fprintf(stderr, "Error setting elfc phdr data: %s\n",
				strerror(elfc_get_errno(elf)));
			goto out_err;
		}
		list_unlink(&e->link);
		free(e);
	}

	return elf;

out_err:
	list_for_each_item_safe(&mems, e, tmpe, struct mementry, link) {
		list_unlink(&e->link);
		free(e);
	}
	if (buf)
		free(buf);
	if (elf)
		elfc_free(elf);
	if (velf)
		elfc_free(velf);
	if (vfd != -1)
		close(vfd);
	if (mfd != -1)
		close(mfd);
	return NULL;
}
