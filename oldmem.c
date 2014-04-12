/*
 * oldmem.c
 *
 * Handling for reading /dev/mem and /proc/vmcore into an elf format
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

#include "kdump-tool.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <setjmp.h>
#include <sys/mman.h>
#include <signal.h>

#include "list.h"
#include "elfc.h"

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

#define MAP_SIZE 1024 * 1024

struct fdio_data {
	int fd;
	int local_pgsize;
	int target_pgsize;
};

static int
fdio_do_write(struct elfc *e, int fd, GElf_Phdr *phdr,
	      void *data, void *userdata)
{
	struct fdio_data *d = userdata;
	int rv;
	char *map;
	off_t loff = 0;
	off_t pos;
	off_t mapsize;
	int lerrno;

	/*
	 * Align on a page size and get the offset from there.
	 */
	pos = phdr->p_paddr;
	loff = pos - (pos & ~((off_t) d->local_pgsize - 1));
	pos -= loff;
	mapsize = phdr->p_filesz;

	/*
	 * Copy in sections.
	 */
	while ((mapsize + loff) > MAP_SIZE) {
		map = mmap(NULL, MAP_SIZE, PROT_READ, MAP_SHARED, d->fd, pos);
		if (map == MAP_FAILED)
			return -1;
		rv = write(fd, map + loff, MAP_SIZE - loff);
		lerrno = errno;
		munmap(map, MAP_SIZE);
		if (rv == -1) {
			errno = lerrno;
			return -1;
		}
		mapsize -= MAP_SIZE - loff;
		pos += MAP_SIZE;
		loff = 0;
	}
	map = mmap(NULL, mapsize + loff, PROT_READ, MAP_SHARED, d->fd, pos);
	if (map == MAP_FAILED)
		return -1;
	rv = write(fd, map + loff, mapsize);
	lerrno = errno;
	munmap(map, mapsize + loff);
	if (rv == -1) {
		errno = lerrno;
		return -1;
	}
	return 0;
}

static int
fdio_get_data(struct elfc *e, GElf_Phdr *phdr, void *data,
	      GElf_Off off, void *odata, size_t len,
	      void *userdata)
{
	struct fdio_data *d = userdata;
	char *map;
	off_t loff = 0;
	off_t pos;
	off_t mapsize;
	char *wdata = odata;

	if ((off > phdr->p_filesz) || ((off + len) > phdr->p_filesz)) {
		errno = EINVAL;
		return -1;
	}

	/*
	 * Align on a page size and get the offset from there.
	 */
	pos = phdr->p_paddr + off;
	loff = pos - (pos & ~((off_t) d->local_pgsize - 1));
	pos -= loff;
	mapsize = len + loff;

	/*
	 * Copy in sections.
	 */
	while ((mapsize + loff) > MAP_SIZE) {
		map = mmap(NULL, MAP_SIZE, PROT_READ, MAP_SHARED, d->fd, pos);
		if (map == MAP_FAILED)
			return -1;
		memcpy(wdata, map + loff, MAP_SIZE - loff);
		munmap(map, MAP_SIZE);
		mapsize -= MAP_SIZE - loff;
		wdata += MAP_SIZE - loff;
		pos += MAP_SIZE;
		loff = 0;
	}
	map = mmap(NULL, mapsize + loff, PROT_READ, MAP_SHARED, d->fd, pos);
	if (map == MAP_FAILED)
		return -1;
	memcpy(wdata, map + loff, mapsize - loff);
	munmap(map, mapsize + loff);
	return 0;
}

static int
fdio_set_data(struct elfc *e, GElf_Phdr *phdr, void *data,
	      GElf_Off off, const void *idata, size_t len,
	      void *userdata)
{
	return -1;
}

struct memrange {
	uint64_t start;
	uint64_t size;
};

static struct memrange init_memrange = { 0, -1ULL };

static struct memrange *memrange = &init_memrange;
static int num_memrange = 1;

static int memrange_handler(const char *name, const char *str,
			    int strlen, void *userdata)
{
	uint64_t start, size;
	static struct memrange *new_memrange;

	if (memrange == &init_memrange) {
		num_memrange = 0;
		memrange = NULL;
	}

	if (parse_memrange(str, &start, &size) == -1)
		goto out_err;

	new_memrange = malloc(sizeof(*new_memrange) * (num_memrange + 1));
	if (memrange) {
		memcpy(new_memrange, memrange, 
		       sizeof(*new_memrange) * num_memrange);
		free(memrange);
	}
	memrange = new_memrange;
	memrange[num_memrange].start = start;
	memrange[num_memrange].size = size;
	num_memrange++;

	return 0;

out_err:
	fprintf(stderr, "Invalid memrange in vmcoreinfo\n");
	return -1;
}

static sigjmp_buf acc_err_jump;
static void
acc_err_hnd(int sig)
{
	siglongjmp(acc_err_jump, 1);
}
static char dummy_buf;

static int
scan_memrange(int mfd, uint64_t rangestart, uint64_t rangesize,
	      unsigned char *buf, int page_size, const char *oldmem,
	      struct list *mems)
{
	off_t start = rangestart;
	off_t pos = rangestart;
	int nr_phdr = 0;
	struct mementry *e;
	int rv;
	char *map;
	struct sigaction act, oldsegv, oldbus;

	memset(&act, 0, sizeof(act));
	act.sa_handler = acc_err_hnd;
	rv = sigaction(SIGSEGV, &act, &oldsegv);
	if (rv == -1) {
		fprintf(stderr, "Unable to set up signal handler: %s\n",
			strerror(errno));
		return -1;
	}
	rv = sigaction(SIGBUS, &act, &oldbus);
	if (rv == -1) {
		fprintf(stderr, "Unable to set up signal handler: %s\n",
			strerror(errno));
		nr_phdr = -1;
		goto out_set_segv;
	}
	while (pos < (rangestart + rangesize)) {
		map = mmap(NULL, page_size, PROT_READ, MAP_SHARED, mfd, pos);
		if (sigsetjmp(acc_err_jump, 0) || map == MAP_FAILED) {
			if (start != pos) {
				e = newmems(0, start, pos - start);
				if (!e) {
					if (map != MAP_FAILED)
						munmap(map, page_size);
					goto out_err;
				}
				list_add_last(mems, &e->link);
				nr_phdr++;
			}
			start = pos + page_size;
		} else {
			/* Make sure we can access the memory */
			dummy_buf = *map;
		}
		if (map != MAP_FAILED)
			munmap(map, page_size);

		pos += page_size;
		if (((Elf32_Word) ((pos - start) + page_size)) < page_size) {
			/* Next page will not fit in phdr */
			e = newmems(start, start, pos - start);
			if (!e)
				goto out_err;
			list_add_last(mems, &e->link);
			nr_phdr++;
			start = pos;
		}
	}
	if (start != pos) {
		e = newmems(0, start, pos - start);
		if (!e)
			goto out_err;
		list_add_last(mems, &e->link);
		nr_phdr++;
	}

out:
	sigaction(SIGSEGV, &oldbus, NULL);
out_set_segv:
	sigaction(SIGSEGV, &oldsegv, NULL);
	return nr_phdr;

out_err:
	nr_phdr = -1;
	goto out;
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
	struct fdio_data *fdio_data;
	struct vmcoreinfo_data vmci[] = {
		{ "PAGESIZE", 10 },
		{ "SYMBOL(swapper_pg_dir)", 16 },
		{ "ADDRESS(phys_pgd_ptr)", 16 },
		{ NULL }
	};
	int page_size;
	int memr;

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
		fprintf(stderr,
			"Warning: Page size not in vmcore, assuming %d\n",
			page_size);
	}

	rv = find_vmcore_entries(velf, "MEMRANGE(sysram)",
				 memrange_handler, NULL);
	if (rv) {
		fprintf(stderr,
			"Error: Unable to scan memrange entries.\n");
		goto out_err;
	}
	if (memrange == &init_memrange) {
		fprintf(stderr,
			"Warning: No memrange entries from old nernel.\n"
			"  Will try to scan all of memory.\n");
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
	/*
	 * 32-bit architectures often can address more than 32-bits of
	 * physical memory.  So always use 64-bits.
	 */ 
	elfc_setclass(elf, ELFCLASS64);
	elfc_setencoding(elf, elfc_getencoding(velf));
	copy_elf_notes(elf, velf);

	if (!vmci[2].found) {
		/* Add phys_pgd_ptr to the notes if it doesn't already exist */
		GElf_Addr virt_pgdir;
		GElf_Addr phys_pgdir;
		char buf[128];

		if (!vmci[1].found) {
			fprintf(stderr,
				"Error: swapper_pg_dir not in vmcore\n");
			goto out_err;
		}
		virt_pgdir = vmci[1].val;
		rv = elfc_vmem_to_pmem(velf, virt_pgdir, &phys_pgdir);
		if (rv == -1) {
			fprintf(stderr, "Error getting swapper_pg_dir phys"
				" addr: %s\n",
				strerror(elfc_get_errno(elf)));
			goto out_err;
		}
		sprintf(buf, "ADDRESS(phys_pgd_ptr)=%llx\n",
			(unsigned long long) phys_pgdir);
		rv = elfc_add_note(elf, 0, "VMCOREINFO", 12,
				   buf, strlen(buf) + 1);
		if (rv == -1) {
			fprintf(stderr, "Error adding phys_pgd_ptr note: %s\n",
				strerror(elfc_get_errno(elf)));
			goto out_err;
		}
	}
	
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

	for (memr = 0; memr < num_memrange; memr++) {
		rv = scan_memrange(mfd,
				   memrange[memr].start, memrange[memr].size,
				   buf, page_size, oldmem, &mems);
		if (rv == -1)
			goto out_err;
		nr_phdr += rv;
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
		fdio_data->local_pgsize = sysconf(_SC_PAGE_SIZE);
		fdio_data->target_pgsize = page_size;
		
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
