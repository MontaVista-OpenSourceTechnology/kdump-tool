/*
 * kdump-mips.c
 *
 * MIPS specific code for handling coredumps
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
#include <string.h>
#include <endian.h>
#include <malloc.h>

#include "elfc.h"

struct arm_walk_data {
	struct elfc *pelf;
	int is_bigendian;
	uint32_t (*conv32)(void *in);
};

static int
handle_pte(struct arm_walk_data *awd, GElf_Addr vaddr, GElf_Addr pteaddr,
	   GElf_Addr begin_addr, GElf_Addr end_addr,
	   handle_page_f handle_page, void *userdata)
{
	uint32_t pte[256];
	int i;
	int rv;
	uint32_t start = begin_addr >> 12;
	uint32_t end = end_addr >> 12;

	begin_addr &= 0x00000fff;
	end_addr &= 0x00000fff;
	rv = elfc_read_pmem(awd->pelf, pteaddr, pte, sizeof(pte));
	if (rv == -1) {
		fprintf(stderr, "Unable to read page table entry at"
			" %llx: %s\n", (unsigned long long) pteaddr,
			strerror(elfc_get_errno(awd->pelf)));
		return -1;
	}

	for (i = start; i <= end; i++) {
		uint64_t lpte = awd->conv32(&pte[i]);

		switch (lpte & 0x3) {
		case 0:
			continue;
		case 1:
			/* 64k page */
			rv = handle_page(awd->pelf, 
					 lpte & ~0xffff,
					 vaddr | ((GElf_Addr) i) << 16,
					 1 << 16, userdata);
			if (rv == -1)
				return -1;
			i += 15; /* 16 duplicate page entries */
			break;
		case 2:
		case 3:
			/* 4k page */
			rv = handle_page(awd->pelf, 
					 lpte & ~0xfff,
					 vaddr | ((GElf_Addr) i) << 12,
					 1 << 12, userdata);
			if (rv == -1)
				return -1;
			break;
		}
	}
	return 0;
}

static int
arm_task_ptregs(struct kdt_data *d, GElf_Addr task, void *regs)
{
	uint64_t thread_info;
	uint32_t *pt_regs = regs;
	uint32_t offset = d->arm_thread_info_cpu_context;
	int rv;

	if (!d->arm_thread_info_cpu_context_found ||
	    !d->arm___switch_to_found) {
		pr_err("ARM thread_info cpu_context offset or __switch to "
		       "missing from vminfo, unable to convert processes "
		       "to gdb threads\n");
		return -1;
	}

	rv = fetch_vaddrlong(d, task + d->task_stack, &thread_info,
			     "task_stack");
	if (rv)
		return rv;

#define GETREG(name, num, coffset) do { \
	rv = fetch_vaddr32(d, thread_info + offset + (coffset * 4),	    \
			   pt_regs + num, name);			    \
	if (rv)								    \
		return rv;						    \
	} while(0)

	GETREG("r4", 4, 0);
	GETREG("r5", 5, 1);
	GETREG("r6", 6, 2);
	GETREG("r7", 7, 3);
	GETREG("r8", 8, 4);
	GETREG("r9", 9, 5);
	GETREG("sl", 10, 6);
	GETREG("fp", 11, 7);
	GETREG("sp", 13, 8);
	/*
	 * This is called "pc" in cpu_context_save, but we save from the
	 * inside of __switch_to, so it's really lr.
	 */
	GETREG("lr", 14, 9);
	pt_regs[15] = d->arm___switch_to;

	return 0;
}

static int
arm_arch_setup(struct elfc *pelf, struct kdt_data *d, void **arch_data)
{
	struct arm_walk_data *awd;

	awd = malloc(sizeof(*awd));
	if (!awd) {
		fprintf(stderr, "Out of memory allocating arm arch data\n");
		return -1;
	}
	memset(awd, 0, sizeof(*awd));

	awd->pelf = pelf;
	awd->conv32 = d->conv32;

	d->section_size_bits = 28;
	d->max_physmem_bits = 32;

	d->fetch_ptregs = arm_task_ptregs;
	d->pt_regs_size = 18 * 4 + 4; /* 4 extra bytes at the end. */

	*arch_data = awd;

	return 0;
}

static void
arm_arch_cleanup(void *arch_data)
{
	free(arch_data);
}

static int
arm_walk(struct elfc *pelf, GElf_Addr pgdaddr,
	 GElf_Addr begin_addr, GElf_Addr end_addr, void *arch_data,
	 handle_page_f handle_page, void *userdata)
{
	uint32_t pgd[4096];
	struct arm_walk_data *awd = arch_data;
	int i;
	int rv;
	uint32_t start = (begin_addr & 0xffffffff) >> 20;
	uint32_t end = (end_addr & 0xffffffff) >> 20;

	begin_addr &= 0x000fffff;
	end_addr &= 0x000fffff;
	rv = elfc_read_pmem(pelf, pgdaddr, pgd, sizeof(pgd));
	if (rv == -1) {
		fprintf(stderr, "Unable to read page table descriptors at"
			" %llx: %s\n", (unsigned long long) pgdaddr,
			strerror(elfc_get_errno(pelf)));
		return -1;
	}

	for (i = start; i <= end; i++) {
		uint32_t lpgd = awd->conv32(&pgd[i]);

		switch (lpgd & 0x3) {
		case 0:
		case 3:
			/* Unused entry */
			continue;
		case 1:
			rv = handle_pte(awd, ((GElf_Addr) i) << 20,
					lpgd & ~0x3ff,
					begin_addr, end_addr,
					handle_page, userdata);
			if (rv == -1)
				return -1;
			break;
		case 2:
			if (lpgd & (1 << 18)) {
				fprintf(stderr, "Warning: Supersection "
					"pages are not supported\n");
				continue;
			}
			rv = handle_page(pelf, 
					 lpgd & ~0xfffff,
					 ((GElf_Addr) i) << 20,
					 1 << 20, userdata);
			if (rv == -1)
				return -1;
			break;
		}
	}
	return 0;
}

struct archinfo arm_arch = {
	.name = "arm",
	.elfmachine = EM_ARM,
	.default_elfclass = ELFCLASS32,
	.setup_arch_pelf = arm_arch_setup,
	.cleanup_arch_data = arm_arch_cleanup,
	.walk_page_table = arm_walk
};
