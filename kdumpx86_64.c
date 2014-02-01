/*
 * kdumpx86_64.c
 *
 * x86_64 specific code for handling coredumps
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
#include <string.h>

#include "elfhnd.h"

#define PHYSADDRMASK_4K 0x0000fffffffff000
#define PAGESHIFT_4K	12
#define PAGESIZE_4K	(1 << PAGESHIFT_4K)
#define PHYSADDRMASK_2M 0x0000ffffffe00000
#define PAGESHIFT_2M	21
#define PAGESIZE_2M	(1 << PAGESHIFT_2M)
#define PHYSADDRMASK_1G 0x0000ffffc0000000
#define PAGESHIFT_1G	30
#define PAGESIZE_1G	(1 << PAGESHIFT_1G)
#define KERNBASE	0xffff000000000000

static int
handle_pte(struct elfc *pelf, GElf_Addr vaddr, GElf_Addr pteaddr,
	   handle_page_f handle_page, void *userdata)
{
	uint64_t pte[512];
	uint64_t i;
	int rv;

	rv = elfc_read_pmem(pelf, pteaddr, pte, sizeof(pte));
	if (rv == -1) {
		fprintf(stderr, "Unable to read page table entry at"
			" %llx: %s\n", (unsigned long long) pteaddr,
			strerror(elfc_get_errno(pelf)));
		return -1;
	}

	for (i = 0; i < 512; i++) {
		GElf_Addr newvaddr;

		if (!(pte[i] & 0x1))
			continue;

		newvaddr = vaddr | (i << PAGESHIFT_4K);

		/* 4K page */
		rv = handle_page(pelf, 
				 pte[i] & PHYSADDRMASK_4K,
				 newvaddr | KERNBASE,
				 PAGESIZE_4K, userdata);
		if (rv == -1)
			return -1;
	}
	return 0;
}

static int
handle_pde(struct elfc *pelf, GElf_Addr vaddr, GElf_Addr pdeaddr,
	   handle_page_f handle_page, void *userdata)
{
	uint64_t pde[512];
	uint64_t i;
	int rv;

	rv = elfc_read_pmem(pelf, pdeaddr, pde, sizeof(pde));
	if (rv == -1) {
		fprintf(stderr, "Unable to read page directory entry at"
			" %llx: %s\n", (unsigned long long) pdeaddr,
			strerror(elfc_get_errno(pelf)));
		return -1;
	}

	for (i = 0; i < 512; i++) {
		GElf_Addr newvaddr;

		if (!(pde[i] & 0x1))
			continue;

		newvaddr = vaddr | (i << PAGESHIFT_2M);
		if (pde[i] & (1 << 7)) {
			/* 2mb page */
			rv = handle_page(pelf, 
					 pde[i] & PHYSADDRMASK_2M,
					 newvaddr | KERNBASE,
					 PAGESIZE_2M, userdata);
		} else {
			rv = handle_pte(pelf, newvaddr,
					pde[i] & PHYSADDRMASK_4K,
					handle_page, userdata);
		}
		if (rv == -1)
			return -1;
	}
	return 0;
}

static int
handle_pdp(struct elfc *pelf, GElf_Addr vaddr, GElf_Addr pdpaddr,
	   handle_page_f handle_page, void *userdata)
{
	uint64_t pdp[512];
	uint64_t i;
	int rv;

	rv = elfc_read_pmem(pelf, pdpaddr, pdp, sizeof(pdp));
	if (rv == -1) {
		fprintf(stderr, "Unable to read page directory pointer at"
			" %llx: %s\n", (unsigned long long) pdpaddr,
			strerror(elfc_get_errno(pelf)));
		return -1;
	}

	for (i = 0; i < 512; i++) {
		GElf_Addr newvaddr;

		if (!(pdp[i] & 0x1))
			continue;

		newvaddr = vaddr | (i << PAGESHIFT_1G);
		if (pdp[i] & (1 << 7)) {
			/* 1gb page */
			rv = handle_page(pelf, 
					 pdp[i] & PHYSADDRMASK_1G,
					 newvaddr | KERNBASE,
					 PAGESIZE_1G, userdata);
		} else {
			rv = handle_pde(pelf, newvaddr,
					pdp[i] & PHYSADDRMASK_4K,
					handle_page, userdata);
		}
		if (rv == -1)
			return -1;
	}
	return 0;
}

static int
x86_64_walk(struct elfc *pelf, GElf_Addr pgd,
	    handle_page_f handle_page, void *userdata)
{
	uint64_t pml[512];
	uint64_t i;
	int rv;

	rv = elfc_read_pmem(pelf, pgd, pml, sizeof(pml));
	if (rv == -1) {
		fprintf(stderr, "Unable to read page table descriptors at"
			" %llx: %s\n", (unsigned long long) pgd,
			strerror(elfc_get_errno(pelf)));
		return -1;
	}

	for (i = 0; i < 512; i++) {
		if (!(pml[i] & 0x1))
			continue;

		rv = handle_pdp(pelf, i << 39, pml[i] & PHYSADDRMASK_4K,
				handle_page, userdata);
		if (rv == -1)
			return -1;
	}
	return 0;
}

struct archinfo x86_64_arch = {
	.name = "x86_64",
	.elfmachine = EM_X86_64,
	.walk_page_table = x86_64_walk
};
