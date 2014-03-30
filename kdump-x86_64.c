/*
 * kdump-x86_64.c
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

#include "kdump-tool.h"
#include <stdio.h>
#include <string.h>
#include <endian.h>

#include "elfc.h"

#define PHYSADDRMASK		0x0000ffffffffffff

#define PAGESHIFT_4K		12
#define PAGEMASK_4K		((1ULL << PAGESHIFT_4K) - 1)
#define PHYSADDRMASK_4K		(PHYSADDRMASK & ~PAGEMASK_4K)
#define PAGESIZE_4K		(1 << PAGESHIFT_4K)

#define PAGESHIFT_2M		21
#define PAGEMASK_2M		((1ULL << PAGESHIFT_2M) - 1)
#define PHYSADDRMASK_2M		(PHYSADDRMASK & ~PAGEMASK_2M)
#define PAGESIZE_2M		(1 << PAGESHIFT_2M)

#define PAGESHIFT_1G		30
#define PAGEMASK_1G		((1ULL << PAGESHIFT_1G) - 1)
#define PHYSADDRMASK_1G		(PHYSADDRMASK & ~PAGEMASK_1G)
#define PAGESIZE_1G		(1 << PAGESHIFT_1G)

#define PAGESHIFT_L1		39
#define PAGEMASK_L1		((1ULL << PAGESHIFT_L1) - 1)
#define PHYSADDRMASK_L1		(PHYSADDRMASK & ~PAGEMASK_L1)
#define PAGESIZE_L1		(1 << PAGESHIFT_L1)

#define KERNBASE		0xffff000000000000

static int
handle_pte(struct elfc *pelf, GElf_Addr vaddr, GElf_Addr pteaddr,
	   GElf_Addr begin_addr, GElf_Addr end_addr,
	   handle_page_f handle_page, void *userdata)
{
	uint64_t pte[512];
	uint64_t i;
	int rv;
	uint64_t start = begin_addr >> PAGESHIFT_4K;
	uint64_t end = end_addr >> PAGESHIFT_4K;

	begin_addr &= PAGEMASK_4K;
	end_addr &= PAGEMASK_4K;
	rv = elfc_read_pmem(pelf, pteaddr, pte, sizeof(pte));
	if (rv == -1) {
		fprintf(stderr, "Unable to read page table entry at"
			" %llx: %s\n", (unsigned long long) pteaddr,
			strerror(elfc_get_errno(pelf)));
		return -1;
	}

	for (i = start; i <= end; i++) {
		GElf_Addr newvaddr;
		uint64_t lpte = le64toh(pte[i]);

		if (!(lpte & 0x1))
			continue;

		newvaddr = vaddr | (i << PAGESHIFT_4K);

		/* 4K page */
		rv = handle_page(pelf, 
				 lpte & PHYSADDRMASK_4K,
				 newvaddr | KERNBASE,
				 PAGESIZE_4K, userdata);
		if (rv == -1)
			return -1;
	}
	return 0;
}

static int
handle_pde(struct elfc *pelf, GElf_Addr vaddr, GElf_Addr pdeaddr,
	   GElf_Addr begin_addr, GElf_Addr end_addr,
	   handle_page_f handle_page, void *userdata)
{
	uint64_t pde[512];
	uint64_t i;
	int rv;
	uint64_t start = begin_addr >> PAGESHIFT_2M;
	uint64_t end = end_addr >> PAGESHIFT_2M;

	begin_addr &= PAGEMASK_2M;
	end_addr &= PAGEMASK_2M;
	rv = elfc_read_pmem(pelf, pdeaddr, pde, sizeof(pde));
	if (rv == -1) {
		fprintf(stderr, "Unable to read page directory entry at"
			" %llx: %s\n", (unsigned long long) pdeaddr,
			strerror(elfc_get_errno(pelf)));
		return -1;
	}

	for (i = start; i <= end; i++) {
		GElf_Addr newvaddr;
		uint64_t lpde = le64toh(pde[i]);

		if (!(lpde & 0x1))
			continue;

		newvaddr = vaddr | (i << PAGESHIFT_2M);
		if (lpde & (1 << 7)) {
			/* 2mb page */
			rv = handle_page(pelf, 
					 lpde & PHYSADDRMASK_2M,
					 newvaddr | KERNBASE,
					 PAGESIZE_2M, userdata);
		} else {
			rv = handle_pte(pelf, newvaddr,
					lpde & PHYSADDRMASK_4K,
					begin_addr, end_addr,
					handle_page, userdata);
		}
		if (rv == -1)
			return -1;
	}
	return 0;
}

static int
handle_pdp(struct elfc *pelf, GElf_Addr vaddr, GElf_Addr pdpaddr,
	   GElf_Addr begin_addr, GElf_Addr end_addr,
	   handle_page_f handle_page, void *userdata)
{
	uint64_t pdp[512];
	uint64_t i;
	int rv;
	uint64_t start = begin_addr >> PAGESHIFT_1G;
	uint64_t end = end_addr >> PAGESHIFT_1G;

	begin_addr &= PAGEMASK_1G;
	end_addr &= PAGEMASK_1G;
	rv = elfc_read_pmem(pelf, pdpaddr, pdp, sizeof(pdp));
	if (rv == -1) {
		fprintf(stderr, "Unable to read page directory pointer at"
			" %llx: %s\n", (unsigned long long) pdpaddr,
			strerror(elfc_get_errno(pelf)));
		return -1;
	}

	for (i = start; i <= end; i++) {
		GElf_Addr newvaddr;
		uint64_t lpdp = le64toh(pdp[i]);

		if (!(lpdp & 0x1))
			continue;

		newvaddr = vaddr | (i << PAGESHIFT_1G);
		if (lpdp & (1 << 7)) {
			/* 1gb page */
			rv = handle_page(pelf, 
					 lpdp & PHYSADDRMASK_1G,
					 newvaddr | KERNBASE,
					 PAGESIZE_1G, userdata);
		} else {
			rv = handle_pde(pelf, newvaddr,
					lpdp & PHYSADDRMASK_4K,
					begin_addr, end_addr,
					handle_page, userdata);
		}
		if (rv == -1)
			return -1;
	}
	return 0;
}

static int
x86_64_walk(struct elfc *pelf, GElf_Addr pgd,
	    GElf_Addr begin_addr, GElf_Addr end_addr, void *arch_data,
	    handle_page_f handle_page, void *userdata)
{
	uint64_t pml[512];
	uint64_t i;
	int rv;
	uint64_t start = begin_addr >> PAGESHIFT_L1;
	uint64_t end = end_addr >> PAGESHIFT_L1;

	begin_addr &= PAGEMASK_L1;
	end_addr &= PAGEMASK_L1;
	rv = elfc_read_pmem(pelf, pgd, pml, sizeof(pml));
	if (rv == -1) {
		fprintf(stderr, "Unable to read page table descriptors at"
			" %llx: %s\n", (unsigned long long) pgd,
			strerror(elfc_get_errno(pelf)));
		return -1;
	}

	for (i = start; i <= end; i++) {
		uint64_t lpml = le64toh(pml[i]);
		if (!(lpml & 0x1))
			continue;

		rv = handle_pdp(pelf, i << PAGESHIFT_L1,
				lpml & PHYSADDRMASK_4K,
				begin_addr, end_addr,
				handle_page, userdata);
		if (rv == -1)
			return -1;
	}
	return 0;
}

struct archinfo x86_64_arch = {
	.name = "x86_64",
	.elfmachine = EM_X86_64,
	.default_elfclass = ELFCLASS64,
	.walk_page_table = x86_64_walk
};
