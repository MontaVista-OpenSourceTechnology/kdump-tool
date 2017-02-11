/*
 * kdump-ppc32.c
 *
 * 32-bit PowerPC specific code for handling coredumps
 *
 * Author: MontaVista Software, Inc.
 *         Nikita Yushchenko <nyushchenko@dev.rtsoft.ru>
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
#include <string.h>
#include <endian.h>
#include "elfc.h"

struct ppc32_walk_data {

	struct elfc *pelf;

	uint32_t pagesize;

	uint32_t linear_start_phys;
	uint32_t linear_start_virt;
	uint32_t linear_size;

	bool pte_is_64bit;
	bool pgd_contains_vaddr;/* for BOOKE, pmd has virtual addresses,
				   for others, pmd has physical addresses */

	uint32_t pgd_area_size;	/* size of address space covered by
				   one pgd entry */
	uint32_t pgd_size;	/* pgd table size, in bytes */
				/* (pte table size is one page) */
	uint32_t pgd_addr_mask;	/* mask to extract pte table virtual address
				   from pgd table entry */
	int pte_present_mask;	/* defines location of page presence bit inside
				   pte */
	int pte_rpn_shift;	/* defines location of page frame number
				   inside pte */

	uint32_t pgd_paddr;	/* physicall address of loaded pgd table */
	uint32_t *pgd;		/* loaded pgd table */

	uint32_t pgd_area_vaddr;/* virtual address of start of area that
				   corresponds to loaded pte table */
	union {			/* loaded pte table */
		void *pte;
		uint32_t *pte32;
		uint64_t *pte64;
	};

	uint64_t (*conv64)(void *in);
	uint32_t (*conv32)(void *in);
};

static bool
linear_mapped_vaddr(struct ppc32_walk_data *md, uint32_t vaddr)
{
	return vaddr >= md->linear_start_virt &&
	       vaddr < md->linear_start_virt + md->linear_size;
}

static uint32_t
linear_virt_to_phys(struct ppc32_walk_data *md, uint32_t vaddr)
{
	return md->linear_start_phys + (vaddr - md->linear_start_virt);
}

static uint32_t
next_pgd_area_vaddr(struct ppc32_walk_data *md, uint32_t vaddr)
{
	return (vaddr & ~(md->pgd_area_size - 1)) + md->pgd_area_size;
}

static bool
ensure_pgd_from(struct ppc32_walk_data *md, uint32_t pgd_paddr)
{
	int rv;

	if (md->pgd_paddr == pgd_paddr)
		return true;

	rv = elfc_read_pmem(md->pelf, pgd_paddr, md->pgd, md->pgd_size);
	if (rv == -1) {
		fprintf(stderr, "Unable to read PGD table at 0x%x: %s\n",
			pgd_paddr, strerror(elfc_get_errno(md->pelf)));
		return false;
	}

	md->pgd_paddr = pgd_paddr;
	return true;
}

static uint32_t
pgd_for_vaddr(struct ppc32_walk_data *md, uint32_t vaddr)
{
	return md->conv32(md->pgd + (vaddr / md->pgd_area_size));
}

static bool
ensure_pte_for(struct ppc32_walk_data *md, uint32_t vaddr, uint32_t lpgd)
{
	uint32_t pgd_area_vaddr, pte_page_vaddr, pte_page_paddr;
	int rv;

	pgd_area_vaddr = vaddr & ~(md->pgd_area_size - 1);
	if (md->pgd_area_vaddr == pgd_area_vaddr)
		return true;

	if (md->pgd_contains_vaddr) {
		pte_page_vaddr = lpgd & md->pgd_addr_mask;
		if (!linear_mapped_vaddr(md, pte_page_vaddr)) {
			fprintf(stderr, "Unsupported: PTE table for address "
					"0x%08x is at virtual address 0x%08x "
					"which is outside of linear mapped "
					"area\n",
				vaddr, pte_page_vaddr);
			return false;
		}
		pte_page_paddr = linear_virt_to_phys(md, pte_page_vaddr);
	} else
		pte_page_paddr = lpgd & md->pgd_addr_mask;

	rv = elfc_read_pmem(md->pelf, pte_page_paddr, md->pte, md->pagesize);
	if (rv == -1) {
		fprintf(stderr, "Unable to read PTE table for address 0x%08x "
				"at 0x%x: %s\n",
			vaddr, pte_page_paddr,
			strerror(elfc_get_errno(md->pelf)));
		return false;
	}

	md->pgd_area_vaddr = pgd_area_vaddr;
	return true;
}

static bool
present_pte_at_index(struct ppc32_walk_data *md, int index)
{
	if (md->pte_is_64bit) {
		uint64_t lpte = md->conv64(md->pte64 + index);
		return (lpte & md->pte_present_mask) != 0;
	} else {
		uint32_t lpte = md->conv32(md->pte32 + index);
		return (lpte & md->pte_present_mask) != 0;
	}
}

static uint32_t
paddr_from_pte_at_index(struct ppc32_walk_data *md, int index)
{
	if (md->pte_is_64bit) {
		uint64_t lpte = md->conv64(md->pte64 + index);
		return (lpte >> md->pte_rpn_shift) * md->pagesize;
	} else {
		uint32_t lpte = md->conv32(md->pte32 + index);
		return (lpte >> md->pte_rpn_shift) * md->pagesize;
	}
}

static int
ppc32_arch_setup(struct elfc *pelf, struct kdt_data *d, void **arch_data)
{
	struct ppc32_walk_data *md;

	enum vmcoreinfo_labels {
		VMCI_SIZE_list_head,
		VMCI_ADDRESS_PAGE_OFFSET,
		VMCI_ADDRESS_MEMORY_START,
		VMCI_NUMBER_total_lowmem,
		VMCI_PAGESIZE,
		VMCI_CONFIG_BOOKE,
		VMCI_CONFIG_PTE_64BIT,
		VMCI_NUMBER__PAGE_PRESENT,
		VMCI_NUMBER_PTE_RPN_SHIFT,
	};

	struct vmcoreinfo_data vmci[] = {
		VMCI_SIZE(list_head),
		VMCI_ADDRESS(PAGE_OFFSET),
		VMCI_ADDRESS(MEMORY_START),
		VMCI_NUMBER(total_lowmem),
		VMCI_PAGESIZE(),
		VMCI_CONFIG(BOOKE),
		VMCI_CONFIG(PTE_64BIT),
		VMCI_NUMBER(_PAGE_PRESENT),
		VMCI_NUMBER(PTE_RPN_SHIFT),
		{ NULL }
	};

	uint32_t ptes_per_page;
	int i;

	md = malloc(sizeof(*md));
	if (!md) {
		fprintf(stderr, "Out of memory allocating ppc32 arch data\n");
		return -1;
	}
	memset(md, 0, sizeof(*md));

	md->pelf = pelf;

	handle_vminfo_notes(pelf, vmci);

	for (i = 0; vmci[i].name; i++) {

		/* CONFIG_xxx do not exist in notes if CONFIG_xxx is not defined */
		if (vmci[i].base == VMINFO_YN_BASE)
			continue;

		if (!vmci[i].found) {
			fprintf(stderr, "%s not present in input file notes, "
					"it is required for operation\n",
				vmci[i].name);
			goto err;
		}
	}

	if (vmci[VMCI_SIZE_list_head].val != 2 * sizeof(uint32_t)) {
		fprintf(stderr, "%s value %llu is not expected - "
				"is input file 32-bit?\n",
			vmci[VMCI_SIZE_list_head].name,
			(unsigned long long) vmci[VMCI_SIZE_list_head].val);
		goto err;
	}

	md->pagesize = vmci[VMCI_PAGESIZE].val;
	if (md->pagesize == 0 || ((md->pagesize & (md->pagesize - 1)) != 0)) {
		fprintf(stderr, "%s value %u is not valid, cannot continue\n",
			vmci[VMCI_PAGESIZE].name,
			(uint32_t)vmci[VMCI_PAGESIZE].val);
		goto err;
	}

	md->linear_start_phys = vmci[VMCI_ADDRESS_MEMORY_START].val;
	if ((md->linear_start_phys & (md->pagesize - 1)) != 0) {
		fprintf(stderr, "%s value 0x%08x is not page-aligned\n",
			vmci[VMCI_ADDRESS_MEMORY_START].name,
			(uint32_t)vmci[VMCI_ADDRESS_MEMORY_START].val);
		goto err;
	}

	md->linear_start_virt = vmci[VMCI_ADDRESS_PAGE_OFFSET].val;
	if ((md->linear_start_virt & (md->pagesize - 1)) != 0) {
		fprintf(stderr, "%s value 0x%08x is not page-aligned\n",
			vmci[VMCI_ADDRESS_PAGE_OFFSET].name,
			(uint32_t)vmci[VMCI_ADDRESS_PAGE_OFFSET].val);
		goto err;
	}

	md->linear_size = vmci[VMCI_NUMBER_total_lowmem].val;
	if ((md->linear_size & (md->pagesize - 1)) != 0) {
		fprintf(stderr, "%s value 0x%08x is not page-aligned\n",
			vmci[VMCI_NUMBER_total_lowmem].name,
			(uint32_t)vmci[VMCI_NUMBER_total_lowmem].val);
		goto err;
	}

	md->pgd_contains_vaddr = !!vmci[VMCI_CONFIG_BOOKE].val;
	md->pte_is_64bit = !!vmci[VMCI_CONFIG_PTE_64BIT].val;

	md->pte_present_mask = vmci[VMCI_NUMBER__PAGE_PRESENT].val;
	if (md->pte_present_mask == 0 ||
	    (md->pte_present_mask & (md->pte_present_mask - 1)) != 0) {
		fprintf(stderr, "%s value %llu is not valid\n",
			vmci[VMCI_NUMBER__PAGE_PRESENT].name,
			(unsigned long long) vmci[VMCI_NUMBER__PAGE_PRESENT].val);
		goto err;

	}

	md->pte_rpn_shift = vmci[VMCI_NUMBER_PTE_RPN_SHIFT].val;
	if (md->pte_rpn_shift < 6 ||
	    md->pte_rpn_shift > (md->pte_is_64bit ? 63 : 31)) {
		fprintf(stderr, "%s value %llu is out of range\n",
			vmci[VMCI_NUMBER_PTE_RPN_SHIFT].name,
			(unsigned long long) vmci[VMCI_NUMBER_PTE_RPN_SHIFT].val);
		goto err;
	}

	ptes_per_page = md->pagesize /
		(md->pte_is_64bit ? sizeof(uint64_t) : sizeof(uint32_t));
	md->pgd_area_size = ptes_per_page * md->pagesize;
	md->pgd_size = sizeof(uint32_t) * ((1ull << 32) / md->pgd_area_size);
	md->pgd_addr_mask = ~(ptes_per_page - 1);

	md->pgd_paddr = md->pgd_area_vaddr = ~0;

	md->pgd = malloc(md->pgd_size);
	if (!md->pgd) {
		fprintf(stderr, "Out of memory allocating pgd space\n");
		goto err;
	}

	md->pte = malloc(md->pagesize);
	if (!md->pte) {
		fprintf(stderr, "Out of memory allocation pte space\n");
		goto err1;
	}

	/* This is from kernel's arch/powerpc/include/asm/sparsemem.h */
	d->section_size_bits = 24;
	d->max_physmem_bits = 46;

	md->conv32 = d->conv32;
	md->conv64 = d->conv64;

	*arch_data = md;
	return 0;

err1:
	free(md->pgd);
err:
	free(md);
	return -1;
}

static int
ppc32_walk(struct elfc *pelf, GElf_Addr pgdaddr,
	   GElf_Addr begin_addr, GElf_Addr end_addr, void *arch_data,
	   handle_page_f handle_page, void *userdata)
{
	struct ppc32_walk_data *md = arch_data;
	uint32_t lpgd, vaddr, paddr, psize, tmp_vaddr, pshift;
	int ptei;

	/* Need to distinguish between zero vaddr at beginning and zero vaddr
	 * after overflow - thus using 'do' loop with special condition */

	if (end_addr < begin_addr) {
		fprintf(stderr, "Internal error: invalid call to %s()\n",
				__FUNCTION__);
		return -1;
	}

	vaddr = begin_addr;
	while (vaddr && vaddr < end_addr) {
		if (linear_mapped_vaddr(md, vaddr)) {
			psize = md->pagesize;
			vaddr &= ~(psize - 1);
			paddr = linear_virt_to_phys(md, vaddr);
			goto ready;
		}

		if (!ensure_pgd_from(md, pgdaddr)) {
			/* No PGD .. can process only linear mapping */
			if (vaddr < md->linear_start_virt)
				vaddr = md->linear_start_virt;
			else
				vaddr = end_addr;
			continue;
		}

		lpgd = pgd_for_vaddr(md, vaddr);

		if (lpgd == 0) {
			/* No PGD entry for this address */
			vaddr = next_pgd_area_vaddr(md, vaddr);
			continue;
		}

		/* For ppc32, huge pages are supported only for FSL_BOOKE and
		 * only for 64-bit PTEs
		 *
		 * For FSL_BOOKE huge page:
		 * - lpgd has cleared most significant bit,
		 * - lpgd has 6 least significant bits encoding page size,
		 * - huge page is always large enough to cover one or more
		 *   entire pgd area (no several ptes per pgd)
		 * - one or more pgd entries are equal and point to single
		 *   pte
		 */
		if (md->pgd_contains_vaddr && (lpgd & (1ul << 31)) == 0) {

			/* Huge page */

			if (!md->pte_is_64bit) {
				fprintf(stderr, "Unsupported: PGD for 0x%08x references "
						"huge page in 32bit PTE mode\n",
					vaddr);
				vaddr = next_pgd_area_vaddr(md, vaddr);
				continue;
			}
			pshift = (lpgd & 0x3f);
			if (pshift >= 32 || (1 << pshift) < md->pgd_area_size) {
				fprintf(stderr, "Unsupported: PGD for 0x%08x references "
						"huge page of size 0x%llu\n",
					vaddr, 1ull << pshift);
				vaddr = next_pgd_area_vaddr(md, vaddr);
				continue;
			}

			psize = (1 << (lpgd & 0x3f));
			tmp_vaddr = vaddr & ~(psize - 1);

			/* paranoia check */
			if (lpgd != pgd_for_vaddr(md, tmp_vaddr)) {
				fprintf(stderr, "Unexpected: PGD for 0x%08x references "
						"huge page of size 0x%08x, but PGD for "
						"0x%08x contains different value\n",
					vaddr, psize, tmp_vaddr);
				vaddr = next_pgd_area_vaddr(md, vaddr);
				continue;
			}

			lpgd |= (1ul << 31);
			vaddr = tmp_vaddr;
			ptei = 0;

		} else {

			/* Normal page */

			psize = md->pagesize;
			vaddr = vaddr & ~(psize - 1);
			ptei = (vaddr & (md->pgd_area_size - 1)) / psize;
		}

		if (!ensure_pte_for(md, vaddr, lpgd)) {
			/* No PTE table for this area - skip to next area */
			vaddr = next_pgd_area_vaddr(md, vaddr);
			continue;
		}

		if (!present_pte_at_index(md, ptei)) {
			/* Per PTE, page is not present */
			vaddr += psize;
			continue;
		}

		paddr = paddr_from_pte_at_index(md, ptei);
ready:
		handle_page(pelf, paddr, vaddr, psize, userdata);

		vaddr += psize;

	}

	return 0;
}

static void ppc32_arch_cleanup(void *arch_data)
{
	struct ppc32_walk_data *md = arch_data;

	free(md->pte);
	free(md->pgd);
	free(md);
}

struct archinfo ppc32_arch = {
	.name = "ppc32",
	.elfmachine = EM_PPC,
	.default_elfclass = ELFCLASS32,
	.setup_arch_pelf = ppc32_arch_setup,
	.cleanup_arch_data = ppc32_arch_cleanup,
	.walk_page_table = ppc32_walk,
};
