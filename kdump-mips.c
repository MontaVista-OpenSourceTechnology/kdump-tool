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
#include <stdlib.h>
#include <string.h>
#include <endian.h>

#include "elfc.h"

#define ENTRIES_PER_PGTAB(d, type, pgtab_size)				\
	((1 << mwd->type ##_order) * (1 << mwd->page_shift) / (pgtab_size))

#define MAX_SHIFT 16
#define MIN_SHIFT 12
#define MAX_ORDER 1
#define MAX_PGTAB_ENTRIES(pgentry_size) ((1 << MAX_SHIFT) * (1 << MAX_ORDER) / \
					 (pgentry_size))

#define ADDR32_MASK(shift) ((1 << (shift)) - 1)
#define ADDR64_MASK(shift) ((1ULL << (shift)) - 1)

/*
 * Order here does not matter, as long as the required elements are all
 * last.
 */
enum vmcoreinfo_labels {
	VMCI_SIZE_list_head,
	VMCI_ADDRESS__text,
	VMCI_ADDRESS__end,
	VMCI_ADDRESS__phys_to_kernel_offset,
	VMCI_ADDRESS_CKSEG0,
	VMCI_ADDRESS_CKSSEG,
	VMCI_ADDRESS_PHYS_OFFSET,
	VMCI_NUMBER_PMD_ORDER,
	VMCI_NUMBER__PAGE_HUGE,
	VMCI_ADDRESS_IO_BASE,
	/* Begin required elements. */
#define VREQ	VMCI_NUMBER_PAGE_SHIFT
	VMCI_NUMBER_PAGE_SHIFT,
	VMCI_NUMBER_PGD_ORDER,
	VMCI_NUMBER_PTE_ORDER,
	VMCI_NUMBER__PAGE_PRESENT,
	VMCI_NUMBER__PFN_SHIFT,
	VMCI_ADDRESS_PAGE_OFFSET,
	/* End actual elements. */
	VMCI_NUM_ELEMENTS
};

struct mips_walk_data {
	unsigned int page_shift;
	unsigned int page_size;
	unsigned int pgd_order;
	unsigned int pgd_shift;
	int pmd_present;
	unsigned int pmd_order;
	unsigned int pmd_shift;
	unsigned int pte_order;
	unsigned int pfn_shift;
	/* pte_shift is page_shift */
	uint64_t page_present_mask;
	bool is_64bit;
	uint64_t (*conv64)(void *in);
	uint32_t (*conv32)(void *in);
	uint64_t page_mask;

	uint64_t _text;
	uint64_t _end;
	uint64_t phys_to_kernel_offset;
	int mapped_kernel;

	uint64_t _PAGE_HUGE;

	uint64_t CKSEG0;
	uint64_t CKSSEG;

	uint64_t PAGE_OFFSET;
	uint64_t PHYS_OFFSET;
	uint64_t IO_BASE;
};

static int
mips_virt_to_phys32(const struct mips_walk_data *mwd,
		    GElf_Addr addr, int offset,
		    uint32_t vaddr, uint32_t *paddr)
{
	/* Convert to a physical address. */
	*paddr = vaddr - mwd->PAGE_OFFSET + mwd->PHYS_OFFSET;
	return 0;
}

typedef int (*walk_mips)(struct elfc *pelf, const struct mips_walk_data *mwd,
			 GElf_Addr pgdaddr,
			 GElf_Addr begin_addr, GElf_Addr end_addr,
			 handle_page_f handle_page, void *userdata);

/*
 * Scan a defined range of memory from r_start to r_end.  If some or all of
 * the range from begin_addr to end_addr is in the defined range, call page
 * table handlers on it.  After done, adjust begin_addr and end_addr to
 * remove the range we just scanned, if necessary.
 *
 * Returns -1 on error, 0 if the caller shouldkeep going, 1 if the caller
 * should return success immediately.
 */
static int
scan_range(struct elfc *pelf, const struct mips_walk_data *mwd,
	   GElf_Addr pgdaddr, uint64_t phys_offset,
	   GElf_Addr *begin_addr, GElf_Addr *end_addr,
	   GElf_Addr r_start, GElf_Addr r_end,
	   handle_page_f handle_page, void *userdata,
	   walk_mips walk)
{
	int rv;
	uint64_t start, end, addr;

	if (((*begin_addr <= r_start) && (*end_addr >= r_start)) ||
	    ((*begin_addr <= r_end) && (*end_addr >= r_end)) ||
	    ((*begin_addr > r_start) && (*end_addr < r_end)))
	{
		start = *begin_addr;
		if (start < r_start)
			start = r_start;
		end = *end_addr;
		if (end > r_end)
			end = r_end;

		start &= mwd->page_mask;
		/*
		 * The +1 converts it to one past the end, better for
		 * scanning the range.
		 */
		end = (end + 1 + mwd->page_size - 1) & mwd->page_mask;

		for (addr = start; addr < end; addr += mwd->page_size) {
			rv = handle_page(pelf,
					 addr - phys_offset,
					 addr,
					 1 << mwd->page_shift, userdata);
			if (rv == -1)
				return -1;
		}

		if ((*begin_addr >= r_start) && (*end_addr <= r_end))
			/* Region was completely inside text */
			return 1;
		else if ((*begin_addr < r_start) && (*end_addr > r_end)) {
			/* Region overlaps, have to do two ranges. */
			rv = walk(pelf, mwd, pgdaddr,
				  *begin_addr, r_start - 1,
				  handle_page, userdata);
			if (rv != -1)
				rv = walk(pelf, mwd, pgdaddr,
					  r_end, *end_addr,
					  handle_page, userdata);
			if (rv == -1)
				return -1;
			return 1;
		} else if (*begin_addr < r_start)
			*end_addr = r_start - 1;
		else if (*end_addr > r_end)
			*begin_addr = r_end + 1;
	}

	return 0;
}

static int
handle_32pte(struct elfc *pelf, const struct mips_walk_data *mwd,
	     GElf_Addr vaddr, GElf_Addr pteaddr,
	     GElf_Addr begin_addr, GElf_Addr end_addr,
	     handle_page_f handle_page, void *userdata)
{
	uint32_t pte[MAX_PGTAB_ENTRIES(sizeof(uint32_t))];
	int pte_count = ENTRIES_PER_PGTAB(d, pte, sizeof(uint32_t));
	int i;
	int rv;
	uint32_t start = begin_addr >> mwd->page_shift;
	uint32_t end = end_addr >> mwd->page_shift;

	begin_addr &= ADDR32_MASK(mwd->page_shift);
	end_addr &= ADDR32_MASK(mwd->page_shift);
	rv = elfc_read_pmem(pelf, pteaddr, pte,
			    pte_count * sizeof(uint32_t));
	if (rv == -1) {
		fprintf(stderr, "Unable to read page table entry at"
			" %llx: %s\n", (unsigned long long) pteaddr,
			strerror(elfc_get_errno(pelf)));
		return -1;
	}

	if (end < (pte_count - 1))
		pte_count = end + 1;

	for (i = start; i < pte_count; i++) {
		uint32_t lpte = mwd->conv32(&pte[i]);

		if (!(lpte & mwd->page_present_mask))
			continue;

		rv = handle_page(pelf,
				 lpte >> mwd->pfn_shift << mwd->page_shift,
				 vaddr | i << mwd->page_shift,
				 1 << mwd->page_shift, userdata);
		if (rv == -1)
			return -1;
	}
	return 0;
}

static int
handle_32pmd(struct elfc *pelf, const struct mips_walk_data *mwd,
	     GElf_Addr vaddr, GElf_Addr pmdaddr,
	     GElf_Addr begin_addr, GElf_Addr end_addr,
	     handle_page_f handle_page, void *userdata)
{
	uint32_t pmd[MAX_PGTAB_ENTRIES(sizeof(uint32_t))];
	int pmd_count = ENTRIES_PER_PGTAB(d, pmd, sizeof(uint32_t));
	int i;
	int rv;
	uint32_t start = begin_addr >> mwd->pmd_shift;
	uint32_t end = end_addr >> mwd->pmd_shift;

	begin_addr &= ADDR32_MASK(mwd->pmd_shift);
	end_addr &= ADDR32_MASK(mwd->pmd_shift);
	rv = elfc_read_pmem(pelf, pmdaddr, pmd,
			    pmd_count * sizeof(uint32_t));
	if (rv == -1) {
		fprintf(stderr, "Unable to read page middle directory at"
			" %llx: %s\n", (unsigned long long) pmdaddr,
			strerror(elfc_get_errno(pelf)));
		return -1;
	}

	if (end < (pmd_count - 1))
		pmd_count = end + 1;

	for (i = start; i < pmd_count; i++) {
		uint32_t lpmd = mwd->conv32(&pmd[i]);

		if (mips_virt_to_phys32(mwd, pmdaddr, i, lpmd, &lpmd) == -1)
			continue;

		rv = handle_32pte(pelf, mwd, vaddr | i << mwd->pmd_shift,
				  lpmd, begin_addr, end_addr,
				  handle_page, userdata);
		if (rv == -1)
			return -1;
	}
	return 0;
}

static int
walk_mips32(struct elfc *pelf, const struct mips_walk_data *mwd,
	    GElf_Addr pgdaddr,
	    GElf_Addr begin_addr, GElf_Addr end_addr,
	    handle_page_f handle_page, void *userdata)
{
	uint32_t pgd[MAX_PGTAB_ENTRIES(sizeof(uint32_t))];
	int pgd_count = ENTRIES_PER_PGTAB(d, pgd, sizeof(uint32_t));
	int i;
	int rv;
	GElf_Addr maxaddr;
	uint32_t dir_offset = mwd->PAGE_OFFSET - mwd->PHYS_OFFSET;
	uint32_t start, end;

	/*
	 * Add the direct mapping first.
	 */
	maxaddr = elfc_max_paddr(pelf);
	rv = scan_range(pelf, mwd, pgdaddr, dir_offset, &begin_addr, &end_addr,
			dir_offset, dir_offset + maxaddr - 1,
			handle_page, userdata, walk_mips32);
	if (rv == -1)
		return rv;
	if (rv == 1)
		return 0;

	rv = elfc_read_pmem(pelf, pgdaddr, pgd,
			    pgd_count * sizeof(uint32_t));
	if (rv == -1) {
		fprintf(stderr, "Unable to read page directory at"
			" %llx: %s\n", (unsigned long long) pgdaddr,
			strerror(elfc_get_errno(pelf)));
		return -1;
	}

	start = begin_addr >> mwd->pgd_shift;
	end = end_addr >> mwd->pgd_shift;
	begin_addr &= ADDR32_MASK(mwd->pgd_shift);
	end_addr &= ADDR32_MASK(mwd->pgd_shift);

	for (i = start; i <= end; i++) {
		uint32_t lpgd = mwd->conv32(&pgd[i]);

		if (mips_virt_to_phys32(mwd, pgdaddr, i, lpgd, &lpgd) == -1)
			continue;

		if (mwd->pmd_present)
			rv = handle_32pmd(pelf, mwd, i << mwd->pgd_shift,
					  lpgd, begin_addr, end_addr,
					  handle_page, userdata);
		else
			rv = handle_32pte(pelf, mwd, i << mwd->pgd_shift,
					  lpgd, begin_addr, end_addr,
					  handle_page, userdata);
		if (rv == -1)
			return -1;
	}
	return 0;
}

static int
mips_virt_to_phys64(const struct mips_walk_data *mwd,
		    GElf_Addr addr, int offset,
		    GElf_Addr vaddr, GElf_Addr *paddr)
{
	/* Convert to a physical address. */
	if (mwd->is_64bit) {
		if (mwd->mapped_kernel) {
			if ((vaddr >= mwd->_text) && (vaddr < mwd->_end)) {
				*paddr = vaddr - mwd->phys_to_kernel_offset;
				return 0;
			}
		}
		if (vaddr < mwd->CKSEG0) {
			*paddr = vaddr & 0x000000ffffffffffULL;
			return 0;
		}
		if (vaddr < mwd->CKSSEG) {
			*paddr = vaddr & 0x1fffffffULL;
			return 0;
		}

		fprintf(stderr, "Unknown virtual address type in "
			"table %llx:%d: %llx\n",
			(unsigned long long) addr, offset,
			(unsigned long long) vaddr);
		return -1;
	} else {
		*paddr = vaddr - mwd->PAGE_OFFSET + mwd->PHYS_OFFSET;
	}
	return 0;
}

static int
handle_64pte(struct elfc *pelf, const struct mips_walk_data *mwd,
	     GElf_Addr vaddr, GElf_Addr pteaddr,
	     GElf_Addr begin_addr, GElf_Addr end_addr,
	     handle_page_f handle_page, void *userdata)
{
	uint64_t pte[MAX_PGTAB_ENTRIES(sizeof(uint64_t))];
	int pte_count = ENTRIES_PER_PGTAB(d, pte, sizeof(uint64_t));
	int i;
	int rv;
	uint64_t start = begin_addr >> mwd->page_shift;
	uint64_t end = end_addr >> mwd->page_shift;

	begin_addr &= ADDR64_MASK(mwd->page_shift);
	end_addr &= ADDR64_MASK(mwd->page_shift);
	rv = elfc_read_pmem(pelf, pteaddr, pte,
			    pte_count * sizeof(uint64_t));
	if (rv == -1) {
		fprintf(stderr, "Unable to read page table entry at"
			" %llx: %s\n", (unsigned long long) pteaddr,
			strerror(elfc_get_errno(pelf)));
		return -1;
	}

	if (end < (pte_count - 1))
		pte_count = end + 1;

	for (i = start; i < pte_count; i++) {
		uint64_t lpte = mwd->conv64(&pte[i]);

		if (!(lpte & mwd->page_present_mask))
			continue;

		rv = handle_page(pelf,
				 lpte >> mwd->pfn_shift << mwd->page_shift,
				 vaddr | ((GElf_Addr) i) << mwd->page_shift,
				 1 << mwd->page_shift, userdata);
		if (rv == -1)
			return -1;
	}
	return 0;
}

static int
handle_64pmd(struct elfc *pelf, const struct mips_walk_data *mwd,
	     GElf_Addr vaddr, GElf_Addr pmdaddr,
	     GElf_Addr begin_addr, GElf_Addr end_addr,
	     handle_page_f handle_page, void *userdata)
{
	uint64_t pmd[MAX_PGTAB_ENTRIES(sizeof(uint64_t))];
	int pmd_count = ENTRIES_PER_PGTAB(d, pmd, sizeof(uint64_t));
	unsigned int i;
	int rv;
	uint64_t start = begin_addr >> mwd->pmd_shift;
	uint64_t end = end_addr >> mwd->pmd_shift;

	begin_addr &= ADDR64_MASK(mwd->pmd_shift);
	end_addr &= ADDR64_MASK(mwd->pmd_shift);

	rv = elfc_read_pmem(pelf, pmdaddr, pmd,
			    pmd_count * sizeof(uint64_t));
	if (rv == -1) {
		fprintf(stderr, "Unable to read page middle directory at"
			" %llx: %s\n", (unsigned long long) pmdaddr,
			strerror(elfc_get_errno(pelf)));
		return -1;
	}

	if (end < (pmd_count - 1))
		pmd_count = end + 1;

	for (i = start; i < pmd_count; i++) {
		GElf_Addr lpmd = mwd->conv64(&pmd[i]);

		if ((lpmd & mwd->_PAGE_HUGE) &&
		    (lpmd & mwd->page_present_mask)) {
			rv = handle_page(pelf,
				 lpmd >> mwd->pfn_shift << mwd->page_shift,
				 vaddr | ((GElf_Addr) i) << mwd->pmd_shift,
				 1 << mwd->pmd_shift, userdata);
			if (rv == -1)
				return -1;
		}
		if (mips_virt_to_phys64(mwd, pmdaddr, i, lpmd, &lpmd) == -1)
			continue;

		rv = handle_64pte(pelf, mwd,
				  vaddr | ((GElf_Addr) i) << mwd->pmd_shift,
				  lpmd, begin_addr, end_addr,
				  handle_page, userdata);
		if (rv == -1)
			return -1;
	}
	return 0;
}

static int
walk_mips64(struct elfc *pelf, const struct mips_walk_data *mwd,
	    GElf_Addr pgdaddr,
	    GElf_Addr begin_addr, GElf_Addr end_addr,
	    handle_page_f handle_page, void *userdata)
{
	uint64_t pgd[MAX_PGTAB_ENTRIES(sizeof(uint64_t))];
	int pgd_count = ENTRIES_PER_PGTAB(d, pgd, sizeof(uint64_t));
	unsigned int i;
	int rv;
	GElf_Addr maxaddr;
	uint64_t start, end;

	/*
	 * Add the default page tables for iomem and kernel.
	 * This is ioremap addresses and the kernel address space.
	 * MIPS uses hardwired TLBs for some of these, and some are
	 * intrinsic to processors.
	 */
	if (mwd->mapped_kernel) {
		rv = scan_range(pelf, mwd, pgdaddr, mwd->phys_to_kernel_offset,
				&begin_addr, &end_addr,
				mwd->_text, mwd->_end - 1,
				handle_page, userdata, walk_mips64);
		if (rv == -1)
			return rv;
		if (rv == 1)
			return 0;
	}

	maxaddr = elfc_max_paddr(pelf);
	rv = scan_range(pelf, mwd, pgdaddr, mwd->PAGE_OFFSET,
			&begin_addr, &end_addr,
			mwd->PAGE_OFFSET, mwd->PAGE_OFFSET + maxaddr - 1,
			handle_page, userdata, walk_mips64);
	if (rv == -1)
		return rv;
	if (rv == 1)
		return 0;

	if (maxaddr > 0x20000000)
		maxaddr = 0x20000000;
	rv = scan_range(pelf, mwd, pgdaddr,  mwd->CKSEG0,
			&begin_addr, &end_addr,
			mwd->CKSEG0, mwd->CKSEG0 + maxaddr - 1,
			handle_page, userdata, walk_mips64);
	if (rv == -1)
		return rv;
	if (rv == 1)
		return 0;

	/* Now do the page tables. */
	rv = elfc_read_pmem(pelf, pgdaddr, pgd,
			    pgd_count * sizeof(uint64_t));
	if (rv == -1) {
		fprintf(stderr, "Unable to read page directory at"
			" %llx: %s\n", (unsigned long long) pgdaddr,
			strerror(elfc_get_errno(pelf)));
		return -1;
	}

	start = begin_addr >> mwd->pgd_shift;
	end = end_addr >> mwd->pgd_shift;
	if (end < (pgd_count - 1))
		pgd_count = end + 1;

	for (i = start; i < pgd_count; i++) {
		GElf_Addr lpgd = mwd->conv64(&pgd[i]);

		if (mips_virt_to_phys64(mwd, pgdaddr, i, lpgd, &lpgd) == -1)
			continue;

		if (mwd->pmd_present)
			rv = handle_64pmd(pelf, mwd,
					  ((GElf_Addr) i) << mwd->pgd_shift,
					  lpgd, begin_addr, end_addr,
					  handle_page, userdata);
		else
			rv = handle_64pte(pelf, mwd,
					  ((GElf_Addr) i) << mwd->pgd_shift,
					  lpgd, begin_addr, end_addr,
					  handle_page, userdata);
		if (rv == -1)
			return -1;
	}
	return 0;
}

static int
mips_arch_setup(struct elfc *pelf, struct kdt_data *d, void **arch_data)
{
	struct mips_walk_data *mwd;
	struct vmcoreinfo_data vmci[VMCI_NUM_ELEMENTS + 1] = {
		VMCI_SIZE(list_head),
		VMCI_ADDRESS(_text),
		VMCI_ADDRESS(_end),
		VMCI_ADDRESS(_phys_to_kernel_offset),
		VMCI_ADDRESS(CKSEG0),
		VMCI_ADDRESS(CKSSEG),
		VMCI_ADDRESS(PAGE_OFFSET),
		VMCI_ADDRESS(PHYS_OFFSET),
		VMCI_ADDRESS(IO_BASE),
		VMCI_NUMBER(PMD_ORDER),
		VMCI_NUMBER(_PAGE_HUGE),
		VMCI_NUMBER(PAGE_SHIFT),
		VMCI_NUMBER(PGD_ORDER),
		VMCI_NUMBER(PTE_ORDER),
		VMCI_NUMBER(_PAGE_PRESENT),
		VMCI_NUMBER(_PFN_SHIFT)
	};
	int i;

	mwd = malloc(sizeof(*mwd));
	if (!mwd) {
		fprintf(stderr, "Out of memory allocating mips arch data\n");
		return -1;
	}
	memset(mwd, 0, sizeof(*mwd));

	handle_vminfo_notes(pelf, vmci);
	for (i = VREQ; vmci[i].name; i++) { 
		if (!vmci[i].found) {
			fprintf(stderr, "%s not present in input file notes, "
				"it is required for operation\n", vmci[i].name);
			return -1;
		}
	}

	mwd->page_shift = vmci[VMCI_NUMBER_PAGE_SHIFT].val;
	mwd->page_size = (1 << mwd->page_shift);
	mwd->pgd_order = vmci[VMCI_NUMBER_PGD_ORDER].val;
	mwd->pte_order = vmci[VMCI_NUMBER_PTE_ORDER].val;
	mwd->page_present_mask = vmci[VMCI_NUMBER__PAGE_PRESENT].val;
	mwd->pfn_shift = vmci[VMCI_NUMBER__PFN_SHIFT].val;
	mwd->_PAGE_HUGE = vmci[VMCI_NUMBER__PAGE_HUGE].val;/* Zero if not set */
	mwd->PAGE_OFFSET = vmci[VMCI_ADDRESS_PAGE_OFFSET].val;

	/*
	 * Don't get this from kdt_data, we may be called without
	 * kdt_data in the case that a lookup is being done on a virtual
	 * address and it fails.
	 */
	if (vmci[VMCI_SIZE_list_head].val == 8) {
		mwd->is_64bit = false;
	} else if (vmci[VMCI_SIZE_list_head].val == 16) {
		mwd->is_64bit = true;
	} else {
		fprintf(stderr, "Error: list_head size not valid: %llu\n",
			(unsigned long long) vmci[VMCI_SIZE_list_head].val);
		return -1;
	}

	mwd->pmd_present = vmci[VMCI_NUMBER_PMD_ORDER].found;
	mwd->pmd_order = vmci[VMCI_NUMBER_PMD_ORDER].val;

	if (mwd->pgd_order > MAX_ORDER) {
		fprintf(stderr, "pgd_order is %d, only 0 or 1 are supported.\n",
			mwd->pgd_order);
		return -1;
	}

	if (mwd->pmd_present && mwd->pmd_order > MAX_ORDER) {
		fprintf(stderr, "pmd_order is %d, only 0 or 1 are supported.\n",
			mwd->pmd_order);
		return -1;
	}

	if (mwd->pte_order > MAX_ORDER) {
		fprintf(stderr, "pte_order is %d, only 0 or 1 are supported.\n",
			mwd->pte_order);
		return -1;
	}

	if ((mwd->page_shift > MAX_SHIFT) || (mwd->page_shift < MIN_SHIFT)) {
		fprintf(stderr, "page_shift is %d, only %d-%d are supported.\n",
			mwd->page_shift, MIN_SHIFT, MAX_SHIFT);
		return -1;
	}

	mwd->page_mask = ~((uint64_t) (mwd->page_size - 1));

	mwd->conv32 = d->conv32;
	mwd->conv64 = d->conv64;

	if (mwd->is_64bit) {
		i = vmci[VMCI_ADDRESS__text].found +
			vmci[VMCI_ADDRESS__end].found +
			vmci[VMCI_ADDRESS__phys_to_kernel_offset].found;
		if (i != 0) {
			if (i != 3) {
				fprintf(stderr, "All of _text, _end, and"
					" phys_to_kernel_offset not present\n");
				return -1;
			}
			mwd->_text = vmci[VMCI_ADDRESS__text].val;
			mwd->_end = vmci[VMCI_ADDRESS__end].val;
			mwd->phys_to_kernel_offset =
				vmci[VMCI_ADDRESS__phys_to_kernel_offset].val;
			mwd->mapped_kernel = 1;
		} else
			mwd->mapped_kernel = 0;

		if (!vmci[VMCI_ADDRESS_CKSEG0].found) {
			fprintf(stderr, "CKSEG0 not present in core file\n");
			return -1;
		}
		mwd->CKSEG0 = vmci[VMCI_ADDRESS_CKSEG0].val;

		if (!vmci[VMCI_ADDRESS_CKSSEG].found) {
			fprintf(stderr, "CKSSEG not present in core file\n");
			return -1;
		}
		mwd->CKSSEG = vmci[VMCI_ADDRESS_CKSSEG].val;

		if (mwd->pmd_present) {
			mwd->pmd_shift = mwd->page_shift + 
				(mwd->pte_order ? 10 : 9);
			mwd->pgd_shift = mwd->pmd_shift +
				(mwd->pmd_order ? 10 : 9);
		} else {
			mwd->pgd_shift = mwd->page_shift +
				(mwd->pte_order ? 10 : 9);
		}
	} else {
		if (mwd->pmd_present) {
			mwd->pmd_shift = mwd->page_shift +
				(mwd->pte_order ? 11 : 10);
			mwd->pgd_shift = mwd->pmd_shift +
				(mwd->pmd_order ? 11 : 10);
		} else
			mwd->pgd_shift = mwd->page_shift +
				(mwd->pte_order ? 11 : 10);
		
		if (!vmci[VMCI_ADDRESS_PHYS_OFFSET].found) {
			fprintf(stderr,
				"PHYS_OFFSET not present in core file\n");
			return -1;
		}
		mwd->PHYS_OFFSET = vmci[VMCI_ADDRESS_PHYS_OFFSET].val;
	}

	if ((mwd->_PAGE_HUGE) && (d->page_size == 65536))
		d->section_size_bits = 29;
	else
		d->section_size_bits = 28;
	d->max_physmem_bits = 38;

	*arch_data = mwd;

	return 0;
}

static void
mips_arch_cleanup(void *arch_data)
{
	free(arch_data);
}

static int
mips_walk(struct elfc *pelf, GElf_Addr pgd,
	  GElf_Addr begin_addr, GElf_Addr end_addr, void *arch_data,
	  handle_page_f handle_page, void *userdata)
{
	const struct mips_walk_data *mwd = arch_data;
	int rv;

	printf("Walking using pgd %llx from %llx to %llx\n",
	       (unsigned long long) pgd,
	       (unsigned long long) begin_addr,
	       (unsigned long long) end_addr);
	if (mwd->is_64bit)
		rv = walk_mips64(pelf, mwd, pgd, begin_addr, end_addr,
				 handle_page, userdata);
	else
		rv = walk_mips32(pelf, mwd, pgd, begin_addr, end_addr,
				 handle_page, userdata);

	return rv;
}

/*
 * kexec doesn't add the virtual address to the PHDRs, at least for
 * MIPS64.  So we have to hack something.
 */
static int 
mips_vmem_to_pmem(struct elfc *elf, GElf_Addr vaddr, GElf_Addr *paddr,
		  void *arch_data)
{
	const struct mips_walk_data *mwd = arch_data;

	if (!mwd->is_64bit)
		return -1;
	if ((vaddr >= mwd->CKSEG0) && (vaddr < mwd->CKSEG0 + 0x20000000)) {
		*paddr = vaddr - mwd->CKSEG0;
		return 0;
	}
	return -1;
}

struct archinfo mips_arch = {
	.name = "mips",
	.elfmachine = EM_MIPS,
	.default_elfclass = ELFCLASS64,
	.setup_arch_pelf = mips_arch_setup,
	.cleanup_arch_data = mips_arch_cleanup,
	.walk_page_table = mips_walk,
	.vmem_to_pmem = mips_vmem_to_pmem
};
