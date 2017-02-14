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

/*
 * How MIPS memory is laid out in Linux
 *
 * Just a note: This is complicated.
 *
 * Unlike most other processors, MIPS does not have a hardware page table
 * loader.  Instead, software can load the TLBs directly, so a page fault
 * on a valid memory address requires some software to load the TLB before
 * the memory access can be done.  This means that a lot about the MIPS
 * system is flexible.  Linux makes extreme use of this flexibility,
 * there are all kinds of page table sizes and options.
 *
 * 64-bit
 *
 * Memory is divided into 8 sections:
 *
 *  XKUSEG 0x0000000000000000
 *    This is where userspace lives.
 *
 *  XKSSEG 0x4000000000000000
 *    I have no idea what this range does.
 *
 *  XKPHYS 0x8000000000000000
 *    This is a physical 1-1 map of memory.  This is done in hardware and
 *    no TLBs are required.  On Cavium processors this is the base, on
 *    other processors the map is in the area but at different locations.
 *    See CAC_BASE in the MIPS include files.
 *
 *  XKSEG  0xc000000000000000
 *    This is normally where vmalloc memory lives.  However, this depends
 *    on configuration.
 *
 *  CKSEG0 0xffffffff80000000
 *    The kernel and it's data normally go into this area.
 *
 *  CKSEG1 0xffffffffa0000000
 *    I think I/O lives in this area
 *
 *  CKSSEG 0xffffffffc0000000
 *    This is where module memory lives
 *
 *  CKSEG3 0xffffffffe0000000
 *    I can't find any use for this memory.
 *
 * The system actually has a separate page table for kernel and
 * userland.  The kernel page table is the page table owned by the
 * init task, although you can pick any kernel thread for this.  The
 * page table for a userland process only has userland pages.  The
 * page table refill routines will look at the memory address, if it's
 * less than XKSSEG, it uses the userland page tables, otherwise it
 * uses the kernel page tables.
 *
 * vmalloc memory is simply an overlay over the kernel page table.
 * The CKxxxx segments are also an overlay onto the kernel page
 * table, though they obviously start at CKSEG0.
 *
 * As an example, suppose we have a standard 4K page with a 40-bit
 * memory space. 0x000000ffffffffff is 40 bits.  This means that
 * 0xffffffffc0000000 and 0xc0000000c0000000 point to the same
 * physical page.
 *
 * Cavium has added support for a 48-bit memory space with
 * CONFIG_MIPS_VA_BITS_48.
 *
 * Page tables can be two, three, or four levels.  The four levels are:
 *   pgd (always present)
 *   pud (only present for 48 bit address spaces on 4k and 8k pages)
 *   pmd (present on everything but 64K pages without 48-bit address space)
 *   pte (always present)
 *
 * The xxx_order of a page table gives how many pages a level takes, as
 * a power of 2.  So 0 is 1 page, 1 is 2 pages, 2 is 4 pages, etc.
 * For instance, with 4K pages and pgd_order is 1, then the pgd will
 * take 8k of RAM (two pages) and have 1024 entries at that level
 * (each page table entry is 8 bytes).  With 1024 entries, this covers
 * 10 bits of address space.
 *
 * The xxx_shift of a page table give the number of bits below where
 * the page table is.  In our 4k page configuration with 40 bits and
 * pgd_order of 1, that means the number of bits below the pgd bits
 * is 30, so pgd_shift is 30.
 *
 * arch/mips/include/asm/pgtable-64.h has a lot more information on this.
 *
 * By default the maximum address space for a task is 40 bits.  This is
 * independent of the maximum bits the page tables can address, all
 * standard page tables can address 40 bits or more.  This limit is
 * set in arch/mips/include/processor.h, it's TASK_SIZE64.  With 48-bit
 * address space, this is increased to 48-bits and page table sizes
 * are adjusted appropriately.
 *
 * To use this, you take your address and chop off the bits above 40
 * (or 48).  Then you take your number, shift it to the right pgd_shift
 * bits, and use that to index the pgd, that entry in the pgd points
 * to the pud (4-level page table), pmd (3-level page table), or pte
 * (2-level page table).  If it's pud, then you remove the bits above
 * pgd_shift and shift it to the right pud_shift, which gives you the
 * pointer to the pmd entry.  And so forth, until you get to the pte,
 * which gives you the pointer to the actual page.
 *
 * 32-bit
 *
 * This is not tested, I don't have access to a 32-bit target, and it's
 * all theoretical at this point.
 */

#include "kdump-tool.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <endian.h>

#include "elfc.h"

#define ENTRIES_PER_PGTAB(mwd, type, pgtab_size)			\
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
	VMCI_ADDRESS_phys_to_kernel_offset,
	VMCI_ADDRESS_kernel_image_end,
	VMCI_ADDRESS_CKSEG0,
	VMCI_ADDRESS_CKSSEG,
	VMCI_ADDRESS_PHYS_OFFSET,
	VMCI_NUMBER_PMD_ORDER,
	VMCI_NUMBER_PUD_ORDER,
	VMCI_NUMBER__PAGE_HUGE,
	VMCI_NUMBER_TASK_SIZE64,
	VMCI_ADDRESS_IO_BASE,
	VMCI_ADDRESS_MAP_BASE,
	/* Begin required elements. */
#define VREQ	VMCI_NUMBER_PAGE_SHIFT
	VMCI_NUMBER_PAGE_SHIFT,
	VMCI_NUMBER_PGD_ORDER,
	VMCI_NUMBER_PTE_ORDER,
	VMCI_NUMBER__PAGE_PRESENT,
	VMCI_NUMBER__PFN_SHIFT,
	VMCI_ADDRESS_phys_pgd_ptr,
	VMCI_ADDRESS_PAGE_OFFSET,
	/* End actual elements. */
	VMCI_NUM_ELEMENTS
};

struct mips_walk_data {
	unsigned int page_shift;
	unsigned int page_size;
	unsigned int pgd_order;
	unsigned int pgd_shift;
	int pud_present;
	unsigned int pud_order;
	unsigned int pud_shift;
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
	uint64_t kernel_image_end;
	int mapped_kernel;

	uint64_t phys_pgd_ptr;

	uint64_t TASK_SIZE64;
	uint64_t _PAGE_HUGE;

	uint64_t CKSEG0;
	uint64_t CKSSEG;

	uint64_t PAGE_OFFSET;
	uint64_t PHYS_OFFSET;
	uint64_t IO_BASE;
	uint64_t MAP_BASE;
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

static int
addr_range_covered(GElf_Addr start, GElf_Addr end,
		   GElf_Addr r_start, GElf_Addr r_end)
{
	return (((start <= r_start) && (end > r_start)) ||
		((start <= r_end) && (end >= r_end)) ||
		((start >= r_start) && (end <= r_end)));
}

/*
 * Scan a defined range of memory from r_start to r_end.  If some or all of
 * the range from begin_addr to end_addr is in the defined range, call page
 * table handlers on it.  After done, adjust begin_addr and end_addr to
 * remove the range we just scanned, if necessary.
 *
 * Returns -1 on error, 0 if the caller should keep going, 1 if the caller
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
	int rv = 0;
	uint64_t start, end, addr;

	if (addr_range_covered(*begin_addr, *end_addr, r_start, r_end)) {
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
				goto out;
		}

		if ((*begin_addr >= r_start) && (*end_addr <= r_end)) {
			/* Region was completely inside text */
			rv = 1;
			goto out;
		} else if ((*begin_addr < r_start) && (*end_addr > r_end)) {
			/* Region overlaps, have to do two ranges. */
			rv = walk(pelf, mwd, pgdaddr,
				  *begin_addr, r_start - 1,
				  handle_page, userdata);
			if (rv != -1)
				rv = walk(pelf, mwd, pgdaddr,
					  r_end + 1, *end_addr,
					  handle_page, userdata);
			if (rv == -1)
				goto out;
			rv = 1;
			goto out;
		} else if (*begin_addr < r_start)
			*end_addr = r_start - 1;
		else if (*end_addr > r_end)
			*begin_addr = r_end + 1;
	}

out:
	return rv;
}

static int
handle_32pte(struct elfc *pelf, const struct mips_walk_data *mwd,
	     GElf_Addr vaddr, GElf_Addr pteaddr,
	     GElf_Addr begin_addr, GElf_Addr end_addr,
	     handle_page_f handle_page, void *userdata)
{
	uint32_t pte[MAX_PGTAB_ENTRIES(sizeof(uint32_t))];
	int pte_count = ENTRIES_PER_PGTAB(mwd, pte, sizeof(uint32_t));
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
	int pmd_count = ENTRIES_PER_PGTAB(mwd, pmd, sizeof(uint32_t));
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
	int pgd_count = ENTRIES_PER_PGTAB(mwd, pgd, sizeof(uint32_t));
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
	     GElf_Addr topbits, GElf_Addr vaddr, GElf_Addr pteaddr,
	     GElf_Addr begin_addr, GElf_Addr end_addr,
	     handle_page_f handle_page, void *userdata)
{
	uint64_t pte[MAX_PGTAB_ENTRIES(sizeof(uint64_t))];
	int pte_count = ENTRIES_PER_PGTAB(mwd, pte, sizeof(uint64_t));
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
			topbits | vaddr | ((GElf_Addr) i) << mwd->page_shift,
			1 << mwd->page_shift, userdata);
		if (rv == -1)
			return -1;
	}
	return 0;
}

static int
handle_64pmd(struct elfc *pelf, const struct mips_walk_data *mwd,
	     GElf_Addr topbits, GElf_Addr vaddr, GElf_Addr pmdaddr,
	     GElf_Addr begin_addr, GElf_Addr end_addr,
	     handle_page_f handle_page, void *userdata)
{
	uint64_t pmd[MAX_PGTAB_ENTRIES(sizeof(uint64_t))];
	int pmd_count = ENTRIES_PER_PGTAB(mwd, pmd, sizeof(uint64_t));
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
				(topbits | vaddr |
				 ((GElf_Addr) i) << mwd->pmd_shift),
				1 << mwd->pmd_shift, userdata);
			if (rv == -1)
				return -1;
		}
		if (mips_virt_to_phys64(mwd, pmdaddr, i, lpmd, &lpmd) == -1)
			continue;

		rv = handle_64pte(pelf, mwd, topbits,
				  vaddr | ((GElf_Addr) i) << mwd->pmd_shift,
				  lpmd, begin_addr, end_addr,
				  handle_page, userdata);
		if (rv == -1)
			return -1;
	}
	return 0;
}

static int
handle_64pud(struct elfc *pelf, const struct mips_walk_data *mwd,
	     GElf_Addr topbits, GElf_Addr vaddr, GElf_Addr pudaddr,
	     GElf_Addr begin_addr, GElf_Addr end_addr,
	     handle_page_f handle_page, void *userdata)
{
	uint64_t pud[MAX_PGTAB_ENTRIES(sizeof(uint64_t))];
	int pud_count = ENTRIES_PER_PGTAB(mwd, pud, sizeof(uint64_t));
	unsigned int i;
	int rv;
	uint64_t start = begin_addr >> mwd->pud_shift;
	uint64_t end = end_addr >> mwd->pud_shift;

	begin_addr &= ADDR64_MASK(mwd->pud_shift);
	end_addr &= ADDR64_MASK(mwd->pud_shift);

	rv = elfc_read_pmem(pelf, pudaddr, pud,
			    pud_count * sizeof(uint64_t));
	if (rv == -1) {
		fprintf(stderr, "Unable to read page middle directory at"
			" %llx: %s\n", (unsigned long long) pudaddr,
			strerror(elfc_get_errno(pelf)));
		return -1;
	}

	if (end < (pud_count - 1))
		pud_count = end + 1;

	for (i = start; i < pud_count; i++) {
		GElf_Addr lpud = mwd->conv64(&pud[i]);

		if (mips_virt_to_phys64(mwd, pudaddr, i, lpud, &lpud) == -1)
			continue;

		rv = handle_64pmd(pelf, mwd, topbits,
				  vaddr | ((GElf_Addr) i) << mwd->pud_shift,
				  lpud, begin_addr, end_addr,
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
	int pgd_count = ENTRIES_PER_PGTAB(mwd, pgd, sizeof(uint64_t));
	unsigned int i;
	int rv = 0;
	GElf_Addr maxaddr, topbits = 0, scan_start, scan_end;
	uint64_t start, end;

	if (pgdaddr != mwd->phys_pgd_ptr) {
		/*
		 * This is a request for a user page map, the user specified
		 * a page that wasn't the kernel's map.  So only do user
		 * addresses.
		 */
		if (addr_range_covered(begin_addr, end_addr, 0,
				       mwd->TASK_SIZE64 - 1)) {
			scan_start = 0;
			scan_end = mwd->TASK_SIZE64 - 1;
			goto page_scan_range;
		}
		return 0;
	}

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
		if (rv)
			goto out;
	}

	maxaddr = elfc_max_paddr(pelf);
	rv = scan_range(pelf, mwd, pgdaddr, mwd->PAGE_OFFSET,
			&begin_addr, &end_addr,
			mwd->PAGE_OFFSET, mwd->PAGE_OFFSET + maxaddr - 1,
			handle_page, userdata, walk_mips64);
	if (rv)
		goto out;

	if (maxaddr > 0x20000000)
		maxaddr = 0x20000000;
	rv = scan_range(pelf, mwd, pgdaddr,  mwd->CKSEG0,
			&begin_addr, &end_addr,
			mwd->CKSEG0, mwd->CKSEG0 + maxaddr - 1,
			handle_page, userdata, walk_mips64);
	if (rv)
		goto out;

	/* Now do the page tables. */
	rv = elfc_read_pmem(pelf, pgdaddr, pgd,
			    pgd_count * sizeof(uint64_t));
	if (rv == -1) {
		fprintf(stderr, "Unable to read page directory at"
			" %llx: %s\n", (unsigned long long) pgdaddr,
			strerror(elfc_get_errno(pelf)));
		goto out;
	}

	if (addr_range_covered(begin_addr, end_addr,
			       mwd->MAP_BASE,
			       mwd->MAP_BASE + mwd->TASK_SIZE64 - 1)) {
		scan_start = mwd->MAP_BASE;
		scan_end = mwd->MAP_BASE + mwd->TASK_SIZE64 - 1;
	} else if (addr_range_covered(begin_addr, end_addr,
				mwd->CKSEG0, mwd->CKSEG0 + 0x20000000 - 1)) {
		scan_start = mwd->CKSEG0;
		scan_end = mwd->CKSEG0 + 0x20000000 - 1;
	} else if (mwd->mapped_kernel &&
		   addr_range_covered(begin_addr, end_addr,
			   mwd->kernel_image_end,
			   (mwd->_text & ~(0x20000000 - 1)) + 0x20000000 - 1)) {
		scan_start = mwd->kernel_image_end;
		scan_end = (mwd->_text & ~(0x20000000 - 1)) + 0x20000000 - 1;
	} else if (addr_range_covered(begin_addr, end_addr,
				mwd->CKSSEG, mwd->CKSSEG + 0x20000000 - 1)) {
		scan_start = mwd->CKSSEG;
		scan_end = mwd->CKSSEG + 0x20000000 - 1;
	} else {
		return 0;
	}

page_scan_range:
	/*
	 * We only scan one range at a time, if we have areas outside
	 * the range we scan them separately.
	 */
	if (begin_addr < scan_start) {
		rv = walk_mips64(pelf, mwd, pgdaddr,
				 begin_addr, scan_start,
				 handle_page, userdata);
		begin_addr = scan_start;
	}
	if (end_addr > scan_end) {
		rv = walk_mips64(pelf, mwd, pgdaddr,
				 mwd->CKSSEG + 0x20000000, end_addr,
				 handle_page, userdata);
		end_addr = scan_end;
	}

	/*
	 * begin_addr and end_addr have to be in the same region, so
	 * topbits will be the same no matter which we choose.
	 */
	topbits = begin_addr & ~(mwd->TASK_SIZE64 - 1);
	start = begin_addr & (mwd->TASK_SIZE64 - 1);
	end = end_addr & (mwd->TASK_SIZE64 - 1);
	start >>= mwd->pgd_shift;
	end >>= mwd->pgd_shift;
	if (end < (pgd_count - 1))
		pgd_count = end + 1;

	begin_addr &= ADDR64_MASK(mwd->pgd_shift);
	end_addr &= ADDR64_MASK(mwd->pgd_shift);

	for (i = start; i < pgd_count; i++) {
		GElf_Addr lpgd = mwd->conv64(&pgd[i]);

		if (mips_virt_to_phys64(mwd, pgdaddr, i, lpgd, &lpgd) == -1)
			continue;

		if (mwd->pud_present)
			rv = handle_64pud(pelf, mwd, topbits,
					  ((GElf_Addr) i) << mwd->pgd_shift,
					  lpgd, begin_addr, end_addr,
					  handle_page, userdata);
		else if (mwd->pmd_present)
			rv = handle_64pmd(pelf, mwd, topbits,
					  ((GElf_Addr) i) << mwd->pgd_shift,
					  lpgd, begin_addr, end_addr,
					  handle_page, userdata);
		else
			rv = handle_64pte(pelf, mwd, topbits,
					  ((GElf_Addr) i) << mwd->pgd_shift,
					  lpgd, begin_addr, end_addr,
					  handle_page, userdata);
		if (rv == -1)
			goto out;
	}

out:
	if (rv == -1)
		return rv;
	if (rv == 1)
		return 0;
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
		VMCI_ADDRESS(phys_to_kernel_offset),
		VMCI_ADDRESS(kernel_image_end),
		VMCI_ADDRESS(CKSEG0),
		VMCI_ADDRESS(CKSSEG),
		VMCI_ADDRESS(PAGE_OFFSET),
		VMCI_ADDRESS(PHYS_OFFSET),
		VMCI_ADDRESS(IO_BASE),
		VMCI_ADDRESS(MAP_BASE),
		VMCI_NUMBER(PMD_ORDER),
		VMCI_NUMBER(PUD_ORDER),
		VMCI_NUMBER(TASK_SIZE64),
		VMCI_NUMBER(_PAGE_HUGE),
		VMCI_NUMBER(PAGE_SHIFT),
		VMCI_NUMBER(PGD_ORDER),
		VMCI_NUMBER(PTE_ORDER),
		VMCI_NUMBER(_PAGE_PRESENT),
		VMCI_NUMBER(_PFN_SHIFT),
		VMCI_ADDRESS(phys_pgd_ptr)
	};
	int i, base_shift;

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
	mwd->phys_pgd_ptr = vmci[VMCI_ADDRESS_phys_pgd_ptr].val;

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

	mwd->pud_present = vmci[VMCI_NUMBER_PUD_ORDER].found;
	mwd->pud_order = vmci[VMCI_NUMBER_PUD_ORDER].val;

	if (vmci[VMCI_NUMBER_TASK_SIZE64].found)
		mwd->TASK_SIZE64 = vmci[VMCI_NUMBER_TASK_SIZE64].val;
	else
		mwd->TASK_SIZE64 = (1ULL << 40);

	if (vmci[VMCI_ADDRESS_MAP_BASE].found)
		mwd->MAP_BASE = vmci[VMCI_ADDRESS_MAP_BASE].val;
	else
		mwd->MAP_BASE = 0xc000000000000000ULL;

	if (mwd->pgd_order > MAX_ORDER) {
		fprintf(stderr, "pgd_order is %d, max is %d.\n",
			mwd->pgd_order, MAX_ORDER);
		return -1;
	}

	if (mwd->pud_present && mwd->pud_order > MAX_ORDER) {
		fprintf(stderr, "pud_order is %d, max is %d.\n",
			mwd->pud_order, MAX_ORDER);
		return -1;
	}

	if (mwd->pmd_present && mwd->pmd_order > MAX_ORDER) {
		fprintf(stderr, "pmd_order is %d, max is %d.\n",
			mwd->pmd_order, MAX_ORDER);
		return -1;
	}

	if (mwd->pte_order > MAX_ORDER) {
		fprintf(stderr, "pte_order is %d, max is %d.\n",
			mwd->pte_order, MAX_ORDER);
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
			vmci[VMCI_ADDRESS_phys_to_kernel_offset].found;
		if (i != 0) {
			if (i != 3) {
				fprintf(stderr, "All of _text, _end, and"
					" phys_to_kernel_offset not present\n");
				return -1;
			}
			mwd->_text = vmci[VMCI_ADDRESS__text].val;
			mwd->_end = vmci[VMCI_ADDRESS__end].val;
			mwd->phys_to_kernel_offset =
				vmci[VMCI_ADDRESS_phys_to_kernel_offset].val;
			mwd->mapped_kernel = 1;

			/*
			 * For mapped kernels, kernel_image_end is where
			 * modules exist, in normal paged memory.
			 */
			if (vmci[VMCI_ADDRESS_kernel_image_end].found)
				mwd->kernel_image_end =
					vmci[VMCI_ADDRESS_kernel_image_end].val;
			else
				mwd->kernel_image_end =
					((mwd->_end & 0xffffffffff000000) +
					 0x1000000);
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

		base_shift = 9;
	} else {
		if (!vmci[VMCI_ADDRESS_PHYS_OFFSET].found) {
			fprintf(stderr,
				"PHYS_OFFSET not present in core file\n");
			return -1;
		}
		mwd->PHYS_OFFSET = vmci[VMCI_ADDRESS_PHYS_OFFSET].val;

		base_shift = 10;
	}

	if (mwd->pud_present) {
		mwd->pmd_shift = mwd->page_shift + base_shift + mwd->pte_order;
		mwd->pud_shift = mwd->pmd_shift + base_shift + mwd->pmd_order;
		mwd->pgd_shift = mwd->pud_shift + base_shift + mwd->pud_order;
	} else if (mwd->pmd_present) {
		mwd->pmd_shift = mwd->page_shift + base_shift + mwd->pte_order;
		mwd->pgd_shift = mwd->pmd_shift + base_shift + mwd->pmd_order;
	} else {
		mwd->pgd_shift = mwd->page_shift + base_shift + mwd->pte_order;
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
