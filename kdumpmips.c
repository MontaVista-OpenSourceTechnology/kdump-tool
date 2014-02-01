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
#include <endian.h>

#include "elfhnd.h"

#define ENTRIES_PER_PGTAB(d, pgtab_size) \
	((1 << d->pgd_order) * (1 << d->page_shift) / (pgtab_size))

#define MAX_SHIFT 16
#define MIN_SHIFT 12
#define MAX_ORDER 1
#define MAX_PGTAB_ENTRIES(pgentry_size) ((1 << MAX_SHIFT) * (1 << MAX_ORDER) / \
					 (pgentry_size))

static uint64_t convbe64toh(uint64_t val)
{
	return be64toh(val);
}
static uint64_t convle64toh(uint64_t val)
{
	return le64toh(val);
}
static uint32_t convbe32toh(uint32_t val)
{
	return be32toh(val);
}
static uint32_t convle32toh(uint32_t val)
{
	return le32toh(val);
}

struct mips_walk_data {
	struct elfc *pelf;
	unsigned int page_shift;
	unsigned int pgd_order;
	unsigned int pgd_shift;
	int pmd_present;
	unsigned int pmd_order;
	unsigned int pmd_shift;
	unsigned int pte_order;
	/* pte_shift is page_shift */
	uint64_t page_present_mask;
	int is_64bit;
	int is_bigendian;
	uint64_t (*conv64)(uint64_t val);
	uint32_t (*conv32)(uint32_t val);
	uint64_t page_mask;
};

static int
handle_32pte(struct mips_walk_data *d, GElf_Addr vaddr, GElf_Addr pteaddr,
	     handle_page_f handle_page, void *userdata)
{
	uint32_t pte[MAX_PGTAB_ENTRIES(sizeof(uint32_t))];
	int pte_count = ENTRIES_PER_PGTAB(d,  sizeof(uint32_t));
	int i;
	int rv;

	rv = elfc_read_pmem(d->pelf, pteaddr, pte,
			    pte_count * sizeof(uint32_t));
	if (rv == -1) {
		fprintf(stderr, "Unable to read page middle directory at"
			" %llx: %s\n", (unsigned long long) pteaddr,
			strerror(elfc_get_errno(d->pelf)));
		return -1;
	}

	for (i = 0; i < pte_count; i++) {
		uint32_t lpte = d->conv32(pte[i]);

		if (!(lpte & d->page_present_mask))
			continue;

		rv = handle_page(d->pelf,
				 lpte & d->page_mask,
				 vaddr | i << d->page_shift,
				 1 << d->page_shift, userdata);
		if (rv == -1)
			return -1;
	}
	return 0;
}

static int
handle_32pmd(struct mips_walk_data *d, GElf_Addr vaddr, GElf_Addr pmdaddr,
	     handle_page_f handle_page, void *userdata)
{
	uint32_t pmd[MAX_PGTAB_ENTRIES(sizeof(uint32_t))];
	int pmd_count = ENTRIES_PER_PGTAB(d,  sizeof(uint32_t));
	int i;
	int rv;

	rv = elfc_read_pmem(d->pelf, pmdaddr, pmd,
			    pmd_count * sizeof(uint32_t));
	if (rv == -1) {
		fprintf(stderr, "Unable to read page middle directory at"
			" %llx: %s\n", (unsigned long long) pmdaddr,
			strerror(elfc_get_errno(d->pelf)));
		return -1;
	}

	for (i = 0; i < pmd_count; i++) {
		uint32_t lpmd = d->conv32(pmd[i]);

		if (!(lpmd & d->page_present_mask))
			continue;

		rv = handle_32pte(d, vaddr | i << d->pmd_shift,
				  lpmd & d->page_mask,
				  handle_page, userdata);
		if (rv == -1)
			return -1;
	}
	return 0;
}

static int
walk_mips32(struct mips_walk_data *d, GElf_Addr pgdaddr,
	    handle_page_f handle_page, void *userdata)
{
	uint32_t pgd[MAX_PGTAB_ENTRIES(sizeof(uint32_t))];
	int pgd_count = ENTRIES_PER_PGTAB(d,  sizeof(uint32_t));
	int i;
	int rv;

	if (d->is_bigendian)
		d->conv32 = convbe32toh;
	else
		d->conv32 = convle32toh;

	if (d->pmd_present) {
		d->pmd_shift = d->page_shift + (d->pte_order ? 11 : 10);
		d->pgd_shift = d->pmd_shift + (d->pmd_order ? 11 : 10);
	} else
		d->pgd_shift = d->page_shift + (d->pte_order ? 11 : 10);

	rv = elfc_read_pmem(d->pelf, pgdaddr, pgd,
			    pgd_count * sizeof(uint32_t));
	if (rv == -1) {
		fprintf(stderr, "Unable to read page directory at"
			" %llx: %s\n", (unsigned long long) pgdaddr,
			strerror(elfc_get_errno(d->pelf)));
		return -1;
	}

	for (i = 0; i < pgd_count; i++) {
		uint32_t lpgd = d->conv32(pgd[i]);

		if (!(lpgd & d->page_present_mask))
			continue;

		if (d->pmd_present)
			rv = handle_32pmd(d, i << d->pgd_shift,
					  lpgd & d->page_mask,
					  handle_page, userdata);
		else
			rv = handle_32pte(d, i << d->pgd_shift,
					  lpgd & d->page_mask,
					  handle_page, userdata);
		if (rv == -1)
			return -1;
	}
	return 0;
}

static int
handle_64pte(struct mips_walk_data *d, GElf_Addr vaddr, GElf_Addr pteaddr,
	     handle_page_f handle_page, void *userdata)
{
	uint64_t pte[MAX_PGTAB_ENTRIES(sizeof(uint64_t))];
	int pte_count = ENTRIES_PER_PGTAB(d,  sizeof(uint64_t));
	int i;
	int rv;

	rv = elfc_read_pmem(d->pelf, pteaddr, pte,
			    pte_count * sizeof(uint64_t));
	if (rv == -1) {
		fprintf(stderr, "Unable to read page middle directory at"
			" %llx: %s\n", (unsigned long long) pteaddr,
			strerror(elfc_get_errno(d->pelf)));
		return -1;
	}

	for (i = 0; i < pte_count; i++) {
		uint64_t lpte = d->conv64(pte[i]);

		if (!(lpte & d->page_present_mask))
			continue;

		rv = handle_page(d->pelf,
				 lpte & d->page_mask,
				 vaddr | i << d->page_shift,
				 1 << d->page_shift, userdata);
		if (rv == -1)
			return -1;
	}
	return 0;
}

static int
handle_64pmd(struct mips_walk_data *d, GElf_Addr vaddr, GElf_Addr pmdaddr,
	     handle_page_f handle_page, void *userdata)
{
	uint64_t pmd[MAX_PGTAB_ENTRIES(sizeof(uint64_t))];
	int pmd_count = ENTRIES_PER_PGTAB(d,  sizeof(uint64_t));
	int i;
	int rv;

	rv = elfc_read_pmem(d->pelf, pmdaddr, pmd,
			    pmd_count * sizeof(uint64_t));
	if (rv == -1) {
		fprintf(stderr, "Unable to read page middle directory at"
			" %llx: %s\n", (unsigned long long) pmdaddr,
			strerror(elfc_get_errno(d->pelf)));
		return -1;
	}

	for (i = 0; i < pmd_count; i++) {
		uint64_t lpmd = d->conv64(pmd[i]);

		if (!(lpmd & d->page_present_mask))
			continue;

		rv = handle_64pte(d, vaddr | i << d->pmd_shift,
				  lpmd & d->page_mask,
				  handle_page, userdata);
		if (rv == -1)
			return -1;
	}
	return 0;
}

static int
walk_mips64(struct mips_walk_data *d, GElf_Addr pgdaddr,
	    handle_page_f handle_page, void *userdata)
{
	uint64_t pgd[MAX_PGTAB_ENTRIES(sizeof(uint64_t))];
	int pgd_count = ENTRIES_PER_PGTAB(d,  sizeof(uint64_t));
	int i;
	int rv;

	if (d->is_bigendian)
		d->conv64 = convbe64toh;
	else
		d->conv64 = convle64toh;

	if (d->pmd_present) {
		d->pmd_shift = d->page_shift + (d->pte_order ? 10 : 9);
		d->pgd_shift = d->pmd_shift + (d->pmd_order ? 10 : 9);
	} else {
		d->pgd_shift = d->page_shift + (d->pte_order ? 10 : 9);
	}

	rv = elfc_read_pmem(d->pelf, pgdaddr, pgd,
			    pgd_count * sizeof(uint64_t));
	if (rv == -1) {
		fprintf(stderr, "Unable to read page directory at"
			" %llx: %s\n", (unsigned long long) pgdaddr,
			strerror(elfc_get_errno(d->pelf)));
		return -1;
	}

	for (i = 0; i < pgd_count; i++) {
		uint64_t lpgd = d->conv64(pgd[i]);

		if (!(lpgd & d->page_present_mask))
			continue;

		if (d->pmd_present)
			rv = handle_64pmd(d, i << d->pgd_shift,
					  lpgd & d->page_mask,
					  handle_page, userdata);
		else
			rv = handle_64pte(d, i << d->pgd_shift,
					  lpgd & d->page_mask,
					  handle_page, userdata);
		if (rv == -1)
			return -1;
	}
	return 0;
}

static int
mips_walk(struct elfc *pelf, GElf_Addr pgd,
	  handle_page_f handle_page, void *userdata)
{
	struct mips_walk_data ds, *d = &ds;
	int i;
	int rv;
	struct vmcoreinfo_data vmci[] = {
		{ "NUMBER(PMD_ORDER)=", 10 }, /* Optional */
		{ "NUMBER(PAGE_SHIFT)=", 10 },
		{ "NUMBER(PGD_ORDER)=", 10 },
		{ "NUMBER(PTE_ORDER)=", 10 },
		{ "NUMBER(_PAGE_PRESENT)=", 10 },
		{ NULL }
	};

	handle_vminfo_notes(pelf, vmci);
	for (i = 1; vmci[i].name; i++) { 
		if (!vmci[i].found) {
			fprintf(stderr, "%s not present in input file notes, "
				"it is required for operation\n", vmci[i].name);
			return -1;
		}
	}

	d->pelf = pelf;
	d->page_shift = vmci[1].val;
	d->pgd_order = vmci[2].val;
	d->pmd_present = vmci[0].found;
	d->pmd_order = vmci[0].val;
	d->pte_order = vmci[3].val;
	d->page_present_mask = vmci[4].val;
	d->is_64bit = elfc_getclass(pelf) == ELFCLASS64;
	d->is_bigendian = elfc_getencoding(pelf) == ELFDATA2MSB;

	if (d->pgd_order > MAX_ORDER) {
		fprintf(stderr, "pgd_order is %d, only 0 or 1 are supported.",
			d->pgd_order);
		return -1;
	}

	if (d->pmd_present && d->pmd_order > MAX_ORDER) {
		fprintf(stderr, "pmd_order is %d, only 0 or 1 are supported.",
			d->pmd_order);
		return -1;
	}

	if (d->pte_order > MAX_ORDER) {
		fprintf(stderr, "pte_order is %d, only 0 or 1 are supported.",
			d->pte_order);
		return -1;
	}

	if ((d->page_shift > MAX_SHIFT) || (d->page_shift < MIN_SHIFT)) {
		fprintf(stderr, "page_shift is %d, only %d-%d are supported.",
			d->page_shift, MIN_SHIFT, MAX_SHIFT);
		return -1;
	}

	d->page_mask = ~((uint64_t) (1 << d->page_shift) - 1);

	if (d->is_64bit)
		rv = walk_mips64(d, pgd, handle_page, userdata);
	else
		rv = walk_mips32(d, pgd, handle_page, userdata);

	return rv;
}

struct archinfo mips_arch = {
	.name = "mips",
	.elfmachine = EM_MIPS,
	.walk_page_table = mips_walk
};
