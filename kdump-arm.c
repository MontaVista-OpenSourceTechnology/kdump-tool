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

#include "elfc.h"

struct arm_walk_data {
	struct elfc *pelf;
	int is_bigendian;
	uint32_t (*conv32)(uint32_t val);
};

static uint32_t convbe32toh(uint32_t val)
{
	return be32toh(val);
}
static uint32_t convle32toh(uint32_t val)
{
	return le32toh(val);
}

static int
handle_pte(struct arm_walk_data *d, GElf_Addr vaddr, GElf_Addr pteaddr,
	   handle_page_f handle_page, void *userdata)
{
	uint32_t pte[256];
	int i;
	int rv;

	rv = elfc_read_pmem(d->pelf, pteaddr, pte, sizeof(pte));
	if (rv == -1) {
		fprintf(stderr, "Unable to read page table entry at"
			" %llx: %s\n", (unsigned long long) pteaddr,
			strerror(elfc_get_errno(d->pelf)));
		return -1;
	}

	for (i = 0; i < 256; i++) {
		uint64_t lpte = d->conv32(pte[i]);

		switch (lpte & 0x3) {
		case 0:
			continue;
		case 1:
			/* 64k page */
			rv = handle_page(d->pelf, 
					 lpte & ~0xffff,
					 vaddr | i << 16,
					 1 << 16, userdata);
			if (rv == -1)
				return -1;
			i += 15; /* 16 duplicate page entries */
			break;
		case 2:
		case 3:
			/* 4k page */
			rv = handle_page(d->pelf, 
					 lpte & ~0xfff,
					 vaddr | i << 12,
					 1 << 12, userdata);
			if (rv == -1)
				return -1;
			break;
		}
	}
	return 0;
}

static int
arm_walk(struct elfc *pelf, GElf_Addr pgdaddr,
	  handle_page_f handle_page, void *userdata)
{
	uint32_t pgd[4096];
	struct arm_walk_data data, *d = &data;
	int i;
	int rv;

	rv = elfc_read_pmem(pelf, pgdaddr, pgd, sizeof(pgd));
	if (rv == -1) {
		fprintf(stderr, "Unable to read page table descriptors at"
			" %llx: %s\n", (unsigned long long) pgdaddr,
			strerror(elfc_get_errno(pelf)));
		return -1;
	}

	d->pelf = pelf;
	d->is_bigendian = elfc_getencoding(pelf) == ELFDATA2MSB;
	if (d->is_bigendian)
		d->conv32 = convbe32toh;
	else
		d->conv32 = convle32toh;

	for (i = 0; i < 4096; i++) {
		uint32_t lpgd = d->conv32(pgd[i]);

		switch (lpgd & 0x3) {
		case 0:
		case 3:
			/* Unused entry */
			continue;
		case 1:
			rv = handle_pte(d, i << 20, lpgd & ~0xff3,
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
					 i << 20,
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
	.walk_page_table = arm_walk
};
