/*
 * kdump-tool.c
 *
 * Tool for extracting and handling coredumps
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

/* Must be first */
#include "kdump-tool.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <gelf.h>
#include <stdarg.h>

#include "list.h"
#include "elfc.h"

const char *progname;
const char *subcmd;

int debug;

#define dpr(...) \
	do {					\
		if (debug)			\
			printf(__VA_ARGS__);	\
	} while(0)

void pr_err(const char *fmt, ...)
{
	va_list ap;
	FILE *out = stderr;

	va_start(ap, fmt);
	if (debug) /* Make error and debug output align in stdout. */
		out = stdout;
	vfprintf(out, fmt, ap);
	va_end(ap);
}

void
subcmd_usage(const char *error, ...)
{
	va_list ap;

	va_start(ap, error);
	fprintf(stderr, "%s %s: ", progname, subcmd);
	vfprintf(stderr, error, ap);
	va_end(ap);
	fprintf(stderr, "Use --help for usage information\n");
	exit(1);
}

void
subcmd_help(const char *extra, const struct option *longopts,
	    const char *helpstr[])
{
	int i;

	printf("Usage: %s %s [options]%s\n", progname, subcmd, extra);
	printf("Options are:\n");
	for (i = 0; longopts[i].name; i++)
		printf("  [-%c | --%s]: %s\n", longopts[i].val,
		       longopts[i].name, helpstr[i]);
	for (; helpstr[i]; i++)
		printf("%s\n", helpstr[i]);
}

static uint64_t convbe64toh(void *in)
{
	return be64toh(*((uint64_t *) in));
}
static uint64_t convle64toh(void *in)
{
	return le64toh(*((uint64_t *) in));
}
static uint32_t convbe32toh(void *in)
{
	return be32toh(*((uint32_t *) in));
}
static uint32_t convle32toh(void *in)
{
	return le32toh(*((uint32_t *) in));
}
static void convhtobe64(void *out, uint64_t val)
{
	*((uint64_t *) out) = htobe64(val);
}
static void convhtole64(void *out, uint64_t val)
{
	*((uint64_t *) out) = htole64(val);
}
static void convhtobe32(void *out, uint32_t val)
{
	*((uint32_t *) out) = htobe32(val);
}
static void convhtole32(void *out, uint32_t val)
{
	*((uint32_t *) out) = htole32(val);
}

static int
process_levels(char *levelstr)
{
	if (strcmp(levelstr, "all") == 0)
		return DUMP_ALL;
	else if (strcmp(levelstr, "inuse") == 0)
		return DUMP_INUSE;
	else if (strcmp(levelstr, "user") == 0)
		return DUMP_USER;
	else if (strcmp(levelstr, "cache") == 0)
		return DUMP_CACHE;
	else if (strcmp(levelstr, "kernel") == 0)
		return DUMP_KERNEL;
	else
		return -1;
}

static unsigned int
val_to_shift(uint64_t val)
{
	unsigned int shift = 0;
	if (!val)
		return 0;
	while (!(val & 1)) {
		shift++;
		val >>= 1;
	}
	return shift;
}

enum base_vmci {
	VMCI_ADDRESS_phys_pgd_ptr,
	VMCI_SIZE_list_head,
	VMCI_OFFSET_list_head__next,
	VMCI_OFFSET_list_head__prev,
	VMCI_SYMBOL__stext,
	VMCI_PAGESIZE
};

#define _VMCI_CHECK_FOUND(vmci, fullname)				\
	({if (!vmci[VMCI_ ## fullname].found) {		\
		pr_err("Error: %s not in vmcore\n", #fullname); \
		return -1;						      \
	}})
#define VMCI_CHECK_FOUND(vmci, type, name)				\
	_VMCI_CHECK_FOUND(vmci, type ## _ ## name)

int process_base_vmci(struct kdt_data *d, struct vmcoreinfo_data *vmci,
		      struct elfc *elf)
{
	int rv;

	VMCI_CHECK_FOUND(vmci, SYMBOL, _stext);

	VMCI_CHECK_FOUND(vmci, SIZE, list_head);
	d->list_head_size = vmci[VMCI_SIZE_list_head].val;
	if (d->list_head_size == 8) {
		d->is_64bit = false;
		d->ptrsize = 4;
	} else if (d->list_head_size == 16) {
		d->is_64bit = true;
		d->ptrsize = 8;
	} else {
		pr_err("Error: list_head size not valid: %llu\n",
			(unsigned long long) vmci[VMCI_SIZE_list_head].val);
		return -1;
	}
	VMCI_CHECK_FOUND(vmci, OFFSET, list_head__next);
	d->list_head_next_offset = vmci[VMCI_OFFSET_list_head__next].val;
	VMCI_CHECK_FOUND(vmci, OFFSET, list_head__prev);
	d->list_head_prev_offset = vmci[VMCI_OFFSET_list_head__prev].val;

	_VMCI_CHECK_FOUND(vmci, PAGESIZE);
	d->page_size = vmci[VMCI_PAGESIZE].val;
	d->page_shift = val_to_shift(d->page_size);

	d->is_bigendian = elfc_getencoding(d->elf) == ELFDATA2MSB;
	if (d->is_bigendian) {
		d->conv32 = convbe32toh;
		d->conv64 = convbe64toh;
		d->store32 = convhtobe32;
		d->store64 = convhtobe64;
	} else {
		d->conv32 = convle32toh;
		d->conv64 = convle64toh;
		d->store32 = convhtole32;
		d->store64 = convhtole64;
	}

	d->arch = find_arch(elfc_getmachine(elf));
	if (!d->arch) {
		pr_err("Unknown ELF machine in input file: %d\n",
			elfc_getmachine(elf));
		return -1;
	}

	if (d->arch->setup_arch_pelf) {
		rv = d->arch->setup_arch_pelf(elf, d, &d->arch_data);
		if (rv == -1)
			return -1;
	}

	return 0;
}

int parse_memrange(const char *str, uint64_t *start, uint64_t *size)
{
	const char *c;
	char *end;

	for (c = str; *c && (*c != '@') && (*c != '\n'); c++)
		;
	if (*c != '@')
		return -1;

	*size = strtoull(str, &end, 16);
	if (*end != '@')
		return -1;

	*start = strtoull(c + 1, &end, 16);
	if ((*end != '\n') && (*end != '\0'))
		return -1;

	return 0;
}

typedef int (*vminfo_item_handler)(const char *name, int namelen,
				   const char *val, int vallen,
				   void *userdata);

static int
handle_vmcoreinfo(const char *data, size_t len,
		  vminfo_item_handler handler, void *userdata)
{
	size_t off = 0;

	while (off < len) {
		size_t next_off = off;
		int eqsign = -1;

		if (*(data + next_off) == '\0')
			break;
		while (next_off < len) {
			if (*(data + next_off) == '\n')
				break;
			if (*(data + next_off) == '\0')
				break;
			if ((eqsign == -1) && (*(data + next_off) == '='))
				eqsign = next_off;
			next_off++;
		}
		if (eqsign == -1)
			return -1;
		/*
		 * This is to ensure that the strtoull() will not go
		 * past the end of the data.  Require that the string
		 * end in \n or \0.
		 */
		if (next_off >= len) {
			size_t neqsign = eqsign - off;
			size_t nlen = next_off - off + 1;
			char *ndata = malloc(nlen);
			if (!ndata) {
				pr_err("Out of memory\n");
				return -1;
			}
			memcpy(ndata, data + off, nlen);
			ndata[nlen] = '\0';
			handler(ndata, neqsign,
				ndata + neqsign + 1, nlen - eqsign - 1,
				userdata);
			free(ndata);
		} else {
			if (*(data + next_off) != '\0')
				next_off++;
			handler(data + off, eqsign - off,
				data + eqsign + 1, next_off - eqsign - 1,
				userdata);
		}
		off = next_off;
	}
	return 0;
}

static int
scan_for_vminfo_notes(struct elfc *elf,
		      vminfo_item_handler handler, void *userdata)
{
	int rv = 0;
	int i;
	int nr_notes = elfc_get_num_notes(elf);

	if (nr_notes == -1)
		return -1;

	for (i = 0; i < nr_notes; i++) {
		const char *name;
		const void *data;
		size_t datalen;
		GElf_Word type;
		int rv = elfc_get_note(elf, i, &type, &name, NULL,
				       &data, &datalen);
		if (rv == -1)
			return -1;

		if (strcmp(name, "VMCOREINFO") != 0)
			continue;

		rv = handle_vmcoreinfo(data, datalen, handler, userdata);
		if (rv == -1)
			return -1;
	}

	return rv;
}

struct vmcore_finder_data {
	int (*handler)(const char *name, const char *str, int strlen,
		       void *userdata);
	const char *name;
	void *userdata;
	int namelen;
};

static int
vmcoreinfo_scanner(const char *nameptr, int namelen,
		   const char *valptr, int vallen,
		   void *userdata)
{
	struct vmcoreinfo_data *vals = userdata;
	int i;

	for (i = 0; vals[i].name; i++) {
		char *name = vals[i].name;
		int namesize = strlen(name);
		uint64_t val;
		char *end;

		if (namelen != namesize)
			continue;
		if (strncmp(name, nameptr, namelen) != 0)
			continue;
		if (vals[i].found)
			/*
			 * Only handle the first one, so extra_vminfo
			 * overrides.
			 */
			continue;

		if (vals[i].base == VMINFO_YN_BASE) {
			if (*valptr == 'y')
				val = 1;
			else
				val = 0;
		} else {
			val = strtoull(valptr, &end, vals[i].base);
			if ((*end != '\n') && (*end != '\0'))
				continue;
		}

		vals[i].val = val;
		vals[i].found = 1;
	}
	return 0;
}

int
handle_vminfo_notes(struct elfc *elf, struct vmcoreinfo_data *vals,
		    char *extra_vminfo)
{
	int rv;
	int extra_vminfo_len = 0;

	if (extra_vminfo)
		extra_vminfo_len = strlen(extra_vminfo);
	rv = handle_vmcoreinfo(extra_vminfo, extra_vminfo_len,
			       vmcoreinfo_scanner, vals);
	if (rv == -1)
		return rv;
	return scan_for_vminfo_notes(elf, vmcoreinfo_scanner, vals);
}

int
copy_elf_notes(struct elfc *out, struct elfc *in,
	       int (*fixup)(GElf_Word type, const char *name, size_t namelen,
			    void *data, size_t data_len, void *userdata),
	       void *userdata)
{
	int i;
	int nr_notes = elfc_get_num_notes(in);

	if (nr_notes == -1)
		return -1;

	for (i = 0; i < nr_notes; i++) {
		const char *name;
		const void *rdata;
		void *data = NULL;
		size_t namelen, datalen;
		GElf_Word type;
		int rv = elfc_get_note(in, i, &type, &name, &namelen,
				       &rdata, &datalen);

		if (rv == -1)
			return -1;

		if (fixup) {
			/*
			 * Data may need to be modified, so we need
			 * our own memory for that.
			 */
			data = malloc(datalen);
			if (!data) {
				pr_err("Out of memory getting note"
					" data\n");
				return -1;
			}
			memcpy(data, rdata, datalen);

			rv = fixup(type, name, namelen, data, datalen,
				   userdata);
			if (rv)
				goto out_err;
			rdata = data;
		}
		rv = elfc_add_note(out, type, name, namelen, rdata, datalen);
		if (data)
			free(data);
		if (rv == -1)
			goto out_err;
		continue;
	out_err:
		if (data)
			free(data);
		return -1;
	}
	return 0;
}

static struct page_range *
find_pfn_range(struct kdt_data *d, uint64_t pfn)
{
	struct page_range *range;

	list_for_each_item(&d->page_maps, range, struct page_range, link) {
		if ((pfn >= range->start_page) &&
		    (pfn < range->start_page + range->nr_pages))
			return range;
	}
	return NULL;
}

static struct page_range *
find_page_addr_range(struct kdt_data *d, GElf_Addr addr)
{
	struct page_range *range;

	list_for_each_item(&d->page_maps, range, struct page_range, link) {
		if ((addr >= range->mapaddr) &&
		    (addr < range->mapaddr + (d->size_page * range->nr_pages)))
			return range;
	}
	return NULL;
}

/*
 * Given a page's "struct page" address, mark it skipped.
 */
static int
page_addr_mark_skipped(struct kdt_data *d, GElf_Addr addr, unsigned int count)
{
	struct page_range *range;
	uint64_t pfno;
	int dummy1;
	GElf_Off dummy2;
	GElf_Addr paddr;

	range = find_page_addr_range(d, addr);
	if (!range)
		return -1;

	pfno = (addr - range->mapaddr) / d->size_page;
	paddr = (pfno + range->start_page) << d->page_shift;

	dpr("Marking skipped: paddr %llx, page %llu (%d pages)\n",
	    (unsigned long long) paddr,
	    (unsigned long long) (pfno + range->start_page),
	    count);
	while (count) {
		if (pfno >= range->nr_pages) {
			pr_err("Page free maps are insane: "
				"pfno=%lld nr_pages=%lld\n",
				(unsigned long long) pfno,
				(unsigned long long) range->nr_pages);
			return -1;
		}
		if (elfc_pmem_offset(d->elf, paddr, d->page_size,
				     &dummy1, &dummy2) != -1)
			range->bitmap[pfno / 8] |= (1 << (pfno % 8));
		pfno++;
		count--;
		paddr += d->page_size;
	}
	return 0;
}

static void
set_pfn_skipped(struct kdt_data *d, struct page_range *range, uint64_t pfn)
{
	dpr("Marking skipped: page %llu\n", (unsigned long long) pfn);
	pfn -= range->start_page;
	range->bitmap[pfn / 8] |= 1 << (pfn % 8);
}

static bool
is_pfn_skipped(struct kdt_data *d, struct page_range *range, uint64_t pfn)
{
	pfn -= range->start_page;
	return (range->bitmap[pfn / 8] & (1 << (pfn % 8)));
}

struct vfetchinfo {
	unsigned char *out;
	GElf_Addr addr;
	unsigned int len;
};

static int
vfetch_page_handler(struct elfc *elf,
		    GElf_Addr paddr,
		    GElf_Addr vaddr,
		    GElf_Addr pgsize,
		    void *userdata)
{
	struct vfetchinfo *vfd = userdata;
	GElf_Addr offset = vfd->addr - vaddr;
	unsigned int len = vfd->len;
	int rv;

	if ((offset + len) > pgsize)
		len = pgsize - offset;

	rv = elfc_read_pmem(elf, paddr + offset, vfd->out, len);
	if (rv) {
		pr_err("Error reading physical memory at %llx: %s\n",
			(unsigned long long) paddr + offset,
			strerror(elfc_get_errno(elf)));
		return -1;
	}
	vfd->out += len;
	vfd->len -= len;
	vfd->addr += len;
	return 0;
}

/*
 * Fetch data from a virtual address using page tables, not elf header
 * virtual addresses.
 */
static int
fetch_vaddr_data(struct kdt_data *d,
		 GElf_Addr addr, unsigned int len, void *out)
{
	struct vfetchinfo vfd;
	int rv;

	vfd.out = out;
	vfd.addr = addr;
	vfd.len = len;
	rv = d->arch->walk_page_table(d->elf, d->pgd, addr, addr + len - 1,
				      d->arch_data, vfetch_page_handler,
				      &vfd);
	if (rv)
		return rv;
	if (vfd.len != 0)
		return -1;
	return 0;
}

int
fetch_vaddr_data_err(struct kdt_data *d,
		     GElf_Addr addr, unsigned int len, void *out, char *name)
{
	int rv = fetch_vaddr_data(d, addr, len, out);

	if (rv && name)
		pr_err("Error fetching %s at %llx len %u\n", name, addr, len);

	return rv;
}

int
fetch_vaddr32(struct kdt_data *d, GElf_Addr addr, uint32_t *out, char *name)
{
	uint32_t val;
	int rv;

	rv = fetch_vaddr_data_err(d, addr, sizeof(val), &val, name);
	if (rv)
		return rv;
	*out = d->conv32(&val);
	return 0;
}

int
fetch_vaddr64(struct kdt_data *d, GElf_Addr addr, uint64_t *out, char *name)
{
	uint64_t val;
	int rv;

	rv = fetch_vaddr_data_err(d, addr, sizeof(val), &val, name);
	if (rv)
		return rv;
	*out = d->conv64(&val);
	return 0;
}

int
fetch_vaddrlong(struct kdt_data *d, GElf_Addr addr, uint64_t *out, char *name)
{
	int rv;

	if (d->is_64bit) {
		uint64_t val = 0;
		rv = fetch_vaddr64(d, addr, &val, name);
		if (rv == 0)
			*out = val;
	} else {
		uint32_t val = 0;
		rv = fetch_vaddr32(d, addr, &val, name);
		if (rv == 0)
			*out = val;
	}

	return rv;
}

static int
fetch_struct32(struct kdt_data *d,
	       unsigned char *data, unsigned int data_size,
	       uint32_t offset, uint32_t *out,
	       char *name)
{
	if (data_size < offset + 4) {
		pr_err("Data item %s outside of structure\n", name);
		return -1;
	}

	*out = d->conv32(data + offset);
	return 0;
}

static int
fetch_struct64(struct kdt_data *d,
	       unsigned char *data, unsigned int data_size,
	       uint32_t offset, uint64_t *out,
	       char *name)
{
	if (data_size < offset + 8) {
		pr_err("Data item %s outside of structure\n", name);
		return -1;
	}

	*out = d->conv64(data + offset);
	return 0;
}

static int
fetch_structlong(struct kdt_data *d,
		 unsigned char *data, unsigned int data_size,
		 uint32_t offset, uint64_t *out,
		 char *name)
{
	int rv;

	if (d->is_64bit) {
		uint64_t val = 0;
		rv = fetch_struct64(d, data, data_size, offset, &val, name);
		if (rv == 0)
			*out = val;
	} else {
		uint32_t val = 0;
		rv = fetch_struct32(d, data, data_size, offset, &val, name);
		if (rv == 0)
			*out = val;
	}

	return rv;
}

static int
find_page_by_pfn(struct kdt_data *d, struct page_range *range, uint64_t pfn,
		 struct page_info *page)
{
	int rv;
	GElf_Addr offset;

	if (!range)
		return -1;

	offset = range->mapaddr + ((pfn - range->start_page) * d->size_page);
	rv = fetch_vaddr_data(d, offset, d->size_page, d->pagedata);
	if (rv == -1)
		goto out_err;

	rv = fetch_structlong(d, d->pagedata, d->size_page,
			      d->page_flags_offset,
			      &page->flags, "page.flags");
	if (rv == -1)
		goto out_err;
	rv = fetch_struct32(d, d->pagedata, d->size_page,
			    d->page_count_offset,
			    &page->count, "page.count");
	if (rv == -1)
		goto out_err;
	rv = fetch_structlong(d, d->pagedata, d->size_page,
			      d->page_mapping_offset,
			      &page->mapping, "page.mapping");
	if (rv == -1)
		goto out_err;
	rv = fetch_structlong(d, d->pagedata, d->size_page,
			      d->page_lru_offset,
			      &(page->lru[0]), "page.lru.next");
	if (rv == -1)
		goto out_err;
	rv = fetch_structlong(d, d->pagedata, d->size_page,
			      d->page_lru_offset + d->ptrsize,
			      &(page->lru[1]), "page.lru.prev");
	if (rv == -1)
		goto out_err;
	rv = fetch_struct32(d, d->pagedata, d->size_page,
			    d->page_mapcount_offset,
			    &page->mapcount, "page.mapcount");
	if (rv == -1)
		goto out_err;
	rv = fetch_structlong(d, d->pagedata, d->size_page,
			      d->page_private_offset,
			      &page->private, "page.private");
	if (rv == -1)
		goto out_err;
out_err:
	return rv;
}

enum page_map_vmci {
	VMCI_SYMBOL_mem_map,
	VMCI_SYMBOL_contig_page_data,
	VMCI_SYMBOL_mem_section,
	VMCI_LENGTH_mem_section,
	VMCI_SIZE_mem_section,
	VMCI_OFFSET_mem_section__section_mem_map,
	VMCI_SIZE_page,
	VMCI_OFFSET_page__flags,
	VMCI_OFFSET_page___count,
	VMCI_OFFSET_page__mapping,
	VMCI_OFFSET_page__lru,
	VMCI_OFFSET_page___mapcount,
	VMCI_OFFSET_page__private,
	VMCI_NUMBER_PAGE_BUDDY_MAPCOUNT_VALUE,
	VMCI_NUMBER_NR_FREE_PAGES,
	VMCI_NUMBER_PG_lru,
	VMCI_NUMBER_PG_private,
	VMCI_NUMBER_PG_swapcache,
	VMCI_NUMBER_PG_slab,
	VMCI_NUMBER_PG_poison,
	VMCI_SIZE_pglist_data,
	VMCI_OFFSET_pglist_data__node_zones,
	VMCI_OFFSET_pglist_data__nr_zones,
	VMCI_OFFSET_pglist_data__node_mem_map,
	VMCI_OFFSET_pglist_data__node_start_pfn,
	VMCI_OFFSET_pglist_data__node_spanned_pages,
	VMCI_OFFSET_pglist_data__node_id,
	VMCI_SIZE_zone,
	VMCI_OFFSET_zone__vm_stat,
	VMCI_OFFSET_zone__spanned_pages,
	VMCI_OFFSET_zone__free_area,
	VMCI_LENGTH_zone__free_area,
	VMCI_SIZE_free_area,
	VMCI_OFFSET_free_area__free_list,
	VMCI_LENGTH_free_area__free_list,
	VMCI_SYMBOL_node_data,
	VMCI_LENGTH_node_data,
	NR_PAGE_MAP_VMCI
};

static unsigned char *
read_pglist(struct kdt_data *d, GElf_Addr pglist_addr)
{
	int rv;
	unsigned char *pglist = NULL;
	uint64_t pglist_size = d->pglist_data_size;

	pglist = malloc(pglist_size);
	if (!pglist) {
		pr_err("Could not allocate pglist data, size was"
			" %lld bytes\n", (unsigned long long) pglist_size);
		return NULL;
	}

	rv = fetch_vaddr_data(d, pglist_addr, pglist_size, pglist);
	if (rv == -1) {
		pr_err("Could not fetch pglist data at %llx\n",
			(unsigned long long) pglist_addr);
		free(pglist);
		pglist = NULL;
	}

	return pglist;
}

static int
add_page_range(struct kdt_data *d,
	       GElf_Addr map, uint64_t start, uint64_t count)
{
	struct page_range *range;

	range = malloc(sizeof(*range));
	if (!range) {
		pr_err("Out of memory allocating page range\n");
		return -1;
	}

	range->start_page = start;
	range->nr_pages = count;
	range->mapaddr = map;
	range->bitmap = malloc(divide_round_up(count, 8));
	if (!range->bitmap) {
		free(range);
		pr_err("Out of memory allocating page bitmap\n");
		return -1;
	}
	memset(range->bitmap, 0, divide_round_up(count, 8));
	list_add_last(&d->page_maps, &range->link);
	return 0;
}

static int64_t
process_free_list(struct kdt_data *d, unsigned int order, unsigned char *list)
{
	GElf_Addr head_next;
	GElf_Addr next;
	unsigned char link[16];
	int rv;
	int64_t count = 0;

	rv = fetch_structlong(d, list, d->list_head_size,
			      d->list_head_next_offset,
			      &head_next, "free_list.head_next");
	if (rv == -1)
		return -1;

	if (head_next == 0)
		return 0;

	next = head_next;
	for (;;) {
		GElf_Addr page_offset = next - d->page_lru_offset;

		rv = fetch_vaddr_data(d, next, d->list_head_size, link);
		if (rv == -1)
			return -1;

		rv = fetch_structlong(d, link, d->list_head_size,
				      d->list_head_next_offset,
				      &next, "free_list.next");
		if (rv == -1)
			return -1;

		if (next == head_next)
			break;

		d->skipped_free += 1 << order;
		page_addr_mark_skipped(d, page_offset, 1 << order);
		count += (1 << order);
	}

	return count;
}

static int64_t
process_free_area_free_lists(struct kdt_data *d, unsigned int order,
			     unsigned char *free_area)
{
	uint32_t i;
	int rv;
	int64_t count = 0;

	for (i = 0; i < d->free_list_length; i++) {
		rv = process_free_list(d, order, free_area +
				       d->free_list_offset +
				       (d->list_head_size * i));
		if (rv == -1)
			return -1;
		count += rv;
	}

	return count;
}

static int64_t
process_zone_free_lists(struct kdt_data *d, unsigned char *zone)
{
	uint32_t i;
	int rv;
	int64_t count = 0;

	for (i = 0; i < d->free_area_length; i++) {
		rv = process_free_area_free_lists(d, i, zone +
						  d->free_area_offset +
						  (d->free_area_size * i));
		if (rv == -1)
			return -1;
		count += rv;
	}
	return count;
}

static int64_t
process_pglist_free_lists(struct kdt_data *d, unsigned char *pglist)
{
	uint32_t count = 0;
	uint32_t i;
	int rv;
	int64_t total = 0;

	if (d->level == DUMP_ALL)
		return 0;

	rv = fetch_struct32(d, pglist, d->pglist_data_size,
			    d->nr_zones_offset,
			    &count, "pglist.nr_zones");
	if (rv == -1)
		return -1;

	for (i = 0; i < count; i++) {
		rv = process_zone_free_lists(d, pglist + d->node_zones_offset +
					     (d->zone_size * i));
		if (rv == -1)
			return -1;
		total += rv;
	}

	return 0;
}

static int
process_pglist(struct kdt_data *d, GElf_Addr pglist_addr)
{
	int rv;
	unsigned char *pglist;
	uint64_t node_start_pfn;
	uint64_t node_spanned_pages;
	uint64_t node_mem_map;

	pglist = read_pglist(d, pglist_addr);
	if (!pglist)
		return -1;

	rv = fetch_structlong(d, pglist, d->pglist_data_size,
			      d->node_start_pfn_offset,
			      &node_start_pfn, "node_start_pfn");
	if (rv == -1)
		goto out_err;

	rv = fetch_structlong(d, pglist, d->pglist_data_size,
			      d->node_spanned_pages_offset,
			      &node_spanned_pages, "node_spanned_pages");
	if (rv == -1)
		goto out_err;

	rv = fetch_structlong(d, pglist, d->pglist_data_size,
			      d->node_mem_map_offset,
			      &node_mem_map, "node_mem_map");
	if (rv == -1)
		goto out_err;

	rv = add_page_range(d, node_mem_map, node_start_pfn,
			    node_spanned_pages);
	if (rv == -1)
		goto out_err;

	rv = process_pglist_free_lists(d, pglist);
	if (rv == -1)
		goto out_err;

out_err:
	free(pglist);
	return rv;
}

static int
read_flat_page_maps(struct kdt_data *d, struct vmcoreinfo_data *vmci)
{
	dpr("Flat\n");

	VMCI_CHECK_FOUND(vmci, SYMBOL, contig_page_data);
	VMCI_CHECK_FOUND(vmci, OFFSET, pglist_data__node_mem_map);
	d->node_mem_map_offset =
		vmci[VMCI_OFFSET_pglist_data__node_mem_map].val;

	return process_pglist(d, vmci[VMCI_SYMBOL_contig_page_data].val);
}

static int
process_mem_section(struct kdt_data *d, uint64_t sectionnr,
		    unsigned char *section)
{
	int rv;
	struct page_range *range;
	uint64_t section_mem_map;

	rv = fetch_structlong(d, section, d->mem_section_size,
			      d->section_mem_map_offset,
			      &section_mem_map, "section_mem_map");
	if (rv == -1)
		return -1;

	if (!(section_mem_map & SECTION_HAS_MEM_MAP))
		return 0;

	section_mem_map &= SECTION_MAP_MASK;

	range = malloc(sizeof(*range));
	if (!range) {
		pr_err("Out of memory allocating page range\n");
		return -1;
	}

	range->start_page = sectionnr * d->pages_per_section;
	range->nr_pages = d->pages_per_section;
	range->mapaddr = section_mem_map + (range->start_page * d->size_page);
	range->bitmap = malloc(divide_round_up(d->pages_per_section, 8));
	if (!range->bitmap) {
		free(range);
		pr_err("Out of memory allocating page bitmap\n");
		return -1;
	}
	memset(range->bitmap, 0, divide_round_up(d->pages_per_section, 8));
	list_add_last(&d->page_maps, &range->link);
	return 0;
}

static int
read_sparse_maps(struct kdt_data *d, struct vmcoreinfo_data *vmci, bool extreme)
{
	int rv;
	unsigned int i, j;
	unsigned char *mem_sections = NULL;
	unsigned int mem_sections_size;
	unsigned char *sections = NULL;
	unsigned int sections_size = 0; /* shut up compiler warning. */
	unsigned char *pglist;

	dpr("Sparse %d %s\n", extreme, extreme ? "extreme" : "static");

	d->pages_per_section = 1 << (d->section_size_bits - d->page_shift);
	if (extreme) {
		mem_sections_size = d->mem_section_length * d->ptrsize;
		d->sections_per_root = d->page_size / d->mem_section_size;
		sections_size = (d->mem_section_size * d->sections_per_root);
		sections = malloc(sections_size);
		if (!sections) {
			pr_err("Could not allocate section\n");
			rv = -1;
			goto out_err;
		}
	} else {
		mem_sections_size = d->mem_section_length * d->mem_section_size;
		d->sections_per_root = 1;
	}

	mem_sections = malloc(mem_sections_size);
	if (!mem_sections) {
		pr_err("Could not allocate mem section\n");
		return -1;
	}

	rv = fetch_vaddr_data(d, vmci[VMCI_SYMBOL_mem_section].val,
			      mem_sections_size, mem_sections);
	if (rv == -1)
		goto out_err;

	for (i = 0; i < d->mem_section_length; i++) {
		if (extreme) {
			uint64_t sectionptr;
			rv = fetch_structlong(d, mem_sections,
					      mem_sections_size, i * d->ptrsize,
					      &sectionptr,  "sectionptr");
			if (rv == -1)
				goto out_err;
			if (!sectionptr)
				continue;
			rv = fetch_vaddr_data(d, sectionptr, sections_size,
					      sections);
			if (rv == -1)
				goto out_err;
		} else {
			sections = mem_sections + (i * d->mem_section_size);
		}

		for (j = 0; j < d->sections_per_root; j++) {
			rv = process_mem_section
				(d,
				 ((uint64_t) i) * d->sections_per_root + j,
				 sections + (j * d->mem_section_size));
			if (rv == -1)
				goto out_err;
		}
	}

	if (vmci[VMCI_SYMBOL_contig_page_data].found) {
		pglist = read_pglist(d, vmci[VMCI_SYMBOL_contig_page_data].val);
		if (!pglist)
			return -1;
		rv = process_pglist_free_lists(d, pglist);
		free(pglist);
	}

out_err:
	if (mem_sections)
		free(mem_sections);
	if (extreme && sections)
		free(sections);
	return rv;
}

static int
read_discontig_maps(struct kdt_data *d, struct vmcoreinfo_data *vmci)
{
	int rv;
	GElf_Addr node_data_addr;
	unsigned int count, i;
	unsigned char *node_data;

	dpr("Discontig\n");

	VMCI_CHECK_FOUND(vmci, SYMBOL, node_data);
	node_data_addr = vmci[VMCI_SYMBOL_node_data].val;

	VMCI_CHECK_FOUND(vmci, LENGTH, node_data);
	count = vmci[VMCI_LENGTH_node_data].val;

	node_data = malloc(count * d->ptrsize);
	if (!node_data) {
		pr_err("Out of memory allocating node data\n");
		return -1;
	}

	rv = fetch_vaddr_data(d, node_data_addr, count * d->ptrsize, node_data);
	if (rv == -1)
		goto out_err;

	for (i = 0; i < count; i++) {
		uint64_t pglist_addr;

		rv = fetch_structlong(d, node_data, d->ptrsize * count,
				      d->ptrsize * i,
				      &pglist_addr, "node_data.pgdata");
		if (rv == -1)
			goto out_err;

		if (pglist_addr) {
			rv = process_pglist(d, pglist_addr);
			if (rv == -1)
				goto out_err;
		}
	}

out_err:
	free(node_data);
	return rv;
}

static int
read_page_maps(struct kdt_data *d)
{
	struct vmcoreinfo_data vmci[] = {
		VMCI_SYMBOL(mem_map),
		VMCI_SYMBOL(contig_page_data),
		VMCI_SYMBOL(mem_section),
		VMCI_LENGTH(mem_section),
		VMCI_SIZE(mem_section),
		VMCI_OFFSET(mem_section, section_mem_map),
		VMCI_SIZE(page),
		VMCI_OFFSET(page, flags),
		VMCI_OFFSET(page, _count),
		VMCI_OFFSET(page, mapping),
		VMCI_OFFSET(page, lru),
		VMCI_OFFSET(page, _mapcount),
		VMCI_OFFSET(page, private),
		VMCI_NUMBER(PAGE_BUDDY_MAPCOUNT_VALUE),
		VMCI_NUMBER(NR_FREE_PAGES),
		VMCI_NUMBER(PG_lru),
		VMCI_NUMBER(PG_private),
		VMCI_NUMBER(PG_swapcache),
		VMCI_NUMBER(PG_slab),
		VMCI_NUMBER(PG_poison),
		VMCI_SIZE(pglist_data),
		VMCI_OFFSET(pglist_data, node_zones),
		VMCI_OFFSET(pglist_data, nr_zones),
		VMCI_OFFSET(pglist_data, node_mem_map), /* FLAT_NODE_MEM_MAP */
		VMCI_OFFSET(pglist_data, node_start_pfn),
		VMCI_OFFSET(pglist_data, node_spanned_pages),
		VMCI_OFFSET(pglist_data, node_id),
		VMCI_SIZE(zone),
		VMCI_OFFSET(zone, free_area),
		VMCI_SLENGTH(zone, free_area),
		VMCI_OFFSET(zone, vm_stat),
		VMCI_OFFSET(zone, spanned_pages),
		VMCI_SIZE(free_area),
		VMCI_OFFSET(free_area, free_list),
		VMCI_SLENGTH(free_area, free_list),
		VMCI_SYMBOL(node_data),
		VMCI_LENGTH(node_data),
		{ NULL }
	};
	int rv = -1;

	list_init(&d->page_maps);

	handle_vminfo_notes(d->elf, vmci, d->extra_vminfo);

	d->pagedata = malloc(d->page_size);
	if (!d->pagedata) {
		pr_err("Error: Out of memory allocating page data\n");
		return -1;
	}

	if (vmci[VMCI_NUMBER_PAGE_BUDDY_MAPCOUNT_VALUE].found)
		d->buddy_mapcount_found = 1;
	d->buddy_mapcount = vmci[VMCI_NUMBER_PAGE_BUDDY_MAPCOUNT_VALUE].val;
	VMCI_CHECK_FOUND(vmci, NUMBER, NR_FREE_PAGES);
	d->NR_FREE_PAGES = vmci[VMCI_NUMBER_NR_FREE_PAGES].val;
	VMCI_CHECK_FOUND(vmci, NUMBER, PG_lru);
	d->PG_lru = 1ULL << vmci[VMCI_NUMBER_PG_lru].val;
	VMCI_CHECK_FOUND(vmci, NUMBER, PG_private);
	d->PG_private = 1ULL << vmci[VMCI_NUMBER_PG_private].val;
	VMCI_CHECK_FOUND(vmci, NUMBER, PG_swapcache);
	d->PG_swapcache = 1ULL << vmci[VMCI_NUMBER_PG_swapcache].val;
	VMCI_CHECK_FOUND(vmci, NUMBER, PG_slab);
	d->PG_slab = 1ULL << vmci[VMCI_NUMBER_PG_slab].val;
	if (vmci[VMCI_NUMBER_PG_poison].found)
		d->PG_poison = 1ULL << vmci[VMCI_NUMBER_PG_poison].val;

	VMCI_CHECK_FOUND(vmci, SIZE, page);
	d->size_page = vmci[VMCI_SIZE_page].val;

	VMCI_CHECK_FOUND(vmci, OFFSET, page__flags);
	d->page_flags_offset = vmci[VMCI_OFFSET_page__flags].val;
	VMCI_CHECK_FOUND(vmci, OFFSET, page___count);
	d->page_count_offset = vmci[VMCI_OFFSET_page___count].val;
	VMCI_CHECK_FOUND(vmci, OFFSET, page__mapping);
	d->page_mapping_offset = vmci[VMCI_OFFSET_page__mapping].val;
	VMCI_CHECK_FOUND(vmci, OFFSET, page__lru);
	d->page_lru_offset = vmci[VMCI_OFFSET_page__lru].val;
	VMCI_CHECK_FOUND(vmci, OFFSET, page___mapcount);
	d->page_mapcount_offset = vmci[VMCI_OFFSET_page___mapcount].val;
	VMCI_CHECK_FOUND(vmci, OFFSET, page__private);
	d->page_private_offset = vmci[VMCI_OFFSET_page__private].val;

	VMCI_CHECK_FOUND(vmci, SIZE, pglist_data);
	d->pglist_data_size = vmci[VMCI_SIZE_pglist_data].val;
	VMCI_CHECK_FOUND(vmci, OFFSET, pglist_data__node_zones);
	d->node_zones_offset = vmci[VMCI_OFFSET_pglist_data__node_zones].val;
	VMCI_CHECK_FOUND(vmci, OFFSET, pglist_data__nr_zones);
	d->nr_zones_offset = vmci[VMCI_OFFSET_pglist_data__nr_zones].val;
	VMCI_CHECK_FOUND(vmci, OFFSET, pglist_data__node_start_pfn);
	d->node_start_pfn_offset =
		vmci[VMCI_OFFSET_pglist_data__node_start_pfn].val;
	VMCI_CHECK_FOUND(vmci, OFFSET, pglist_data__node_spanned_pages);
	d->node_spanned_pages_offset =
		vmci[VMCI_OFFSET_pglist_data__node_spanned_pages].val;
	VMCI_CHECK_FOUND(vmci, OFFSET, pglist_data__node_id);

	VMCI_CHECK_FOUND(vmci, SIZE, zone);
	d->zone_size = vmci[VMCI_SIZE_zone].val;
	VMCI_CHECK_FOUND(vmci, OFFSET, zone__free_area);
	d->free_area_offset = vmci[VMCI_OFFSET_zone__free_area].val;
	VMCI_CHECK_FOUND(vmci, OFFSET, free_area__free_list);
	d->free_list_offset = vmci[VMCI_OFFSET_free_area__free_list].val;
	VMCI_CHECK_FOUND(vmci, LENGTH, zone__free_area);
	d->free_area_length = vmci[VMCI_LENGTH_zone__free_area].val;
	VMCI_CHECK_FOUND(vmci, LENGTH, free_area__free_list);
	d->free_list_length = vmci[VMCI_LENGTH_free_area__free_list].val;

	VMCI_CHECK_FOUND(vmci, SIZE, free_area);
	d->free_area_size = vmci[VMCI_SIZE_free_area].val;

	if (vmci[VMCI_SYMBOL_mem_section].found) {
		bool is_sparse_extreme;
		/* Sparse memory */

		VMCI_CHECK_FOUND(vmci, SIZE, mem_section);
		d->mem_section_size = vmci[VMCI_SIZE_mem_section].val;
		VMCI_CHECK_FOUND(vmci, LENGTH, mem_section);
		d->mem_section_length = vmci[VMCI_LENGTH_mem_section].val;
		VMCI_CHECK_FOUND(vmci, OFFSET, mem_section__section_mem_map);
		d->section_mem_map_offset =
			vmci[VMCI_OFFSET_mem_section__section_mem_map].val;

		if (d->mem_section_length ==
		    ((1 << (d->max_physmem_bits - d->section_size_bits)) /
		     (d->page_size / d->mem_section_size)))
			is_sparse_extreme = true;
		else
			is_sparse_extreme = false;
		rv = read_sparse_maps(d, vmci, is_sparse_extreme);
	} else if (!vmci[VMCI_SYMBOL_mem_map].found) {
		/* Discontiguous memory */
		rv = read_discontig_maps(d, vmci);
	} else {
		/* Flat Memory */
		rv = read_flat_page_maps(d, vmci);
	}
	return rv;
}

struct velf_data {
	struct elfc *velf;
	GElf_Addr start_vaddr;
	GElf_Addr next_vaddr;
	GElf_Addr start_paddr;
	GElf_Addr next_paddr;
	GElf_Addr last_pgsize;
	int prev_present;
	int prev_pnum;

	struct kdt_data *d;
};

static int
velf_do_write(struct elfc *e, int fd, GElf_Phdr *phdr, void *data,
	      void *userdata)
{
	struct velf_data *dpage = userdata;
	struct kdt_data *d = dpage->d;
	int rv;
	GElf_Off addr = phdr->p_paddr;
	size_t size = phdr->p_filesz;
	size_t buf_size = 1024 * 1024;
	char *buf;

	if (buf_size > size)
		buf_size = size;
	buf = malloc(buf_size);
	if (!buf) {
		errno = ENOMEM;
		return -1;
	}

	while (size) {
		if (buf_size > size)
			buf_size = size;
		rv = elfc_read_pmem(d->elf, addr, buf, buf_size);
		if (rv == -1) {
			errno = elfc_get_errno(d->elf);
			goto out_err;
		}
		rv = write(fd, buf, buf_size);
		if (rv == -1)
			goto out_err;
		if (rv != buf_size) {
			errno = EINVAL;
			goto out_err;
		}
		size -= buf_size;
		addr += buf_size;
	}
	free(buf);
	return 0;
out_err:
	free(buf);
	return -1;
}

static int
velf_get_data(struct elfc *e, GElf_Phdr *phdr, void *data,
	      GElf_Off off, void *odata, size_t len,
	      void *userdata)
{
	struct velf_data *dpage = userdata;
	struct kdt_data *d = dpage->d;
	int rv;

	if ((off > phdr->p_filesz) || ((off + len) > phdr->p_filesz)) {
		errno = EINVAL;
		return -1;
	}

	rv = elfc_read_pmem(d->elf, phdr->p_paddr + off, odata, len);
	if (rv == -1) {
		errno = elfc_get_errno(d->elf);
		return -1;
	}

	return 0;
}

static int
velf_set_data(struct elfc *e, GElf_Phdr *phdr, void *data,
	      GElf_Off off, const void *idata, size_t len,
	      void *userdata)
{
	struct velf_data *dpage = userdata;
	struct kdt_data *d = dpage->d;
	int rv;

	if ((off > phdr->p_filesz) || ((off + len) > phdr->p_filesz)) {
		errno = EINVAL;
		return -1;
	}

	rv = elfc_write_pmem(d->elf, phdr->p_paddr + off, idata, len);
	if (rv == -1) {
		errno = elfc_get_errno(d->elf);
		return -1;
	}

	return 0;
}

static int
gen_new_phdr(struct elfc *pelf, struct velf_data *dpage)
{
	int rv;

	rv = elfc_add_phdr(dpage->velf, PT_LOAD,
			   dpage->start_vaddr,
			   dpage->start_paddr,
			   dpage->next_paddr - dpage->start_paddr,
			   dpage->next_paddr - dpage->start_paddr,
			   PF_R | PF_W | PF_X,
			   dpage->last_pgsize);
	if (rv == -1) {
		pr_err("Unable to add phdr: %s\n",
			strerror(elfc_get_errno(dpage->velf)));
		return -1;
	}
	rv = elfc_set_phdr_data(dpage->velf, rv, NULL,
				NULL, NULL, velf_do_write, NULL,
				velf_get_data, velf_set_data,
				dpage);
	if (rv) {
		pr_err("Unable to set phdr data: %s\n",
			strerror(elfc_get_errno(dpage->velf)));
		return -1;
	}

	return 0;
}

static void
print_pginfo(char *op, char *type, struct page_info *page,
	     GElf_Addr paddr, GElf_Addr vaddr)
{
	printf("%s%s page, paddr %llx vaddr %llx, flags:%llx count:%d "
	       "mapping:%llx mapcount:%d private:%llx\n",
	       op, type,
	       (unsigned long long) paddr,
	       (unsigned long long) vaddr,
	       (unsigned long long) page->flags,
	       page->count,
	       (unsigned long long) page->mapping,
	       page->mapcount,
	       (unsigned long long) page->private);
}

static void
handle_skip(struct kdt_data *d, char *type,
	    struct page_info *page, struct page_range *range,
	    uint64_t pfn, GElf_Addr paddr, GElf_Addr vaddr)
{
	set_pfn_skipped(d, range, pfn);
	if (debug)
		print_pginfo("Skipping ", type, page, paddr, vaddr);
}

static int
process_page(struct velf_data *dpage,
	     struct elfc *pelf,
	     GElf_Addr paddr,
	     GElf_Addr vaddr,
	     GElf_Addr pgsize)
{
	struct kdt_data *d = dpage->d;
	GElf_Off dummy;
	int pnum, present, rv;
	uint64_t pfn = paddr >> d->page_shift;
	struct page_range *range;
	struct page_info page;

	range = find_pfn_range(d, pfn);
	if (!range) {
		dpr("Page not present in range, paddr %llx vaddr %llx\n",
		    (unsigned long long) paddr,
		    (unsigned long long) vaddr);
		return 0;
	}

	if (is_pfn_skipped(d, range, pfn))
		/* Already been handled. */
		return 0;

	present = elfc_pmem_offset(d->elf, paddr, pgsize, &pnum, &dummy) != -1;
	if (!present) {
		dpr("Page not present in memory, paddr %llx vaddr %llx\n",
		    (unsigned long long) paddr,
		    (unsigned long long) vaddr);
		set_pfn_skipped(d, range, pfn);
		d->skipped_not_present++;
		return 0;
	}

	rv = find_page_by_pfn(d, range, pfn, &page);
	if (rv == -1) {
		dpr("Page not present, paddr %llx vaddr %llx\n",
		    (unsigned long long) paddr,
		    (unsigned long long) vaddr);
		set_pfn_skipped(d, range, pfn);
		d->skipped_not_present++;
		return 0;
	}

	if (page.flags & d->PG_poison) {
		/* Always skip poison pages. */
		d->skipped_poison++;
		handle_skip(d, "poison", &page, range, pfn, paddr, vaddr);
		return 0;
	}

	if (d->level != DUMP_ALL && d->buddy_mapcount_found) {
		if (!(page.flags & d->PG_slab)
		    && (page.mapcount == d->buddy_mapcount))
		{
			d->skipped_free++;
			handle_skip(d, "free2", &page, range, pfn, paddr, vaddr);
			return 0;
		}
	}

	if (d->level == DUMP_USER || d->level == DUMP_KERNEL) {
		/* Exclude cache pages */
		if ((page.flags & (d->PG_lru | d->PG_swapcache))
		    && !(page.mapping & PAGE_MAPPING_ANON)) {
			d->skipped_cache++;
			handle_skip(d, "cached", &page, range, pfn, paddr, vaddr);
			return 0;
		}
	}

	if (d->level == DUMP_CACHE || d->level == DUMP_KERNEL) {
		/* Exclude user pages */
		if (page.mapping & PAGE_MAPPING_ANON) {
			d->skipped_user++;
			handle_skip(d, "user", &page, range, pfn, paddr, vaddr);
			return 0;
		}
	}

	d->not_skipped++;
	if (debug)
		print_pginfo("Accepting", "", &page, paddr, vaddr);

	/*
	 * We require entries to be contiguous in physical and virtual
	 * space to be combined.  We also require them to be in the same
	 * segment of the pelf file.  The pelf file was carefully written
	 * to have no segments larger than 4GB so the offset remains <
	 * UINT32_MAX.  Preserve that in the velf file.
	 */
	if ((vaddr && (dpage->next_vaddr != vaddr)) ||
	    dpage->next_paddr != paddr ||
	    dpage->prev_pnum != pnum) {
		if (dpage->prev_present) {
			rv = gen_new_phdr(pelf, dpage);
			if (rv == -1)
				return -1;
		}
		dpage->start_vaddr = vaddr;
		dpage->start_paddr = paddr;
	}
	if (!dpage->prev_present) {
		dpage->start_vaddr = vaddr;
		dpage->start_paddr = paddr;
	}

	dpage->prev_present = present;
	dpage->prev_pnum = pnum;
	dpage->next_vaddr = vaddr + pgsize;
	dpage->next_paddr = paddr + pgsize;
	dpage->last_pgsize = pgsize;
	return 0;
}

static int
flush_dpage(struct elfc *pelf, struct velf_data *dpage)
{
	int rv;

	if (dpage->prev_present) {
		rv = gen_new_phdr(pelf, dpage);
		if (rv)
			return -1;
	}
	return 0;
}

static void
print_skipped(struct kdt_data *d)
{
	printf("Skipped %llu not present pages\n",
	       (unsigned long long) d->skipped_not_present);
	printf("        %llu free pages\n",
	       (unsigned long long) d->skipped_free);
	printf("        %llu cache pages\n",
	       (unsigned long long) d->skipped_cache);
	printf("        %llu user pages\n",
	       (unsigned long long) d->skipped_user);
	printf("        %llu poison pages\n",
	       (unsigned long long) d->skipped_poison);
	printf("Accepted %llu pages\n",
	       (unsigned long long) d->not_skipped);
}

static int
read_vminfofile(char *filename, char **contents)
{
	int fd = -1, rv;
	struct stat stats;
	char *buf = 0;
	off_t pos = 0;

	fd = open(filename, O_RDONLY);
	if (fd == -1)
		goto out_err;

	rv = fstat(fd, &stats);
	if (rv == -1)
		goto out_err;

	buf = malloc(stats.st_size + 1);
	if (!buf) {
		rv = ENOMEM;
		goto out_err;
	}

	while (stats.st_size > pos) {
		rv = read(fd, buf + pos, stats.st_size - pos);
		if (rv < 0) {
			if (errno == EAGAIN)
				continue;
			rv = errno;
			goto out_err;
		} else if (rv == 0) {
			break;
		} else {
			pos += rv;
		}
	}
	buf[pos] = '\0';

	*contents = buf;
	return 0;

out_err:
	rv = errno;
	if (fd != -1)
		close(fd);
	if (buf)
		free(buf);
	return rv;
}

static int
topelf(int argc, char *argv[])
{
	char *outfile = NULL;
	char *oldmem = NULL;
	char *vmcore = "/proc/vmcore";
	static const struct option longopts[] = {
		{ "help",	no_argument,		NULL, 'h' },
		{ "oldmem",	required_argument,	NULL, 'i' },
		{ "outfile",	required_argument,	NULL, 'o' },
		{ "vmcore",	required_argument,	NULL, 'v' },
		{ "elfclass",	required_argument,	NULL, 'c' },
		{ "level",	required_argument,	NULL, 'l' },
		{ "debug",	no_argument,		NULL, 'd' },
		{ "extravminfo",required_argument,	NULL, 'e' },
		{ NULL }
	};
	static const char *helpstr[] = {
		"This info",
		"File to use for raw memory (like /dev/mem), unused by default",
		"File send output to instead of stdout",
		"The vmcore file, defaults to /proc/vmcore",
		"Set the elfclass (either 32 or 64)",
		"Set the dump level: all, inuse, user, cache, or kernel",
		"increment the debug level",
		"Override or add new vminfo information",
		NULL
	};
	int ofd = 1;
	int rv = 0;
	struct vmcoreinfo_data vmci[] = {
		VMCI_ADDRESS(phys_pgd_ptr),
		VMCI_SIZE(list_head),
		VMCI_OFFSET(list_head, next),
		VMCI_OFFSET(list_head, prev),
		VMCI_SYMBOL(_stext),
		VMCI_PAGESIZE(),
		{ NULL }
	};
	struct kdt_data kdt_data, *d = &kdt_data;
	struct elfc *velf = NULL;
	struct velf_data dpage;
	int elfclass = ELFCLASSNONE;
	int level = DUMP_KERNEL;
	int num_phdrs;
	int i;
	GElf_Addr addr;
	char *extra_vminfofile = NULL;

	memset(d, 0, sizeof(*d));
	for (;;) {
		int curr_optind = optind;
		int c = getopt_long(argc, argv, "+ho:i:v:c:l:de:", longopts,
				    NULL);
		if (c == -1)
			break;
		switch (c) {
		case 'o':
			outfile = optarg;
			break;
		case 'i':
			oldmem = optarg;
			break;
		case 'v':
			vmcore = optarg;
			break;
		case 'e':
			extra_vminfofile = optarg;
			break;
		case 'c':
			if (strcmp(optarg, "32") == 0) {
				elfclass = ELFCLASS32;
			} else if (strcmp(optarg, "64") == 0) {
				elfclass = ELFCLASS64;
			} else {
				subcmd_usage("Unknown ELF class: %s\n",
					     optarg);
			}
			break;
		case 'l':
			level = process_levels(optarg);
			if (level == -1) {
				subcmd_usage("Unknown dump level: %s\n",
					     optarg);
			}
			break;
		case 'h':
			subcmd_help("", longopts, helpstr);
			return 0;
		case 'd':
			debug++;
			break;
		case '?':
			subcmd_usage("Unknown option: %s\n", argv[curr_optind]);
		}
	}

	d->level = level;

	if (optind < argc)
		subcmd_usage("Too many arguments, starting at %s\n",
			     argv[optind]);

	if (extra_vminfofile) {
		rv = read_vminfofile(extra_vminfofile, &d->extra_vminfo);
		if (rv) {
			pr_err("Unable to read vminfofile %s: %s\n",
			       extra_vminfofile, strerror(rv));
			goto out_err;
		}
	}

	d->elf = read_oldmem(oldmem, vmcore, d->extra_vminfo);
	if (!d->elf)
		goto out_err;

	handle_vminfo_notes(d->elf, vmci, d->extra_vminfo);

	rv = process_base_vmci(d, vmci, d->elf);
	if (rv)
		goto out_err;

	if (!vmci[VMCI_ADDRESS_phys_pgd_ptr].found) {
		if (d->level == DUMP_ALL)
			pr_err("Warning: phys pgd ptr not in vmcore\n");
		else {
			pr_err("Error: phys pgd ptr not in vmcore, can"
			       " only do all dump level\n");
			goto out_err;
		}
	}
	d->pgd = vmci[VMCI_ADDRESS_phys_pgd_ptr].val;

	if (outfile) {
		ofd = creat(outfile, 0644);
		if (ofd == -1) {
			pr_err("Unable to open %s: %s\n", outfile,
				strerror(errno));
			goto out_err;
		}
	}

	if (d->level == DUMP_ALL) {
		elfc_set_fd(d->elf, ofd);
		rv = elfc_write(d->elf);
		if (rv == -1) {
			pr_err("Error writing elfc file: %s\n",
				strerror(elfc_get_errno(d->elf)));
			goto out_err;
		}
		goto out;
	}

	velf = elfc_alloc();
	if (!velf) {
		pr_err("Out of memory allocating elf obj\n");
		goto out_err;
	}
	rv = elfc_setup(velf, elfc_gettype(d->elf));
	if (rv == -1) {
		pr_err("Error writing elfc file: %s\n",
			strerror(elfc_get_errno(d->elf)));
		goto out_err;
	}
	elfc_setmachine(velf, elfc_getmachine(d->elf));
	elfc_setencoding(velf, elfc_getencoding(d->elf));
	copy_elf_notes(velf, d->elf, NULL, NULL);

	elfc_set_fd(velf, ofd);

	if (elfclass == ELFCLASSNONE) {
		elfc_setclass(velf, d->arch->default_elfclass);
	} else {
		elfc_setclass(velf, elfclass);
	}

	rv = read_page_maps(d);
	if (rv == -1)
		goto out_err;

	memset(&dpage, 0, sizeof(dpage));
	dpage.velf = velf;
	dpage.d = d;

	num_phdrs = elfc_get_num_phdrs(d->elf);
	for (i = 0; i < num_phdrs; i++) {
		GElf_Phdr phdr;
		rv = elfc_get_phdr(d->elf, i, &phdr);
		if (rv) {
			pr_err("Error reading phdr %d from input"
				"file: %s",
				i, strerror(elfc_get_errno(d->elf)));
			goto out_err;
		}

		for (addr = phdr.p_paddr; addr < phdr.p_paddr + phdr.p_memsz;
		     addr += d->page_size)
		{
			rv = process_page(&dpage, d->elf, addr, 0,
					  d->page_size);
			if (rv == -1)
				goto out_err;
		}
	}

	rv = flush_dpage(d->elf, &dpage);
	if (rv == -1)
		goto out_err;

	if (ofd != 1)
		/* Don't print stuff if the elf file goes to stdout */
		print_skipped(d);

	rv = elfc_write(velf);
	if (rv == -1) {
		pr_err("Error writing elfc file: %s\n",
			strerror(elfc_get_errno(d->elf)));
		goto out_err;
	}

out:
	if (d->arch && d->arch_data)
		d->arch->cleanup_arch_data(d->arch_data);
	if (velf)
		elfc_free(velf);
	if (d->elf) {
		close(elfc_get_fd(d->elf));
		elfc_free(d->elf);
	}
	if ((ofd != -1) && (ofd != 1))
		close(ofd);
	return rv;

out_err:
	rv = 1;
	goto out;
}

static int
add_auxv(struct elfc *e, const char *vmlinux, GElf_Addr dyn_stext)
{
	int rv = -1;
        unsigned char elfclass;
	struct elfc *vml_elf = NULL;
	int vml_fd = -1;
	GElf_Sym sym;
	GElf_Addr dyn_entry;

	vml_elf = elfc_alloc();
	if (!vml_elf) {
		pr_err("Unable to allocate ELF data for vmlinux\n");
		return -1;
	}
	vml_fd = open(vmlinux, O_RDWR);
	if (vml_fd == -1) {
		pr_err("Error opening vmlinux: %s\n", strerror(errno));
		goto out;
	}

	if (elfc_open(vml_elf, vml_fd) == -1) {
		pr_err("Error elf opening vmlinux: %s\n",
			strerror(elfc_get_errno(vml_elf)));
		goto out;
	}

	if (elfc_lookup_sym(vml_elf, "_stext", &sym, 0, NULL) == -1) {
		pr_err("Can't find _stext in vmlinux: %s\n",
			strerror(elfc_get_errno(vml_elf)));
		goto out;
	}

	if (dyn_stext == sym.st_value) {
		/* No need for this, return 0 to say we didn't do anything. */
		rv = 0;
		goto out;
	}

	dyn_entry = elfc_getentry(vml_elf) + (dyn_stext - sym.st_value);

	elfclass = elfc_getclass(e);
	if (elfclass == ELFCLASS32) {
		Elf32_auxv_t auxv;

		auxv.a_type = elfc_putAddr(e, AT_ENTRY);
		auxv.a_un.a_val = elfc_putAddr(e, dyn_entry);
		rv = elfc_add_note(e, NT_AUXV, "CORE", 5, &auxv, sizeof(auxv));
	} else if (elfclass == ELFCLASS64) {
		Elf64_auxv_t auxv;

		auxv.a_type = elfc_putAddr(e, AT_ENTRY);
		auxv.a_un.a_val = elfc_putAddr(e, dyn_entry);
		rv = elfc_add_note(e, NT_AUXV, "CORE", 5, &auxv, sizeof(auxv));
	} else {
		pr_err("Unknown elfclass?: %d\n", elfclass);
		rv = -1;
	}

	/* Return 1 to denote that we changed something. */
	if (rv == 0)
		rv = 1;

out:
	if (vml_elf)
		elfc_free(vml_elf);
	if (vml_fd != -1)
		close(vml_fd);
	return rv;
}


static int
velf_page_handler(struct elfc *pelf,
		  GElf_Addr paddr,
		  GElf_Addr vaddr,
		  GElf_Addr pgsize,
		  void *userdata)
{
	int rv;
	struct velf_data *dpage = userdata;
	struct kdt_data *d = dpage->d;
	unsigned int i, pages = divide_round_up(pgsize, d->page_size);

	for (i = 0; i < pages; i++) {
		rv = process_page(dpage, pelf, paddr, vaddr, d->page_size);
		if (rv == -1)
			return rv;
		paddr += d->page_size;
		vaddr += d->page_size;
	}
	return 0;
}

/*
 * Called when copying the ELF notes, so we can know what CPUs are
 * there.
 */
static int
add_cpu_info(GElf_Word type, const char *name, size_t namelen,
	     void *data, size_t data_len, void *userdata)
{
	struct kdt_data *d = userdata;
	struct cpu_info *cpu;

	if (type != NT_PRSTATUS)
		return 0;

	cpu = malloc(sizeof(*cpu));
	if (!cpu) {
		pr_err("Out of memory in add_cpu_info\n");
		return -1;
	}

	if (d->is_64bit) {
		struct kd_elf_prstatus64 *pr = data;

		if (data_len < sizeof(*pr)) {
			pr_err("Invalid note size: %d bytes\n", (int) data_len);
			return -1;
		}

		cpu->pid = d->conv32(&pr->pr_pid);
	} else {
		struct kd_elf_prstatus32 *pr = data;

		if (data_len < sizeof(*pr)) {
			pr_err("Invalid note size: %d bytes\n", (int) data_len);
			return -1;
		}

		cpu->pid = d->conv32(&pr->pr_pid);
	}
	cpu->cpu = d->cpunum;
	cpu->next = d->cpus;
	d->cpus = cpu;
	d->cpunum++;

	return 0;
}

enum thread_info_labels {
	VMCI_SYMBOL_resume, /* for MIPS */
	VMCI_SYMBOL___thread_sleep_point, /* for X86 */
	VMCI_OFFSET_thread_struct__sp, /* for X86 */
	VMCI_SIZE_context_switch_frame, /* For x86 */
	VMCI_OFFSET_thread_info__cpu_context, /* for ARM */
	VMCI_SYMBOL___switch_to, /* for ARM */
	/* Begin required elements. */
#define KV_REQ VMCI_SYMBOL_init_task
	VMCI_SYMBOL_init_task,
	VMCI_OFFSET_task_struct__stack,
	VMCI_OFFSET_task_struct__tasks,
	VMCI_OFFSET_task_struct__thread_node,
	VMCI_OFFSET_task_struct__signal,
	VMCI_OFFSET_task_struct__pid,
	VMCI_OFFSET_task_struct__thread,
	VMCI_OFFSET_signal_struct__thread_head
};

typedef int (*thread_handler)(struct kdt_data *d, GElf_Addr task,
			      void *userdata);

static int
handle_kernel_process_threads(struct kdt_data *d, GElf_Addr task,
			      thread_handler handler, void *userdata)
{
	uint64_t signal, thread_head, thread_link;
	int rv;
	long count = 0;

	rv = fetch_vaddrlong(d, task + d->task_signal, &signal, "task.signal");
	if (rv)
		return rv;

	thread_head = signal + d->signal_thread_head;

	rv = fetch_vaddrlong(d, thread_head + d->list_head_next_offset,
			     &thread_link, "first thread");
	if (rv)
		return rv;

	while (thread_link != thread_head) {
		rv = handler(d, thread_link - d->task_thread_node, userdata);
		if (rv)
			return rv;

		rv = fetch_vaddrlong(d, thread_link + d->list_head_next_offset,
				     &thread_link, "next thread");
		if (rv)
			return rv;

		if (count++ > 65536) {
			pr_err("Too many threads in list, aborting\n");
			return -1;
		}
	}

	return 0;
}

static int
handle_kernel_processes_threads(struct kdt_data *d, thread_handler handler,
				void *userdata)
{
	struct vmcoreinfo_data vmci[] = {
		VMCI_SYMBOL(resume),
		VMCI_SYMBOL(__thread_sleep_point),
		VMCI_OFFSET(thread_struct, sp),
		VMCI_SIZE(context_switch_frame),
		VMCI_OFFSET(thread_info, cpu_context),
		VMCI_SYMBOL(__switch_to),
		VMCI_SYMBOL(init_task),
		VMCI_OFFSET(task_struct, stack),
		VMCI_OFFSET(task_struct, tasks),
		VMCI_OFFSET(task_struct, thread_node),
		VMCI_OFFSET(task_struct, signal),
		VMCI_OFFSET(task_struct, pid),
		VMCI_OFFSET(task_struct, thread),
		VMCI_OFFSET(signal_struct, thread_head),
		{ NULL }
	};
	uint64_t task_addr, init_task_addr;
	long count = 0;
	unsigned int i;

	handle_vminfo_notes(d->elf, vmci, d->extra_vminfo);
	for (i = KV_REQ; vmci[i].name; i++) {
		if (!vmci[i].found) {
			pr_err("vmcoreinfo value %s not found.  You need to "
			       "run the gdb command to supply these values "
			       "and supply them with the -e option to this "
			       "program.\n", vmci[i].name);
			return -1;
		}
	}

	d->task_stack = vmci[VMCI_OFFSET_task_struct__stack].val;
	d->task_tasks_next = vmci[VMCI_OFFSET_task_struct__tasks].val +
		d->list_head_next_offset;
	d->task_thread_node = vmci[VMCI_OFFSET_task_struct__thread_node].val;
	d->task_signal = vmci[VMCI_OFFSET_task_struct__signal].val;
	d->task_pid = vmci[VMCI_OFFSET_task_struct__pid].val;
	d->signal_thread_head = vmci[VMCI_OFFSET_signal_struct__thread_head].val;
	d->task_thread = vmci[VMCI_OFFSET_task_struct__thread].val;
	d->mips_task_resume_found = vmci[VMCI_SYMBOL_resume].found;
	if (d->mips_task_resume_found)
		d->mips_task_resume = vmci[VMCI_SYMBOL_resume].val;
	d->x86___thread_sleep_point_found =
		vmci[VMCI_SYMBOL___thread_sleep_point].found;
	if (d->x86___thread_sleep_point_found)
		d->x86___thread_sleep_point =
			vmci[VMCI_SYMBOL___thread_sleep_point].val;
	d->thread_sp_found = vmci[VMCI_OFFSET_thread_struct__sp].found;
	if (d->thread_sp_found)
		d->thread_sp = vmci[VMCI_OFFSET_thread_struct__sp].val;
	d->x86_context_switch_frame_size_found =
		vmci[VMCI_SIZE_context_switch_frame].found;
	if (d->x86_context_switch_frame_size_found)
		d->x86_context_switch_frame_size =
			vmci[VMCI_SIZE_context_switch_frame].val;
	d->arm_thread_info_cpu_context_found =
		vmci[VMCI_OFFSET_thread_info__cpu_context].found;
	if (d->arm_thread_info_cpu_context_found)
		d->arm_thread_info_cpu_context =
			vmci[VMCI_OFFSET_thread_info__cpu_context].val;
	d->arm___switch_to_found = vmci[VMCI_SYMBOL___switch_to].found;
	if (d->arm___switch_to_found)
		d->arm___switch_to = vmci[VMCI_SYMBOL___switch_to].val;

	init_task_addr = vmci[VMCI_SYMBOL_init_task].val;

	task_addr = init_task_addr;
	do {
		int rv = handle_kernel_process_threads(d, task_addr,
						       handler, userdata);
		if (rv)
			return rv;

		rv = fetch_vaddrlong(d, task_addr + d->task_tasks_next,
				     &task_addr, "next task");
		if (rv)
			return rv;
		task_addr -= d->task_tasks_next;

		if (count++ > 65536) {
			pr_err("Too many processes in list, aborting\n");
			return -1;
		}
	} while (task_addr != init_task_addr);

	return 0;
}

static int add_proc_thread(struct kdt_data *d, GElf_Addr task, void *userdata)
{
	void *data, *pt_regsptr;
	unsigned int len;
	int rv;
	uint32_t pid;
	struct cpu_info *cpu;

	if (!d->fetch_ptregs || !d->pt_regs_size) {
		pr_err("Architecture can't fetch task registers, can't "
		       "convert kernel processes to gdb threads\n");
		return -1;
	}

	rv = fetch_vaddr32(d, task + d->task_pid, &pid, "task.pid");
	if (rv)
		return rv;

	/* If it's a running thread, use the one provided by the kernel. */
	for (cpu = d->cpus; cpu; cpu = cpu->next) {
		if (cpu->pid == pid)
			return 0;
	}

	if (d->is_64bit) {
		struct kd_elf_prstatus64 *pr;

		pr = malloc(sizeof(*pr) + d->pt_regs_size);
		if (!pr)
			goto out_no_mem;
		memset(pr, 0, sizeof(*pr));
		data = pr;

		d->store32(&pr->pr_pid, pid);
		pt_regsptr = ((char *) pr) + sizeof(*pr);
		len = sizeof(*pr) + d->pt_regs_size;
	} else {
		struct kd_elf_prstatus32 *pr;

		pr = malloc(sizeof(*pr) + d->pt_regs_size);
		if (!pr)
			goto out_no_mem;
		memset(pr, 0, sizeof(*pr));
		data = pr;

		d->store32(&pr->pr_pid, pid);
		pt_regsptr = ((char *) pr) + sizeof(*pr);
		len = sizeof(*pr) + d->pt_regs_size;
	}

	memset(pt_regsptr, 0, d->pt_regs_size);
	rv = d->fetch_ptregs(d, task, pt_regsptr);
	if (rv)
		goto out_err;

	rv = elfc_add_note(d->velf, NT_PRSTATUS, "CORE", 5, data, len);
	if (rv)
		pr_err("Unable to add thread info note: %s\n",
		       strerror(elfc_get_errno(d->velf)));

out_err:
	free(data);

	return rv;

out_no_mem:
	pr_err("Out of memory creating thread info note\n");
	return -1;
}

static int
tovelf(int argc, char *argv[])
{
	char *outfile = NULL;
	char *infile = NULL;
	char *vmcore = "/proc/vmcore";
	static const struct option longopts[] = {
		{ "help",	no_argument,		NULL, 'h' },
		{ "infile",	required_argument,	NULL, 'i' },
		{ "outfile",	required_argument,	NULL, 'o' },
		{ "vmcore",	required_argument,	NULL, 'v' },
		{ "intype",	required_argument,	NULL, 'I' },
		{ "physpgd",	required_argument,	NULL, 'P' },
		{ "elfclass",	required_argument,	NULL, 'c' },
		{ "level",	required_argument,	NULL, 'l' },
		{ "debug",	no_argument,		NULL, 'd' },
		{ "vmlinux",	required_argument,	NULL, 'm' },
		{ "extravminfo",required_argument,	NULL, 'e' },
		{ "procthreads",no_argument,		NULL, 'p' },
		{ NULL }
	};
	static const char *helpstr[] = {
		"This info",
		"The input file, defaults to unused if intype is oldmem,"
		" otherwise required",
		"File send output to, stdout if not specified",
		"The vmcore file, defaults to /proc/vmcore, only for oldmem",
		"The file type, either pelf or oldmem, defaults to pelf",
		"The physical address of the kernel page descriptor",
		"Set the elfclass (either 32 or 64)",
		"Set the dump level: all, inuse, user, cache, or kernel",
		"Increment the debug level",
		"Set the vmlinux file for this build, required if the dumped"
		" kernel has a randomized base to set the offset (or use"
		" addrandomoffset later).",
		"Override or add new vminfo information",
		"Convert kernel processes/threads into gdb threads",
		NULL
	};
	int fd = -1;
	int ofd = 1;
	int rv = 0;
	struct kdt_data kdt_data, *d = &kdt_data;
	int pgd_set = 0;
	struct elfc *velf = NULL;
	struct vmcoreinfo_data vmci[] = {
		VMCI_ADDRESS(phys_pgd_ptr),
		VMCI_SIZE(list_head),
		VMCI_OFFSET(list_head, next),
		VMCI_OFFSET(list_head, prev),
		VMCI_SYMBOL(_stext),
		VMCI_PAGESIZE(),
		{ NULL }
	};
	int do_oldmem = 0;
	struct velf_data dpage;
	int elfclass = ELFCLASSNONE;
	int level = DUMP_KERNEL;
	char *vmlinux = NULL;
	char *extra_vminfofile = NULL;
	bool proc_threads = false;

	memset(d, 0, sizeof(*d));
	for (;;) {
		int curr_optind = optind;
		int c = getopt_long(argc, argv, "+ho:i:v:I:P:c:l:dm:e:p",
				    longopts, NULL);
		if (c == -1)
			break;
		switch (c) {
		case 'o':
			outfile = optarg;
			break;
		case 'i':
			infile = optarg;
			break;
		case 'v':
			vmcore = optarg;
			break;
		case 'e':
			extra_vminfofile = optarg;
			break;
		case 'p':
			proc_threads = true;
			break;
		case 'I':
			if (strcmp(optarg, "oldmem") == 0) {
				do_oldmem = 1;
			} else if (strcmp(optarg, "pelf") == 0) {
				do_oldmem = 0;
			} else {
				subcmd_usage("Unknown input type: %s\n",
					     optarg);
			}
			break;
		case 'P': {
			char *end;

			d->pgd = strtoull(optarg, &end, 0);
			if ((end == optarg) || (*end != '\0'))
				subcmd_usage("Invalid pgd number: %s\n",
					     optarg);
			pgd_set = 1;
			break;
		}
		case 'c':
			if (strcmp(optarg, "32") == 0) {
				elfclass = ELFCLASS32;
			} else if (strcmp(optarg, "64") == 0) {
				elfclass = ELFCLASS64;
			} else {
				subcmd_usage("Unknown ELF class: %s\n",
					     optarg);
			}
			break;
		case 'l':
			level = process_levels(optarg);
			if (level == -1) {
				subcmd_usage("Unknown dump level: %s\n",
					     optarg);
			}
			break;
		case 'm':
			vmlinux = optarg;
			break;
		case 'h':
			subcmd_help("", longopts, helpstr);
			return 0;
		case 'd':
			debug++;
			break;
		case '?':
			subcmd_usage("Unknown option: %s\n", argv[curr_optind]);
		}
	}

	d->level = level;

	if (optind < argc) {
		subcmd_usage("Too many arguments, starting at %s\n",
			     argv[optind]);
		goto out_err;
	}

	if (extra_vminfofile) {
		rv = read_vminfofile(extra_vminfofile, &d->extra_vminfo);
		if (rv) {
			pr_err("Unable to read vminfofile %s: %s\n",
			       extra_vminfofile, strerror(rv));
			goto out_err;
		}
	}

	if (do_oldmem) {
		d->elf = read_oldmem(infile, vmcore, d->extra_vminfo);
		if (!d->elf)
			goto out_err;
	} else {
		if (!infile)
			subcmd_usage("No input file specified\n");
		fd = open(infile, O_RDONLY);
		if (fd == -1) {
			pr_err("Unable to open %s: %s\n", infile,
				strerror(errno));
			goto out_err;
		}
		d->elf = elfc_alloc();
		if (!d->elf) {
			pr_err("Out of memory allocating elf obj\n");
			goto out_err;
		}
		rv = elfc_open(d->elf, fd);
		if (rv) {
			pr_err("Unable to elfc open %s: %s\n", infile,
				strerror(elfc_get_errno(d->elf)));
			goto out_err;
		}
		fd = -1;
	}

	handle_vminfo_notes(d->elf, vmci, d->extra_vminfo);

	rv = process_base_vmci(d, vmci, d->elf);
	if (rv)
		goto out_err;

	if (!pgd_set) {
		if (vmci[VMCI_ADDRESS_phys_pgd_ptr].found)
			d->pgd = vmci[VMCI_ADDRESS_phys_pgd_ptr].val;
		else {
			pr_err("pgd not given and not in input file.\n");
			goto out_err;
		}
	}

	if (outfile) {
		ofd = creat(outfile, 0644);
		if (ofd == -1) {
			pr_err("Unable to open %s: %s\n", outfile,
				strerror(errno));
			goto out_err;
		}
	}

	velf = elfc_alloc();
	if (!velf) {
		pr_err("Out of memory allocating elf obj\n");
		goto out_err;
	}
	d->velf = velf;
	rv = elfc_setup(velf, elfc_gettype(d->elf));
	if (rv == -1) {
		pr_err("Error writing elfc file: %s\n",
			strerror(elfc_get_errno(d->elf)));
		goto out_err;
	}
	elfc_setmachine(velf, elfc_getmachine(d->elf));
	elfc_setencoding(velf, elfc_getencoding(d->elf));
	copy_elf_notes(velf, d->elf, add_cpu_info, d);

	elfc_set_fd(velf, ofd);

	if (proc_threads) {
		rv = handle_kernel_processes_threads(d, add_proc_thread, NULL);
		if (rv)
			goto out_err;
	}

	rv = read_page_maps(d);
	if (rv == -1)
		goto out_err;

	if (elfclass == ELFCLASSNONE) {
		elfc_setclass(velf, d->arch->default_elfclass);
	} else {
		elfc_setclass(velf, elfclass);
	}

	memset(&dpage, 0, sizeof(dpage));
	dpage.velf = velf;
	dpage.d = d;
	rv = d->arch->walk_page_table(d->elf, d->pgd, 0, ~((GElf_Addr) 0),
				      d->arch_data, velf_page_handler, &dpage);
	if (rv == -1)
		goto out_err;

	rv = flush_dpage(d->elf, &dpage);
	if (rv == -1)
		goto out_err;

	if (ofd != 1)
		/* Don't print stuff if the elf file goes to stdout */
		print_skipped(d);

	if (vmlinux) {
		rv = add_auxv(velf, vmlinux, vmci[VMCI_SYMBOL__stext].val);
		if (rv == -1)
			pr_err("Warning: Unable to add auxv: %s\n",
				strerror(elfc_get_errno(d->elf)));
	}

	rv = elfc_write(velf);
	if (rv == -1) {
		pr_err("Error writing elfc file: %s\n",
			strerror(elfc_get_errno(d->elf)));
		goto out_err;
	}

out:
	if (d->arch && d->arch_data)
		d->arch->cleanup_arch_data(d->arch_data);
	if (fd != -1)
		close(fd);
	if (velf)
		elfc_free(velf);
	if (d->elf) {
		close(elfc_get_fd(d->elf));
		elfc_free(d->elf);
	}
	if ((ofd != -1) && (ofd != 1))
		close(ofd);
	return rv;

out_err:
	rv = 1;
	goto out;
}

static int
addrandomoffset(int argc, char *argv[])
{
	int rv = 1;
	struct elfc *velf = NULL;
	int vfd = -1;
	int i;
	int num_notes;
	struct vmcoreinfo_data vmci[] = {
		VMCI_ADDRESS(phys_pgd_ptr),
		VMCI_SIZE(list_head),
		VMCI_OFFSET(list_head, next),
		VMCI_OFFSET(list_head, prev),
		VMCI_SYMBOL(_stext),
		{ NULL }
	};
	static const struct option longopts[] = {
		{ "help",	no_argument,		NULL, 'h' },
		{ "vmcore",	required_argument,	NULL, 'v' },
		{ "vmlinux",	required_argument,	NULL, 'm' },
		{ "extravminfo",required_argument,	NULL, 'e' },
		{ NULL }
	};
	static const char *helpstr[] = {
		"This info",
		"The vmcore file, required",
		"Set the vmlinux file for this core, required.",
		"Override or add new vminfo information",
		NULL
	};
	const char *vmcore = NULL, *vmlinux = NULL;
	char *extra_vminfofile = NULL;
	char *extra_vminfo = NULL;

	for (;;) {
		int curr_optind = optind;
		int c = getopt_long(argc, argv, "+hv:m:e:", longopts,
				    NULL);
		if (c == -1)
			break;
		switch (c) {
		case 'v':
			vmcore = optarg;
			break;
		case 'm':
			vmlinux = optarg;
			break;
		case 'e':
			extra_vminfofile = optarg;
			break;
		case 'h':
			subcmd_help("", longopts, helpstr);
			return 0;
		case '?':
			subcmd_usage("Unknown option: %s\n", argv[curr_optind]);
		}
	}

	if (!vmcore) {
		pr_err("No vmcore file given\n");
		goto out;
	}

	if (!vmlinux) {
		pr_err("No vmlinux file given\n");
		goto out;
	}

	if (extra_vminfofile) {
		rv = read_vminfofile(extra_vminfofile, &extra_vminfo);
		if (rv) {
			pr_err("Unable to read vminfofile %s: %s\n",
			       extra_vminfofile, strerror(rv));
			goto out;
		}
	}

	velf = elfc_alloc();
	if (!velf) {
		pr_err("Unable to allocate ELF data for %s\n", vmcore);
		goto out;
	}
	vfd = open(vmcore, O_RDWR);
	if (vfd == -1) {
		pr_err("Error opening %s: %s\n", vmcore,
			strerror(errno));
		goto out;
	}

	if (elfc_open(velf, vfd) == -1) {
		pr_err("Error elf opening %s: %s\n", vmcore,
			strerror(elfc_get_errno(velf)));
		goto out;
	}

	handle_vminfo_notes(velf, vmci, extra_vminfo);
	if (!vmci[VMCI_SYMBOL__stext].found) {
		pr_err("No _stext symbol found in %ss notes\n",
			vmcore);
		goto out;
	}

	num_notes = elfc_get_num_notes(velf);
	for (i = 0; i < num_notes; i++) {
		GElf_Word note_type;
		rv = elfc_get_note(velf, i, &note_type, NULL, NULL, NULL, NULL);
		if (rv == -1) {
			pr_err("Error getting note from %s: %s\n",
				vmcore, strerror(elfc_get_errno(velf)));
			goto out;
		}

		if (note_type != NT_AUXV)
			continue;

		rv = elfc_del_note(velf, i);
		if (rv == -1) {
			pr_err("Error getting auxv from %s: %s\n",
				vmcore, strerror(elfc_get_errno(velf)));
			goto out;
		}
		break;
	}

	rv = add_auxv(velf, vmlinux, vmci[VMCI_SYMBOL__stext].val);
	if (rv == -1)
		pr_err("Unable to add auxv: %s\n",
			strerror(elfc_get_errno(velf)));
	else if (rv == 1) {
		rv = elfc_write(velf);
		if (rv == -1) {
			pr_err("Unable to write elf file: %s\n",
				strerror(elfc_get_errno(velf)));
		}
	}
out:
	if (velf)
		elfc_free(velf);
	if (vfd)
		close(vfd);

	return rv;
}


static int makedyn_one_exec(const char *file)
{
	int fd, rv;
	unsigned char e_ident[EI_NIDENT + 2];
	Elf64_Half type;

	fd = open(file, O_RDWR);
	if (fd == -1) {
		pr_err("Unable to open %s: %s\n", file,
			strerror(errno));
		return 1;
	}

	rv = read(fd, e_ident, sizeof(e_ident));
	if (rv == -1) {
		pr_err("Unable to read %s: %s\n", file,
			strerror(errno));
		goto out_err;
	}
	if (rv < sizeof(e_ident)) {
		pr_err("Only able to read %d bytes from %s\n",
			rv, file);
		goto out_err;
	}
	if (memcmp(ELFMAG, e_ident, SELFMAG) != 0) {
		pr_err("%s not an ELF file\n", file);
		goto out_err;
	}

	if (e_ident[EI_DATA] == ELFDATA2LSB) {
		type = e_ident[EI_NIDENT] | e_ident[EI_NIDENT + 1] << 8;
	} else if (e_ident[EI_DATA] == ELFDATA2MSB) {
		type = e_ident[EI_NIDENT + 1] | e_ident[EI_NIDENT] << 8;
	} else {
		pr_err("%s: Unknown data encoding: %d\n", file,
			e_ident[EI_DATA]);
		goto out_err;
	}

	if (type == ET_DYN) {
		/* Already dynamic. */
		return 0;
	}
	if (type != ET_EXEC) {
		pr_err("%s: Not a fixed executable, type is: %d\n",
			file, type);
		goto out_err;
	}

	type = ET_DYN;
	if (e_ident[EI_DATA] == ELFDATA2LSB) {
		e_ident[EI_NIDENT] = type & 0xff;
		e_ident[EI_NIDENT + 1] = type >> 8;
	} else if (e_ident[EI_DATA] == ELFDATA2MSB) {
		e_ident[EI_NIDENT + 1] = type & 0xff;
		e_ident[EI_NIDENT] = type >> 8;
	}

	rv = lseek(fd, EI_NIDENT, SEEK_SET);
	if (rv == -1) {
		pr_err("Unable to seek %s: %s\n", file,
			strerror(errno));
		goto out_err;
	}

	rv = write(fd, e_ident + EI_NIDENT, sizeof(type));
	if (rv == -1) {
		pr_err("Unable to write to %s: %s\n", file,
			strerror(errno));
		goto out_err;
	}

	close(fd);
	return 0;

out_err:
	close(fd);
	return 1;
}

static int
makedyn(int argc, char *argv[])
{
	int rv = 0;
	static struct option longopts[] = {
		{ "help",	no_argument,	NULL, 'h' },
		{ NULL }
	};
	static const char *helpstr[] = {
		"This info",
		NULL
	};

	for (;;) {
		int curr_optind = optind;
		int c = getopt_long(argc, argv, "+h", longopts, NULL);
		if (c == -1)
			break;
		switch (c) {
		case 'h':
			subcmd_help(" <vmlinux> [<vmlinux> [...]]",
				    longopts, helpstr);
			return 0;
		case '?':
			subcmd_usage("Unknown option: %s\n", argv[curr_optind]);
		}
	}

	while (optind < argc) {
		rv = makedyn_one_exec(argv[optind]);
		if (rv)
			break;
		optind++;
	}

	return rv;
}

static void
dump_memory(unsigned char *buf, GElf_Addr addr, size_t size)
{
	char cbuf[17];

	cbuf[16] = '\0';
	while (size >= 16) {
		int i;

		for (i = 0; i < 16; i++)
			cbuf[i] = isprint(buf[i]) ? buf[i] : '.';
		printf("%llx: %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x  %s\n",
		       (unsigned long long) addr,
		       buf[0], buf[1], buf[2], buf[3],
		       buf[4], buf[5], buf[6], buf[7],
		       buf[8], buf[9], buf[10], buf[11],
		       buf[12], buf[13], buf[14], buf[15], cbuf);
		buf += 16;
		size -= 16;
		addr += 16;
	}
	if (size > 0) {
		int i;

		printf("%llx:", (unsigned long long) addr);
		for (i = 0; i < size; i++) {
			cbuf[i] = isprint(buf[i]) ? buf[i] : '.';
			printf(" %2.2x", buf[i]);
		}
		for (; i < 16; i++) {
			cbuf[i] = isprint(buf[i]) ? buf[i] : ' ';
			printf("   ");
		}
		printf("%s\n", cbuf);
	}
}

static int
dumpmem(int argc, char *argv[])
{
	char *infile = NULL;
	char *vmcore = "/proc/vmcore";
	static const struct option longopts[] = {
		{ "help",	no_argument,		NULL, 'h' },
		{ "infile",	required_argument,	NULL, 'i' },
		{ "vmcore",	required_argument,	NULL, 'v' },
		{ "intype",	required_argument,	NULL, 'I' },
		{ "is_physical",no_argument,		NULL, 'p' },
		{ "extravminfo",required_argument,	NULL, 'e' },
		{ NULL }
	};
	static const char *helpstr[] = {
		"This info",
		"The input file, defaults to unused if intype is oldmem,"
		" otherwise required",
		"The vmcore file, defaults to /proc/vmcore, only for oldmem",
		"The file type, either pelf or oldmem, defaults to pelf",
		"Is the address physical or virtual?",
		"Override or add new vminfo information",
		"<addr> - Start address",
		"<size> - Number of bytes to dump",
		NULL
	};
	int fd = -1;
	int rv = 0;
	struct elfc *elf = NULL;
	int do_oldmem = 0;
	GElf_Addr addr;
	GElf_Addr size;
	int is_phys = 0;
	char *endc;
	void *buf;
	char *extra_vminfofile = NULL;
	char *extra_vminfo = NULL;

	for (;;) {
		int curr_optind = optind;
		int c = getopt_long(argc, argv, "+hi:v:I:pe:", longopts,
				    NULL);
		if (c == -1)
			break;
		switch (c) {
		case 'i':
			infile = optarg;
			break;
		case 'v':
			vmcore = optarg;
			break;
		case 'e':
			extra_vminfofile = optarg;
			break;
		case 'I':
			if (strcmp(optarg, "oldmem") == 0) {
				do_oldmem = 1;
			} else if (strcmp(optarg, "pelf") == 0) {
				do_oldmem = 0;
			} else {
				subcmd_usage("Unknown input type: %s\n",
					     optarg);
			}
			break;
		case 'h':
			subcmd_help(" <addr> <size>", longopts, helpstr);
			return 0;
		case 'p':
			is_phys = 1;
			break;
		case '?':
			subcmd_usage("Unknown option: %s\n", argv[curr_optind]);
		}
	}

	if (optind >= argc) {
		subcmd_usage("Start address not given\n");
		return 1;
	}
	addr = strtoull(argv[optind], &endc, 16);
	if (*endc != '\0') {
		subcmd_usage("Invalid start address: %s\n",
			     argv[optind]);
		return 1;
	}
	optind++;

	if (optind >= argc) {
		subcmd_usage("Dump size not given\n");
		return 1;
	}
	size = strtoull(argv[optind], &endc, 16);
	if (*endc != '\0') {
		subcmd_usage("Invalid dump size: %s\n",
			     argv[optind]);
		return 1;
	}
	optind++;

	if (optind < argc) {
		subcmd_usage("Too many arguments, starting at %s\n",
			     argv[optind]);
		return 1;
	}

	if (extra_vminfofile) {
		rv = read_vminfofile(extra_vminfofile, &extra_vminfo);
		if (rv) {
			pr_err("Unable to read vminfofile %s: %s\n",
			       extra_vminfofile, strerror(rv));
			goto out_err;
		}
	}

	if (do_oldmem) {
		elf = read_oldmem(infile, vmcore, extra_vminfo);
		if (!elf)
			goto out_err;
	} else {
		if (!infile)
			subcmd_usage("No input file specified\n");
		fd = open(infile, O_RDONLY);
		if (fd == -1) {
			pr_err("Unable to open %s: %s\n", infile,
				strerror(errno));
			goto out_err;
		}
		elf = elfc_alloc();
		if (!elf) {
			pr_err("Out of memory allocating elf obj\n");
			goto out_err;
		}
		rv = elfc_open(elf, fd);
		if (rv) {
			pr_err("Unable to elfc open %s: %s\n", infile,
				strerror(elfc_get_errno(elf)));
			goto out_err;
		}
		fd = -1;
	}

	buf = malloc(size);
	if (!buf) {
		pr_err("Out of memory allocating buffer\n");
		goto out_err;
	}

	if (is_phys)
		rv = elfc_read_pmem(elf, addr, buf, size);
	else
		rv = elfc_read_vmem(elf, addr, buf, size);
	if (rv == -1) {
		pr_err("Unable read data from file: %s\n",
			strerror(elfc_get_errno(elf)));
		goto out_err;
	}

	dump_memory(buf, addr, size);

out:
	if (fd != -1)
		close(fd);
	if (elf) {
		close(elfc_get_fd(elf));
		elfc_free(elf);
	}
	return rv;

out_err:
	rv = 1;
	goto out;
}

static int
virttophys_page_handler(struct elfc *pelf,
			GElf_Addr paddr,
			GElf_Addr vaddr,
			GElf_Addr pgsize,
			void *userdata)
{
	struct velf_data *dpage = userdata;

	if ((dpage->start_vaddr >= vaddr) &&
	    (dpage->start_vaddr < vaddr + pgsize)) {
		printf("%llx\n", ((unsigned long long)
				  paddr + (vaddr - dpage->start_vaddr)));
	}
	return 0;
}

static int
virttophys(int argc, char *argv[])
{
	char *infile = NULL;
	char *vmcore = "/proc/vmcore";
	static const struct option longopts[] = {
		{ "help",	no_argument,		NULL, 'h' },
		{ "infile",	required_argument,	NULL, 'i' },
		{ "vmcore",	required_argument,	NULL, 'v' },
		{ "intype",	required_argument,	NULL, 'I' },
		{ "physpgd",	required_argument,	NULL, 'P' },
		{ "extravminfo",required_argument,	NULL, 'e' },
		{ NULL }
	};
	static const char *helpstr[] = {
		"This info",
		"The input file, defaults to unused if intype is oldmem,"
		" otherwise required",
		"File send output to, stdout if not specified",
		"The vmcore file, defaults to /proc/vmcore, only for oldmem",
		"The file type, either pelf or oldmem, defaults to pelf",
		"The physical address of the kernel page descriptor",
		"<addr> - The address to convert",
		"Override or add new vminfo information",
		NULL
	};
	int fd = -1;
	int rv = 0;
	struct kdt_data kdt_data, *d = &kdt_data;
	int pgd_set = 0;
	struct vmcoreinfo_data vmci[] = {
		VMCI_ADDRESS(phys_pgd_ptr),
		VMCI_SIZE(list_head),
		VMCI_OFFSET(list_head, next),
		VMCI_OFFSET(list_head, prev),
		VMCI_PAGESIZE(),
		{ NULL }
	};
	int do_oldmem = 0;
	struct velf_data dpage;
	GElf_Addr addr;
	char *endc;
	char *extra_vminfofile = NULL;

	memset(d, 0, sizeof(*d));
	for (;;) {
		int curr_optind = optind;
		int c = getopt_long(argc, argv, "+ho:i:v:I:P:c:l:de:", longopts,
				    NULL);
		if (c == -1)
			break;
		switch (c) {
		case 'i':
			infile = optarg;
			break;
		case 'v':
			vmcore = optarg;
			break;
		case 'e':
			extra_vminfofile = optarg;
			break;
		case 'I':
			if (strcmp(optarg, "oldmem") == 0) {
				do_oldmem = 1;
			} else if (strcmp(optarg, "pelf") == 0) {
				do_oldmem = 0;
			} else {
				subcmd_usage("Unknown input type: %s\n",
					     optarg);
			}
			break;
		case 'P': {
			char *end;

			d->pgd = strtoull(optarg, &end, 0);
			if ((end == optarg) || (*end != '\0'))
				subcmd_usage("Invalid pgd number: %s\n",
					     optarg);
			pgd_set = 1;
			break;
		}
		case 'h':
			subcmd_help("", longopts, helpstr);
			return 0;
		case '?':
			subcmd_usage("Unknown option: %s\n", argv[curr_optind]);
		}
	}

	if (optind >= argc) {
		subcmd_usage("Address not given\n");
		return 1;
	}
	addr = strtoull(argv[optind], &endc, 16);
	if (*endc != '\0') {
		subcmd_usage("Invalid address: %s\n", argv[optind]);
		return 1;
	}
	optind++;

	if (optind < argc) {
		subcmd_usage("Too many arguments, starting at %s\n",
			     argv[optind]);
		goto out_err;
	}

	if (extra_vminfofile) {
		rv = read_vminfofile(extra_vminfofile, &d->extra_vminfo);
		if (rv) {
			pr_err("Unable to read vminfofile %s: %s\n",
			       extra_vminfofile, strerror(rv));
			goto out_err;
		}
	}

	if (do_oldmem) {
		d->elf = read_oldmem(infile, vmcore, d->extra_vminfo);
		if (!d->elf)
			goto out_err;
	} else {
		if (!infile)
			subcmd_usage("No input file specified\n");
		fd = open(infile, O_RDONLY);
		if (fd == -1) {
			pr_err("Unable to open %s: %s\n", infile,
				strerror(errno));
			goto out_err;
		}
		d->elf = elfc_alloc();
		if (!d->elf) {
			pr_err("Out of memory allocating elf obj\n");
			goto out_err;
		}
		rv = elfc_open(d->elf, fd);
		if (rv) {
			pr_err("Unable to elfc open %s: %s\n", infile,
				strerror(elfc_get_errno(d->elf)));
			goto out_err;
		}
		fd = -1;
	}

	handle_vminfo_notes(d->elf, vmci, d->extra_vminfo);

	rv = process_base_vmci(d, vmci, d->elf);
	if (rv)
		goto out_err;

	if (!pgd_set) {
		if (vmci[VMCI_ADDRESS_phys_pgd_ptr].found)
			d->pgd = vmci[VMCI_ADDRESS_phys_pgd_ptr].val;
		else {
			pr_err("pgd not given and not in input file.\n");
			goto out_err;
		}
	}

	rv = read_page_maps(d);
	if (rv == -1)
		goto out_err;

	memset(&dpage, 0, sizeof(dpage));
	dpage.start_vaddr = addr;
	dpage.d = d;
	rv = d->arch->walk_page_table(d->elf, d->pgd, 0, ~((GElf_Addr) 0),
				      d->arch_data, virttophys_page_handler,
				      &dpage);
	if (rv == -1)
		goto out_err;

out:
	if (d->arch && d->arch_data)
		d->arch->cleanup_arch_data(d->arch_data);
	if (fd != -1)
		close(fd);
	if (d->elf) {
		close(elfc_get_fd(d->elf));
		elfc_free(d->elf);
	}
	return rv;

out_err:
	rv = 1;
	goto out;
}

static struct list arches = LIST_INIT(arches);

struct archinfo *
find_arch(int elfmachine)
{
	struct archinfo *arch;

	list_for_each_item(&arches, arch, struct archinfo, link) {
		if (arch->elfmachine == elfmachine)
			return arch;
	}
	return NULL;
}

void
add_arch(struct archinfo *arch)
{
	list_add_last(&arches, &arch->link);
}


struct {
	const char *name;
	int (*handler)(int argc, char *argv[]);
	const char *help;
} subcommands[] = {
	{ "topelf", topelf, "Convert /dev/mem to a physical"
	  " elf file" },
	{ "tovelf", tovelf, "Convert /dev/mem or a pelf file to a"
	  " virtual elf file" },
	{ "dumpmem", dumpmem, "Dump raw memory in an elf or oldmem file" },
	{ "virttophys", virttophys, "Convert a virtual address to a"
	  " physical one" },
	{ "addrandoff", addrandomoffset, "Calculate the load offset of a"
	  " randomized base kernel and create an auxv entry so gdb can"
	  " debug it with symbols." },
	{ "makedyn", makedyn, "Set a vmlinux file to by dynamically"
	  " executable so that gdb will load the random offset for a"
	  " randomized base kernel" },
	{ NULL }
};

static void
help(void)
{
	int i;

	printf("Usage: %s <subcommand> <subcommand options>\n", progname);
	printf("Subcommands are:\n");
	for (i = 0; subcommands[i].name; i++)
		printf("  %s: %s\n", subcommands[i].name, subcommands[i].help);
	printf("Use %s <subcommand> -h for help on specific subcommands\n",
	       progname);
}

static void
usage(const char *error, ...)
{
	va_list ap;

	va_start(ap, error);
	fprintf(stderr, "%s: ", progname);
	vfprintf(stderr, error, ap);
	va_end(ap);
	fprintf(stderr, "Use --help for usage information\n");
	exit(1);
}

int
main(int argc, char *argv[])
{
	int i;
	static struct option longopts[] = {
		{ "help",	no_argument,	NULL, 'h' },
		{ NULL }
	};

	progname = argv[0];
	opterr = 0;

	for (;;) {
		int curr_optind = optind;
		int c = getopt_long(argc, argv, "+h", longopts, NULL);
		if (c == -1)
			break;
		switch (c) {
		case 'h':
			help();
			exit(0);
		case '?':
			usage("Unknown option: %s\n", argv[curr_optind]);
		}
	}

	if (optind >= argc) {
		usage("No subcommand given\n");
		exit(1);
	}

	add_arch(&x86_64_arch);
	add_arch(&i386_arch);
	add_arch(&mips_arch);
	add_arch(&arm_arch);
	add_arch(&ppc32_arch);

	for (i = 0; subcommands[i].name; i++) {
		if (strcmp(subcommands[i].name, argv[optind]) == 0)
			break;
	}
	if (!subcommands[i].name) {
		usage("Unknown subcommand: %s\n", argv[optind]);
		exit(1);
	}
	optind++;

	subcmd = subcommands[i].name;
	return subcommands[i].handler(argc, argv);
}
