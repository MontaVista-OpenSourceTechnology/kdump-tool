/*
 * kdumptool.h
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

#ifndef KDUMPTOOL_H
#define KDUMPTOOL_H

#define _FILE_OFFSET_BITS 64

#include <stdbool.h>
#include <getopt.h>

#include "elfc.h"
#include "list.h"

extern const char *progname;
extern const char *subcmd;

void subcmd_usage(const char *error, ...);
void subcmd_help(const char *extra, const struct option *longopts,
		 const char *helpstr[]);

int parse_memrange(const char *str, uint64_t *start, uint64_t *size);

/*
 * Copy all the notes from in to out.
 */
int copy_elf_notes(struct elfc *out, struct elfc *in);

/*
 * Scan the vmcoreinfo in the notes looking for values.  A value
 * matching "name" will be hunted for.  If found, "found" will be set
 * to true and the value will be extracted using "base" (like base 10,
 * base 16, zero means use C conventions) and stored in "val".  If
 * base is VMINFO_YN_BASE, val is 1 if the part after the "=" is 'y'
 * and 0 otherwise.
 */
struct vmcoreinfo_data {
	char *name;
	int base;
	int found;
	uint64_t val;
};
int handle_vminfo_notes(struct elfc *elf, struct vmcoreinfo_data *vals);
#define VMINFO_YN_BASE		-1

#define VMCI_ADDRESS(lbl)						\
	[VMCI_ADDRESS_ ## lbl] = { "ADDRESS(" #lbl ")", 16, 0, 0 }
#define VMCI_PAGESIZE()						\
	[VMCI_PAGESIZE] = { "PAGESIZE", 10, 0, 0 }
#define VMCI_NUMBER(lbl)						\
	[VMCI_NUMBER_ ## lbl] = { "NUMBER(" #lbl ")", 10, 0, 0 }
#define VMCI_SYMBOL(lbl)						\
	[VMCI_SYMBOL_ ## lbl] = { "SYMBOL(" #lbl ")", 16, 0, 0 }
#define VMCI_SIZE(lbl)						\
	[VMCI_SIZE_ ## lbl] = { "SIZE(" #lbl ")", 10, 0, 0 }
#define VMCI_LENGTH(lbl)						\
	[VMCI_LENGTH_ ## lbl ] = { "LENGTH(" #lbl ")", 10, 0, 0 }
#define VMCI_SLENGTH(str, elem)						\
	[VMCI_LENGTH_ ## str ## __ ## elem] = { "LENGTH(" #str "." #elem ")", \
	 10, 0, 0 }
#define VMCI_OFFSET(str, elem)						\
	[VMCI_OFFSET_ ## str ## __ ## elem] = { "OFFSET(" #str "." #elem ")", \
	 10, 0, 0 }

/*
 * Search for, and call handler on, every instance of the given entry
 * name in the vmcoreinfo note.
 */
int find_vmcore_entries(struct elfc *elf, const char *entry,
			int (*handler)(const char *name, const char *str,
				       int strlen, void *userdata),
			void *userdata);

#define divide_round_up(x, y) (((x) + ((y) - 1)) / (y))

typedef int (*handle_page_f)(struct elfc *pelf,
			     GElf_Addr paddr,
			     GElf_Addr vaddr,
			     GElf_Addr pgsize,
			     void *userdata);

struct kdt_data;

struct page_info {
	uint64_t flags; /* unsigned long */
	uint32_t count; /* atomic_t */
	uint32_t mapcount; /* atomic_t */
	GElf_Addr mapping;
#define PAGE_MAPPING_ANON	(1)
	GElf_Addr lru[2]; /* list_head */
	uint64_t private; /* unsigned long */
};

struct archinfo {
	struct link link; /* For internal use */
	char *name;
	int  elfmachine;
	int  default_elfclass;
	int (*setup_arch_pelf)(struct elfc *pelf, struct kdt_data *data,
			       void **arch_data);
	void (*cleanup_arch_data)(void *arch_data);
	int (*walk_page_table)(struct elfc *pelf, GElf_Addr pgd,
			       GElf_Addr begin_addr, GElf_Addr end_addr,
			       void *arch_data,
			       handle_page_f handle_page,
			       void *userdata);
	bool (*skip_this_page_vaddr)(struct kdt_data *d,
				     GElf_Addr vaddr);
	bool (*skip_this_page_paddr)(struct kdt_data *d,
				     struct page_info *page,
				     GElf_Addr vaddr, GElf_Addr paddr);
};
struct archinfo *find_arch(int elfmachine);
void add_arch(struct archinfo *arch);

struct elfc *read_oldmem(char *oldmem, char *vmcore);

struct page_range {
	struct link link;
	uint64_t start_page;
	uint64_t nr_pages;
	GElf_Addr mapaddr;
	unsigned char *bitmap;
};

enum dump_levels {
	DUMP_ALL,
	DUMP_INUSE,
	DUMP_USER,
	DUMP_CACHE,
	DUMP_KERNEL
};

struct kdt_data {
	struct elfc *elf;
	GElf_Addr pgd;
	struct archinfo *arch;
	void *arch_data;
	bool is_64bit;
	bool is_bigendian;
	unsigned int ptrsize;

	enum dump_levels level;

	GElf_Addr crashkernel_start;
	GElf_Addr crashkernel_end;

	uint64_t (*conv64)(void *in);
	uint32_t (*conv32)(void *in);

	unsigned int list_head_size;
	unsigned int list_head_next_offset;
	unsigned int list_head_prev_offset;

	unsigned int page_size;
	unsigned char *pagedata; /* Temporary working data for a struct page */
	unsigned int page_shift;

	/* Offsets into struct page */
	unsigned int size_page;
	unsigned int page_flags_offset;
	unsigned int page_count_offset;
	unsigned int page_mapping_offset;
	unsigned int page_lru_offset;
	unsigned int page_mapcount_offset;
	unsigned int page_private_offset;

	/* page flag bits */
	uint64_t PG_lru;
	uint64_t PG_private;
	uint64_t PG_swapcache;
	uint64_t PG_slab;
	uint64_t PG_poison;

	/* struct pglist_data offsets */
	unsigned int pglist_data_size;
	unsigned int node_zones_offset;
	unsigned int nr_zones_offset;
	unsigned int node_start_pfn_offset;
	unsigned int node_spanned_pages_offset;
	unsigned int node_mem_map_offset;

	/* struct zones offsets */
	unsigned int zone_size;
	unsigned int free_area_offset;
	unsigned int free_area_length;

	/* struct free_area offsets */
	unsigned int free_area_size;
	unsigned int free_list_offset;
	unsigned int free_list_length;

	/* Set by arch code. */
	unsigned int section_size_bits;
	unsigned int max_physmem_bits;

	/* Other */
	unsigned int pages_per_section;

	unsigned int buddy_mapcount;
	uint64_t NR_FREE_PAGES; 

	/* sparsemem */
	uint64_t sections_per_root;
	/* struct mem_section */
	unsigned int mem_section_size;
	unsigned int mem_section_length;
	unsigned int section_mem_map_offset;
#define	SECTION_MARKED_PRESENT	(1ULL<<0)
#define SECTION_HAS_MEM_MAP	(1ULL<<1)
#define SECTION_MAP_LAST_BIT	(1ULL<<2)
#define SECTION_MAP_MASK	(~(SECTION_MAP_LAST_BIT-1))

	struct list page_maps;

	uint64_t skipped_free;
	uint64_t skipped_cache;
	uint64_t skipped_user;
	uint64_t skipped_poison;
	uint64_t skipped_arch_vaddr;
	uint64_t skipped_arch_paddr;
	uint64_t skipped_crashkernel;
	uint64_t not_skipped;
};

extern struct archinfo x86_64_arch;
extern struct archinfo i386_arch;
extern struct archinfo mips_arch;
extern struct archinfo arm_arch;

#endif /* KDUMPTOOL_H */
