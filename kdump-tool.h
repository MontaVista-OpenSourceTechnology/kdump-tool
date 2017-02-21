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

/* Standard error printing routing. */
void pr_err(const char *fmt, ...);

/*
 * Copy all the notes from in to out.
 */
int copy_elf_notes(struct elfc *out, struct elfc *in,
		   int (*fixup)(GElf_Word type, const char *name,
				size_t namelen,	void *data, size_t data_len,
				void *userdata),
		   void *userdata);

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
int handle_vminfo_notes(struct elfc *elf, struct vmcoreinfo_data *vals,
			char *extra_vminfo);
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
#define VMCI_CONFIG(lbl)						\
	[VMCI_CONFIG_ ## lbl] = { "CONFIG_" #lbl, VMINFO_YN_BASE, 0, 0 }

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
	int (*vmem_to_pmem)(struct elfc *elf, GElf_Addr vaddr,
			    GElf_Addr *paddr, void *arch_data);
};
struct archinfo *find_arch(int elfmachine);
void add_arch(struct archinfo *arch);

struct elfc *read_oldmem(char *oldmem, char *vmcore, char *extra_vminfo);

int fetch_vaddr_data_err(struct kdt_data *d, GElf_Addr addr, unsigned int len,
			 void *out, char *name);
int fetch_vaddr32(struct kdt_data *d, GElf_Addr addr,
		  uint32_t *out, char *name);
int fetch_vaddr64(struct kdt_data *d, GElf_Addr addr,
		  uint64_t *out, char *name);
int fetch_vaddrlong(struct kdt_data *d, GElf_Addr addr,
		    uint64_t *out, char *name);

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

struct cpu_info {
	unsigned int cpu;
	int32_t pid;
	struct cpu_info *next;
};

struct kdt_data {
	struct elfc *elf;
	struct elfc *velf;
	GElf_Addr pgd;
	struct archinfo *arch;
	void *arch_data;
	bool is_64bit;
	bool is_bigendian;
	unsigned int ptrsize;

	enum dump_levels level;

	uint64_t (*conv64)(void *in);
	uint32_t (*conv32)(void *in);
	void (*store64)(void *out, uint64_t val);
	void (*store32)(void *out, uint32_t val);
	int (*fetch_ptregs)(struct kdt_data *d, GElf_Addr task, void *regs);

	struct cpu_info *cpus;
	unsigned int cpunum;

	char *extra_vminfo;

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

	/* Offsets for task struct and friends. */
	unsigned int task_stack;
	unsigned int task_tasks_next;
	unsigned int task_thread_node;
	unsigned int task_signal;
	unsigned int signal_thread_head;
	unsigned int task_pid;
	unsigned int task_thread;
	bool mips_task_resume_found;
	uint64_t mips_task_resume;
	bool thread_sp_found; /* x86-only for now, maybe others. */
	uint64_t thread_sp;
	bool x86___thread_sleep_point_found;
	uint64_t x86___thread_sleep_point;
	bool x86_context_switch_frame_size_found;
	uint64_t x86_context_switch_frame_size;

	/* Set by arch code. */
	unsigned int section_size_bits;
	unsigned int max_physmem_bits;
	unsigned int pt_regs_size;

	/* Other */
	unsigned int pages_per_section;

	int buddy_mapcount_found;
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

	uint64_t skipped_not_present;
	uint64_t skipped_free;
	uint64_t skipped_cache;
	uint64_t skipped_user;
	uint64_t skipped_poison;
	uint64_t not_skipped;
};

extern struct archinfo x86_64_arch;
extern struct archinfo i386_arch;
extern struct archinfo mips_arch;
extern struct archinfo arm_arch;
extern struct archinfo ppc32_arch;

/*
 * All the following structures are stolen and modified from
 * include/linux/elfcore.h and adjusted so they can work cross.
 */
struct kd_elf_siginfo
{
	int32_t	si_signo;			/* signal number */
	int32_t	si_code;			/* extra code */
	int32_t	si_errno;			/* errno */
};

typedef int32_t kd_pid_t;
typedef struct { int32_t tv_sec; int32_t tv_usec; } kd_timeval32_t;
typedef struct { int64_t tv_sec; int64_t tv_usec; } kd_timeval64_t;

struct kd_elf_prstatus32
{
	struct kd_elf_siginfo pr_info;
	int16_t	pr_cursig;
	uint32_t pr_sigpend;
	uint32_t pr_sighold;
	kd_pid_t pr_pid;
	kd_pid_t pr_ppid;
	kd_pid_t pr_pgrp;
	kd_pid_t pr_sid;
	kd_timeval32_t pr_utime;
	kd_timeval32_t pr_stime;
	kd_timeval32_t pr_cutime;
	kd_timeval32_t pr_cstime;
	/* unsigned char pr_regs[n]; */
};

struct kd_elf_prstatus64
{
	struct kd_elf_siginfo pr_info;
	int16_t	pr_cursig;
	uint64_t pr_sigpend;
	uint64_t pr_sighold;
	kd_pid_t pr_pid;
	kd_pid_t pr_ppid;
	kd_pid_t pr_pgrp;
	kd_pid_t pr_sid;
	kd_timeval64_t pr_utime;
	kd_timeval64_t pr_stime;
	kd_timeval64_t pr_cutime;
	kd_timeval64_t pr_cstime;
	/* unsigned char pr_regs[n]; */
};

#endif /* KDUMPTOOL_H */
