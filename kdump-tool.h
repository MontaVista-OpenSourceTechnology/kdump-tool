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

#include <getopt.h>

#include "elfc.h"
#include "list.h"

extern const char *progname;
extern const char *subcmd;

void subcmd_usage(const char *error, ...);
void subcmd_help(const char *extra, const struct option *longopts,
		 const char *helpstr[]);

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

/*
 * Search for, and call handler on, every instance of the given entry
 * name in the vmcoreinfo note.
 */
int find_vmcore_entries(struct elfc *elf, const char *entry,
			int (*handler)(const char *name, const char *str,
				       int strlen, void *userdata),
			void *userdata);


typedef int (*handle_page_f)(struct elfc *pelf,
			     GElf_Addr paddr,
			     GElf_Addr vaddr,
			     GElf_Addr pgsize,
			     void *userdata);

struct archinfo {
	struct link link; /* For internal use */
	char *name;
	int  elfmachine;
	int  default_elfclass;
	int (*walk_page_table)(struct elfc *pelf, GElf_Addr pgd,
			       handle_page_f handle_page,
			       void *userdata);
};
struct archinfo *find_arch(int elfmachine);
void add_arch(struct archinfo *arch);

struct elfc *read_oldmem(char *oldmem, char *vmcore);

extern struct archinfo x86_64_arch;
extern struct archinfo i386_arch;
extern struct archinfo mips_arch;
extern struct archinfo arm_arch;

#endif /* KDUMPTOOL_H */
