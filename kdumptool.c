/*
 * kdumptool.c
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
#include "kdumptool.h"

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
#include "elfhnd.h"

const char *progname;
const char *subcmd;

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

static int
handle_vmcoreinfo(struct vmcoreinfo_data *vals, const char *data, size_t len)
{
	size_t off = 0;

	while (off < len) {
		int i;
		size_t next_off = off;

		if (*(data + next_off) == '\0')
			break;
		while (next_off < len) {
			if (*(data + next_off) == '\n')
				break;
			if (*(data + next_off) == '\0')
				break;
			next_off++;
		}
		/*
		 * This is to ensure that the strtoull() will not go
		 * past the end of the data.  Require that the string
		 * end in \n or \0.
		 */
		if (next_off >= len)
			return -1;
		next_off++;

		for (i = 0; vals[i].name; i++) {
			char *name = vals[i].name;
			int namesize = strlen(name);
			uint64_t val;
			char *end;

			if (off + namesize >= next_off)
				continue;
			if (strncmp(data + off, name, namesize) != 0)
				continue;
			off += namesize;
			if (vals[i].base == VMINFO_YN_BASE) {
				if (*(data + off) == 'y')
					val = 1;
				else
					val = 0;
			} else {
				val = strtoull(data + off, &end, vals[i].base);
				if ((*end != '\n') && (*end != '\0'))
					continue;
			}
			vals[i].val = val;
			vals[i].found = 1;
			break;
		}
		off = next_off;
	}
	return 0;
}

int
handle_vminfo_notes(struct elfc *elf, struct vmcoreinfo_data *vals)
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

		handle_vmcoreinfo(vals, data, datalen);
	}

	return rv;
}

int
copy_elf_notes(struct elfc *out, struct elfc *in)
{
	int i;
	int nr_notes = elfc_get_num_notes(in);

	if (nr_notes == -1)
		return -1;

	for (i = 0; i < nr_notes; i++) {
		const char *name;
		const void *data;
		size_t namelen, datalen;
		GElf_Word type;
		int rv = elfc_get_note(in, i, &type, &name, &namelen,
				       &data, &datalen);

		if (rv == -1)
			return -1;

		rv = elfc_add_note(out, type, name, namelen, data, datalen);
		if (rv == -1)
			return -1;
	}	
	return 0;
}

static int
topelf(int argc, char *argv[])
{
	char *outfile = NULL;
	char *oldmem = "/dev/oldmem";
	char *vmcore = "/proc/vmcore";
	static const struct option longopts[] = {
		{ "help",	no_argument,		NULL, 'h' },
		{ "oldmem",	required_argument,	NULL, 'i' },
		{ "outfile",	required_argument,	NULL, 'o' },
		{ "vmcore",	required_argument,	NULL, 'v' },
		{ NULL }
	};
	static const char *helpstr[] = {
		"This info",
		"File to use instead of /dev/oldmem",
		"File send output to, instead of stdout",
		"The vmcore file, defaults to /proc/vmcore",
		NULL
	};
	int ofd = -1;
	int rv = 0;
	struct elfc *elf = NULL;
	struct vmcoreinfo_data vmci[] = {
		{ "NUMBER(phys_pgd_ptr)=", 10 },
		{ NULL }
	};

	for (;;) {
		int curr_optind = optind;
		int c = getopt_long(argc, argv, "+ho:i:v:", longopts,
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
		case 'h':
			subcmd_help("", longopts, helpstr);
			return 0;
		case '?':
			subcmd_usage("Unknown option: %s\n", argv[curr_optind]);
		}
	}

	if (optind < argc)
		subcmd_usage("Too many arguments, starting at %s\n",
			     argv[optind]);

	elf = read_oldmem(oldmem, vmcore);
	if (!elf)
		goto out_err;

	handle_vminfo_notes(elf, vmci);
	if (!vmci[0].found)
		fprintf(stderr, "Warning: phys pgd ptr not in vmcore\n");

	if (!outfile)
		subcmd_usage("No output file given\n");

	ofd = creat(outfile, 0644);
	if (ofd == -1) {
		fprintf(stderr, "Unable to open %s: %s\n", outfile,
			strerror(errno));
		rv = -1;
		goto out_err;
	}

	elfc_set_fd(elf, ofd);

	rv = elfc_write(elf);
	if (rv == -1) {
		fprintf(stderr, "Error writing elfc file: %s\n",
			strerror(elfc_get_errno(elf)));
		goto out_err;
	}

out_err:
	if (elf)
		elfc_free(elf);
	if (ofd != -1)
		close(ofd);
	return rv;
}

struct velf_data {
	struct elfc *pelf;
	GElf_Off pelf_base;
	struct elfc *velf;
	GElf_Off velf_base;
	GElf_Addr start_vaddr;
	GElf_Addr next_vaddr;
	GElf_Addr start_paddr;
	GElf_Addr next_paddr;
	GElf_Addr last_pgsize;
	int prev_present;
};

static int
velf_do_write(struct elfc *e, int fd, GElf_Phdr *phdr, void *data,
	      void *userdata)
{
	struct velf_data *d = userdata;
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
		rv = elfc_read_pmem(d->pelf, addr, buf, buf_size);
		if (rv == -1) {
			errno = elfc_get_errno(d->pelf);
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
	struct velf_data *d = userdata;
	int rv;

	if ((off > phdr->p_filesz) || ((off + len) > phdr->p_filesz)) {
		errno = EINVAL;
		return -1;
	}

	rv = elfc_read_pmem(d->pelf, phdr->p_paddr + off, odata, len);
	if (rv == -1) {
		errno = elfc_get_errno(d->pelf);
		return -1;
	}

	return 0;
}

static int
velf_set_data(struct elfc *e, GElf_Phdr *phdr, void *data,
	      GElf_Off off, const void *idata, size_t len,
	      void *userdata)
{
	struct velf_data *d = userdata;
	int rv;

	if ((off > phdr->p_filesz) || ((off + len) > phdr->p_filesz)) {
		errno = EINVAL;
		return -1;
	}

	rv = elfc_write_pmem(d->pelf, phdr->p_paddr + off, idata, len);
	if (rv == -1) {
		errno = elfc_get_errno(d->pelf);
		return -1;
	}

	return 0;
}

static int
gen_new_phdr(struct elfc *pelf, struct velf_data *d)
{
	int rv;

	rv = elfc_add_phdr(d->velf, PT_LOAD,
			   d->start_vaddr,
			   d->start_paddr,
			   d->next_paddr - d->start_paddr,
			   d->next_paddr - d->start_paddr,
			   PF_R | PF_W | PF_X,
			   4096);
	if (rv == -1) {
		fprintf(stderr, "Unable to add phdr: %s\n",
			strerror(elfc_get_errno(d->velf)));
		return -1;
	}
	rv = elfc_set_phdr_data(d->velf, rv, NULL,
				NULL, NULL, velf_do_write, NULL,
				velf_get_data, velf_set_data,
				d);
	if (rv) {
		fprintf(stderr, "Unable to set phdr data: %s\n",
			strerror(elfc_get_errno(d->velf)));
		return -1;
	}

	return 0;
}

static int
velf_page_handler(struct elfc *pelf,
		  GElf_Addr paddr,
		  GElf_Addr vaddr,
		  GElf_Addr pgsize,
		  void *userdata)
{
	struct velf_data *d = userdata;
	GElf_Off dummy;
	int rv;
	int present;

	present = elfc_pmem_file_offset(d->pelf, paddr, pgsize, &dummy) != -1;
	if ((d->next_vaddr != vaddr) || (d->next_paddr != paddr) || !present) {
		if (d->prev_present) {
			rv = gen_new_phdr(pelf, d);
			if (rv == -1)
				return -1;
		}
		d->start_vaddr = vaddr;
		d->start_paddr = paddr;
	}
	if (!d->prev_present) {
		d->start_vaddr = vaddr;
		d->start_paddr = paddr;
	}

	d->prev_present = present;
	d->next_vaddr = vaddr + pgsize;
	d->next_paddr = paddr + pgsize;
	d->last_pgsize = pgsize;
	return 0;
}

static int
velf_cleanup(struct elfc *pelf, struct velf_data *d)
{
	int rv;

	if ((d->next_vaddr - d->last_pgsize) != d->start_vaddr) {
		rv = gen_new_phdr(pelf, d);
		if (rv)
			return -1;
	}
	return 0;
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
		{ NULL }
	};
	static const char *helpstr[] = {
		"This info",
		"The input file, defaults to /dev/oldmem if intype is oldmem, "
		"otherwise required",
		"File send output to, instead of stdout",
		"The vmcore file, defaults to /proc/vmcore, only for oldmem",
		"The file type, either pelf or oldmem, defaults to pelf",
		"The physical address of the kernel page descriptor",
		NULL
	};
	int fd = -1;
	int ofd = -1;
	int rv = 0;
	GElf_Addr pgd;
	int pgd_set = 0;
	struct elfc *elf = NULL, *velf = NULL;
	struct vmcoreinfo_data vmci[] = {
		{ "NUMBER(phys_pgd_ptr)=", 10 },
		{ NULL }
	};
	int do_oldmem = 0;
	struct archinfo *arch;
	struct velf_data d;

	for (;;) {
		int curr_optind = optind;
		int c = getopt_long(argc, argv, "+ho:i:v:I:", longopts,
				    NULL);
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

			pgd = strtoull(optarg, &end, 0);
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

	if (optind < argc) {
		subcmd_usage("Too many arguments, starting at %s\n",
			     argv[optind]);
	}

	if (do_oldmem) {
		if (!infile)
			infile = "/dev/oldmem";
		elf = read_oldmem(infile, vmcore);
		if (!elf)
			goto out_err;
	} else {
		if (!infile)
			subcmd_usage("No input file specified\n");
		fd = open(infile, O_RDONLY);
		if (fd == -1) {
			fprintf(stderr, "Unable to open %s: %s\n", infile,
				strerror(errno));
			goto out_err;
		}
		elf = elfc_alloc();
		if (!elf) {
			fprintf(stderr, "Out of memory allocating elf obj\n");
			goto out_err;
		}
		rv = elfc_open(elf, fd);
		if (rv) {
			fprintf(stderr, "Unable to elfc open %s: %s\n", infile,
				strerror(elfc_get_errno(velf)));
			goto out_err;
		}
		fd = -1;
	}

	if (!pgd_set) {
		handle_vminfo_notes(elf, vmci);
		if (vmci[0].found) {
			pgd = vmci[0].val;
			printf("Found phys pgd ptr = %llx\n",
			       (unsigned long long) pgd);
		} else
			goto nopgd;
	} else {
nopgd:
		fprintf(stderr, "pgd not given and not in input file.\n");
		goto out_err;
	}

	if (!outfile)
		subcmd_usage("No output file given\n");

	ofd = creat(outfile, 0644);
	if (ofd == -1) {
		fprintf(stderr, "Unable to open %s: %s\n", outfile,
			strerror(errno));
		rv = -1;
		goto out_err;
	}

	velf = elfc_alloc();
	if (!velf) {
		fprintf(stderr, "Out of memory allocating elf obj\n");
		goto out_err;
	}
	rv = elfc_setup(velf, elfc_gettype(elf));
	if (rv == -1) {
		fprintf(stderr, "Error writing elfc file: %s\n",
			strerror(elfc_get_errno(elf)));
		goto out_err;
	}
	elfc_setmachine(velf, elfc_getmachine(elf));
	elfc_setclass(velf, elfc_getclass(elf));
	elfc_setencoding(velf, elfc_getencoding(elf));
	copy_elf_notes(velf, elf);

	elfc_set_fd(velf, ofd);

	arch = find_arch(elfc_getmachine(elf));
	if (!arch) {
		fprintf(stderr, "Unknown ELF machine in %s: %d\n", infile,
			elfc_getmachine(elf));
		goto out_err;
	}

	memset(&d, 0, sizeof(d));
	d.velf = velf;
	d.pelf = elf;
	rv = arch->walk_page_table(elf, pgd, velf_page_handler, &d);
	if (rv == -1)
		goto out_err;
	rv = velf_cleanup(elf, &d);
	if (rv == -1)
		goto out_err;

	d.velf_base = elfc_data_offset_start(velf);
	d.pelf_base = elfc_data_offset_start(elf);
	rv = elfc_write(velf);
	if (rv == -1) {
		fprintf(stderr, "Error writing elfc file: %s\n",
			strerror(elfc_get_errno(elf)));
		goto out_err;
	}

out_err:
	if (fd != -1)
		close(fd);
	if (velf)
		elfc_free(velf);
	if (elf) {
		close(elfc_get_fd(elf));
		elfc_free(elf);
	}
	if ((ofd != 1) && (ofd != -1))
		close(ofd);
	return rv;
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
	{ "topelf", topelf, "Convert /dev/oldmem to a physical "
	  "elf file" },
	{ "tovelf", tovelf, "Convert /dev/oldmem or a pelf file to a "
	  "virtual elf file" },
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
