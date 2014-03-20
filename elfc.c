/*
 * elfc.c
 *
 * ELF file handling
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

#define _FILE_OFFSET_BITS 64

#include <endian.h>
#include <gelf.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "elfc.h"

#define elfc_align(v, a) (((v) + (a) - 1) & ~((typeof(v)) (a - 1)))

struct elfc_note {
	Elf64_Word type;
	char *name;
	size_t namelen;
	void *data;
	size_t datalen;
};

struct elfc_phdr {
	GElf_Phdr p;
	void *data;
	void *userdata;
	void (*data_free)(struct elfc *e, void *data, void *userdata);
	int (*pre_write)(struct elfc *e, GElf_Phdr *phdr,
			 void *data, void *userdata);
	int (*do_write)(struct elfc *e, int fd, GElf_Phdr *phdr,
			void *data, void *userdata);
	void (*post_write)(struct elfc *e, GElf_Phdr *phdr,
			   void *data, void *userdata);
	int (*get_data)(struct elfc *e, GElf_Phdr *phdr, void *data,
			GElf_Off off,
			void *odata, size_t len, void *userdata);
	int (*set_data)(struct elfc *e, GElf_Phdr *phdr, void *data,
			GElf_Off off,
			const void *idata, size_t len, void *userdata);
};

struct elfc {
	GElf_Ehdr hdr;
	int eerrno;
	int fd;

	void *userdata;

	GElf_Off after_headers;

	struct elfc_phdr *phdrs;
	int num_phdrs;
	int alloced_phdrs;

	struct elfc_note *notes;
	int num_notes;
	int alloced_notes;
};

static int elfc_read_notes(struct elfc *e);

#define Phdr32_Entries \
	PhdrE(Word,	type);		\
	PhdrE(Off,	offset);	\
	PhdrE(Addr,	vaddr);		\
	PhdrE(Addr,	paddr);		\
	PhdrE(Word,	filesz);	\
	PhdrE(Word,	memsz);		\
	PhdrE(Word,	flags);		\
	PhdrE(Word,	align);

#define Phdr64_Entries \
	PhdrE(Word,	type);		\
	PhdrE(Off,	offset);	\
	PhdrE(Addr,	vaddr);		\
	PhdrE(Addr,	paddr);		\
	PhdrE(Xword,	filesz);	\
	PhdrE(Xword,	memsz);		\
	PhdrE(Word,	flags);		\
	PhdrE(Xword,	align);

static int
extend_phdrs(struct elfc *e)
{
	if (e->num_phdrs == e->alloced_phdrs) {
		struct elfc_phdr *phdrs;

		phdrs = malloc(sizeof(*phdrs) * (e->alloced_phdrs + 32));
		if (!phdrs) {
			e->eerrno = ENOMEM;
			return -1;
		}
		memcpy(phdrs, e->phdrs, sizeof(*phdrs) * e->alloced_phdrs);
		e->alloced_phdrs += 32;
		if (e->phdrs)
			free(e->phdrs);
		e->phdrs = phdrs;
	}
	return 0;
}

int
elfc_insert_phdr(struct elfc *e, int pnum,
		 GElf_Word type, GElf_Addr vaddr, GElf_Addr paddr,
		 GElf_Word filesz, GElf_Word memsz, GElf_Word flags,
		 GElf_Word align)
{
	GElf_Off offset = 0;

	if (pnum > (e->num_phdrs + 1)) {
		e->eerrno = EINVAL;
		return -1;
	}

	if (extend_phdrs(e) == -1)
		return -1;

	memmove(e->phdrs + pnum + 1, e->phdrs + pnum,
		sizeof(*e->phdrs) * (e->num_phdrs - pnum));

	memset(e->phdrs + pnum, 0, sizeof(*e->phdrs));

#define PhdrE(type, name) e->phdrs[pnum].p.p_ ## name = name;
	Phdr64_Entries;
#undef PhdrE
	e->num_phdrs++;
	return pnum;
}

int
elfc_add_phdr(struct elfc *e,
	      GElf_Word type, GElf_Addr vaddr, GElf_Addr paddr,
	      GElf_Word filesz, GElf_Word memsz, GElf_Word flags,
	      GElf_Word align)
{
	GElf_Off offset = 0;
	int i;

	extend_phdrs(e);

	i = e->num_phdrs;
	memset(&e->phdrs[i], 0, sizeof(e->phdrs[i]));
#define PhdrE(type, name) e->phdrs[i].p.p_ ## name = name;
	Phdr64_Entries;
#undef PhdrE
	e->num_phdrs++;
	return i;
}

int
elfc_del_phdr(struct elfc *e, int pnum)
{
	if (pnum >= e->num_phdrs) {
		e->eerrno = EINVAL;
		return -1;
	}

	if (e->phdrs[pnum].data_free)
		e->phdrs[pnum].data_free(e, e->phdrs[pnum].data,
					 e->phdrs[pnum].userdata);
	memmove(e->phdrs + pnum, e->phdrs + pnum + 1,
		sizeof(*e->phdrs) * (e->num_phdrs - pnum - 1));
	e->num_phdrs--;
	return 0;
}

void
elfc_gen_phdr_free(struct elfc *e, void *data, void *userdata)
{
	if (data)
		free(data);
	if (userdata)
		free(userdata);
}

int
elfc_tmpfd(void)
{
	char *tmpdir;
	static char *rname = "elfcXXXXXX";
	char *fname;
	int fd;

	tmpdir = getenv("TMPDIR");
	if (!tmpdir)
		tmpdir = "/tmp";

	fname = malloc(strlen(tmpdir) + strlen(rname) + 2);
	if (!fname) {
		errno = ENOMEM;
		return -1;
	}
	sprintf(fname, "%s/%s", tmpdir, rname);
	fd = open(fname, O_RDWR | O_TRUNC | O_CREAT, S_IRUSR | S_IWUSR);
	free(fname);
	if (fd == -1)
		return -1;
	unlink(fname);
	return fd;
}

int
elfc_copy_fd_range(int out, int in, size_t size)
{
	char *buf;
	size_t buf_size = 1024 * 1024;
	int rv = 0;

	if (buf_size > size)
		buf_size = size;
	buf = malloc(buf_size);
	if (!buf) {
		errno = ENOMEM;
		return -1;
	}
	while (size) {
		int iosize = buf_size;
		if (iosize > size)
			iosize = size;
		rv = read(in, buf, iosize);
		if (rv == -1)
			goto out;
		if (rv != iosize) {
			rv = -1;
			errno = ERANGE;
			goto out;
		}
		rv = write(out, buf, iosize);
		if (rv == -1)
			goto out;
		if (rv != iosize) {
			rv = -1;
			errno = ERANGE;
			goto out;
		}
		size -= iosize;
	}
out:
	free(buf);
	return rv;
}

struct elfc_tmpfile {
	int fd;
};

static void *
elfc_phdr_tmpfile_alloc(struct elfc *e)
{
	struct elfc_tmpfile *tf;

	tf = malloc(sizeof(*tf));
	if (tf)
		tf->fd = -1;
	return tf;
}

/*
 * Create a copy of the contents in a temparary file.  This way if we
 * are reading and writing the same file, the data won't be clobbered.
 */
static int
elfc_phdr_tmpfile_pre_write(struct elfc *e, GElf_Phdr *phdr,
			    void *data, void *userdata)
{
	struct elfc_tmpfile *tf = userdata;
	int fd;
	int rv;

	tf->fd = elfc_tmpfd();
	if (tf->fd == -1)
		return -1;

	fd = elfc_get_fd(e);
	rv = lseek(fd, phdr->p_offset, SEEK_SET);
	if (rv == -1)
		e->eerrno = errno;
	rv = elfc_copy_fd_range(tf->fd, fd, phdr->p_filesz);
	if (rv == -1)
		return -1;
	return 0;
}

static int
elfc_phdr_tmpfile_do_write(struct elfc *e, int fd, GElf_Phdr *phdr,
			   void *data, void *userdata)
{
	struct elfc_tmpfile *tf = userdata;
	int rv;

	rv = lseek(tf->fd, 0, SEEK_SET);
	if (rv == -1)
		return -1;

	rv = elfc_copy_fd_range(fd, tf->fd, phdr->p_filesz);
	if (rv == -1)
		return -1;

	close(tf->fd);
	tf->fd = -1;
	return 0;
}

static void
elfc_phdr_tmpfile_post_write(struct elfc *e, GElf_Phdr *phdr,
			     void *data, void *userdata)
{
	struct elfc_tmpfile *tf = userdata;

	if (tf->fd != -1) {
		close(tf->fd);
		tf->fd = -1;
	}
}

static int
elfc_phdr_tmpfile_get_data(struct elfc *e, GElf_Phdr *phdr, void *data,
			   GElf_Off off, void *odata, size_t len,
			   void *userdata)
{
	int rv;

	if ((off > phdr->p_filesz) || ((off + len) > phdr->p_filesz)) {
		errno = EINVAL;
		return -1;
	}
	rv = lseek(e->fd, off + phdr->p_offset, SEEK_SET);
	if (rv == -1)
		return -1;
	rv = read(e->fd, odata, len);
	if (rv == -1)
		return -1;
	if (rv != len) {
		errno = EINVAL;
		return -1;
	}
	return 0;
}

static int
elfc_phdr_tmpfile_set_data(struct elfc *e, GElf_Phdr *phdr, void *data,
			   GElf_Off off, const void *idata, size_t len,
			   void *userdata)
{
	int rv;

	if ((off > phdr->p_filesz) || ((off + len) > phdr->p_filesz)) {
		errno = EINVAL;
		return -1;
	}
	rv = lseek(e->fd, off + phdr->p_offset, SEEK_SET);
	if (rv == -1)
		return -1;
	rv = write(e->fd, idata, len);
	if (rv == -1)
		return -1;
	if (rv != len) {
		errno = EINVAL;
		return -1;
	}
	return 0;
}

static void
elfc_phdr_tmpfile_free(struct elfc *e, void *data, void *userdata)
{
	if (userdata)
		free(userdata);
}

int
elfc_phdr_block_get_data(struct elfc *e, GElf_Phdr *phdr, void *data,
			 GElf_Off off, void *odata, size_t len,
			 void *userdata)
{
	if ((off > phdr->p_filesz) || ((off + len) > phdr->p_filesz)) {
		errno = EINVAL;
		return -1;
	}

	memcpy(odata, ((char *) data) + off, len);
	return 0;
}

int
elfc_phdr_block_set_data(struct elfc *e, GElf_Phdr *phdr, void *data,
			 GElf_Off off, const void *idata, size_t len,
			 void *userdata)
{
	if ((off > phdr->p_filesz) || ((off + len) > phdr->p_filesz)) {
		errno = EINVAL;
		return -1;
	}

	memcpy(data, ((char *) idata) + off, len);
	return 0;
}

int
elfc_phdr_block_do_write(struct elfc *e, int fd, GElf_Phdr *phdr,
			 void *data, void *userdata)
{
	int rv;

	rv = write(fd, data, phdr->p_filesz);
	if (rv == -1)
		return -1;
	if (rv != phdr->p_filesz) {
		errno = EINVAL;
		return -1;
	}
	return 0;
}

int
elfc_set_phdr_data(struct elfc *e, int pnum, void *data,
		   void (*free_func)(struct elfc *e, void *data,
				     void *userdata),
		   int (*pre_write)(struct elfc *e, GElf_Phdr *phdr,
				    void *data, void *userdata),
		   int (*do_write)(struct elfc *e, int fd, GElf_Phdr *phdr,
				   void *data, void *userdata),
		   void (*post_write)(struct elfc *e, GElf_Phdr *phdr,
				      void *data, void *userdata),
		   int (*get_data)(struct elfc *e, GElf_Phdr *phdr, void *data,
				   GElf_Off off, void *odata, size_t len,
				   void *userdata),
		   int (*set_data)(struct elfc *e, GElf_Phdr *phdr, void *data,
				   GElf_Off off, const void *idata, size_t len,
				   void *userdata),
		   void *userdata)
{
	if (pnum >= e->num_phdrs) {
		e->eerrno = EINVAL;
		return -1;
	}

	if (e->phdrs[pnum].data_free)
		e->phdrs[pnum].data_free(e, e->phdrs[pnum].data,
					 e->phdrs[pnum].userdata);
	e->phdrs[pnum].data = data;
	e->phdrs[pnum].data_free = free_func;
	e->phdrs[pnum].pre_write = pre_write;
	e->phdrs[pnum].do_write = do_write;
	e->phdrs[pnum].post_write = post_write;
	e->phdrs[pnum].get_data = get_data;
	e->phdrs[pnum].set_data = set_data;
	e->phdrs[pnum].userdata = userdata;
	return 0;
}

int
elfc_get_num_phdrs(struct elfc *e)
{
	return e->num_phdrs;
}

int
elfc_get_phdr_offset(struct elfc *e, int pnum, GElf_Off *off)
{
	if (pnum >= e->num_phdrs) {
		e->eerrno = EINVAL;
		return -1;
	}
	*off = e->phdrs[pnum].p.p_offset;
	return 0;
}

int
elfc_get_phdr(struct elfc *e, int pnum, GElf_Phdr *hdr)
{
	if (pnum >= e->num_phdrs) {
		e->eerrno = EINVAL;
		return -1;
	}
	*hdr = e->phdrs[pnum].p;
	return 0;
}

int
elfc_set_phdr_offset(struct elfc *e, int pnum, GElf_Off offset)
{
	if (pnum >= e->num_phdrs) {
		e->eerrno = EINVAL;
		return -1;
	}
	e->phdrs[pnum].p.p_offset = offset;
	return 0;
}

static int
elfc_add_note_nocheck(struct elfc *e, Elf32_Word type,
		      const char *name, int namelen,
		      const void *data, int datalen)
{
	if (e->num_notes == e->alloced_notes) {
		struct elfc_note *notes;

		notes = malloc(sizeof(*notes) * (e->alloced_notes + 32));
		if (!notes) {
			e->eerrno = ENOMEM;
			return -1;
		}
		memcpy(notes, e->notes, sizeof(*notes) * e->alloced_notes);
		e->alloced_notes += 32;
		if (e->notes)
			free(e->notes);
		e->notes = notes;
	}

	e->notes[e->num_notes].type = type;
	e->notes[e->num_notes].name = malloc(namelen + 1);
	if (!e->notes[e->num_notes].name) {
		e->eerrno = ENOMEM;
		return -1;
	}
	e->notes[e->num_notes].data = malloc(datalen);
	if (!e->notes[e->num_notes].data) {
		free(e->notes[e->num_notes].name);
		e->eerrno = ENOMEM;
		return -1;
	}
	memcpy(e->notes[e->num_notes].name, name, namelen);
	e->notes[e->num_notes].name[namelen] = '\0';
	e->notes[e->num_notes].namelen = namelen;
	memcpy(e->notes[e->num_notes].data, data, datalen);
	e->notes[e->num_notes].datalen = datalen;
	e->num_notes++;
	return 0;
}

int
elfc_add_note(struct elfc *e, Elf32_Word type,
	      const char *name, int namelen,
	      const void *data, int datalen)
{
	if (!e->notes && (e->fd != -1)) {
		int rv = elfc_read_notes(e);
		if (rv == -1)
			return rv;
	}

	return elfc_add_note_nocheck(e, type, name, namelen, data, datalen);
}

#define elfc_accessor(name, type)	\
void						\
elfc_set ## name(struct elfc *e, type name)	\
{						\
	e->hdr.e_ ## name = name;		\
}						\
type						\
elfc_get ## name(struct elfc *e)		\
{						\
	return e->hdr.e_ ## name;		\
}

elfc_accessor(machine, GElf_Half);
elfc_accessor(type, GElf_Half);

void
elfc_setclass(struct elfc *e, unsigned char class)
{
	e->hdr.e_ident[EI_CLASS] = class;
}

unsigned char
elfc_getclass(struct elfc *e)
{
	return e->hdr.e_ident[EI_CLASS];
}

void
elfc_setencoding(struct elfc *e, unsigned char encoding)
{
	e->hdr.e_ident[EI_DATA] = encoding;
}

unsigned char
elfc_getencoding(struct elfc *e)
{
	return e->hdr.e_ident[EI_DATA];
}

static int elfarch = 
#ifdef __x86_64__
	EM_X86_64
#elif defined(__mips__)
	EM_MIPS
#else
	EM_NONE
#endif
	;

static int elfendian =
#if (__BYTE_ORDER == __LITTLE_ENDIAN)
	ELFDATA2LSB
#elif (__BYTE_ORDER == __BIG_ENDIAN)
	ELFDATA2MSB
#else
	ELFDATANONE
#endif
	;

static int elfclass = ELFCLASSNONE;

#define elfc_getput(type, len)				\
static GElf_ ## type						\
elfc_get ## type(struct elfc *e, GElf_## type w)	\
{							\
	if (e->hdr.e_ident[EI_DATA] == ELFDATA2LSB)	\
		return le ## len ## toh(w);		\
	else						\
		return be ## len ## toh(w);		\
}							\
static GElf_ ## type						\
elfc_put ## type(struct elfc *e, GElf_## type w)	\
{							\
	if (e->hdr.e_ident[EI_DATA] == ELFDATA2LSB)	\
		return htole ## len(w);			\
	else						\
		return htobe ## len(w);			\
}

elfc_getput(Half, 16)
elfc_getput(Word, 32)
elfc_getput(Xword, 64)

static GElf_Addr
elfc_getAddr(struct elfc *e, GElf_Addr w)
{
	if (e->hdr.e_ident[EI_CLASS] == ELFCLASS32) {
		if (e->hdr.e_ident[EI_DATA] == ELFDATA2LSB)
			return elfc_getWord(e, w);
		else
			return elfc_getWord(e, w);
	} else {
		if (e->hdr.e_ident[EI_DATA] == ELFDATA2LSB)
			return elfc_getXword(e, w);
		else
			return elfc_getXword(e, w);
	}
}

static GElf_Off
elfc_getOff(struct elfc *e, GElf_Off w)
{
	if (e->hdr.e_ident[EI_CLASS] == ELFCLASS32) {
		if (e->hdr.e_ident[EI_DATA] == ELFDATA2LSB)
			return elfc_getWord(e, w);
		else
			return elfc_getWord(e, w);
	} else {
		if (e->hdr.e_ident[EI_DATA] == ELFDATA2LSB)
			return elfc_getXword(e, w);
		else
			return elfc_getXword(e, w);
	}
}

static GElf_Addr
elfc_putAddr(struct elfc *e, GElf_Addr w)
{
	if (e->hdr.e_ident[EI_CLASS] == ELFCLASS32) {
		if (e->hdr.e_ident[EI_DATA] == ELFDATA2LSB)
			return elfc_putWord(e, w);
		else
			return elfc_putWord(e, w);
	} else {
		if (e->hdr.e_ident[EI_DATA] == ELFDATA2LSB)
			return elfc_putXword(e, w);
		else
			return elfc_putXword(e, w);
	}
}

static GElf_Off
elfc_putOff(struct elfc *e, GElf_Off w)
{
	if (e->hdr.e_ident[EI_CLASS] == ELFCLASS32) {
		if (e->hdr.e_ident[EI_DATA] == ELFDATA2LSB)
			return elfc_putWord(e, w);
		else
			return elfc_putWord(e, w);
	} else {
		if (e->hdr.e_ident[EI_DATA] == ELFDATA2LSB)
			return elfc_putXword(e, w);
		else
			return elfc_putXword(e, w);
	}
}

int
elfc_read_data(struct elfc *e, GElf_Off off, void *odata, size_t len)
{
	int rv;

	rv = lseek(e->fd, off, SEEK_SET);
	if (rv == -1) {
		e->eerrno = errno;
		return -1;
	}
	rv = read(e->fd, odata, len);
	if (rv == -1) {
		e->eerrno = errno;
		return -1;
	}
	if (rv != len) {
		e->eerrno = EINVAL;
		return -1;
	}
	return 0;
}

int
elfc_alloc_read_data(struct elfc *e, GElf_Off off, void **odata, size_t len)
{
	void *buf = malloc(len);
	int rv;

	if (!buf) {
		e->eerrno = ENOMEM;
		return -1;
	}
	rv = elfc_read_data(e, off, buf, len);
	if (rv == -1)
		free(buf);
	else
		*odata = buf;

	return rv;
}

int
elfc_phdr_read(struct elfc *e, int pnum, GElf_Off off,
	       void *odata, size_t len)
{
	int rv;

	if (pnum > (e->num_phdrs + 1)) {
		e->eerrno = EINVAL;
		return -1;
	}
	if (!e->phdrs[pnum].get_data) {
		e->eerrno = ENOSYS;
		return -1;
	}
	rv = e->phdrs[pnum].get_data(e, &e->phdrs[pnum].p, e->phdrs[pnum].data,
				     off, odata, len, e->phdrs[pnum].userdata);
	if (rv)
		e->eerrno = errno;
	return rv;
}

int
elfc_phdr_write(struct elfc *e, int pnum, GElf_Off off,
		const void *odata, size_t len)
{
	int rv;

	if (pnum > (e->num_phdrs + 1)) {
		e->eerrno = EINVAL;
		return -1;
	}
	if (!e->phdrs[pnum].set_data) {
		e->eerrno = ENOSYS;
		return -1;
	}
	rv = e->phdrs[pnum].set_data(e, &e->phdrs[pnum].p, e->phdrs[pnum].data,
				     off, odata, len, e->phdrs[pnum].userdata);
	if (rv)
		e->eerrno = errno;
	return rv;
}

int
elfc_phdr_alloc_read(struct elfc *e, int pnum, GElf_Off off,
		     void **odata, size_t len)
{
	int rv;
	char *buf;

	if (pnum > (e->num_phdrs + 1)) {
		e->eerrno = EINVAL;
		return -1;
	}
	if (!e->phdrs[pnum].get_data) {
		e->eerrno = ENOSYS;
		return -1;
	}
	buf = malloc(len);
	if (!buf) {
		e->eerrno = ENOMEM;
		return -1;
	}
	rv = e->phdrs[pnum].get_data(e, &e->phdrs[pnum].p, e->phdrs[pnum].data,
				     off, buf, len, e->phdrs[pnum].userdata);
	if (rv) {
		free(buf);
		e->eerrno = errno;
	} else
		*odata = buf;

	return rv;
}

GElf_Off
elfc_file_size(struct elfc *e)
{
	int i;
	GElf_Off s_end;
	GElf_Off rv = 0;

	for (i = 0; i < e->num_phdrs; i++) {
		s_end = e->phdrs[i].p.p_offset + e->phdrs[i].p.p_filesz;
		if (s_end > rv)
			rv = s_end;
	}
	return rv;
}

int
elfc_vmem_offset(struct elfc *e, GElf_Addr addr, size_t len,
		 int *pnum, GElf_Off *off)
{
	int i;
	GElf_Addr s_beg;
	GElf_Addr s_end;

	for (i = 0; i < e->num_phdrs; i++) {
		s_beg = e->phdrs[i].p.p_vaddr;
		s_end = s_beg + e->phdrs[i].p.p_filesz;

		if ((addr >= s_beg) && ((addr + len) < s_end)) {
			*off = addr - s_beg;
			*pnum = i;
			return 0;
		}
	}
	e->eerrno = ENOENT;
	return -1;
}

int
elfc_pmem_offset(struct elfc *e, GElf_Addr addr, size_t len,
		 int *pnum, GElf_Off *off)
{
	int i;
	GElf_Addr s_beg;
	GElf_Addr s_end;

	for (i = 0; i < e->num_phdrs; i++) {
		s_beg = e->phdrs[i].p.p_paddr;
		s_end = s_beg + e->phdrs[i].p.p_filesz;

		if ((addr >= s_beg) && ((addr + len) < s_end)) {
			*off = addr - s_beg;
			*pnum = i;
			return 0;
		}
	}
	e->eerrno = ENOENT;
	return -1;
}

int
elfc_pmem_present(struct elfc *e, GElf_Addr addr, size_t len)
{
	GElf_Off off;
	int pnum;

	if (elfc_pmem_offset(e, addr, len, &pnum, &off) == -1)
		return 0;
	return 1;
}

int
elfc_vmem_present(struct elfc *e, GElf_Addr addr, size_t len)
{
	GElf_Off off;
	int pnum;

	if (elfc_vmem_offset(e, addr, len, &pnum, &off) == -1)
		return 0;
	return 1;
}

GElf_Addr
elfc_max_paddr(struct elfc *e)
{
	int i;
	GElf_Addr max = 0;
	GElf_Addr s_end;

	for (i = 0; i < e->num_phdrs; i++) {
		s_end = e->phdrs[i].p.p_paddr + e->phdrs[i].p.p_filesz;
		if (max < s_end)
			max = s_end;
	}
	return max;
}

GElf_Addr
elfc_max_vaddr(struct elfc *e)
{
	int i;
	GElf_Addr max = 0;
	GElf_Addr s_end;

	for (i = 0; i < e->num_phdrs; i++) {
		s_end = e->phdrs[i].p.p_vaddr + e->phdrs[i].p.p_filesz;
		if (max < s_end)
			max = s_end;
	}
	return max;
}

int
elfc_vmem_file_offset(struct elfc *e, GElf_Addr addr, size_t len,
		      GElf_Off *off)
{
	int rv;
	GElf_Off poff;
	int pnum;

	rv = elfc_vmem_offset(e, addr, len, &pnum, &poff);
	if (rv == -1)
		return -1;
	*off = poff + e->phdrs[pnum].p.p_offset;
	return 0;
}

int
elfc_pmem_file_offset(struct elfc *e, GElf_Addr addr, size_t len,
		      GElf_Off *off)
{
	int rv;
	GElf_Off poff;
	int pnum;

	rv = elfc_pmem_offset(e, addr, len, &pnum, &poff);
	if (rv == -1)
		return -1;
	*off = poff + e->phdrs[pnum].p.p_offset;
	return 0;
}

int
elfc_read_vmem(struct elfc *e, GElf_Addr addr, void *odata, size_t len)
{
	int rv;
	GElf_Off off;
	int pnum;

	rv = elfc_vmem_offset(e, addr, len, &pnum, &off);
	if (rv == -1)
		return -1;
	return elfc_phdr_read(e, pnum, off, odata, len);
}

int
elfc_read_pmem(struct elfc *e, GElf_Addr addr, void *odata, size_t len)
{
	int rv;
	GElf_Off off;
	int pnum;

	rv = elfc_pmem_offset(e, addr, len, &pnum, &off);
	if (rv == -1)
		return -1;
	return elfc_phdr_read(e, pnum, off, odata, len);
}

int
elfc_alloc_read_vmem(struct elfc *e, GElf_Addr addr, void **odata, size_t len)
{
	int rv;
	GElf_Off off;
	int pnum;

	rv = elfc_vmem_offset(e, addr, len, &pnum, &off);
	if (rv == -1)
		return -1;
	return elfc_phdr_alloc_read(e, pnum, off, odata, len);
}

int
elfc_alloc_read_pmem(struct elfc *e, GElf_Addr addr, void **odata, size_t len)
{
	int rv;
	GElf_Off off;
	int pnum;

	rv = elfc_pmem_offset(e, addr, len, &pnum, &off);
	if (rv == -1)
		return -1;
	return elfc_phdr_alloc_read(e, pnum, off, odata, len);
}

int
elfc_write_vmem(struct elfc *e, GElf_Addr addr, const void *odata, size_t len)
{
	int rv;
	GElf_Off off;
	int pnum;

	rv = elfc_vmem_offset(e, addr, len, &pnum, &off);
	if (rv == -1)
		return -1;
	return elfc_phdr_write(e, pnum, off, odata, len);
}

int
elfc_write_pmem(struct elfc *e, GElf_Addr addr, const void *odata, size_t len)
{
	int rv;
	GElf_Off off;
	int pnum;

	rv = elfc_pmem_offset(e, addr, len, &pnum, &off);
	if (rv == -1)
		return -1;
	return elfc_phdr_write(e, pnum, off, odata, len);
}


#define Ehdr_Entries \
	EhdrE(Half,	type);		\
	EhdrE(Half,	machine);	\
	EhdrE(Word,	version);	\
	EhdrE(Addr,	entry);		\
	EhdrE(Off,	phoff);		\
	EhdrE(Off,	shoff);		\
	EhdrE(Word,	flags);		\
	EhdrE(Half,	ehsize);	\
	EhdrE(Half,	phentsize);	\
	EhdrE(Half,	phnum);		\
	EhdrE(Half,	shentsize);	\
	EhdrE(Half,	shnum);		\
	EhdrE(Half,	shstrndx)

static int
read_elf32_ehdr(struct elfc *e)
{
	Elf32_Ehdr e32;
	size_t l;
	int rv;

	/* Assumes e_ident is already read. */
	l = sizeof(e32) - sizeof(e32.e_ident);
	rv = read(e->fd, &e32.e_type, l);
	if (rv == -1) {
		e->eerrno = errno;
		return -1;
	}
	if (rv != l) {
		e->eerrno = EINVAL;
		return -1;
	}
#define EhdrE(type, name) e->hdr.e_ ## name = elfc_get ## type(e, e32.e_ ## name);
	Ehdr_Entries;
#undef EhdrE
	return 0;
}

static int
read_elf64_ehdr(struct elfc *e)
{
	Elf64_Ehdr e64;
	size_t l;
	int rv;

	/* Assumes e_ident is already read. */
	l = sizeof(e64) - sizeof(e64.e_ident);
	rv = read(e->fd, &e64.e_type, l);
	if (rv == -1) {
		e->eerrno = errno;
		return -1;
	}
	if (rv != l) {
		e->eerrno = EINVAL;
		return -1;
	}
#define EhdrE(type, name) e->hdr.e_ ## name = elfc_get ## type(e, e64.e_ ## name);
	Ehdr_Entries;
#undef EhdrE
	return 0;
}

static int
write_elf32_ehdr(struct elfc *e)
{
	Elf32_Ehdr e32;
	int rv;

	memcpy(e32.e_ident, e->hdr.e_ident, sizeof(e32.e_ident));
#define EhdrE(type, name) e32.e_ ## name = elfc_put ## type(e, e->hdr.e_ ## name);
	Ehdr_Entries;
#undef EhdrE

	rv = write(e->fd, &e32, sizeof(e32));
	if (rv == -1) {
		e->eerrno = errno;
		return -1;
	}
	if (rv != sizeof(e32)) {
		e->eerrno = EINVAL;
		return -1;
	}
	return 0;
}

static int
write_elf64_ehdr(struct elfc *e)
{
	Elf64_Ehdr e64;
	int rv;

	memcpy(e64.e_ident, e->hdr.e_ident, sizeof(e64.e_ident));
#define EhdrE(type, name) e64.e_ ## name = elfc_put ## type(e, e->hdr.e_ ## name);
	Ehdr_Entries;
#undef EhdrE

	rv = write(e->fd, &e64, sizeof(e64));
	if (rv == -1) {
		e->eerrno = errno;
		return -1;
	}
	if (rv != sizeof(e64)) {
		e->eerrno = EINVAL;
		return -1;
	}
	return 0;
}

static void
free_notes(struct elfc *e)
{
	int i;

	if (!e->notes)
		return;
	for (i = 0; i < e->num_notes; i++) {
		free(e->notes[i].name);
		free(e->notes[i].data);
	}
	free(e->notes);
	e->notes = NULL;
	e->num_notes = 0;
	e->alloced_notes = 0;
}

static int
get_elf32_note(struct elfc *e, char *buf, size_t len)
{
	Elf32_Nhdr *nhdr = (Elf32_Nhdr *) buf;
	GElf_Word namesz, descsz, type;
	char *nameptr, *descptr;
	int rv;

	if (len < sizeof(*nhdr))
		return 0;

	namesz = elfc_getWord(e, nhdr->n_namesz);
	descsz = elfc_getWord(e, nhdr->n_descsz);
	type = elfc_getWord(e, nhdr->n_type);

	if (len < sizeof(*nhdr) + namesz + descsz) {
		e->eerrno = EINVAL;
		return -1;
	}

	nameptr = buf + sizeof(*nhdr);
	descptr = nameptr + elfc_align(namesz, sizeof(GElf_Word));
	rv = elfc_add_note_nocheck(e, type, nameptr, namesz, descptr, descsz);
	if (rv == -1)
		return -1;
	descptr = descptr + elfc_align(descsz, sizeof(GElf_Word));

	return descptr - buf;
}

static int
get_elf64_note(struct elfc *e, char *buf, size_t len)
{
	Elf64_Nhdr *nhdr = (Elf64_Nhdr *) buf;
	GElf_Word namesz, descsz, type;
	char *nameptr, *descptr;
	int rv;

	if (len < sizeof(*nhdr))
		return 0;

	namesz = elfc_getWord(e, nhdr->n_namesz);
	descsz = elfc_getWord(e, nhdr->n_descsz);
	type = elfc_getWord(e, nhdr->n_type);

	if (len < sizeof(*nhdr) + namesz + descsz) {
		e->eerrno = EINVAL;
		return -1;
	}

	nameptr = buf + sizeof(*nhdr);
	descptr = nameptr + elfc_align(namesz, sizeof(GElf_Word));
	rv = elfc_add_note_nocheck(e, type, nameptr, namesz, descptr, descsz);
	if (rv == -1)
		return -1;
	descptr = descptr + elfc_align(descsz, sizeof(GElf_Word));

	return descptr - buf;
}

static int
elfc_read_notes(struct elfc *e)
{
	int i, rv;

	free_notes(e);

	for (i = 0; i < e->num_phdrs; i++) {
		void *buf;
		char *nbuf;
		size_t size;

		if (e->phdrs[i].p.p_type != PT_NOTE)
			continue;

		size = e->phdrs[i].p.p_filesz;
		rv = elfc_alloc_read_data(e, e->phdrs[i].p.p_offset,
					  &buf, size);
		if (rv == -1)
			return -1;

		nbuf = buf;
		for (;;) {
			if (e->hdr.e_ident[EI_CLASS] == ELFCLASS32)
				rv = get_elf32_note(e, nbuf, size);
			else
				rv = get_elf64_note(e, nbuf, size);
			if (rv == -1)
				return -1;
			if (rv == 0)
				break;
			nbuf += rv;
			size -= rv;
		}

		free(buf);

		/* Once we load a note phdr, we delete it. */
		elfc_del_phdr(e, i);
		i--;
	}

	return 0;
}

static int
put_elf32_note(struct elfc *e, int nnum, char *buf, size_t len)
{
	Elf32_Nhdr *nhdr = (Elf32_Nhdr *) buf;
	GElf_Off size, aligned;

	if (nnum > e->num_notes) {
		e->eerrno = EINVAL;
		return -1;
	}

	if (len < sizeof(*nhdr)
	    + e->notes[nnum].namelen + e->notes[nnum].datalen) {
		e->eerrno = EINVAL;
		return -1;
	}

	nhdr->n_namesz = elfc_putWord(e, e->notes[nnum].namelen);
	nhdr->n_descsz = elfc_getWord(e, e->notes[nnum].datalen);
	nhdr->n_type = elfc_getWord(e, e->notes[nnum].type);
	size = sizeof(*nhdr);
	memcpy(buf + size, e->notes[nnum].name, e->notes[nnum].namelen);
	size += e->notes[nnum].namelen;
	aligned = elfc_align(size, sizeof(GElf_Word));
	while (size < aligned)
		buf[size++] = 0;
	memcpy(buf + size, e->notes[nnum].data, e->notes[nnum].datalen);
	size += e->notes[nnum].datalen;
	aligned = elfc_align(size, sizeof(GElf_Word));
	while (size < aligned)
		buf[size++] = 0;

	return size;
}

static int
put_elf64_note(struct elfc *e, int nnum, char *buf, size_t len)
{
	Elf64_Nhdr *nhdr = (Elf64_Nhdr *) buf;
	GElf_Off size, aligned;

	if (nnum > e->num_notes) {
		e->eerrno = EINVAL;
		return -1;
	}

	if (len < sizeof(*nhdr)
	    + e->notes[nnum].namelen + e->notes[nnum].datalen) {
		e->eerrno = EINVAL;
		return -1;
	}

	nhdr->n_namesz = elfc_putWord(e, e->notes[nnum].namelen);
	nhdr->n_descsz = elfc_getWord(e, e->notes[nnum].datalen);
	nhdr->n_type = elfc_getWord(e, e->notes[nnum].type);
	size = sizeof(*nhdr);
	memcpy(buf + size, e->notes[nnum].name, e->notes[nnum].namelen);
	size += e->notes[nnum].namelen;
	aligned = elfc_align(size, sizeof(GElf_Word));
	while (size < aligned)
		buf[size++] = 0;
	memcpy(buf + size, e->notes[nnum].data, e->notes[nnum].datalen);
	size += e->notes[nnum].datalen;
	aligned = elfc_align(size, sizeof(GElf_Word));
	while (size < aligned)
		buf[size++] = 0;

	return size;
}

static int
put_elf_note(struct elfc *e, int nnum, char *buf, size_t len)
{
	if (e->hdr.e_ident[EI_CLASS] == ELFCLASS32)
		return put_elf32_note(e, nnum, buf, len);
	else
		return put_elf64_note(e, nnum, buf, len);
}

int
elfc_get_num_notes(struct elfc *e)
{
	if (!e->notes && (e->fd != -1)) {
		int rv = elfc_read_notes(e);
		if (rv == -1)
			return rv;
	}

	return e->num_notes;
}

int
elfc_get_note(struct elfc *e, int index,
	      GElf_Word *type,
	      const char **name, size_t *namelen,
	      const void **data, size_t *datalen)
{
	int rv;

	if (!e->notes && (e->fd != -1)) {
		rv = elfc_read_notes(e);
		if (rv == -1)
			return rv;
	}

	if (index > e->num_notes) {
		e->eerrno = EINVAL;
		return -1;
	}

	if (type)
		*type = e->notes[index].type;
	if (name)
		*name = e->notes[index].name;
	if (namelen)
		*namelen = e->notes[index].namelen;
	if (data)
		*data = e->notes[index].data;
	if (datalen)
		*datalen = e->notes[index].datalen;
	return 0;
}

static void
free_phdrs(struct elfc *e)
{
	int i;

	if (!e->phdrs)
		return;
	for (i = 0; i < e->num_phdrs; i++) {
		if (e->phdrs[i].data_free)
			e->phdrs[i].data_free(e, e->phdrs[i].data,
					      e->phdrs[i].userdata);
	}
	free(e->phdrs);
	e->phdrs = NULL;
	e->num_phdrs = 0;
	e->alloced_phdrs = 0;
}

static int
write_elf32_phdrs(struct elfc *e)
{
	int i;
	int rv;
	Elf32_Phdr *p32;
	size_t l = sizeof(*p32) * e->num_phdrs;

	p32 = malloc(l);
	if (!p32) {
		e->eerrno = ENOMEM;
		return -1;
	}
	for (i = 0; i < e->num_phdrs; i++) {
#define PhdrE(type, name) p32[i].p_ ## name = \
	elfc_put ## type(e, e->phdrs[i].p.p_ ## name)
		Phdr32_Entries;
#undef PhdrE
	}
	rv = write(e->fd, p32, l);
	free(p32);
	if (rv == -1) {
		e->eerrno = errno;
		return -1;
	}
	if (rv != l) {
		e->eerrno = EINVAL;
		return -1;
	}
	return 0;
}

static int
write_elf64_phdrs(struct elfc *e)
{
	int i;
	int rv;
	Elf64_Phdr *p64;
	size_t l = sizeof(*p64) * e->num_phdrs;

	p64 = malloc(l);
	if (!p64) {
		e->eerrno = ENOMEM;
		return -1;
	}
	for (i = 0; i < e->num_phdrs; i++) {
#define PhdrE(type, name) p64[i].p_ ## name = \
	elfc_put ## type(e, e->phdrs[i].p.p_ ## name)
		Phdr64_Entries;
#undef PhdrE
	}
	rv = write(e->fd, p64, l);
	free(p64);
	if (rv == -1) {
		e->eerrno = errno;
		return -1;
	}
	if (rv != l) {
		e->eerrno = EINVAL;
		return -1;
	}
	return 0;
}

static int
elfc_write_phdrs(struct elfc *e)
{
	if (e->hdr.e_ident[EI_CLASS] == ELFCLASS32)
		return write_elf32_phdrs(e);
	else
		return write_elf64_phdrs(e);
}

static int
read_elf32_phdrs(struct elfc *e, char *buf)
{
	int i;
	struct elfc_phdr *phdrs;

	phdrs = malloc(sizeof(*phdrs) * e->hdr.e_phnum);
	if (!phdrs) {
		e->eerrno = ENOMEM;
		return -1;
	}

	if (e->phdrs) {
		free(e->phdrs);
	}
	e->num_phdrs = e->hdr.e_phnum;
	e->alloced_phdrs = e->hdr.e_phnum;
	e->phdrs = phdrs;

	for (i = 0; i < e->num_phdrs; i++) {
		Elf32_Phdr *p32 = ((Elf32_Phdr *)
				   (buf + (i * e->hdr.e_phentsize)));;
#define PhdrE(type, name) e->phdrs[i].p.p_ ## name = \
	elfc_get ## type(e, p32->p_ ## name)
		Phdr32_Entries;
#undef PhdrE
	}

	return 0;
}

static int
read_elf64_phdrs(struct elfc *e, char *buf)
{
	int i;
	struct elfc_phdr *phdrs;

	phdrs = malloc(sizeof(*phdrs) * e->hdr.e_phnum);
	if (!phdrs) {
		e->eerrno = ENOMEM;
		return -1;
	}

	if (e->phdrs) {
		free(e->phdrs);
	}
	e->num_phdrs = e->hdr.e_phnum;
	e->alloced_phdrs = e->hdr.e_phnum;
	e->phdrs = phdrs;

	for (i = 0; i < e->num_phdrs; i++) {
		Elf64_Phdr *p64 = ((Elf64_Phdr *)
				   (buf + (i * e->hdr.e_phentsize)));

#define PhdrE(type, name) e->phdrs[i].p.p_ ## name = \
	elfc_get ## type(e, p64->p_ ## name)
		Phdr64_Entries;
#undef PhdrE
	}

	return 0;
}

static int
elfc_read_phdrs(struct elfc *e)
{
	void *buf;
	int rv;

	rv = elfc_alloc_read_data(e, e->hdr.e_phoff, &buf,
				  e->hdr.e_phentsize * e->hdr.e_phnum);
	if (rv == -1)
		return -1;

	if (e->hdr.e_ident[EI_CLASS] == ELFCLASS32)
		rv = read_elf32_phdrs(e, buf);
	else
		rv = read_elf64_phdrs(e, buf);
	free(buf);
	if (rv != -1) {
		int i;

		for (i = 0; i < e->num_phdrs; i++) {
			e->phdrs[i].userdata = elfc_phdr_tmpfile_alloc(e);
			if (!e->phdrs[i].userdata) {
				e->eerrno = ENOMEM;
				return -1;
			}
			e->phdrs[i].pre_write = elfc_phdr_tmpfile_pre_write;
			e->phdrs[i].do_write = elfc_phdr_tmpfile_do_write;
			e->phdrs[i].post_write = elfc_phdr_tmpfile_post_write;
			e->phdrs[i].data_free = elfc_phdr_tmpfile_free;
			e->phdrs[i].get_data = elfc_phdr_tmpfile_get_data;
			e->phdrs[i].set_data = elfc_phdr_tmpfile_set_data;
		}
	}
	return rv;
}

struct elfc *
elfc_alloc(void)
{
	struct elfc *e;

	e = malloc(sizeof(*e));
	if (!e)
		return NULL;
	memset(e, 0, sizeof(*e));
	e->fd = -1;
	return e;
}

int
elfc_setup(struct elfc *e, GElf_Half type)
{
	if (!elfclass) {
		if (sizeof(char *) == 4)
			elfclass = ELFCLASS32;
		else
			elfclass = ELFCLASS64;
	}

	memset(&e->hdr, 0, sizeof(e->hdr));
	e->hdr.e_ident[EI_MAG0] = ELFMAG0;
	e->hdr.e_ident[EI_MAG1] = ELFMAG1;
	e->hdr.e_ident[EI_MAG2] = ELFMAG2;
	e->hdr.e_ident[EI_MAG3] = ELFMAG3;
	e->hdr.e_ident[EI_CLASS] = elfclass;
	e->hdr.e_ident[EI_DATA] = elfendian;
	e->hdr.e_ident[EI_VERSION] = EV_CURRENT;
	e->hdr.e_ident[EI_OSABI] = ELFOSABI_NONE;
	e->hdr.e_ident[EI_ABIVERSION] = 0;
	e->hdr.e_type = type;
	e->hdr.e_machine = elfarch;
	e->hdr.e_version = EV_CURRENT;
	return 0;
}

static void
elfc_freei(struct elfc *e)
{
	free_phdrs(e);
	free_notes(e);
}

void
elfc_free(struct elfc *e)
{
	elfc_freei(e);
	free(e);
}

static int
validate_elf_header(struct elfc *e)
{
	if (e->hdr.e_phoff < e->hdr.e_ehsize)
		return -1;
	if (e->hdr.e_phentsize < elfc_phdr_size_one(e))
		return -1;

	e->after_headers = e->hdr.e_phoff +
		(e->hdr.e_phentsize * e->hdr.e_phnum);
	return 0;
}

int
elfc_open(struct elfc *e, int fd)
{
	int rv;
	size_t l;

	elfc_freei(e);
	memset(e, 0, sizeof(*e));
	rv = lseek(fd, 0, SEEK_SET);
	if (rv == -1) {
		e->eerrno = errno;
		return -1;
	}
	l = sizeof(e->hdr.e_ident);
	rv = read(fd, &e->hdr, l);
	if (rv == -1) {
		e->eerrno = errno;
		return -1;
	}
	if (rv != l) {
		e->eerrno = EINVAL;
		return -1;
	}

	if (memcmp(e->hdr.e_ident, ELFMAG, SELFMAG) != 0) {
		e->eerrno = EINVAL;
		return -1;
	}
	switch (e->hdr.e_ident[EI_CLASS]) {
	case ELFCLASS32:
	case ELFCLASS64:
		break;
	default:
		e->eerrno = EINVAL;
		return -1;
	}

	switch (e->hdr.e_ident[EI_DATA]) {
	case ELFDATA2LSB:
	case ELFDATA2MSB:
		break;
	default:
		e->eerrno = EINVAL;
		return -1;
	}

	if (e->hdr.e_ident[EI_VERSION] != EV_CURRENT) {
		e->eerrno = EINVAL;
		return -1;
	}

	e->fd = fd;
	switch (e->hdr.e_ident[EI_CLASS]) {
	case ELFCLASS32:
		rv = read_elf32_ehdr(e);
		if (rv == -1)
			return rv;
		break;
	case ELFCLASS64:
		rv = read_elf64_ehdr(e);
		break;
	}
	if (rv)
		goto out;

	rv = validate_elf_header(e);
	if (rv == -1) {
		e->eerrno = EINVAL;
		goto out;
	}

	rv = elfc_read_phdrs(e);
out:
	return rv;
}

GElf_Off
elfc_ehdr_size(struct elfc *e)
{
	if (e->hdr.e_ident[EI_CLASS] == ELFCLASS32)
		return sizeof(Elf32_Ehdr);
	else
		return sizeof(Elf64_Ehdr);
}

GElf_Off
elfc_phdr_size_one(struct elfc *e)
{
	if (e->hdr.e_ident[EI_CLASS] == ELFCLASS32)
		return sizeof(Elf32_Phdr);
	else
		return sizeof(Elf64_Phdr);
}

GElf_Off
elfc_phdr_size(struct elfc *e)
{
	GElf_Off size;
	size = elfc_phdr_size_one(e) * e->hdr.e_phnum;
	if (e->notes)
		size += elfc_phdr_size_one(e);
	return size;
}

GElf_Off
elfc_nhdr_size_one(struct elfc *e)
{
	if (e->hdr.e_ident[EI_CLASS] == ELFCLASS32)
		return sizeof(Elf32_Nhdr);
	else
		return sizeof(Elf64_Nhdr);
}

GElf_Off
elfc_notes_size(struct elfc *e)
{
	GElf_Off size = 0;
	int i;

	if (!e->notes && (e->fd != -1))
		elfc_read_notes(e);

	if (!e->num_notes)
		return 0;

	for (i = 0; i < e->num_notes; i++) {
		size += elfc_nhdr_size_one(e);
		size += e->notes[i].namelen;
		size = elfc_align(size, sizeof(GElf_Word));
		size += e->notes[i].datalen;
		size = elfc_align(size, sizeof(GElf_Word));
	}
	return size;
}

GElf_Off
elfc_headers_size(struct elfc *e)
{
	return elfc_ehdr_size(e) + elfc_phdr_size(e);
}

GElf_Off
elfc_data_offset_start(struct elfc *e)
{
	return elfc_headers_size(e) + elfc_notes_size(e);
}

static void
call_phdr_post_write(struct elfc *e, int i)
{
	if (e->phdrs[i].post_write)
		e->phdrs[i].post_write(e, &e->phdrs[i].p,
				       e->phdrs[i].data,
				       e->phdrs[i].userdata);
}

int
elfc_write(struct elfc *e)
{
	int rv;
	int i;
	GElf_Off off;

	if (e->notes) {
		/* Insert a new phdr for the notes then free the notes. */
		GElf_Off nsize = elfc_notes_size(e);
		size_t pos = 0;
		char *ndata = malloc(nsize);

		if (!ndata) {
			e->eerrno = ENOMEM;
			return -1;
		}
		for (i = 0; i < e->num_notes; i++) {
			rv = put_elf_note(e, i, ndata + pos, nsize - pos);
			if (rv == -1) {
				free(ndata);
				return -1;
			}
			pos += rv;
		}
		rv = elfc_insert_phdr(e, 0, PT_NOTE, 0, 0, nsize, 0,
				      0, 0);
		if (rv == -1) {
			free(ndata);
			return -1;
		}
		elfc_set_phdr_data(e, rv, ndata, elfc_gen_phdr_free,
				   NULL, elfc_phdr_block_do_write, NULL,
				   elfc_phdr_block_get_data,
				   elfc_phdr_block_set_data, NULL);
		free_notes(e);
	}

	e->hdr.e_ehsize = elfc_ehdr_size(e);
	e->hdr.e_phoff = e->hdr.e_ehsize;
	if (e->num_phdrs > 65535) {
		/* FIXME */
		return -1;
	}
	e->hdr.e_phnum = e->num_phdrs;
	e->hdr.e_phentsize = elfc_phdr_size_one(e);

	/* Ignore errors here, it will fail on stdin. */
	(void) lseek(e->fd, 0, SEEK_SET);

	if (e->hdr.e_ident[EI_CLASS] == ELFCLASS32)
		rv = write_elf32_ehdr(e);
	else
		rv = write_elf64_ehdr(e);
	if (rv == -1)
		return -1;

	off = elfc_headers_size(e);
	for (i = 0; i < e->num_phdrs; i++) {
		e->phdrs[i].p.p_offset = off;
		off += e->phdrs[i].p.p_filesz;
	}

	for (i = 0; i < e->num_phdrs; i++) {
		if (e->phdrs[i].pre_write) {
			rv = e->phdrs[i].pre_write(e, &e->phdrs[i].p,
						   e->phdrs[i].data,
						   e->phdrs[i].userdata);
			if (rv == -1) {
				e->eerrno = errno;
				i--;
				for (; i > 0; i--)
					call_phdr_post_write(e, i);
				goto out;
			}
		}					
	}

	rv = elfc_write_phdrs(e);
	if (rv == -1)
		goto out;

	for (i = 0; i < e->num_phdrs; i++) {
		if (e->phdrs[i].do_write) {
			/*
			 * Should already be in the correct position
			 * here, no need to seek.
			 */
			rv = e->phdrs[i].do_write(e, e->fd, &e->phdrs[i].p,
						  e->phdrs[i].data,
						  e->phdrs[i].userdata);
			if (rv == -1) {
				e->eerrno = errno;
				goto out;
			}
		}
	}

out:
	for (i = 0; i < e->num_phdrs; i++)
		call_phdr_post_write(e, i);

	return rv;
}

int
elfc_get_errno(struct elfc *e)
{
	return e->eerrno;
}

void
elfc_set_fd(struct elfc *e, int fd)
{
	e->fd = fd;
}

int
elfc_get_fd(struct elfc *e)
{
	return e->fd;
}

void
elfc_set_userdata(struct elfc *e, void *userdata)
{
	e->userdata = userdata;
}

void *
elfc_get_userdata(struct elfc *e)
{
	return e->userdata;
}
