
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <elf.h>

const char *progname;

static int makedyn_one_exec(const char *file)
{
	int fd, rv;
	unsigned char e_ident[EI_NIDENT + 2];
	Elf64_Half type;

	fd = open(file, O_RDWR);
	if (fd == -1) {
		fprintf(stderr, "Unable to open %s: %s\n", file,
			strerror(errno));
		return 1;
	}

	rv = read(fd, e_ident, sizeof(e_ident));
	if (rv == -1) {
		fprintf(stderr, "Unable to read %s: %s\n", file,
			strerror(errno));
		goto out_err;
	}
	if (rv < sizeof(e_ident)) {
		fprintf(stderr, "Only able to read %d bytes from %s\n",
			rv, file);
		goto out_err;
	}
	if (memcmp(ELFMAG, e_ident, SELFMAG) != 0) {
		fprintf(stderr, "%s not an ELF file\n", file);
		goto out_err;
	}

	if (e_ident[EI_DATA] == ELFDATA2LSB) {
		type = e_ident[EI_NIDENT] | e_ident[EI_NIDENT + 1] << 8;
	} else if (e_ident[EI_DATA] == ELFDATA2MSB) {
		type = e_ident[EI_NIDENT + 1] | e_ident[EI_NIDENT] << 8;
	} else {
		fprintf(stderr, "%s: Unknown data encoding: %d\n", file,
			e_ident[EI_DATA]);
		goto out_err;
	}

	if (type == ET_DYN) {
		/* Already dynamic. */
		return 0;
	}
	if (type != ET_EXEC) {
		fprintf(stderr, "%s: Not a fixed executable, type is: %d\n",
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
		fprintf(stderr, "Unable to seek %s: %s\n", file,
			strerror(errno));
		goto out_err;
	}

	rv = write(fd, e_ident + EI_NIDENT, sizeof(type));
	if (rv == -1) {
		fprintf(stderr, "Unable to write to %s: %s\n", file,
			strerror(errno));
		goto out_err;
	}

	close(fd);
	return 0;

out_err:
	close(fd);
	return 1;
}

static void
help(void)
{
	printf("Usage: %s <executable1> [<executable2> [...]]\n", progname);
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

int main(int argc, char *argv[])
{
	int rv;
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

	while (optind < argc) {
		rv = makedyn_one_exec(argv[optind]);
		if (rv)
			break;
		optind++;
	}
		
	return rv;
}
