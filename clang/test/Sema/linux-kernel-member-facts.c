// The "mem" facts: pointer members that are stored, freed or handed on, and
// the report of clang/utils/linux-kernel/member-leaks.py over them.
//
// RUN: rm -rf %t && mkdir %t
// RUN: %clang_cc1 -fsyntax-only -ffreestanding -flinux-kernel-emit-facts=%t/facts %s
// RUN: FileCheck --check-prefix=FACTS --input-file=%t/facts %s
// RUN: %python %S/../../utils/linux-kernel/member-leaks.py %t/facts \
// RUN:   | FileCheck --check-prefix=LEAKS %s

typedef unsigned long size_t;
void *calloc(size_t, size_t);
char *strdup(const char *);
char *strchr(const char *, int);
void free(void *);
void freezero(void *, size_t);
int printf(const char *, ...);
void keep(char *);

struct ssh {
	char *remote_version;	/* stored in one function, freed nowhere */
	char *remote_ipaddr;	/* stored and freed */
	char *handed;		/* stored, read into a local */
	char *passed;		/* stored, passed through a char * parameter */
	char *printed;		/* stored, only printed: that is a read */
	char *borrowed;		/* strchr() result: no fresh allocation */
	const char *name;	/* a const pointer is never fresh */
};

int exchange(struct ssh *ssh, const char *banner)
{
	char *remote_version = 0;
	int r = -1;

	if ((remote_version = calloc(1, 64)) == 0)
		goto out;
	r = 0;
 out:
	ssh->remote_version = remote_version;  /* transferred */
	return r;
}

void setup(struct ssh *ssh, const char *addr)
{
	ssh->remote_ipaddr = strdup(addr);
	ssh->handed = strdup(addr);
	ssh->passed = strdup(addr);
	ssh->printed = strdup(addr);
	ssh->borrowed = strchr(addr, ':');
	ssh->name = addr;
}

void close_ssh(struct ssh *ssh)
{
	char *tmp = ssh->handed;

	free(ssh->remote_ipaddr);
	ssh->remote_ipaddr = 0;
	keep(ssh->passed);
	printf("%s %s\n", ssh->printed, ssh->remote_version);
	freezero(tmp, 1);
}

// The lines are sorted; a member without a flag (borrowed, name) gets none.
// FACTS:      mem{{	}}ssh::handed{{	}}{{.*}}{{	}}SE{{$}}
// FACTS-NEXT: mem{{	}}ssh::passed{{	}}{{.*}}{{	}}SE{{$}}
// FACTS-NEXT: mem{{	}}ssh::printed{{	}}{{.*}}{{	}}S{{$}}
// FACTS-NEXT: mem{{	}}ssh::remote_ipaddr{{	}}{{.*}}{{	}}SF{{$}}
// FACTS-NEXT: mem{{	}}ssh::remote_version{{	}}{{.*}}{{	}}S{{$}}
// FACTS-NOT:  mem{{	}}

// LEAKS:      ssh::printed{{	}}stored in {{.*}}{{	}}never freed or handed on
// LEAKS-NEXT: ssh::remote_version{{	}}stored in {{.*}}{{	}}never freed or handed on
// LEAKS-NOT:  ssh::
