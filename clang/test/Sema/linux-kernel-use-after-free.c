// RUN: %clang_cc1 -fsyntax-only -ffreestanding \
// RUN:   -Wlinux-kernel-use-after-free -verify %s
// RUN: %clang_cc1 -fsyntax-only -ffreestanding -Wall -verify=wall %s

// wall-no-diagnostics

#define NULL ((void *)0)

void kfree(const void *p);
void *kzalloc(unsigned long size, unsigned int flags);
void work(void);

struct item {
  int id;
  char *name;
  struct item *next;
};

struct dev {
  char *buf;
  int len;
};

void refill(struct dev *d);

// Memory that every path has freed.

int use_after_free(struct item *it) {
  kfree(it); // expected-note {{freed here}}
  return it->id; // expected-warning {{'it' is dereferenced here, and every path to this point has freed it}}
}

void wrong_order(struct item *it) {
  kfree(it); // expected-note {{freed here}}
  kfree(it->name); // expected-warning {{'it' is dereferenced here, and every path to this point has freed it}}
}

void right_order(struct item *it) {
  kfree(it->name);
  kfree(it);
}

void freed_twice(struct item *it, int verbose) {
  kfree(it); // expected-note {{freed here}}
  if (verbose)
    work();
  kfree(it); // expected-warning {{'it' is freed again here, and every path to this call has already freed it}}
}

// The loop reads the pointer to the next item from the one it has freed.

void walk(struct item *head) {
  struct item *it;

  for (it = head; it; it = it->next) // expected-warning {{'it' is dereferenced here, and every path to this point has freed it}}
    kfree(it); // expected-note {{freed here}}
}

void walk_safe(struct item *head) {
  struct item *it, *next;

  for (it = head; it; it = next) {
    next = it->next;
    kfree(it);
  }
}

// Not on every path, or not the same memory any more.

int on_one_path(struct item *it, int drop) {
  if (drop)
    kfree(it);
  return it->id;
}

int replaced(struct item *it) {
  kfree(it);
  it = kzalloc(sizeof(*it), 0);
  if (!it)
    return 0;
  return it->id;
}

void member_cleared(struct dev *d) {
  kfree(d->buf);
  d->buf = NULL;
  d->len = 0;
  kfree(d->buf);
}

void member_refilled(struct dev *d) {
  kfree(d->buf);
  refill(d);
  d->buf[0] = 0;
}

void member_freed_twice(struct dev *d) {
  kfree(d->buf); // expected-note {{freed here}}
  d->len = 0;
  kfree(d->buf); // expected-warning {{'d->buf' is freed again here, and every path to this call has already freed it}}
}
