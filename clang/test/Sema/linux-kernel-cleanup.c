// RUN: %clang_cc1 -fsyntax-only -ffreestanding -Wlinux-kernel-cleanup-return \
// RUN:   -Wlinux-kernel-cleanup-escape -verify=free %s
// RUN: %clang_cc1 -fsyntax-only -ffreestanding -Wlinux-kernel \
// RUN:   -Wno-conditional-uninitialized -verify=umbrella %s
// RUN: %clang_cc1 -fsyntax-only -ffreestanding -Wall -verify=wall %s

// wall-no-diagnostics

#define NULL ((void *)0)
#define EINVAL 22
#define ENOMEM 12

_Bool IS_ERR(const void *);
int *make_buffer(void);
void *kzalloc(unsigned long, unsigned int);
void kfree(const void *);
int use(void *);

// What <linux/cleanup.h> provides.
static inline void __free_kfree(void *p) {
  void *_T = *(void **)p;

  if (_T)
    kfree(_T);
}
#define __free(name) __attribute__((cleanup(__free_##name)))
#define no_free_ptr(p)                                                         \
  ({                                                                           \
    __auto_type __ptr = &(p);                                                  \
    __auto_type __val = *__ptr;                                                \
    *__ptr = NULL;                                                             \
    __val;                                                                     \
  })
#define return_ptr(p) return no_free_ptr(p)

struct obj {
  int *data;
};

// A __free() pointer that leaves the function while still armed.

int *returned(void) {
  int *buf __free(kfree) = kzalloc(4, 0); // free-note {{'buf' is declared with a cleanup function here; no_free_ptr() or return_ptr() passes the ownership on}} \
                                          // umbrella-note {{'buf' is declared with a cleanup function here; no_free_ptr() or return_ptr() passes the ownership on}}

  if (!buf)
    return NULL;
  return buf; // free-warning {{'buf' is returned, but its cleanup function '__free_kfree' releases it at this return}} \
              // umbrella-warning {{'buf' is returned, but its cleanup function '__free_kfree' releases it at this return}}
}

int *returned_properly(void) {
  int *buf __free(kfree) = kzalloc(4, 0);

  if (!buf)
    return NULL;
  return_ptr(buf);
}

// An error pointer or NULL: the cleanup function has nothing to release.
int *returned_as_error(void) {
  int *buf __free(kfree) = make_buffer();

  if (IS_ERR(buf))
    return buf;
  if (!buf)
    return buf;
  return_ptr(buf);
}

int stored(struct obj *o) {
  int *buf __free(kfree) = kzalloc(4, 0); // free-note {{'buf' is declared with a cleanup function here; no_free_ptr() or return_ptr() passes the ownership on}}

  if (!buf)
    return -ENOMEM;
  o->data = buf; // free-warning {{'buf' is stored here, but its cleanup function '__free_kfree' releases it when the variable goes out of scope}}
  return 0;
}

int stored_through_parameter(int **out) {
  int *buf __free(kfree) = kzalloc(4, 0); // free-note {{'buf' is declared with a cleanup function here; no_free_ptr() or return_ptr() passes the ownership on}}

  if (!buf)
    return -ENOMEM;
  *out = buf; // free-warning {{'buf' is stored here, but its cleanup function '__free_kfree' releases it when the variable goes out of scope}}
  return 0;
}

int stored_properly(struct obj *o) {
  int *buf __free(kfree) = kzalloc(4, 0);

  if (!buf)
    return -ENOMEM;
  o->data = no_free_ptr(buf);
  return 0;
}

int stored_and_cleared(struct obj *o) {
  int *buf __free(kfree) = kzalloc(4, 0);

  if (!buf)
    return -ENOMEM;
  o->data = buf;
  buf = NULL;
  return 0;
}

// An object of this function does not outlive the pointer.
int stored_locally(void) {
  struct obj tmp;
  int *buf __free(kfree) = kzalloc(4, 0);

  tmp.data = buf;
  return use(&tmp);
}

// -Wuninitialized-cleanup is part of the umbrella.
int never_set(int bad) {
  int *buf __free(kfree); // umbrella-warning {{variable 'buf' is uninitialized when its cleanup function '__free_kfree' runs}}

  if (bad)
    return -ENOMEM; // umbrella-note {{the scope of 'buf' is left here}}
  buf = kzalloc(4, 0);
  return use(buf);
}

// A reference that is taken for the stored pointer: the cleanup function
// drops the other one.

struct node;
struct node *node_get(struct node *n);
struct node *find_node(int id);
static inline void __free_node(void *p) { (void)p; }

struct owner {
  struct node *node;
};

void stored_with_reference(struct owner *o) {
  struct node *n __free(node) = find_node(1);

  o->node = n;
  node_get(n);
}

// Whether there is one: the function returns a truth value, and the node
// is released as it should be.
_Bool node_present(void) {
  struct node *n __free(node) = find_node(1);

  return n;
}
