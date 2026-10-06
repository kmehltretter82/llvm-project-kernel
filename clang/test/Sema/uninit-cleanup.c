// A variable with the cleanup attribute whose cleanup function runs while the
// variable is uninitialized.
//
// RUN: %clang_cc1 -fsyntax-only -Wuninitialized-cleanup \
// RUN:   -Wconditional-uninitialized-cleanup -verify=uninit %s
// RUN: %clang_cc1 -fsyntax-only -Wuninitialized-cleanup -verify=always %s
// RUN: %clang_cc1 -fsyntax-only -Wall -verify=wall %s

// wall-no-diagnostics

#define NULL ((void *)0)
#define EINVAL 22

void *kzalloc(unsigned long, unsigned int);
void kfree(const void *);
int use(void *);

static inline void __free_kfree(void *p) {
  void *_T = *(void **)p;

  if (_T)
    kfree(_T);
}
#define __free(name) __attribute__((cleanup(__free_##name)))

int never_set_on_early_return(int bad) {
  int *buf __free(kfree); // uninit-warning {{variable 'buf' is uninitialized when its cleanup function '__free_kfree' runs}} \
                          // always-warning {{variable 'buf' is uninitialized when its cleanup function '__free_kfree' runs}}

  if (bad)
    return -EINVAL; // uninit-note {{the scope of 'buf' is left here}} \
                    // always-note {{the scope of 'buf' is left here}}
  buf = kzalloc(4, 0);
  return use(buf);
}

int set_on_one_branch(int some) {
  int *buf __free(kfree); // uninit-warning {{variable 'buf' may be uninitialized when its cleanup function '__free_kfree' runs}}

  if (some)
    buf = kzalloc(4, 0);
  return 0; // uninit-note {{the scope of 'buf' is left here}}
}

int set_at_once(int bad) {
  int *buf __free(kfree) = NULL;

  if (bad)
    return -EINVAL;
  buf = kzalloc(4, 0);
  return use(buf);
}

int set_before_any_exit(int bad) {
  int *buf __free(kfree);

  buf = kzalloc(4, 0);
  if (bad)
    return -EINVAL;
  return use(buf);
}

// A cleanup function that only overwrites the variable does not read it.
struct key {
  unsigned char bytes[32];
  int *extra;
};
void *memset(void *, int, unsigned long);
void memzero_explicit(void *, unsigned long);
static inline void wipe_key(struct key *k) { memzero_explicit(k, sizeof(*k)); }
static inline void clear_key(struct key *k) { memset(k, 0, sizeof(*k)); }
static inline void drop_key(struct key *k) {
  kfree(k->extra);
  memset(k, 0, sizeof(*k));
}
int prepare(struct key *);

int wiped_on_early_return(int bad) {
  struct key k __attribute__((cleanup(wipe_key)));
  struct key c __attribute__((cleanup(clear_key)));

  if (bad)
    return -EINVAL;
  return prepare(&k) + prepare(&c);
}

int read_on_early_return(int bad) {
  struct key k __attribute__((cleanup(drop_key))); // uninit-warning {{variable 'k' is uninitialized when its cleanup function 'drop_key' runs}} \
                                                   // always-warning {{variable 'k' is uninitialized when its cleanup function 'drop_key' runs}}

  if (bad)
    return -EINVAL; // uninit-note {{the scope of 'k' is left here}} \
                    // always-note {{the scope of 'k' is left here}}
  return prepare(&k);
}
