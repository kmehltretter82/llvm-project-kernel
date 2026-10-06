// What a function does with its pointer parameters, across translation
// units: the facts of two other units are closed into a contracts file, and
// this unit is checked with it.
//
// RUN: rm -rf %t && mkdir %t
// RUN: %clang_cc1 -fsyntax-only -ffreestanding -DUNIT_A \
// RUN:   -flinux-kernel-emit-facts=%t/facts %s
// RUN: %clang_cc1 -fsyntax-only -ffreestanding -DUNIT_B \
// RUN:   -flinux-kernel-emit-facts=%t/facts %s
// RUN: FileCheck --check-prefix=FACTS --input-file=%t/facts %s
// RUN: %python %S/../../utils/linux-kernel/infer-contracts.py \
// RUN:   -o %t/contracts %t/facts
// RUN: FileCheck --check-prefix=CONTRACTS --input-file=%t/contracts %s
// RUN: %clang_cc1 -fsyntax-only -ffreestanding -Wlinux-kernel-experimental \
// RUN:   -Wlinux-kernel-deref-after-check -flinux-kernel-experimental=all \
// RUN:   -flinux-kernel-contracts=%t/contracts -verify %s
//
// Without the contracts file nothing is known about the other units:
// RUN: %clang_cc1 -fsyntax-only -ffreestanding -Wlinux-kernel-experimental \
// RUN:   -Wlinux-kernel-deref-after-check -flinux-kernel-experimental=all \
// RUN:   -verify=none %s
// none-no-diagnostics

#define NULL ((void *)0)
#define ENODEV 19

struct dev {
  int id;
  int cached;
};

int _printk(const char *fmt, ...);
int xfer(struct dev *d);

void set_id(struct dev *d, int id);
void set_id_checked(struct dev *d, int id);
void set_id_far(struct dev *d, int id);
void forward(struct dev *d);
void differs(struct dev *d);
int read_reg(struct dev *d, int *val);
int read_cached(struct dev *d, int *val);
void read_or_not(struct dev *d, int *val);
int read_differs(struct dev *d, int *val);

#if defined(UNIT_A)

// FACTS-DAG: par{{	}}set_id{{	.*	}}d0
void set_id(struct dev *d, int id) {
  d->id = id;
}

// FACTS-DAG: par{{	}}set_id_checked{{	.*	}}-
void set_id_checked(struct dev *d, int id) {
  if (d)
    d->id = id;
}

// The function that this one hands its parameter to is in the other unit.
// FACTS-DAG: par{{	}}forward{{	.*	}}p0:set_id_far:0
void forward(struct dev *d) {
  set_id_far(d, 1);
}

// FACTS-DAG: par{{	}}differs{{	.*	}}d0
void differs(struct dev *d) {
  d->id = 0;
}

// The first parameter goes to a function that nothing is known about, the
// second is not written when that function fails.
// FACTS-DAG: par{{	}}read_reg{{	.*	}}p0:xfer:0,w1:1
int read_reg(struct dev *d, int *val) {
  int ret = xfer(d);

  if (ret < 0)
    return ret;
  *val = d->id;
  return 0;
}

// FACTS-DAG: par{{	}}read_cached{{	.*	}}d0,w1:2
int read_cached(struct dev *d, int *val) {
  if (d->cached)
    *val = d->id;
  return 0;
}

// FACTS-DAG: par{{	}}read_or_not{{	.*	}}d0,w1:8
void read_or_not(struct dev *d, int *val) {
  if (d->cached)
    return;
  *val = d->id;
}

// FACTS-DAG: par{{	}}read_differs{{	.*	}}d0,w1:1
int read_differs(struct dev *d, int *val) {
  if (!d->cached)
    return -ENODEV;
  *val = d->id;
  return 0;
}

#elif defined(UNIT_B)
#line 1 "unit-b.c"

// FACTS-DAG: par{{	}}set_id_far{{	}}unit-b.c{{	}}d0
void set_id_far(struct dev *d, int id) {
  d->id = id;
}

// Another definition of two functions of the first unit, as a weak default
// and its override are.  This one is prepared for NULL, and always writes.
// FACTS-DAG: par{{	}}differs{{	}}unit-b.c{{	}}-
void differs(struct dev *d) {
  if (!d)
    return;
  d->id = 0;
}

// FACTS-DAG: par{{	}}read_differs{{	}}unit-b.c{{	}}d0
int read_differs(struct dev *d, int *val) {
  *val = d->id;
  return 0;
}

#else

// CONTRACTS-DAG: derefs{{	}}set_id{{	}}0
// CONTRACTS-DAG: derefs{{	}}set_id_far{{	}}0
// CONTRACTS-DAG: derefs{{	}}forward{{	}}0
// CONTRACTS-DAG: derefs{{	}}read_cached{{	}}0
// CONTRACTS-DAG: derefs{{	}}read_differs{{	}}0
// CONTRACTS-DAG: nowrite{{	}}read_reg{{	}}1{{	}}1
// CONTRACTS-DAG: nowrite{{	}}read_cached{{	}}1{{	}}2
// CONTRACTS-DAG: nowrite{{	}}read_or_not{{	}}1{{	}}8
// CONTRACTS-NOT: set_id_checked
// CONTRACTS-NOT: derefs{{	}}differs
// CONTRACTS-NOT: derefs{{	}}read_reg
// CONTRACTS-NOT: nowrite{{	}}read_differs

void null_arguments(void) {
  set_id(NULL, 1); // expected-warning {{NULL is passed for parameter 1 of 'set_id', which dereferences it without a test (experimental check 'null-argument')}} \
                   // expected-note {{'set_id' is defined in another file, and the contracts file says that it dereferences this parameter}}
  forward(NULL); // expected-warning {{NULL is passed for parameter 1 of 'forward', which dereferences it without a test (experimental check 'null-argument')}} \
                 // expected-note {{'forward' is defined in another file, and the contracts file says that it dereferences this parameter}}
  set_id_checked(NULL, 1);
  differs(NULL);
}

int after_check(struct dev *d) {
  if (!d) // expected-note {{'d' is tested here and the path goes on with it being NULL}}
    _printk("no device\n");
  set_id(d, 2); // expected-warning {{'d' is passed to 'set_id', which dereferences it, on a path where the earlier test found it to be NULL}} \
                // expected-note {{'set_id' is defined in another file, and the contracts file says that it dereferences this parameter}}
  return 0;
}

int output_ignored(struct dev *d) {
  int val;

  read_reg(d, &val); // expected-note {{the address of 'val' is passed to 'read_reg' here}} \
                     // expected-note {{'read_reg' is defined in another file, and the contracts file says for which results it leaves the parameter alone}}
  return val; // expected-warning {{'val' is read here, but 'read_reg' does not write to it when it fails, and the result of the call is not tested (experimental check 'uninit-output')}}
}

int output_tested(struct dev *d) {
  int val;

  if (read_reg(d, &val))
    return -1;
  return val;
}

int output_success(struct dev *d) {
  int val;
  int ret = read_cached(d, &val); // expected-note {{the address of 'val' is passed to 'read_cached' here}} \
                                  // expected-note {{'read_cached' is defined in another file, and the contracts file says for which results it leaves the parameter alone}}

  if (ret)
    return ret;
  return val; // expected-warning {{'val' is read here, but 'read_cached' can return 0 without writing to it (experimental check 'uninit-output')}}
}

int output_void(struct dev *d) {
  int val;

  read_or_not(d, &val); // expected-note {{the address of 'val' is passed to 'read_or_not' here}} \
                        // expected-note {{'read_or_not' is defined in another file, and the contracts file says for which results it leaves the parameter alone}}
  return val; // expected-warning {{'val' is read here, but 'read_or_not' can return without writing to it (experimental check 'uninit-output')}}
}

// One of its two definitions always writes.
int output_differs(struct dev *d) {
  int val;

  read_differs(d, &val);
  return val;
}

#endif
