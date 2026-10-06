// RUN: %clang_cc1 -fsyntax-only -ffreestanding -Wlinux-kernel-duplicate-check \
// RUN:   -verify %s
// RUN: %clang_cc1 -fsyntax-only -ffreestanding -Wall -verify=wall %s

// wall-no-diagnostics

#define NULL ((void *)0)
#define EINVAL 22

int step_one(void);
int step_two(void);
void work(void);

struct thing {
  int id;
};
struct thing *lookup(int id);

// The assignment that was meant to come between the two tests is missing.

int lost_assignment(void) {
  int err = step_one();

  if (err) // expected-note {{previous test is here}}
    goto out;
  step_two();
  if (err) // expected-warning {{'err' is always zero here: every path has tested it and it has not changed since}}
    goto out;
  return 0;
out:
  return err;
}

int assigned_between(void) {
  int err = step_one();

  if (err)
    return err;
  err = step_two();
  if (err)
    return err;
  return 0;
}

// The second test went to the wrong pointer.

int wrong_pointer(int a, int b) {
  struct thing *first, *second;

  first = lookup(a);
  if (!first) // expected-note {{previous test is here}}
    return -EINVAL;
  second = lookup(b);
  if (!first) // expected-warning {{'first' is always nonzero here}}
    return -EINVAL;
  return first->id + second->id;
}

int nested(int x) {
  if (x) { // expected-note {{previous test is here}}
    work();
    if (x) // expected-warning {{'x' is always nonzero here}}
      return 1;
  }
  return 0;
}

// Both outcomes of the first test reach the second one.

int both_paths(int x) {
  int n = 0;

  if (x)
    n = 1;
  if (x)
    n += 2;
  return n;
}

int loop(int n) {
  int found = 0;

  while (n--) {
    if (found)
      break;
    found = step_one();
  }
  if (found)
    return 1;
  return 0;
}

// The assignment may be in code that this configuration leaves out.

int conditional_code(void) {
  int err = step_one();

  if (err)
    return err;
#ifdef CONFIG_SECOND_STEP
  err = step_two();
#endif
  if (err)
    return err;
  return 0;
}

#define IS_ENABLED(x) 0

int disabled_branch(void) {
  int err = step_one();

  if (err)
    return err;
  if (IS_ENABLED(CONFIG_SECOND_STEP))
    err = step_two();
  if (err)
    return err;
  return 0;
}

// A test in a macro is not the author's.

#define CHECK(x)                                                               \
  do {                                                                         \
    if (x)                                                                     \
      work();                                                                  \
  } while (0)

int macro_test(int x) {
  if (!x)
    return 0;
  CHECK(x);
  return 1;
}
