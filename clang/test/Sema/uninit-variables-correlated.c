// RUN: %clang_cc1 -fsyntax-only -Wconditional-uninitialized -verify=maybe %s
// RUN: %clang_cc1 -fsyntax-only -Wconditional-uninitialized \
// RUN:   -Wconditional-uninitialized-correlated -verify=maybe,corr %s

// A use that -Wconditional-uninitialized cannot prove initialized is not
// reported when every path that leaves the variable uninitialized contradicts
// a condition it took earlier.  Such uses are available separately under
// -Wconditional-uninitialized-correlated.

int f(void);
void use(int);

void same_condition(int flag) {
  int x; // corr-note {{variable 'x' is declared here}}
  if (flag)
    x = f();
  f();
  if (flag)
    use(x); // corr-warning {{variable 'x' is uninitialized when used here only on paths that an earlier condition excludes}}
}

void flag_set_with_value(int a) {
  int have = 0;
  int x; // corr-note {{variable 'x' is declared here}}
  if (a > 3) {
    x = f();
    have = 1;
  }
  if (have)
    use(x); // corr-warning {{variable 'x' is uninitialized when used here only on paths that an earlier condition excludes}}
}

void loop_runs_at_least_once(void) {
  int i;
  int x; // corr-note {{variable 'x' is declared here}}
  for (i = 0; i < 4; i++)
    x = f();
  use(x); // corr-warning {{variable 'x' is uninitialized when used here only on paths that an earlier condition excludes}}
}

void status_set_with_value(int n) {
  int ret = -1;
  int x; // corr-note {{variable 'x' is declared here}}
  int i;
  for (i = 0; i < n; i++) {
    if (f()) {
      x = i;
      ret = 0;
      break;
    }
  }
  if (ret)
    return;
  use(x); // corr-warning {{variable 'x' is uninitialized when used here only on paths that an earlier condition excludes}}
}

void pointer_set_with_value(int a) {
  const char *name = 0;
  int x; // corr-note {{variable 'x' is declared here}}
  if (a == 1) {
    x = 1;
    name = "one";
  } else if (a == 2) {
    x = 2;
    name = "two";
  }
  if (!name)
    return;
  use(x); // corr-warning {{variable 'x' is uninitialized when used here only on paths that an earlier condition excludes}}
}

void unlikely_wrapper(int flag) {
  int x; // corr-note {{variable 'x' is declared here}}
  if (__builtin_expect(!!(flag), 0))
    x = f();
  if (flag)
    use(x); // corr-warning {{variable 'x' is uninitialized when used here only on paths that an earlier condition excludes}}
}

// The cases below stay ordinary -Wconditional-uninitialized reports.

void unrelated_conditions(int a, int b) {
  int x; // maybe-note {{initialize the variable 'x' to silence this warning}}
  if (a)
    x = f();
  if (b)
    use(x); // maybe-warning {{variable 'x' may be uninitialized when used here}}
}

void condition_changes(int flag) {
  int x; // maybe-note {{initialize the variable 'x' to silence this warning}}
  if (flag)
    x = f();
  flag = f();
  if (flag)
    use(x); // maybe-warning {{variable 'x' may be uninitialized when used here}}
}

void condition_reads_memory(int *p) {
  int x; // maybe-note {{initialize the variable 'x' to silence this warning}}
  if (*p)
    x = f();
  f(); // may change *p
  if (*p)
    use(x); // maybe-warning {{variable 'x' may be uninitialized when used here}}
}

void loop_may_not_run(int n) {
  int i;
  int x; // maybe-note {{initialize the variable 'x' to silence this warning}}
  for (i = 0; i < n; i++)
    x = f();
  use(x); // maybe-warning {{variable 'x' may be uninitialized when used here}}
}

void flag_cleared_again(int a) {
  int have = 0;
  int x; // maybe-note {{initialize the variable 'x' to silence this warning}}
  if (a) {
    x = f();
    have = 1;
  }
  have = f();
  if (have)
    use(x); // maybe-warning {{variable 'x' may be uninitialized when used here}}
}

// A switch on a variable takes the case that its known value selects.
void switch_after_value_check(int cmd) {
  int x; // corr-note {{variable 'x' is declared here}}
  if (cmd != 1 && cmd != 2)
    return;
  switch (cmd) {
  case 1:
    x = f();
    break;
  case 2:
    x = 0;
    break;
  }
  use(x); // corr-warning {{variable 'x' is uninitialized when used here only on paths that an earlier condition excludes}}
}

// Each case edge makes the value known for a later switch or test.
void two_switches(int mode) {
  int x; // corr-note {{variable 'x' is declared here}}
  switch (mode) {
  case 1:
  case 2:
    x = f();
    break;
  default:
    break;
  }
  f();
  switch (mode) {
  case 2:
    use(x); // corr-warning {{variable 'x' is uninitialized when used here only on paths that an earlier condition excludes}}
    break;
  default:
    break;
  }
}

void switch_then_test(int mode) {
  int x; // corr-note {{variable 'x' is declared here}}
  switch (mode) {
  case 4 ... 6:
    x = f();
    break;
  default:
    break;
  }
  if (mode == 5)
    use(x); // corr-warning {{variable 'x' is uninitialized when used here only on paths that an earlier condition excludes}}
}

void switch_leaves_a_value_out(int mode) {
  int x; // maybe-note {{initialize the variable 'x' to silence this warning}}
  switch (mode) {
  case 1:
    x = f();
    break;
  default:
    break;
  }
  if (mode == 1 || mode == 2)
    use(x); // maybe-warning {{variable 'x' may be uninitialized when used here}}
}

void switched_variable_changes(int mode) {
  int x; // maybe-note {{initialize the variable 'x' to silence this warning}}
  switch (mode) {
  case 1:
    x = f();
    break;
  default:
    break;
  }
  mode = f();
  if (mode == 1)
    use(x); // maybe-warning {{variable 'x' may be uninitialized when used here}}
}

// A block that ends in "if (a && b)" tests only b.
void second_operand_decides(int a, int b) {
  int x; // corr-note {{variable 'x' is declared here}}
  if (a && b)
    x = f();
  f();
  if (b && a)
    use(x); // corr-warning {{variable 'x' is uninitialized when used here only on paths that an earlier condition excludes}}
}

// "Not equal" has no value to remember, but the outcome of the test does.
void same_value_test(int mode) {
  int x; // corr-note {{variable 'x' is declared here}}
  if (mode == 2)
    x = f();
  f();
  if (mode == 2)
    use(x); // corr-warning {{variable 'x' is uninitialized when used here only on paths that an earlier condition excludes}}
}

// The iterator macros of the Linux kernel assign in the second operand of
// "&&" under a negation: if (!(cond)) {} else body.
struct set {
  int n;
  int *item[8];
};
#define for_each_if(condition) if (!(condition)) {} else
#define for_each_item(s, p, i)                                                \
  for ((i) = 0; (i) < (s)->n; (i)++)                                          \
    for_each_if ((s)->item[i] && ((p) = (s)->item[i], 1))

void usep(const int *);

void iterator_macro(struct set *s) {
  int *p; // corr-note {{variable 'p' is declared here}}
  int i;
  for_each_item(s, p, i)
    usep(p); // corr-warning {{variable 'p' is uninitialized when used here only on paths that an earlier condition excludes}}
}

// The address of an object is not null.
extern const int table_a[4], table_b[4];

void address_is_not_null(int type) {
  const int *special = 0;
  const int *regular; // corr-note {{variable 'regular' is declared here}}
  switch (type) {
  case 1:
    special = table_a;
    break;
  default:
    regular = table_b;
    break;
  }
  f();
  if (special)
    usep(special);
  else
    usep(regular); // corr-warning {{variable 'regular' is uninitialized when used here only on paths that an earlier condition excludes}}
}

// "a >= b" being false makes "a < b" true.
void same_comparison(int from, int to) {
  int err; // corr-note {{variable 'err' is declared here}}
  if (from >= to)
    return;
  for (; from < to; from++)
    err = f();
  use(err); // corr-warning {{variable 'err' is uninitialized when used here only on paths that an earlier condition excludes}}
}

void other_comparison(int from, int to) {
  int err; // maybe-note {{initialize the variable 'err' to silence this warning}}
  if (from > to)
    return;
  for (; from < to; from++)
    err = f();
  use(err); // maybe-warning {{variable 'err' may be uninitialized when used here}}
}

// A path that dereferences a pointer it knows to be null ends there.
struct node {
  struct node *next;
  int stamp;
};

void companion_of_pointer(struct node **head) {
  struct node **oldest_p; // corr-note {{variable 'oldest_p' is declared here}}
  struct node **p;
  struct node *n, *oldest = 0;

  for (p = head;; p = &n->next) {
    n = *p;
    if (!n)
      break;
    if (!oldest || n->stamp < oldest->stamp) {
      oldest = n;
      oldest_p = p;
    }
  }
  oldest->stamp = 0;
  *oldest_p = oldest->next; // corr-warning {{variable 'oldest_p' is uninitialized when used here only on paths that an earlier condition excludes}}
}

void address_of_member_is_no_access(struct node *n, int a) {
  int x; // maybe-note {{initialize the variable 'x' to silence this warning}}
  struct node **link;
  if (n)
    x = f();
  link = &n->next;
  usep((const int *)link);
  if (a)
    use(x); // maybe-warning {{variable 'x' may be uninitialized when used here}}
}

void access_through_null(struct node *n, int a) {
  int x; // corr-note {{variable 'x' is declared here}}
  if (n)
    x = f();
  n->stamp = 1;
  if (a)
    use(x); // corr-warning {{variable 'x' is uninitialized when used here only on paths that an earlier condition excludes}}
}
