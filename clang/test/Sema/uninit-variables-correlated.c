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
