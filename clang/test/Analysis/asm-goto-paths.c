// RUN: %clang_analyze_cc1 -triple x86_64-pc-linux-gnu \
// RUN:   -analyzer-checker=core,debug.ExprInspection -verify %s

void clang_analyzer_eval(int);
void clang_analyzer_warnIfReached(void);

// The shape of a Linux kernel static branch.
static inline int static_branch(const int *key) {
  asm goto("jmp %l[l_yes]" : : "i"(key) : : l_yes);
  return 0;
l_yes:
  return 1;
}

int key;

void both_ways(void) {
  if (static_branch(&key))
    clang_analyzer_warnIfReached(); // expected-warning {{REACHABLE}}
  else
    clang_analyzer_warnIfReached(); // expected-warning {{REACHABLE}}
  clang_analyzer_warnIfReached();   // expected-warning {{REACHABLE}}
}

int null_after_asm_goto(int *p) {
  if (static_branch(&key))
    p = 0;
  return *p; // expected-warning {{Dereference of null pointer (loaded from variable 'p')}}
}

void outputs_are_forgotten(void) {
  int x = 1;

  asm goto("" : "=r"(x) : : : out);
  clang_analyzer_eval(x == 1); // expected-warning {{UNKNOWN}}
  return;
out:
  clang_analyzer_eval(x == 1); // expected-warning {{UNKNOWN}}
}
