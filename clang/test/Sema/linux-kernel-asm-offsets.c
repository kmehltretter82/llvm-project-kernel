// RUN: %clang_cc1 -fsyntax-only -triple x86_64-unknown-linux-gnu \
// RUN:   -Wlinux-kernel-experimental \
// RUN:   -flinux-kernel-experimental=asm-offsets -verify=expected,lp64 %s
// RUN: %clang_cc1 -fsyntax-only -triple or1k-unknown-linux-gnu \
// RUN:   -Wlinux-kernel-experimental \
// RUN:   -flinux-kernel-experimental=asm-offsets -verify=expected,ilp32 %s
// RUN: %clang_cc1 -fsyntax-only -triple x86_64-unknown-linux-gnu \
// RUN:   -Wlinux-kernel-experimental -flinux-kernel-experimental=all \
// RUN:   -verify=off %s
// off-no-diagnostics

// asm-offsets.c without a code generator: the lines that Kbuild picks out of
// the assembly are printed as diagnostics, with the value of the operand.
// "all" does not turn this on, it is a switch for the scan scripts.

#define DEFINE(sym, val) \
  asm volatile("\n.ascii \"->" #sym " %0 " #val "\"" : : "i" (val))
#define BLANK() asm volatile("\n.ascii \"->\"" : : )
#define COMMENT(x) asm volatile("\n.ascii \"->#" x "\"")
#define OFFSET(sym, str, mem) DEFINE(sym, __builtin_offsetof(struct str, mem))

struct task {
  long state;
  int flags;
  char comm[16];
  long long start;
};

enum { NR_THINGS = 7 };

int main(void) {
  COMMENT("offsets of struct task"); // expected-warning {{.ascii "->#offsets of struct task" (experimental check 'asm-offsets')}}
  OFFSET(TASK_STATE, task, state); // expected-warning {{.ascii "->TASK_STATE 0 __builtin_offsetof(struct task, state)"}}
  OFFSET(TASK_FLAGS, task, flags); // lp64-warning {{.ascii "->TASK_FLAGS 8 __builtin_offsetof(struct task, flags)"}} \
                                   // ilp32-warning {{.ascii "->TASK_FLAGS 4 __builtin_offsetof(struct task, flags)"}}
  OFFSET(TASK_START, task, start); // lp64-warning {{.ascii "->TASK_START 32 }} \
                                   // ilp32-warning {{.ascii "->TASK_START 24 }}
  BLANK(); // expected-warning {{.ascii "->" (experimental check 'asm-offsets')}}
  DEFINE(TASK_SIZE, sizeof(struct task)); // lp64-warning {{.ascii "->TASK_SIZE 40 sizeof(struct task)"}} \
                                          // ilp32-warning {{.ascii "->TASK_SIZE 32 sizeof(struct task)"}}
  DEFINE(NR_THINGS_PLUS_ONE, NR_THINGS + 1); // expected-warning {{.ascii "->NR_THINGS_PLUS_ONE 8 NR_THINGS + 1"}}
  DEFINE(MINUS_ONE, -1); // expected-warning {{.ascii "->MINUS_ONE -1 -1"}}
  return 0;
}

// An asm statement that is not one of these is left alone.
void other(void) {
  asm volatile("nop");
}
