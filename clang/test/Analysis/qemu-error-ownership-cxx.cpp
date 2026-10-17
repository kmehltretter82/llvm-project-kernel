// RUN: %clang_analyze_cc1 -std=c++17 \
// RUN:   -analyzer-checker=core,alpha.qemu.ErrorOwnership -verify %s

// C++ allocation events have implicit arguments and no CallExpr.  The QEMU
// Error checker must ignore them without asking the event for source arguments.
void allocation_is_ignored() {
  int *value = new int(1);
  delete value;
}

// expected-no-diagnostics
