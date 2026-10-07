// RUN: %clang --target=sh4-linux-gnu -pg -S -emit-llvm -o - %s | FileCheck %s

// -pg marks a function for the call of mcount that the backend puts in
// front of the prologue, not for a call in the function body.

int counted(int x) { return x + 1; }
__attribute__((no_instrument_function)) int not_counted(int x) { return x + 2; }

// CHECK: define{{.*}} i32 @counted(i32 noundef %x) [[COUNTED:#[0-9]+]]
// CHECK: define{{.*}} i32 @not_counted(i32 noundef %x) [[NOT:#[0-9]+]]
// CHECK: attributes [[COUNTED]] = {{.*}}"fentry-call"="true"
// CHECK-NOT: attributes [[NOT]] = {{.*}}"fentry-call"
// CHECK-NOT: instrument-function-entry
