// RUN: %clang_cc1 -triple riscv64-unknown-linux-gnu -emit-llvm -o - %s \
// RUN:   | FileCheck %s

void source_site(void) {
  __builtin_riscv_linux_irq_site(39, 7);
}

// CHECK-LABEL: define{{.*}} void @source_site()
// CHECK: call void @llvm.riscv.linux.irq.site(i32 39, i32 7)
// CHECK: ret void
// CHECK: declare void @llvm.riscv.linux.irq.site(i32 immarg, i32 immarg)
