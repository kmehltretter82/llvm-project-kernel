// RUN: %clang_cc1 -triple sh4-unknown-linux-gnu -fcxx-exceptions -fexceptions -emit-llvm -o - %s | FileCheck %s

// A handler that catches a pointer by reference binds the reference to the
// object that was thrown, which is right behind the header of the unwinder.
// struct _Unwind_Exception of libgcc has 20 bytes on SuperH: 64 bits and
// three words, and nothing is aligned to more than four bytes.

void may_throw();

int f() {
  try {
    may_throw();
  } catch (int *&p) {
    return *p;
  }
  return 0;
}

// CHECK-LABEL: define{{.*}} i32 @_Z1fv()
// CHECK: [[EXN:%.*]] = load ptr, ptr %exn.slot
// CHECK: call ptr @__cxa_begin_catch(ptr [[EXN]])
// CHECK: [[OBJECT:%.*]] = getelementptr i8, ptr [[EXN]], i32 20
// CHECK: store ptr [[OBJECT]], ptr %p
