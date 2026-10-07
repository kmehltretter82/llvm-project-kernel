// RUN: %clang_cc1 -triple sh4-unknown-linux-gnu -target-cpu sh4-nofpu -emit-llvm -o - %s | FileCheck --check-prefixes=CHECK,LE %s
// RUN: %clang_cc1 -triple sh4eb-unknown-linux-gnu -target-cpu sh4-nofpu -emit-llvm -o - %s | FileCheck --check-prefixes=CHECK,BE %s
// RUN: %clang_cc1 -triple sh2-unknown-linux-gnu -emit-llvm -o - %s | FileCheck --check-prefixes=CHECK,LE %s

// The convention of GCC without a floating point unit: an argument is the
// words that hold its bytes, and the code generator puts the first four
// words of all arguments into r4 to r7.

// LE: target datalayout = "e-m:e-p:32:32-i64:32-f64:32-n32-S32"
// BE: target datalayout = "E-m:e-p:32:32-i64:32-f64:32-n32-S32"

// Small integers are extended by the caller.
// CHECK: define{{.*}} void @small(i8 noundef signext %a, i16 noundef zeroext %b, i1 noundef zeroext %c)
void small(char a, unsigned short b, _Bool c) {}

// CHECK: define{{.*}} signext i16 @ret_small()
short ret_small(void) { return 1; }

// Floating point numbers go like integers of their size.
// CHECK: define{{.*}} void @floats(float noundef %a, double noundef %b, i64 noundef %c)
void floats(float a, double b, long long c) {}

// A value of less than a word is an integer of its size: it is at the low
// end of its register in either byte order.
struct c1 { char a; };
struct c3 { char a, b, c; };
struct s4 { short a, b; };
// CHECK: define{{.*}} void @tiny(i8 %a.coerce, i24 %b.coerce, i32 %c.coerce)
void tiny(struct c1 a, struct c3 b, struct s4 c) {}

// Larger ones are words in the order of memory.
struct c5 { char a[5]; };
struct i12 { int a, b, c; };
struct mix { char a; long long d; };
// CHECK: define{{.*}} void @words([2 x i32] %a.coerce, [3 x i32] %b.coerce, [3 x i32] %c.coerce)
void words(struct c5 a, struct i12 b, struct mix c) {}

// More than 64 bytes are passed byval: the code generator loads the
// registers that the first words belong in and copies the rest.
struct big { int a[20]; };
// CHECK: define{{.*}} void @large(i32 noundef %n, ptr noundef byval(%struct.big) align 4 %b)
void large(int n, struct big b) {}

// A structure with one floating point member is nothing special here.
struct f1 { float f; };
struct d1 { double d; };
// CHECK: define{{.*}} void @single(i32 %a.coerce, [2 x i32] %b.coerce)
void single(struct f1 a, struct d1 b) {}

// Complex numbers are words as well, two small parts in one.
// CHECK: define{{.*}} void @complex(i16 noundef %a.coerce, i32 noundef %b.coerce, [2 x i32] noundef %c.coerce, [4 x i32] noundef %d.coerce)
void complex(_Complex char a, _Complex short b, _Complex float c, _Complex double d) {}

// A result is in r0 to r3 if GCC gives its type a machine mode: one, two,
// four or eight bytes that are aligned like an integer of that size.
struct i8 { int a, b; };
// CHECK: define{{.*}} i8 @ret_c1()
struct c1 ret_c1(void) { struct c1 r = {1}; return r; }
// CHECK: define{{.*}} [2 x i32] @ret_i8()
struct i8 ret_i8(void) { struct i8 r = {1, 2}; return r; }
// CHECK: define{{.*}} [2 x i32] @ret_mix_pair()
struct pair { char a; int b; } ret_mix_pair(void) { struct pair r = {1, 2}; return r; }

// Four bytes that are aligned to two, three bytes, twelve bytes: memory.
// CHECK: define{{.*}} void @ret_s4(ptr dead_on_unwind noalias writable sret(%struct.s4) align 2 %agg.result)
struct s4 ret_s4(void) { struct s4 r = {1, 2}; return r; }
// CHECK: define{{.*}} void @ret_c3(ptr {{.*}}sret(%struct.c3) align 1 %agg.result)
struct c3 ret_c3(void) { struct c3 r = {1, 2, 3}; return r; }
// CHECK: define{{.*}} void @ret_i12(ptr {{.*}}sret(%struct.i12) align 4 %agg.result)
struct i12 ret_i12(void) { struct i12 r = {1, 2, 3}; return r; }

// A member that is a block of three bytes keeps the structure in memory,
// one of four bytes does not.
struct a3 { char a[3]; char d; int e; };
struct a4 { char a[4]; int e; };
// CHECK: define{{.*}} void @ret_a3(ptr {{.*}}sret(%struct.a3) align 4 %agg.result)
struct a3 ret_a3(void) { struct a3 r = {{1}, 2, 3}; return r; }
// CHECK: define{{.*}} [2 x i32] @ret_a4()
struct a4 ret_a4(void) { struct a4 r = {{1}, 2}; return r; }

// Complex numbers always have a mode, vectors up to sixteen bytes.
// CHECK: define{{.*}} [4 x i32] @ret_cd()
_Complex double ret_cd(void) { return 1.0; }
// CHECK: define{{.*}} i32 @ret_cs()
_Complex short ret_cs(void) { return 1; }
typedef int v4 __attribute__((vector_size(16)));
typedef int v8 __attribute__((vector_size(32)));
// CHECK: define{{.*}} [4 x i32] @ret_v4()
v4 ret_v4(void) { v4 r = {1, 2, 3, 4}; return r; }
// CHECK: define{{.*}} void @ret_v8(ptr {{.*}}sret(<8 x i32>) align 32 %agg.result)
v8 ret_v8(void) { v8 r = {1}; return r; }

// va_list is a pointer, and a value of less than a word is at the end of
// its word on a big-endian processor.
// CHECK-LABEL: define{{.*}} i32 @va(i32 noundef %n, ...)
// CHECK: %ap = alloca ptr
// CHECK: call void @llvm.va_start.p0(ptr %ap)
// CHECK: %argp.cur = load ptr, ptr %ap
// CHECK: %argp.next = getelementptr inbounds i8, ptr %argp.cur, i32 4
// CHECK: store ptr %argp.next, ptr %ap
// BE: getelementptr inbounds i8, ptr %argp.cur, i32 3
// LE-NOT: getelementptr inbounds i8, ptr %argp.cur, i32 3
int va(int n, ...) {
  __builtin_va_list ap;
  __builtin_va_start(ap, n);
  struct c1 c = __builtin_va_arg(ap, struct c1);
  __builtin_va_end(ap);
  return c.a;
}
