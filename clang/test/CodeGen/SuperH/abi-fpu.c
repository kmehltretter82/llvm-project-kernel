// RUN: %clang_cc1 -triple sh4-unknown-linux-gnu -emit-llvm -o - %s | FileCheck --check-prefixes=CHECK,DOUBLE %s
// RUN: %clang_cc1 -triple sh4-unknown-linux-gnu -target-cpu sh3e -emit-llvm -o - %s | FileCheck --check-prefixes=CHECK,SINGLE %s

// The convention of GCC with a floating point unit: float is passed as
// such, and double if the unit computes it.  Everything else is words, of
// which the code generator puts an argument into registers only if all of
// it fits.

// va_list is a structure of five pointers.
// CHECK: %struct.__va_list_tag = type { ptr, ptr, ptr, ptr, ptr }

// CHECK: define{{.*}} void @floats(float noundef %a, double noundef %b, i64 noundef %c)
void floats(float a, double b, long long c) {}

// A structure with one member is passed and returned like the member.
struct f1 { float f; };
struct d1 { double d; };
struct nested { struct f1 a[1]; };
struct ff { float a, b; };
union uf { float f; };
// DOUBLE: define{{.*}} void @single(float %a.coerce, double %b.coerce, float %c.coerce, [2 x i32] %d.coerce, i32 %e.coerce)
// SINGLE: define{{.*}} void @single(float %a.coerce, [2 x i32] %b.coerce, float %c.coerce, [2 x i32] %d.coerce, i32 %e.coerce)
void single(struct f1 a, struct d1 b, struct nested c, struct ff d, union uf e) {}

// CHECK: define{{.*}} float @ret_f1()
struct f1 ret_f1(void) { struct f1 r = {1}; return r; }
// DOUBLE: define{{.*}} double @ret_d1()
// SINGLE: define{{.*}} [2 x i32] @ret_d1()
struct d1 ret_d1(void) { struct d1 r = {1}; return r; }

// A structure that is packed to less than the member needs is not.
struct __attribute__((packed)) packed { double d; };
// CHECK: define{{.*}} void @under_aligned([2 x i32] %a.coerce)
void under_aligned(struct packed a) {}

// A complex number is two registers.  A unit that computes float only
// takes a complex float as a result and not as an argument.
// DOUBLE: define{{.*}} void @complex([2 x float] noundef %a.coerce, [2 x double] noundef %b.coerce)
// SINGLE: define{{.*}} void @complex([2 x i32] noundef %a.coerce, [4 x i32] noundef %b.coerce)
void complex(_Complex float a, _Complex double b) {}
// CHECK: define{{.*}} [2 x float] @ret_cf()
_Complex float ret_cf(void) { return 1.0f; }
// DOUBLE: define{{.*}} [2 x double] @ret_cd()
// SINGLE: define{{.*}} [4 x i32] @ret_cd()
_Complex double ret_cd(void) { return 1.0; }

// An integer comes from the saved integer registers if all of it is left
// there, and from the stack otherwise.
// CHECK-LABEL: define{{.*}} i64 @va_int(i32 noundef %n, ...)
// CHECK: %ap = alloca %struct.__va_list_tag
// CHECK: %next_o.addr = getelementptr inbounds nuw %struct.__va_list_tag, ptr %ap, i32 0, i32 0
// CHECK: %next_o = load ptr, ptr %next_o.addr
// CHECK: %next_o_limit.addr = getelementptr inbounds nuw %struct.__va_list_tag, ptr %ap, i32 0, i32 1
// CHECK: %next_o_limit = load ptr, ptr %next_o_limit.addr
// CHECK: [[NEXT:%.*]] = getelementptr inbounds i8, ptr %next_o, i32 8
// CHECK: [[CMP:%.*]] = icmp ugt ptr [[NEXT]], %next_o_limit
// CHECK: br i1 [[CMP]], label %vaarg.on_stack, label %vaarg.in_regs
// CHECK: vaarg.on_stack:
// CHECK: %next_stack.addr = getelementptr inbounds nuw %struct.__va_list_tag, ptr %ap, i32 0, i32 4
long long va_int(int n, ...) {
  __builtin_va_list ap;
  __builtin_va_start(ap, n);
  long long r = __builtin_va_arg(ap, long long);
  __builtin_va_end(ap);
  return r;
}

// A double comes from the saved floating point registers, where it lies at
// an address that eight divides.
// DOUBLE-LABEL: define{{.*}} double @va_double(i32 noundef %n, ...)
// DOUBLE: %next_fp.addr = getelementptr inbounds nuw %struct.__va_list_tag, ptr %ap, i32 0, i32 2
// DOUBLE: %next_fp = load ptr, ptr %next_fp.addr
// DOUBLE: %next_fp_limit = load ptr, ptr %next_fp_limit.addr
// DOUBLE: %next_fp.odd = and i32 {{%.*}}, 4
// DOUBLE: %next_fp.aligned = getelementptr inbounds i8, ptr %next_fp, i32 %next_fp.odd
// DOUBLE: [[CMP:%.*]] = icmp uge ptr %next_fp.aligned, %next_fp_limit
// DOUBLE: br i1 [[CMP]], label %vaarg.on_stack, label %vaarg.in_regs
//
// Without double in the unit it is two words of the integer registers.
// SINGLE-LABEL: define{{.*}} double @va_double(i32 noundef %n, ...)
// SINGLE: %next_o = load ptr, ptr %next_o.addr
// SINGLE: [[CMP:%.*]] = icmp ugt ptr {{%.*}}, %next_o_limit
// SINGLE: vaarg.on_stack:
// SINGLE-NEXT: store ptr %next_o_limit, ptr %next_o.addr
double va_double(int n, ...) {
  __builtin_va_list ap;
  __builtin_va_start(ap, n);
  double r = __builtin_va_arg(ap, double);
  __builtin_va_end(ap);
  return r;
}

// A little-endian SH-4 stores its registers so that the imaginary part of
// a complex float lies in front of the real part.
// DOUBLE-LABEL: define{{.*}} [2 x float] @va_complex(i32 noundef %n, ...)
// DOUBLE: %vaarg.imag = load float, ptr %next_fp
// DOUBLE: [[REAL:%.*]] = getelementptr inbounds i8, ptr %next_fp, i32 4
// DOUBLE: %vaarg.real = load float, ptr [[REAL]]
_Complex float va_complex(int n, ...) {
  __builtin_va_list ap;
  __builtin_va_start(ap, n);
  _Complex float r = __builtin_va_arg(ap, _Complex float);
  __builtin_va_end(ap);
  return r;
}
