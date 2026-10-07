# bt and bf reach 256 bytes and bra reaches four kilobytes.  Each arm of
# this condition is larger than that, so the branch to the second arm and
# the jump from the end of the first arm over the second are the far form:
# r0 is saved, loaded with a distance from a literal, added to the program
# counter by braf and restored in the delay slot of that.  The distance is
# counted from four bytes behind the braf.  That is position independent,
# so the code is the same with and without -relocation-model=pic.
#
# RUN: %python %s | llc -mtriple=sh4-unknown-linux-gnu -mcpu=sh4-nofpu -verify-machineinstrs | FileCheck %s
# RUN: %python %s | llc -mtriple=sh4-unknown-linux-gnu -mcpu=sh4-nofpu -relocation-model=pic -verify-machineinstrs | FileCheck %s
#
# CHECK-LABEL: f:
# CHECK:         tst r4,r4
# CHECK-NEXT:    bf [[SKIP:\.Ltmp[0-9]+]]
# CHECK-NEXT:    mov.l r0,@-r15
# CHECK-NEXT:    mov.l [[LIT1:\.Ltmp[0-9]+]],r0
# CHECK-NEXT:  [[FROM1:\.Ltmp[0-9]+]]:
# CHECK-NEXT:    braf r0
# CHECK-NEXT:    mov.l @r15+,r0
# CHECK-NEXT:  [[SKIP]]:
# CHECK:       [[LIT1]]:
# CHECK-NEXT:    .ualong [[THEN:\.LBB0_[0-9]+]]-([[FROM1]]+4)
#
# The end of the arm that comes first.
# CHECK:         mov.l r0,@-r15
# CHECK-NEXT:    mov.l [[LIT2:\.Ltmp[0-9]+]],r0
# CHECK-NEXT:  [[FROM2:\.Ltmp[0-9]+]]:
# CHECK-NEXT:    braf r0
# CHECK-NEXT:    mov.l @r15+,r0
# CHECK:       [[LIT2]]:
# CHECK-NEXT:    .ualong [[END:\.LBB0_[0-9]+]]-([[FROM2]]+4)
# CHECK:       [[THEN]]:
# CHECK:       [[END]]:
# CHECK:         jsr @r8

N = 2100

print("define i32 @f(i32 %a, ptr %p) {")
print("entry:")
print("  %c = icmp eq i32 %a, 0")
print("  br i1 %c, label %then, label %else")
# One arm stores and the other loads, so that they have no code in common.
print("then:")
for i in range(N):
    print("  store volatile i32 1, ptr %p")
print("  br label %end")
print("else:")
for i in range(N):
    print("  %%v%d = load volatile i32, ptr %%p" % i)
print("  br label %end")
# Too much to be copied to the end of each arm.
print("end:")
print("  %r = call i32 @g(i32 %a)")
print("  %s = call i32 @g(i32 %r)")
print("  ret i32 %s")
print("}")
print("declare i32 @g(i32)")
