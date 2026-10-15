; RUN: llc -O2 -code-model=medium < %s 2>&1 | FileCheck %s

target triple = "riscv64-unknown-linux-gnu"

declare signext i32 @callee(i32 signext)

define signext i32 @caller(i32 signext %value) {
; CHECK-NOT:   loosing !pcsections
; CHECK-LABEL: caller:
; CHECK:       .Lpcsection0:
; CHECK-NEXT:  call callee
; CHECK:       .Lpcsection1:
; CHECK-NEXT:  ret
; CHECK-NOT:   loosing !pcsections
; CHECK-DAG:   .section .riscv.test.call,"awo",@progbits,.text
; CHECK-DAG:   .section .riscv.test.return,"awo",@progbits,.text
entry:
  %called = call signext i32 @callee(i32 signext %value), !pcsections !0
  %result = add i32 %called, 1
  ret i32 %result, !pcsections !1
}

!0 = !{!".riscv.test.call", !2}
!1 = !{!".riscv.test.return", !3}
!2 = !{i64 17}
!3 = !{i64 23}
