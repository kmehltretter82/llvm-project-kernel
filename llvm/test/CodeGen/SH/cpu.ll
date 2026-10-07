; The processor: a triple names one, -mcpu another.
;
; RUN: llc -mtriple=sh4-unknown-linux-gnu -mcpu=sh4-nofpu < %s | FileCheck --check-prefix=DYN %s
; RUN: llc -mtriple=sh3-unknown-linux-gnu < %s | FileCheck --check-prefix=DYN %s
; RUN: llc -mtriple=sh2-unknown-linux-gnu -mcpu=j2 < %s | FileCheck --check-prefix=DYN %s
; RUN: llc -mtriple=sh4eb-unknown-linux-gnu -mcpu=sh4a-nofpu < %s | FileCheck --check-prefix=DYN %s
; RUN: llc -mtriple=sh4-unknown-linux-gnu < %s | FileCheck --check-prefixes=DYN,FPU %s
; RUN: llc -mtriple=sh4-unknown-linux-gnu -mcpu=sh4-nofpu < %s | FileCheck --check-prefix=NOFPU %s
; RUN: llc -mtriple=sh3-unknown-linux-gnu < %s | FileCheck --check-prefix=NOFPU %s

; DYN-LABEL: shift:
; DYN: shld r5,r0

; A triple with "sh4" is an SH-4 with its floating point unit, as for GCC.
; FPU-LABEL: twice:
; FPU: fadd dr0,dr0
; NOFPU-LABEL: twice:
; NOFPU: __adddf3

@g = global i32 0

define i32 @shift(i32 %a, i32 %n) {
  %r = shl i32 %a, %n
  ret i32 %r
}

define ptr @addr() {
  ret ptr @g
}

define double @twice(double %a) {
  %r = fadd double %a, %a
  ret double %r
}
