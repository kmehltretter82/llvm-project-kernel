; The processor: a triple names one, -mcpu another.
;
; RUN: llc -mtriple=sh4-unknown-linux-gnu -mcpu=sh4-nofpu < %s | FileCheck --check-prefix=DYN %s
; RUN: llc -mtriple=sh3-unknown-linux-gnu < %s | FileCheck --check-prefix=DYN %s
; RUN: llc -mtriple=sh2-unknown-linux-gnu -mcpu=j2 < %s | FileCheck --check-prefix=DYN %s
; RUN: llc -mtriple=sh4eb-unknown-linux-gnu -mcpu=sh4a-nofpu < %s | FileCheck --check-prefix=DYN %s
; RUN: not llc -mtriple=sh4-unknown-linux-gnu < %s 2>&1 | FileCheck --check-prefix=FPU %s
; RUN: not llc -mtriple=sh4-unknown-linux-gnu -mcpu=sh4-single-only < %s 2>&1 | FileCheck --check-prefix=FPU %s
; RUN: not llc -mtriple=sh4-unknown-linux-gnu -mcpu=sh4-nofpu -relocation-model=pic < %s 2>&1 | FileCheck --check-prefix=PIC %s

; DYN-LABEL: shift:
; DYN: shld r5,r0

; FPU: the floating point unit of SuperH is not supported yet
; PIC: position independent code is not supported for SuperH yet

@g = global i32 0

define i32 @shift(i32 %a, i32 %n) {
  %r = shl i32 %a, %n
  ret i32 %r
}

define ptr @addr() {
  ret ptr @g
}
