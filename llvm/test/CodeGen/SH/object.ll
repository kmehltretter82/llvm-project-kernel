; RUN: llc -mtriple=sh4-unknown-linux-gnu -mcpu=sh4-nofpu -filetype=obj -o %t.o < %s
; RUN: llvm-objdump -d -r --no-show-raw-insn %t.o | FileCheck %s
; RUN: llc -mtriple=sh4-unknown-linux-gnu -mcpu=sh4-nofpu -relocation-model=pic -filetype=obj -o %t.pic.o < %s
; RUN: llvm-objdump -d -r --no-show-raw-insn %t.pic.o | FileCheck %s --check-prefix=PIC
; RUN: llvm-readobj -h %t.o | FileCheck %s --check-prefix=HEADER

; The code generator writes an object file without an assembler in between.
; Its instructions with an address of a register and a displacement become
; the two instructions that the processor has ("@Rm" and "@(disp,Rm)"), the
; loads from literals and the branches get their distances, and what a
; literal says is left to the linker.

@g = external global i32
declare i32 @ext(i32)

define i32 @f(ptr %p, i32 %x) {
; CHECK-LABEL: <f>:
; CHECK:        mov.l @(8,r4),r1
; CHECK-NEXT:   mov.l @r4,r0
; CHECK:        tst r5,r5
; CHECK-NEXT:   bt 0xe
; CHECK:        mov.l 0x18,r1
; CHECK-NEXT:   mov.l @r1,r1
; CHECK:        R_SH_DIR32 g
entry:
  %a = load i32, ptr %p
  %q = getelementptr i32, ptr %p, i32 2
  %b = load i32, ptr %q
  %s = add i32 %a, %b
  %c = icmp eq i32 %x, 0
  br i1 %c, label %zero, label %done

zero:
  %v = load i32, ptr @g
  %t = add i32 %s, %v
  ret i32 %t

done:
  ret i32 %s
}

define i32 @call(i32 %x) {
; CHECK-LABEL: <call>:
; CHECK:        jsr @r1
; CHECK:        R_SH_DIR32 ext
;
; PIC-LABEL: <call>:
; PIC:          mova 0x{{[0-9a-f]+}},r0
; PIC:          bsrf r1
; PIC:          R_SH_GOTPC _GLOBAL_OFFSET_TABLE_
; PIC:          R_SH_PLT32 ext
  %r = call i32 @ext(i32 %x)
  %s = add i32 %r, 1
  ret i32 %s
}

; HEADER: Machine: EM_SH
; HEADER: Flags [ (0x10)
