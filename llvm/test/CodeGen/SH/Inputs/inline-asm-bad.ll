; The second half of a value that has one register: GCC names the register
; with the next number, which is not the operand's.  It is refused here.
define i32 @half() {
  %r = call i32 asm "mov.l @r1,${0:S}", "=r"()
  ret i32 %r
}
