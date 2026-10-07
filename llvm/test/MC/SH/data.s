# RUN: llvm-mc -triple=sh4-unknown-linux-gnu -filetype=obj -o %t.o %s
# RUN: llvm-readobj -S %t.o | FileCheck %s
# RUN: llvm-objdump -s -j one -j two -j four -j any %t.o | FileCheck %s --check-prefix=BYTES

# GNU as wants a word at an even address and a long word at a multiple of
# four, and gives the section that alignment.  The tables that the kernel
# makes with ".long" in a section of their own are put together by the
# linker with it.  ".ualong" and its kind are for data at any address and
# ask for nothing.

	.section one,"a"
	.byte	1, 2, -1

	.section two,"a"
	.word	0x1122
	.short	0x3344

	.section four,"a"
	.long	0x11223344	# GNU as takes this as a comment behind data
	.int	5

	.section any,"a"
	.byte	1
	.uaword	0x1122
	.ualong	0x33445566
	.2byte	0x7788
	.4byte	0x99aabbcc

# CHECK:      Name: one
# CHECK:      AddressAlignment: 1
# CHECK:      Name: two
# CHECK:      AddressAlignment: 2
# CHECK:      Name: four
# CHECK:      AddressAlignment: 4
# CHECK:      Name: any
# CHECK:      AddressAlignment: 1

# BYTES:      Contents of section one:
# BYTES-NEXT:  0000 0102ff
# BYTES:      Contents of section two:
# BYTES-NEXT:  0000 22114433
# BYTES:      Contents of section four:
# BYTES-NEXT:  0000 44332211 05000000
# BYTES:      Contents of section any:
# BYTES-NEXT:  0000 01221166 55443388 77ccbbaa 99
