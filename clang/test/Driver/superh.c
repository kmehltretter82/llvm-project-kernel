// The processor: GCC's -m options, and the first part of the triple.
//
// RUN: %clang -### --target=sh4-linux-gnu -c %s 2>&1 | FileCheck --check-prefix=SH4 %s
// RUN: %clang -### --target=sh4-linux-gnu -m4-nofpu -c %s 2>&1 | FileCheck --check-prefix=SH4-NOFPU %s
// RUN: %clang -### --target=sh4-linux-gnu -m4 -m4-nofpu -c %s 2>&1 | FileCheck --check-prefix=SH4-NOFPU %s
// RUN: %clang -### --target=sh4-linux-gnu -m4-single-only -c %s 2>&1 | FileCheck --check-prefix=SH4-SINGLE-ONLY %s
// RUN: %clang -### --target=sh4-linux-gnu -m4a -c %s 2>&1 | FileCheck --check-prefix=SH4A %s
// RUN: %clang -### --target=sh4-linux-gnu -m3 -c %s 2>&1 | FileCheck --check-prefix=SH3 %s
// RUN: %clang -### --target=sh4-linux-gnu -m2 -c %s 2>&1 | FileCheck --check-prefix=SH2 %s
// RUN: %clang -### --target=sh4-linux-gnu -mj2 -c %s 2>&1 | FileCheck --check-prefix=J2 %s
// RUN: %clang -### --target=sh4-linux-gnu -mcpu=sh3e -c %s 2>&1 | FileCheck --check-prefix=SH3E %s
// RUN: %clang -### --target=sh3-linux-gnu -c %s 2>&1 | FileCheck --check-prefix=SH3-TRIPLE %s
// RUN: %clang -### --target=sh-linux-gnu -c %s 2>&1 | FileCheck --check-prefix=SH-TRIPLE %s
// RUN: %clang -### --target=sh2eb-linux-musl -c %s 2>&1 | FileCheck --check-prefix=SH2EB %s
//
// SH4: "-cc1" "-triple" "sh4-unknown-linux-gnu"
// SH4-SAME: "-target-cpu" "sh4"
// SH4-NOFPU: "-target-cpu" "sh4-nofpu"
// SH4-SINGLE-ONLY: "-target-cpu" "sh4-single-only"
// SH4A: "-target-cpu" "sh4a"
// SH3: "-target-cpu" "sh3"
// SH2: "-target-cpu" "sh2"
// J2: "-target-cpu" "j2"
// SH3E: "-target-cpu" "sh3e"
// SH3-TRIPLE: "-target-cpu" "sh3"
// SH-TRIPLE: "-target-cpu" "sh2"
// SH2EB: "-triple" "sh2eb-unknown-linux-musl"
// SH2EB-SAME: "-target-cpu" "sh2"

// The byte order changes the triple and keeps the processor.
//
// RUN: %clang -### --target=sh4-linux-gnu -mb -c %s 2>&1 | FileCheck --check-prefix=BIG %s
// RUN: %clang -### --target=sh4eb-linux-gnu -ml -c %s 2>&1 | FileCheck --check-prefix=LITTLE %s
// RUN: %clang -### --target=sh4-linux-gnu -ml -c %s 2>&1 | FileCheck --check-prefix=LITTLE %s
//
// BIG: "-triple" "sh4eb-unknown-linux-gnu"
// BIG-SAME: "-target-cpu" "sh4"
// BIG: "-big"
// LITTLE: "-triple" "sh4-unknown-linux-gnu"
// LITTLE-SAME: "-target-cpu" "sh4"
// LITTLE: "-little"

// There is no integrated assembler: GNU as gets the byte order, and the
// instruction set if an option names the processor.  No position
// independent executable unless it is asked for.
//
// RUN: %clang -### --target=sh4-linux-gnu -m4-nofpu -c %s 2>&1 | FileCheck --check-prefix=AS-NOFPU %s
// RUN: %clang -### --target=sh4-linux-gnu -m2 -c %s 2>&1 | FileCheck --check-prefix=AS-SH2 %s
// RUN: %clang -### --target=sh4-linux-gnu -c %s 2>&1 | FileCheck --check-prefix=AS-DEFAULT %s
// RUN: %clang -### --target=sh4-linux-gnu %s 2>&1 | FileCheck --check-prefix=LINK %s
// RUN: %clang -### --target=sh4eb-linux-gnu %s 2>&1 | FileCheck --check-prefix=LINK-EB %s
//
// AS-NOFPU: "-no-integrated-as"
// AS-NOFPU: as{{(.exe)?}}" "-little" "--isa=sh4a-nofpu"
// AS-SH2: as{{(.exe)?}}" "-little" "--isa=sh2"
// AS-DEFAULT: "-mrelocation-model" "static"
// AS-DEFAULT-NOT: "--isa
// AS-DEFAULT-NOT: "-faddrsig"
// LINK: "-m" "shlelf_linux"
// LINK-NOT: "-pie"
// LINK: "-dynamic-linker" "/lib/ld-linux.so.2"
// LINK-EB: "-m" "shelf_linux"

// Position independent code where it is asked for.
//
// RUN: %clang -### --target=sh4-linux-gnu -fPIC -c %s 2>&1 | FileCheck --check-prefix=PIC %s
// RUN: %clang -### --target=sh4-linux-gnu -fPIE -pie %s 2>&1 | FileCheck --check-prefix=PIE %s
// RUN: %clang -### --target=sh4-linux-gnu -fPIC -shared %s 2>&1 | FileCheck --check-prefix=SHARED %s
//
// PIC: "-mrelocation-model" "pic" "-pic-level" "2"
// PIE: "-mrelocation-model" "pic" "-pic-level" "2" "-pic-is-pie"
// PIE: "-m" "shlelf_linux" "-pie"
// SHARED: "-mrelocation-model" "pic" "-pic-level" "2"
// SHARED: "-m" "shlelf_linux" "-shared"

// The dynamic linker of musl says whether there is a floating point unit.
//
// RUN: %clang -### --target=sh4-linux-musl %s 2>&1 | FileCheck --check-prefix=MUSL %s
// RUN: %clang -### --target=sh2eb-linux-musl %s 2>&1 | FileCheck --check-prefix=MUSL-EB %s
//
// MUSL: "-dynamic-linker" "/lib/ld-musl-sh.so.1"
// MUSL-EB: "-dynamic-linker" "/lib/ld-musl-sheb-nofpu.so.1"

int x;
