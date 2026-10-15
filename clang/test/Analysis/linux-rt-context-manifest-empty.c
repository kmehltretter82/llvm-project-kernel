// RUN: %clang_analyze_cc1 -triple riscv64-unknown-linux-gnu \
// RUN:   -analyzer-checker=core,alpha.linux.AtomicSleep \
// RUN:   -analyzer-config alpha.linux.AtomicSleep:RTContext=true \
// RUN:   -analyzer-config alpha.linux.AtomicSleep:RTContextManifest=%S/Inputs/linux-rt-context-invalid.json \
// RUN:   -verify=invalid %s
// RUN: %clang_analyze_cc1 -triple riscv64-unknown-linux-gnu \
// RUN:   -analyzer-checker=core,alpha.linux.AtomicSleep \
// RUN:   -analyzer-config alpha.linux.AtomicSleep:RTContextManifest=%S/Inputs/linux-rt-context-invalid.json \
// RUN:   -verify=no-rt %s
// RUN: rm -f %t
// RUN: %clang_analyze_cc1 -triple riscv64-unknown-linux-gnu \
// RUN:   -analyzer-checker=core,alpha.linux.AtomicSleep \
// RUN:   -analyzer-config alpha.linux.AtomicSleep:RTContext=true \
// RUN:   -analyzer-config alpha.linux.AtomicSleep:RTContextManifestOutput=%t \
// RUN:   -verify=output %s
// RUN: test -s %t
// REQUIRES: riscv-registered-target
// output-no-diagnostics

int translation_unit_has_no_function; // invalid-warning {{Invalid RT context manifest JSON}}
                                      // no-rt-warning@-1 {{RT context manifests require RTContext=true}}
