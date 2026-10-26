// RUN: not %clang_analyze_cc1 -analyzer-checker=core,alpha.qemu.GuestMemorySafety \
// RUN:   -analyzer-config alpha.qemu.GuestMemorySafety:SelectiveSummaryManifest=%S/Inputs/qemu-selective-summary-malformed.json \
// RUN:   %s 2>&1 | FileCheck %s --check-prefix=MALFORMED
// RUN: not %clang_analyze_cc1 -analyzer-checker=core,alpha.qemu.GuestMemorySafety \
// RUN:   -analyzer-config alpha.qemu.GuestMemorySafety:SelectiveSummaryManifest=%S/Inputs/qemu-selective-summary-stale.json \
// RUN:   %s 2>&1 | FileCheck %s --check-prefix=STALE
// RUN: %python %S/Inputs/qemu-gms-tamper-selective-summary.py \
// RUN:   %S/../../../../validation/v3-selective-ctu-summary-pci-dma-stage1/current-d7314928-stage1-v2.json %t.manifest
// RUN: not %clang_analyze_cc1 -analyzer-checker=core,alpha.qemu.GuestMemorySafety \
// RUN:   -analyzer-config alpha.qemu.GuestMemorySafety:SelectiveSummaryManifest=%t.manifest \
// RUN:   %s 2>&1 | FileCheck %s --check-prefix=TAMPERED-V2

// MALFORMED: invalid input for checker option 'alpha.qemu.GuestMemorySafety:SelectiveSummaryManifest'
// MALFORMED-SAME: JSON is malformed
// STALE: invalid input for checker option 'alpha.qemu.GuestMemorySafety:SelectiveSummaryManifest'
// STALE-SAME: exact QEMU revision or clean-state identity differs
// TAMPERED-V2: invalid input for checker option 'alpha.qemu.GuestMemorySafety:SelectiveSummaryManifest'
// TAMPERED-V2-SAME: sealed byte identity differs

int translation_unit_is_not_analyzed_after_manifest_rejection;
