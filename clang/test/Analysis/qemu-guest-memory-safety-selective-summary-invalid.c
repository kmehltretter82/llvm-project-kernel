// RUN: not %clang_analyze_cc1 -analyzer-checker=core,alpha.qemu.GuestMemorySafety \
// RUN:   -analyzer-config alpha.qemu.GuestMemorySafety:SelectiveSummaryManifest=%S/Inputs/qemu-selective-summary-malformed.json \
// RUN:   %s 2>&1 | FileCheck %s --check-prefix=MALFORMED
// RUN: not %clang_analyze_cc1 -analyzer-checker=core,alpha.qemu.GuestMemorySafety \
// RUN:   -analyzer-config alpha.qemu.GuestMemorySafety:SelectiveSummaryManifest=%S/Inputs/qemu-selective-summary-stale.json \
// RUN:   %s 2>&1 | FileCheck %s --check-prefix=STALE

// MALFORMED: invalid input for checker option 'alpha.qemu.GuestMemorySafety:SelectiveSummaryManifest'
// MALFORMED-SAME: JSON is malformed
// STALE: invalid input for checker option 'alpha.qemu.GuestMemorySafety:SelectiveSummaryManifest'
// STALE-SAME: exact QEMU revision or clean-state identity differs

int translation_unit_is_not_analyzed_after_manifest_rejection;
