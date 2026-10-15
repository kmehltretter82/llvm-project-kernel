# RISC-V campaign receipt: b5294bcb4282

This qualification ran the clean, assertions-enabled RISC-V-only Clang build
from LLVM commit `b5294bcb4282a79297cbee10881c14f443373c50` on 2026-10-16
(2026-10-15 UTC).  The compiler SHA-256 before and after the campaign was
`f2fa141ec3e7e5bca9296246626e3121ead497f937af334c73f1198a88212a21`.

The serial campaign executed all 29 frozen API-fixture cases under these three
profiles:

- `riscv64-nonrt`
- `riscv64-rt-bh-y`
- `riscv64-rt-bh-n`

All 87 reviewed operation predicates passed.  All 87 analyses completed with
positive path-exploration statistics; there were no timeouts, resource-bound
hits, allocation failures, or unexpected warnings.  The results contained 24
expected manifest-validation rejection records, 18 illegal RT-wait records, 6
ordinary-sleep records, and 60 explicit incomplete post-call-context records.
The highest recorded wall time was 0.066 seconds and the highest recorded RSS
was 33,824 KiB.

The original raw oracle does not qualify because its later frozen coverage
supplement requires the post-call gaps.  Complete coverage is also deliberately
false.  This campaign qualifies only the listed API-fixture predicates; it is
not a real-kernel, Kconfig, runtime, QEMU, FPGA, or hardware safety verdict.

Artifact SHA-256 values:

- `PLAN.json`: `0c5488c14e7e343d4aa6ded66006061d5a5b1bdbaf8f8c20b15879ddf1eedadf`
- `RESULTS.json`: `132160c13cf3447aef955bd885af18945654f6b548e50c3fef012bf5bc91c292`
- `run-riscv.py`: `95c0081fa4021c1472cd666b9174061cd184fa834adc7cb5ad01c6d83a260829`
- `EXPECTED.json`: `7954e906d0b826ef7a49d3b0a32f1a02ac5b3eb41d24de3118920587b5bb2177`
- `COVERAGE-SEMANTICS-SUPPLEMENT.json`: `e23e5e32b341934ca1d3dcdffdb8b06f8c75c608c3cef62612f07520f774f321`
- `ORACLE-FREEZE.json`: `8cc84ede5f614bdb0f0166752073f1d37a56e30a08f89f5df0a574bc7c2f8b7f`
