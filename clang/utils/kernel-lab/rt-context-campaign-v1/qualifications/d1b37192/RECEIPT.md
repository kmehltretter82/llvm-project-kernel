# RISC-V campaign follow-up receipt: d1b37192986d

This follow-up ran the serial RISC-V campaign on 2026-10-15 UTC after the
bottom-half and NMI entry-accounting correction at LLVM commit
`d1b37192986da5cf9e8942458500420acd4d3e1b`.  Clang was rebuilt at that exact
commit with the existing assertions-enabled, RISC-V-only build and `-j1`.

The compiler SHA-256 before and after the campaign was
`e2d03bd990d3ab28cb3f7dfbab0d202ab8dbad212dc3b3f7f94501078a991bf9`.
The pinned build `CMakeCache.txt` SHA-256 was
`d85954ca3061dd6932b92626801dbf5d1e4adc06b358a32436fa71c82fdb553c`.

All 87 reviewed operation predicates passed and all 87 analyzer runs completed
with positive path-exploration statistics.  The results contained 24 expected
manifest-validation rejections, 18 illegal RT-wait records, 6 ordinary-sleep
records, and 60 explicit incomplete post-call-context records.  There were no
timeouts, resource-bound hits, allocation failures, or unexpected warnings.
The highest wall time was 0.0671 seconds and the highest RSS was 33,456 KiB.

The transient full run occupied 14 MiB and was deleted after aggregation.  Its
`PLAN.json` SHA-256 was
`cc1eea6376715469fe93d0de160b306567eb4470dba207795933df7fd05fba6f`; its
`RESULTS.json` SHA-256 was
`5f16fdf64bcedaf6a7c275c9217b10c3975fd5f6f1ba368992fe170eb8e21ff4`.
The committed runner, fixtures, and frozen oracle make the campaign repeatable.

This is a regression receipt for API fixtures only.  It is not a real-kernel,
Kconfig, runtime, QEMU, FPGA, or hardware safety verdict, and complete context
coverage remains false by construction.
