Independent phase-3 manifest API-fixture tests

EXPECTED.json and ORACLE-FREEZE.json froze 29 cases across 6 profiles (174
records) at 2026-10-12T20:06:37.281340Z before any importer binary was executed.
The original fixture/source/evidence/oracle bytes remain unchanged.

COVERAGE-SEMANTICS-SUPPLEMENT.json was fixed before execution at 20:12:38Z:
imported wait/sleep capabilities do not imply preserved post-call context.
Every noninlined imported effect therefore requires a visible incomplete-context
gap, including legal-operation controls. No illegal-wait or ordinary-sleep
predicate changed. The runner reports the original raw verdict separately from
the supplemented supported-operation predicate verdict. Complete kernel/path
coverage is never inferred from a legal-operation control's absent warning.

run.py prepares by default; --run needs --compiler PATH,
--compiler-sha256 HASH and --compiler-manifest PATH. Use a fresh --output name.
Profiles and cases can be narrowed explicitly. It executes direct cc1 with
only core/AtomicSleep/LockBalance, RTContext enabled, no driver-injected -w,
no default checker expansion, no thread-safety annotation analysis, and no
resume/filter shortcut. Limits are serial 120 wall seconds / 3072MiB address
space and CPU 120/122 seconds; raw stdout/stderr, positive paths-explored
statistics, resource/compiler/source/hash before+after, manifest bytes and
exact commands remain visible. Failed/timed-out/bounded/skipped analyses
cannot qualify. Existing frozen benchmark files are not used or edited.

Inputs are explicit API fixtures, not real kernel/Kconfig profiles. Their
minimal generated/autoconf.h macros reflect the six requested RT/BH choices.
Two tests declare a synthetic kernel-shaped configuration to exercise loaded
header/config validation; this is not a real Kbuild or kernel result.

RTContextManifestOutput captures actual target/predefines/loaded-buffer hashes
and canonical type/linkage/source/offset function bindings with no imported
meanings. The encoder copies those exact identities and injects only meanings
from the frozen independent oracle and reviewed fixture evidence. No guessed
predefine hash/type/offset may be used for actual test runs. A conflicting or
missing function binding aborts preparation rather than selecting a name.

prepared-v1/PLAN.json is preparation-only and predates the latest runner
revision; encoder-selfcheck/RESULT.json uses explicit mocked identities and
claims no compiler or semantic validation. Execution remains pending a frozen
new compiler and verification of the actual facts output format.
