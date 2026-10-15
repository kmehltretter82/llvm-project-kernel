#!/usr/bin/env python3

import hashlib
import json
from pathlib import Path
import sys


facts_path, evidence_path, output_path = map(Path, sys.argv[1:])
facts = json.loads(facts_path.read_text())
evidence_path = evidence_path.resolve()
evidence_hash = hashlib.sha256(evidence_path.read_bytes()).hexdigest()

manifest = {
    key: facts[key]
    for key in (
        "target_triple",
        "translation_unit",
        "files",
        "macros",
        "predefines_sha256",
    )
}
manifest.update(
    {
        "schema": 1,
        "effect_model": "linux-rt-context-1",
        "configuration": {"kind": "api-fixture"},
        "functions": [],
    }
)
manifest["files"][str(evidence_path)] = evidence_hash
review = {"path": str(evidence_path), "sha256": evidence_hash}


def binding(name):
    matches = [record for record in facts["functions"] if record["name"] == name]
    if len(matches) != 1:
        raise RuntimeError(f"expected one binding for {name}, got {len(matches)}")
    return dict(matches[0])


def entry(name, kind, irq_mode, **depths):
    record = binding(name)
    context = {
        "kind": kind,
        "irq_mode": irq_mode,
        "preempt": 0,
        "bh": 0,
        "rcu": 0,
        "migration": 0,
    }
    context.update(depths)
    record.update({"kind": "entry", "context": context, "evidence": review})
    manifest["functions"].append(record)


def effect(name, kind):
    record = binding(name)
    record.update({"kind": "effect", "effect": kind, "evidence": review})
    manifest["functions"].append(record)


entry("manifest_hardirq_primitive", "hardirq", "unknown")
entry("manifest_task_effect", "task", "enabled")
entry("manifest_hardirq_effect", "hardirq", "unknown")
entry("manifest_hardirq_sleep", "hardirq", "unknown")
entry("manifest_unknown_effect", "task", "enabled")
entry("manifest_rcu_effect", "task", "enabled", rcu=1)
entry("manifest_softirq_effect", "softirq", "enabled")
entry("manifest_unlisted_external_then_wait", "task", "enabled")
entry("manifest_callback_then_wait", "task", "enabled")
entry("manifest_bh_exit_balanced", "task", "enabled", bh=1)
entry("manifest_softirq_bh_exit_balanced", "softirq", "enabled", bh=1)
entry("manifest_nmi_exit_balanced", "nmi", "unknown")
entry("manifest_nmi_counter_exit_balanced", "nmi", "unknown")
effect("imported_rt_wait", "rt-lock-wait")
effect("imported_sleep", "ordinary-sleep")
effect("imported_unknown", "unknown")

output_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
