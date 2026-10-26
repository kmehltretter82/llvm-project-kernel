#!/usr/bin/env python3

import argparse
import base64
import binascii
from collections import Counter
import json
import re
import sys


MARKER = "QEMU_GMS_WITNESS_NA_V2="
CHECKER = "alpha.qemu.GuestMemorySafety"
MODEL = "qemu-gms-v3-v1"
RULE = "qemu.dma-transfer-result"


def fail(message):
    print(message, file=sys.stderr)
    raise SystemExit(1)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            fail(f"witness JSON has duplicate object key {key!r}")
        result[key] = value
    return result


def reject_constant(value):
    fail(f"witness JSON has non-JSON numeric constant {value}")


def decode(encoded):
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as error:
        fail(f"witness is not strict base64: {error}")
    if base64.b64encode(raw).decode("ascii") != encoded:
        fail("witness base64 is not canonical")
    try:
        record = json.loads(raw, object_pairs_hook=unique_object,
                            parse_constant=reject_constant)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"witness is not valid UTF-8 JSON: {error}")
    canonical = json.dumps(record, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False, allow_nan=False).encode()
    if canonical != raw:
        fail("witness JSON is not compact canonical JSON")
    return record


def validate_record(record, qemu_path):
    if set(record) != {"diagnostic", "identity", "kind", "reason",
                      "schema_version"}:
        fail("not-applicable record has the wrong top-level fields")
    if record["kind"] != "qemu-gms-witness-not-applicable":
        fail("not-applicable record has the wrong kind")
    if type(record["schema_version"]) is not int or record["schema_version"] != 2:
        fail("not-applicable record has the wrong schema version")

    identity = record["identity"]
    if not isinstance(identity, dict) or set(identity) != {
            "catalog_format", "catalog_model_version", "catalog_sha256",
            "model_version", "rule_id"}:
        fail("not-applicable record has the wrong identity fields")
    if type(identity["catalog_format"]) is not int:
        fail("catalog format is not an integer")
    if not isinstance(identity["catalog_model_version"], str) or not identity[
            "catalog_model_version"]:
        fail("catalog model version is invalid")
    if not re.fullmatch(r"[0-9a-f]{64}", identity["catalog_sha256"]):
        fail("catalog SHA-256 is invalid")
    if identity["model_version"] != MODEL or identity["rule_id"] != RULE:
        fail("not-applicable record has the wrong model or rule identity")

    diagnostic = record["diagnostic"]
    if not isinstance(diagnostic, dict) or set(diagnostic) != {
            "checker", "column", "line", "message", "qemu_path"}:
        fail("not-applicable record has the wrong diagnostic fields")
    if diagnostic["checker"] != CHECKER or diagnostic["qemu_path"] != qemu_path:
        fail("not-applicable record has the wrong checker or QEMU path")
    if type(diagnostic["line"]) is not int or diagnostic["line"] <= 0:
        fail("diagnostic line is invalid")
    if type(diagnostic["column"]) is not int or diagnostic["column"] <= 0:
        fail("diagnostic column is invalid")
    if not re.fullmatch(
            r"Level B: DMA transfer failure from "
            r"'(dma_buf_(read|write)|pci_dma_read)' is ignored",
            diagnostic["message"]):
        fail("not-applicable record has the wrong diagnostic message")

    reason = record["reason"]
    expected = {
        "dma-transfer-result-discarded:qemu.selective-summary.dma-buf-read:host-read",
        "dma-transfer-result-discarded:qemu.selective-summary.dma-buf-write:host-write",
        "dma-transfer-result-discarded:qemu.selective-summary.pci-dma-read:host-write",
    }
    if reason not in expected:
        fail(f"not-applicable record has the wrong reason: {reason}")
    function = {
        "dma-transfer-result-discarded:qemu.selective-summary.dma-buf-read:host-read":
            "dma_buf_read",
        "dma-transfer-result-discarded:qemu.selective-summary.dma-buf-write:host-write":
            "dma_buf_write",
        "dma-transfer-result-discarded:qemu.selective-summary.pci-dma-read:host-write":
            "pci_dma_read",
    }[reason]
    if function not in diagnostic["message"]:
        fail("not-applicable reason and diagnostic function disagree")
    return reason


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("qemu_path")
    args = parser.parse_args()
    encoded_records = re.findall(
        re.escape(MARKER) + r"([A-Za-z0-9+/]+={0,2})", sys.stdin.read()
    )
    if len(encoded_records) != 7:
        fail(f"expected 7 not-applicable records, found {len(encoded_records)}")
    reasons = Counter(validate_record(decode(encoded), args.qemu_path)
                      for encoded in encoded_records)
    expected_counts = {
        "dma-transfer-result-discarded:qemu.selective-summary.dma-buf-read:host-read": 3,
        "dma-transfer-result-discarded:qemu.selective-summary.dma-buf-write:host-write": 3,
        "dma-transfer-result-discarded:qemu.selective-summary.pci-dma-read:host-write": 1,
    }
    if reasons != expected_counts:
        fail(f"unexpected selective-summary witness counts: {dict(reasons)}")


if __name__ == "__main__":
    main()
