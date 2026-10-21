#!/usr/bin/env python3

import argparse
import base64
import binascii
import json
from pathlib import Path
import re
import sys


MARKER = "QEMU_GMS_WITNESS_V1="
NOT_APPLICABLE_MARKER = "QEMU_GMS_WITNESS_NA_V1="
CHECKER = "alpha.qemu.GuestMemorySafety"


def fail(message):
    print(message, file=sys.stderr)
    raise SystemExit(1)


def expected_cases():
    cases = {}

    def add(name, message, witness=None, not_applicable=None,
            unaccounted=False):
        if name in cases:
            fail(f"duplicate expected case {name}")
        if sum((witness is not None, not_applicable is not None,
                unaccounted)) != 1:
            fail(f"case {name} must select exactly one witness outcome")
        cases[name] = {
            "message": message,
            "witness": witness,
            "not_applicable": not_applicable,
            "unaccounted": unaccounted,
        }

    def payload(name, concrete, source, constraint, direction, address, size,
                extent, missing, provenance="mmio"):
        return {
            "boundary_values": [
                {"label": "extent-minus-one", "value": "object extent - 1"},
                {"label": "extent", "value": "object extent"},
                {"label": "extent-plus-one", "value": "object extent + 1"},
            ],
            "concrete_value": concrete,
            "constraints": [constraint],
            "context": {
                "callback": name,
                "parser": None,
                "qom_type": None,
                "registration": name + "_ops",
            },
            # The exact diagnostic fields are filled from the bound warning.
            "diagnostic": None,
            "kind": "qemu-gms-witness",
            "provenance": {"class": provenance, "source": source},
            "reproducer": {
                "device": None,
                "interface": provenance,
                "kind": (
                    "packet" if provenance == "network"
                    else "descriptor" if provenance == "dma"
                    else "qtest"
                ),
                "machine": None,
            },
            "schema_version": 1,
            "sink": {
                "access_size": size,
                "address_or_offset": address,
                "direction": direction,
                "object_extent": extent,
            },
            "validation": {"missing_relationship": missing,
                           "status": "unproven"},
        }

    def not_applicable(reason):
        return {
            # The exact diagnostic fields are filled from the bound warning.
            "diagnostic": None,
            "kind": "qemu-gms-witness-not-applicable",
            "reason": reason,
            "schema_version": 1,
        }

    array_message = (
        "Level A: guest-controlled array index exceeds the host object "
        "element count (value 4, elements 4)"
    )
    for element, width in (("char", 1), ("int", 4), ("u64", 8)):
        for operation, direction in (("read", "host-read"),
                                     ("write", "host-write")):
            name = element + "_" + operation
            add(name, array_message, payload(
                name, "4", "expression 'data'",
                "array index >= host object element count", direction,
                "slots[data]", f"bytes {width}", "elements 4",
                "array index < host object element count"))

    offset_message = (
        "Level B: guest-controlled memory-operation offset plus length may "
        "exceed the host object extent "
        "(value [9, 18446744073709551615], bytes 8)"
    )
    for name, direction in (("offset_destination", "host-write"),
                            ("offset_source", "host-read")):
        add(name, offset_message, payload(
            name, None, "offset expression 'data'",
            "memory-operation offset plus length > host object extent",
            direction,
            "effective address 'bytes + data', byte offset "
            "[5, 18446744073709551611] from base 'bytes'",
            "bytes 4", "bytes 8",
            "memory-operation offset plus length <= host object extent"))

    for name, expression, width, end in (
            ("callback_byte", "packet[4]", 1, 5),
            ("callback_scalar", "*(const unsigned int *)(packet + 4)", 4, 8),
            ("callback_memory", "packet + 4", 4, 8)):
        message = (
            "Level A: network receive callback buffer read exceeds the "
            f"available guest-input bytes (access end {end}, bytes 3)"
        )
        add(name, message, payload(
            name, str(end),
            f"callback buffer '{expression}' and length parameter",
            "access end > available guest-input bytes", "host-read",
            "byte offset 4 from callback buffer parameter 'packet'",
            f"bytes {width}", "bytes 3",
            "access end <= available guest-input bytes", "network"))

    bitmap_message = (
        "Level A: guest-controlled bitmap bit index exceeds the host object "
        "bit capacity (value 64, bits 64)"
    )
    for name, direction in (("bitmap_read", "host-read"),
                            ("bitmap_set", "host-write"),
                            ("bitmap_clear", "host-write")):
        add(name, bitmap_message, payload(
            name, "64", "expression 'bit'",
            "bitmap bit index >= host object bit capacity", direction,
            "bitmap base 'bitmap', bit index 64, word index 1 "
            "(unsigned long, 64 bits per word)", "bytes 8", "bits 64",
            "bitmap bit index < host object bit capacity"))

    add(
        "address_only",
        array_message.replace("value 4", "value 5"),
        not_applicable=not_applicable("address-computation-only"),
    )
    add(
        "unresolved_member_access",
        array_message,
        unaccounted=True,
    )
    add("allocation_overflow", (
        "Level B: guest-controlled allocation-size arithmetic overflows before "
        "the allocation (left [9223372036854775808, 18446744073709551615], "
        "right [9223372036854775808, 18446744073709551615])"
    ), not_applicable=not_applicable("allocation-size-arithmetic"))
    add("availability_allocation", (
        "Level C: guest-controlled allocation size in g_malloc has no proven "
        "upper bound below its integer type maximum "
        "(value [0, 18446744073709551615], source MMIO); "
        "allocation failure can terminate QEMU"
    ), not_applicable=not_applicable("allocation-availability"))
    add("usb_setup_state", (
        "Level A: guest-controlled USB setup length state exceeds the host "
        "object extent (value 4097, bytes 4096, source USB setup packet "
        "field 'setup_buf')"
    ), not_applicable=not_applicable("usb-state-capacity-contract"))
    add("dma_map_unmap_contract", (
        "direct DMA unmap arguments match the reversed argument order"
    ), not_applicable=not_applicable("dma-map-unmap-contract"))
    add("dma_use_after_unmap", (
        "direct DMA mapped buffer is accessed after it was unmapped"
    ), payload(
        "dma_use_after_unmap", "1",
        "direct DMA mapping returned by map API",
        "nonzero memory access occurs after direct DMA unmap",
        "host-read", "effective address 'buffer'", "bytes 1", "bytes 8",
        "memory access must precede direct DMA unmap", "dma"))
    add("dma_typed_short_load", (
        "Level A: guest-controlled direct DMA mapped-buffer typed access end "
        "exceeds the host object extent (value 4, bytes 1, source DMA map "
        "returned length)"
    ), payload(
        "dma_typed_short_load", "4", "DMA map returned length",
        "direct DMA mapped-buffer typed access end > host object extent",
        "host-read", "effective address '*(uint32_t *)buffer', byte offset 0 "
        "from base 'direct DMA mapping'", "bytes 4", "bytes 1",
        "direct DMA mapped-buffer typed access end <= host object extent",
        "dma"))
    add("dma_typed_macro_short_load", (
        "Level A: guest-controlled direct DMA mapped-buffer typed access end "
        "exceeds the host object extent (value 4, bytes 1, source DMA map "
        "returned length)"
    ), payload(
        "dma_typed_macro_short_load", "4", "DMA map returned length",
        "direct DMA mapped-buffer typed access end > host object extent",
        "host-read", "effective address '(*(uint32_t *)(buffer))', byte "
        "offset 0 from base 'direct DMA mapping'", "bytes 4", "bytes 1",
        "direct DMA mapped-buffer typed access end <= host object extent",
        "dma"))
    add("dma_typed_macro_argument_short_load", (
        "Level A: guest-controlled direct DMA mapped-buffer typed access end "
        "exceeds the host object extent (value 4, bytes 1, source DMA map "
        "returned length)"
    ), payload(
        "dma_typed_macro_argument_short_load", "4", "DMA map returned length",
        "direct DMA mapped-buffer typed access end > host object extent",
        "host-read", "effective address '*(uint32_t *)buffer', byte offset 0 "
        "from base 'direct DMA mapping'", "bytes 4", "bytes 1",
        "direct DMA mapped-buffer typed access end <= host object extent",
        "dma"))
    add("dma_typed_assignment_macro_short_load", (
        "Level A: guest-controlled direct DMA mapped-buffer typed access end "
        "exceeds the host object extent (value 4, bytes 1, source DMA map "
        "returned length)"
    ), payload(
        "dma_typed_assignment_macro_short_load", "4",
        "DMA map returned length",
        "direct DMA mapped-buffer typed access end > host object extent",
        "host-read", "effective address '(*(uint32_t *)buffer)', byte offset "
        "0 from base 'direct DMA mapping'", "bytes 4", "bytes 1",
        "direct DMA mapped-buffer typed access end <= host object extent",
        "dma"))
    add("dma_typed_multiline_short_store", (
        "Level A: guest-controlled direct DMA mapped-buffer typed access end "
        "exceeds the host object extent (value 4, bytes 1, source DMA map "
        "returned length)"
    ), payload(
        "dma_typed_multiline_short_store", "4", "DMA map returned length",
        "direct DMA mapped-buffer typed access end > host object extent",
        "host-write", "effective address '*(uint32_t *)buffer', byte offset "
        "0 from base 'direct DMA mapping'",
        "bytes 4", "bytes 1",
        "direct DMA mapped-buffer typed access end <= host object extent",
        "dma"))
    add("dma_null_unmap_contract", (
        "direct DMA unmap is called with a null mapping"
    ), not_applicable=not_applicable("dma-map-unmap-contract"))
    return cases


def source_cases(source, expected):
    by_line = {}
    names = set()
    pattern = re.compile(
        r"// (WITNESS|NOT-APPLICABLE|UNACCOUNTED): ([a-z][a-z0-9_]*)\s*$"
    )
    for line_number, line in enumerate(source.read_text().splitlines(), 1):
        match = pattern.search(line)
        if not match:
            continue
        kind, name = match.groups()
        if name not in expected:
            fail(f"unknown source case {name}")
        if name in names or line_number in by_line:
            fail(f"duplicate source case {name}")
        names.add(name)
        expected_kind = (
            "WITNESS" if expected[name]["witness"] is not None
            else "NOT-APPLICABLE"
            if expected[name]["not_applicable"] is not None
            else "UNACCOUNTED"
        )
        if kind != expected_kind:
            fail(f"source case {name} has the wrong witness expectation")
        by_line[line_number] = (name, len(line[:match.start()].rstrip()))
    if names != set(expected):
        fail(f"source cases are incomplete: {sorted(set(expected) - names)}")
    return by_line


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            fail(f"witness JSON has duplicate object key {key!r}")
        result[key] = value
    return result


def reject_constant(value):
    fail(f"witness JSON has non-JSON numeric constant {value}")


def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode()


def decode_witness(encoded):
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as error:
        fail(f"witness is not strict base64: {error}")
    if base64.b64encode(raw).decode("ascii") != encoded:
        fail("witness base64 is not canonical")
    try:
        witness = json.loads(raw, object_pairs_hook=unique_object,
                             parse_constant=reject_constant)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"witness is not valid UTF-8 JSON: {error}")
    if canonical_json(witness) != raw:
        fail("witness JSON is not compact canonical JSON")
    if not isinstance(witness, dict):
        fail("witness JSON is not an object")
    if type(witness.get("schema_version")) is not int:
        fail("witness schema version is not an integer")
    return witness


def validate(lines, source, qemu_path, expect_absent):
    expected = expected_cases()
    by_line = source_cases(source, expected)
    observed = {}
    current = None
    pattern = re.compile(r"^(.*):(\d+):(\d+): (warning|note|error|fatal error): (.*)$")
    suffix = f" [{CHECKER}]"
    for line in lines:
        match = pattern.match(line.rstrip("\n"))
        if not match:
            if MARKER in line or NOT_APPLICABLE_MARKER in line:
                fail("structured witness marker is outside a diagnostic note")
            if re.search(r"(?:^|: )(?:warning|error|fatal error): ", line):
                fail(f"unexpected diagnostic: {line.rstrip()}")
            continue
        filename, line_number, column, level, message = match.groups()
        location = (filename, int(line_number), int(column))
        if level in ("error", "fatal error"):
            fail(f"unexpected analyzer error: {message}")
        if level == "warning":
            if not message.endswith(suffix):
                fail(f"unexpected warning: {message}")
            if Path(filename).resolve() != source.resolve():
                fail(f"warning is not in the test source: {filename}")
            case = by_line.get(location[1])
            if case is None:
                fail(f"warning has no expected case at line {location[1]}")
            name, code_columns = case
            if name in observed:
                fail(f"case {name} emitted more than one warning")
            if not 0 < location[2] <= code_columns:
                fail(f"case {name} has a warning outside the source expression")
            message = message[:-len(suffix)]
            if message != expected[name]["message"]:
                fail(f"case {name} has the wrong warning: {message}")
            current = {"name": name, "location": location,
                       "message": message, "witness": None,
                       "not_applicable": None}
            observed[name] = current
        elif message.startswith(MARKER):
            if current is None:
                fail("witness note has no preceding warning")
            name = current["name"]
            if expect_absent or expected[name]["witness"] is None:
                fail(f"case {name} emitted a forbidden structured witness")
            if current["witness"] is not None:
                fail(f"case {name} emitted more than one witness")
            if location != current["location"]:
                fail(f"case {name} witness does not share its warning location")
            witness = decode_witness(message[len(MARKER):])
            wanted = expected[name]["witness"]
            wanted["diagnostic"] = {
                "checker": CHECKER,
                "qemu_path": qemu_path,
                "line": location[1],
                "column": location[2],
                "message": current["message"],
            }
            if canonical_json(witness) != canonical_json(wanted):
                fail(f"case {name} has the wrong witness\n"
                     f"expected: {json.dumps(wanted, sort_keys=True)}\n"
                     f"actual:   {json.dumps(witness, sort_keys=True)}")
            current["witness"] = witness
        elif message.startswith(NOT_APPLICABLE_MARKER):
            if current is None:
                fail("not-applicable note has no preceding warning")
            name = current["name"]
            if expect_absent or expected[name]["not_applicable"] is None:
                fail(f"case {name} emitted a forbidden not-applicable record")
            if current["not_applicable"] is not None:
                fail(f"case {name} emitted more than one not-applicable record")
            if current["witness"] is not None:
                fail(f"case {name} emitted two structured witness outcomes")
            if location != current["location"]:
                fail(
                    f"case {name} not-applicable record does not share its "
                    "warning location"
                )
            record = decode_witness(message[len(NOT_APPLICABLE_MARKER):])
            wanted = expected[name]["not_applicable"]
            wanted["diagnostic"] = {
                "checker": CHECKER,
                "qemu_path": qemu_path,
                "line": location[1],
                "column": location[2],
                "message": current["message"],
            }
            if canonical_json(record) != canonical_json(wanted):
                fail(
                    f"case {name} has the wrong not-applicable record\n"
                    f"expected: {json.dumps(wanted, sort_keys=True)}\n"
                    f"actual:   {json.dumps(record, sort_keys=True)}"
                )
            current["not_applicable"] = record
        elif MARKER in message or NOT_APPLICABLE_MARKER in message:
            fail("structured witness marker is malformed")

    if set(observed) != set(expected):
        fail(f"missing expected warnings: {sorted(set(expected) - set(observed))}")
    for name, report in observed.items():
        wanted_witness = (
            not expect_absent and expected[name]["witness"] is not None
        )
        wanted_not_applicable = (
            not expect_absent
            and expected[name]["not_applicable"] is not None
        )
        if wanted_witness != (report["witness"] is not None):
            fail(f"case {name} is missing its structured witness")
        if wanted_not_applicable != (report["not_applicable"] is not None):
            fail(f"case {name} is missing its not-applicable record")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--expect-absent", action="store_true")
    parser.add_argument("source", type=Path)
    parser.add_argument("qemu_path")
    args = parser.parse_args()
    validate(sys.stdin, args.source, args.qemu_path, args.expect_absent)


if __name__ == "__main__":
    main()
