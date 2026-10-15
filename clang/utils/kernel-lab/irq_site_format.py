#!/usr/bin/env python3
"""Encode and decode resolved Linux IRQ laboratory site records.

The object-level form carries a relocation in the ``address`` field.  This
small reference implementation handles the post-link, resolved byte format;
the LLVM object tool will eventually own relocatable-object processing.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import struct
import sys
from pathlib import Path
from typing import Iterable, Sequence


SITE_VERSION = 1
SITE_RECORD_SIZE = 32

FLAG_AFTER_PREVIOUS_RETIRE = 1 << 0
FLAG_BEFORE_INSN_AT_SITE = 1 << 1
FLAG_ASSEMBLY = 1 << 2
FLAG_C = 1 << 3
FLAG_NOINSTR = 1 << 4
FLAG_MANUAL_ID = 1 << 5
KNOWN_FLAGS = (
    FLAG_AFTER_PREVIOUS_RETIRE
    | FLAG_BEFORE_INSN_AT_SITE
    | FLAG_ASSEMBLY
    | FLAG_C
    | FLAG_NOINSTR
    | FLAG_MANUAL_ID
)

MANDATORY_BOUNDARY_FLAGS = (
    FLAG_AFTER_PREVIOUS_RETIRE | FLAG_BEFORE_INSN_AT_SITE
)

TRIGGER_PHASE = "AFTER_PREVIOUS_RETIRE/BEFORE_INSN_AT_SITE"

SITE_KIND_NAMES = {
    1: "user-experiment",
    2: "arch-vector-entry",
    3: "arch-vector-return",
    4: "hardirq-entry",
    5: "hardirq-exit",
    6: "nmi-entry",
    7: "nmi-exit",
    8: "exception-entry",
    9: "exception-exit",
    10: "softirq-entry",
    11: "softirq-exit",
    12: "irq-mask-disable",
    13: "irq-mask-enable",
    14: "irq-mask-save",
    15: "irq-mask-restore",
    16: "preempt-count-add",
    17: "preempt-count-sub",
    18: "preempt-count-test",
    19: "trace-recursion-acquire",
    20: "trace-recursion-release",
    21: "trace-recursion-reject",
    22: "task-irq-provenance-set",
    23: "task-irq-provenance-clear",
    24: "task-irq-provenance-save",
    25: "task-irq-provenance-restore",
    26: "rcu-entry",
    27: "rcu-exit",
    28: "rcu-eqs-enter",
    29: "rcu-eqs-exit",
    30: "lock-acquire",
    31: "lock-release",
    32: "rt-lock-wait-begin",
    33: "rt-lock-wait-end",
    34: "migration-disable",
    35: "migration-enable",
    36: "schedule",
    37: "reschedule-check",
    38: "barrier",
    39: "atomic-state-publish",
}


class SiteFormatError(ValueError):
    """The site map is malformed or violates the version-one contract."""


def _layout(endianness: str) -> struct.Struct:
    if endianness == "little":
        prefix = "<"
    elif endianness == "big":
        prefix = ">"
    else:
        raise SiteFormatError("endianness must be 'little' or 'big'")
    layout = struct.Struct(prefix + "BBHIQQQ")
    assert layout.size == SITE_RECORD_SIZE
    return layout


def _bounded(name: str, value: int, bits: int, *, nonzero: bool = False) -> int:
    if not isinstance(value, int):
        raise SiteFormatError(f"{name} must be an integer")
    lower = 1 if nonzero else 0
    if value < lower or value >= (1 << bits):
        qualifier = "nonzero " if nonzero else ""
        raise SiteFormatError(f"{name} must be a {qualifier}uint{bits}")
    return value


def parse_site_id(text: str) -> int:
    if not isinstance(text, str) or len(text) != 32:
        raise SiteFormatError("site_id must contain exactly 32 hexadecimal digits")
    try:
        value = int(text, 16)
    except ValueError as error:
        raise SiteFormatError("site_id is not hexadecimal") from error
    return _bounded("site_id", value, 128, nonzero=True)


def format_site_id(value: int) -> str:
    return f"{_bounded('site_id', value, 128, nonzero=True):032x}"


@dataclasses.dataclass(frozen=True)
class SiteRecord:
    kind: int
    flags: int
    address: int
    site_id: int

    def validate(self) -> None:
        _bounded("kind", self.kind, 16, nonzero=True)
        _bounded("flags", self.flags, 32)
        _bounded("address", self.address, 64)
        _bounded("site_id", self.site_id, 128, nonzero=True)
        if self.kind not in SITE_KIND_NAMES:
            raise SiteFormatError("unknown version-one site kind")
        if self.flags & ~KNOWN_FLAGS:
            raise SiteFormatError("site uses unknown version-one flags")
        if (self.flags & MANDATORY_BOUNDARY_FLAGS) != MANDATORY_BOUNDARY_FLAGS:
            raise SiteFormatError(
                "site lacks the mandatory after-retire/before-instruction boundary"
            )
        if bool(self.flags & FLAG_ASSEMBLY) == bool(self.flags & FLAG_C):
            raise SiteFormatError("site must identify exactly one of assembly or C")

    def pack(self, endianness: str = "little") -> bytes:
        self.validate()
        low = self.site_id & ((1 << 64) - 1)
        high = self.site_id >> 64
        return _layout(endianness).pack(
            SITE_VERSION,
            SITE_RECORD_SIZE,
            self.kind,
            self.flags,
            self.address,
            low,
            high,
        )

    def to_json(self) -> dict[str, object]:
        self.validate()
        return {
            "site_id": format_site_id(self.site_id),
            "kind": self.kind,
            "kind_name": SITE_KIND_NAMES[self.kind],
            "flags": self.flags,
            "address": f"0x{self.address:016x}",
        }

    @classmethod
    def from_json(cls, value: object) -> "SiteRecord":
        if not isinstance(value, dict):
            raise SiteFormatError("each record must be a JSON object")
        try:
            raw_address = value["address"]
            address = (
                int(raw_address, 0)
                if isinstance(raw_address, str)
                else int(raw_address)
            )
            record = cls(
                kind=int(value["kind"]),
                flags=int(value["flags"]),
                address=address,
                site_id=parse_site_id(value["site_id"]),
            )
        except (KeyError, TypeError, ValueError) as error:
            raise SiteFormatError(f"invalid record JSON: {error}") from error
        record.validate()
        return record


def decode_records(data: bytes, endianness: str = "little") -> list[SiteRecord]:
    layout = _layout(endianness)
    if len(data) % SITE_RECORD_SIZE:
        raise SiteFormatError("site section ends with a partial record")
    result: list[SiteRecord] = []
    for offset in range(0, len(data), SITE_RECORD_SIZE):
        version, size, kind, flags, address, low, high = layout.unpack_from(
            data, offset
        )
        if version != SITE_VERSION:
            raise SiteFormatError(f"unsupported site version {version}")
        if size != SITE_RECORD_SIZE:
            raise SiteFormatError(f"unexpected site record size {size}")
        record = SiteRecord(
            kind=kind,
            flags=flags,
            address=address,
            site_id=low | (high << 64),
        )
        record.validate()
        result.append(record)
    if len({record.site_id for record in result}) != len(result):
        raise SiteFormatError("duplicate site identifier")
    return result


def encode_records(
    records: Iterable[SiteRecord], endianness: str = "little"
) -> bytes:
    materialized = list(records)
    if len({record.site_id for record in materialized}) != len(materialized):
        raise SiteFormatError("duplicate site identifier")
    return b"".join(record.pack(endianness) for record in materialized)


def _document(records: Sequence[SiteRecord], endianness: str) -> dict[str, object]:
    return {
        "schema": SITE_VERSION,
        "record_size": SITE_RECORD_SIZE,
        "endianness": endianness,
        "trigger_phase": TRIGGER_PHASE,
        "records": [record.to_json() for record in records],
    }


def _decode(arguments: argparse.Namespace) -> int:
    records = decode_records(arguments.input.read_bytes(), arguments.endianness)
    json.dump(_document(records, arguments.endianness), sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


def _encode(arguments: argparse.Namespace) -> int:
    document = json.loads(arguments.input.read_text(encoding="utf-8"))
    if not isinstance(document, dict) or document.get("schema") != SITE_VERSION:
        raise SiteFormatError("JSON document must use schema 1")
    if document.get("trigger_phase") != TRIGGER_PHASE:
        raise SiteFormatError("JSON document has an incompatible trigger phase")
    endianness = document.get("endianness", arguments.endianness)
    values = document.get("records")
    if not isinstance(values, list):
        raise SiteFormatError("JSON document lacks a records array")
    arguments.output.write_bytes(
        encode_records((SiteRecord.from_json(value) for value in values), endianness)
    )
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(required=True)

    decode = subparsers.add_parser("decode", help="decode resolved records as JSON")
    decode.add_argument("input", type=Path)
    decode.add_argument("--endianness", choices=("little", "big"), default="little")
    decode.set_defaults(handler=_decode)

    encode = subparsers.add_parser("encode", help="encode records from JSON")
    encode.add_argument("input", type=Path)
    encode.add_argument("output", type=Path)
    encode.add_argument("--endianness", choices=("little", "big"), default="little")
    encode.set_defaults(handler=_encode)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        return arguments.handler(arguments)
    except (OSError, json.JSONDecodeError, SiteFormatError) as error:
        print(f"irq-site-format: error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
