#!/usr/bin/env python3

import pathlib
import re
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

import irq_site_format as site


class SiteFormatTest(unittest.TestCase):
    def record(self) -> site.SiteRecord:
        return site.SiteRecord(
            kind=7,
            flags=(
                site.MANDATORY_BOUNDARY_FLAGS
                | site.FLAG_ASSEMBLY
                | site.FLAG_MANUAL_ID
            ),
            address=0x80000120,
            site_id=0x00112233445566778899AABBCCDDEEFF,
        )

    def test_little_endian_round_trip(self) -> None:
        encoded = self.record().pack("little")
        self.assertEqual(len(encoded), 32)
        self.assertEqual(site.decode_records(encoded, "little"), [self.record()])

    def test_big_endian_round_trip(self) -> None:
        encoded = self.record().pack("big")
        self.assertEqual(site.decode_records(encoded, "big"), [self.record()])

    def test_site_id_text_round_trip(self) -> None:
        text = site.format_site_id(self.record().site_id)
        self.assertEqual(len(text), 32)
        self.assertEqual(site.parse_site_id(text), self.record().site_id)

    def test_python_kinds_match_shared_definition(self) -> None:
        definition = (
            pathlib.Path(__file__).resolve().parents[3]
            / "include/clang/Basic/LinuxKernelIRQSiteKinds.def"
        ).read_text(encoding="utf-8")
        parsed = {
            int(value): text
            for _, value, text in re.findall(
                r"KLAB_IRQ_SITE_KIND\(\s*(\w+)\s*,\s*(\d+)\s*,\s*"
                r'"([^"]+)"\s*\)',
                definition,
                re.DOTALL,
            )
        }
        self.assertEqual(parsed, site.SITE_KIND_NAMES)

    def test_rejects_ambiguous_boundary(self) -> None:
        record = site.SiteRecord(
            kind=1,
            flags=site.FLAG_ASSEMBLY,
            address=0,
            site_id=1,
        )
        with self.assertRaisesRegex(site.SiteFormatError, "mandatory"):
            record.pack()

    def test_rejects_language_ambiguity(self) -> None:
        record = site.SiteRecord(
            kind=1,
            flags=site.MANDATORY_BOUNDARY_FLAGS,
            address=0,
            site_id=1,
        )
        with self.assertRaisesRegex(site.SiteFormatError, "exactly one"):
            record.pack()

    def test_rejects_partial_record(self) -> None:
        with self.assertRaisesRegex(site.SiteFormatError, "partial"):
            site.decode_records(self.record().pack()[:-1])

    def test_rejects_unknown_version(self) -> None:
        encoded = bytearray(self.record().pack())
        encoded[0] = 2
        with self.assertRaisesRegex(site.SiteFormatError, "version"):
            site.decode_records(bytes(encoded))

    def test_rejects_unknown_flags(self) -> None:
        record = self.record()
        invalid = site.SiteRecord(
            kind=record.kind,
            flags=record.flags | (1 << 31),
            address=record.address,
            site_id=record.site_id,
        )
        with self.assertRaisesRegex(site.SiteFormatError, "unknown"):
            invalid.pack()

    def test_rejects_unknown_kind(self) -> None:
        record = self.record()
        invalid = site.SiteRecord(
            kind=0xFFFF,
            flags=record.flags,
            address=record.address,
            site_id=record.site_id,
        )
        with self.assertRaisesRegex(site.SiteFormatError, "unknown"):
            invalid.pack()

    def test_rejects_duplicate_ids(self) -> None:
        record = self.record()
        duplicate = site.SiteRecord(
            kind=record.kind + 1,
            flags=record.flags,
            address=record.address + 4,
            site_id=record.site_id,
        )
        with self.assertRaisesRegex(site.SiteFormatError, "duplicate"):
            site.encode_records([record, duplicate])
        with self.assertRaisesRegex(site.SiteFormatError, "duplicate"):
            site.decode_records(record.pack() + duplicate.pack())


if __name__ == "__main__":
    unittest.main()
