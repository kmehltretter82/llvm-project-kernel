#!/usr/bin/env python3

import copy
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock


ANALYZER_UTILS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ANALYZER_UTILS))
import qemu_contract_catalog as catalog_tool
import qemu_contract_catalog_resolver as resolver

CLANG_ROOT = ANALYZER_UTILS.parents[1]
CHECKER_DIR = CLANG_ROOT / "lib" / "StaticAnalyzer" / "Checkers"
CATALOG_PATH = CHECKER_DIR / "QEMUContractCatalog.json"
SCHEMA_PATH = CHECKER_DIR / "QEMUContractCatalog.schema.json"


class QEMUContractCatalogResolverTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.full_catalog = catalog_tool.load_json_strict(CATALOG_PATH)
        cls.schema = catalog_tool.load_json_strict(SCHEMA_PATH)
        cls.clang = os.environ.get("QEMU_CONTRACT_TEST_CLANG") or shutil.which("clang")
        if cls.clang:
            cls.clang = str(Path(cls.clang).resolve())

    def setUp(self):
        if not self.clang:
            self.skipTest("clang is required for AST resolver tests")
        production_resolve = resolver.resolve_catalog
        self.resolve_patch = mock.patch.object(
            resolver,
            "resolve_catalog",
            side_effect=lambda *args, **kwargs: production_resolve(
                *args, validation_profile="test-subset", **kwargs
            ),
        )
        self.resolve_patch.start()
        self.addCleanup(self.resolve_patch.stop)

    def catalog(self, language="c"):
        catalog = {
            "catalog_format": 5,
            "model_version": "qemu-v3-resolver-test",
            "contracts": copy.deepcopy(self.full_catalog["contracts"][:2]),
            "callback_bindings": [],
            "protocols": [],
        }
        catalog["contracts"][0]["selector"].update(
            {
                "name": "catalog_map",
                "header": "include/test/api.h",
                "translation_unit": "probe.{}".format(
                    "cpp" if language == "c++" else "c"
                ),
            }
        )
        catalog["contracts"][1]["selector"].update(
            {
                "name": "catalog_unmap",
                "header": "include/test/api.h",
                "translation_unit": "probe.{}".format(
                    "cpp" if language == "c++" else "c"
                ),
            }
        )
        catalog_tool.validate_catalog(catalog, profile="test-subset")
        return catalog

    def fixture(self, directory, header, source=None, language="c"):
        root = Path(directory) / "source"
        build = Path(directory) / "build"
        header_path = root / "include" / "test" / "api.h"
        header_path.parent.mkdir(parents=True)
        build.mkdir()
        header_path.write_text(header, encoding="utf-8")
        extension = "cpp" if language == "c++" else "c"
        source_path = root / "probe.{}".format(extension)
        source_path.write_text(
            source or '#include "include/test/api.h"\n', encoding="utf-8"
        )
        standard = "-std=c++17" if language == "c++" else "-std=c11"
        compile_commands = build / "compile_commands.json"
        compile_commands.write_text(
            json.dumps(
                [
                    {
                        "directory": str(build),
                        "file": str(source_path),
                        "arguments": [
                            self.clang,
                            standard,
                            "-I",
                            str(root),
                            "-MD",
                            "-MF",
                            str(build / "probe.d"),
                            "-c",
                            str(source_path),
                            "-o",
                            str(build / "probe.o"),
                        ],
                    }
                ],
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        return root, compile_commands

    def c_header(self, map_types="hwaddr addr, hwaddr *plen", map_name="catalog_map"):
        return """\
#ifndef TEST_API_H
#define TEST_API_H
#include <stdbool.h>
typedef unsigned long hwaddr;
typedef struct AddressSpace AddressSpace;
typedef struct MemTxAttrs { unsigned value; } MemTxAttrs;
void *%s(AddressSpace *as, %s, bool is_write, MemTxAttrs attrs);
void catalog_unmap(AddressSpace *as, void *buffer, hwaddr len,
                   bool is_write, hwaddr access_len);
#endif
""" % (map_name, map_types)

    def packet_catalog(self):
        contract = copy.deepcopy(
            next(
                entry
                for entry in self.full_catalog["contracts"]
                if entry["id"] == "qemu.usb.packet-copy"
            )
        )
        contract["selector"].update(
            {
                "header": "include/test/api.h",
                "translation_unit": "probe.c",
            }
        )
        for operand in contract["operands"]:
            for step in operand.get("path", []):
                step["header"] = "include/test/api.h"
        catalog = {
            "catalog_format": 5,
            "model_version": "qemu-v3-usb-resolver-test",
            "contracts": [contract],
            "callback_bindings": [],
            "protocols": [],
        }
        catalog_tool.validate_catalog(catalog, profile="test-subset")
        return catalog

    def packet_header(self, status_field="int status;", endpoint_type="uint8_t"):
        return """\
#ifndef TEST_API_H
#define TEST_API_H
typedef unsigned char uint8_t;
typedef unsigned long uint64_t;
typedef unsigned long size_t;
typedef struct QEMUIOVector {
    union {
        struct { int nalloc; };
        struct { size_t size; };
    };
} QEMUIOVector;
typedef struct USBEndpoint { %s type; } USBEndpoint;
typedef struct USBCombinedPacket { QEMUIOVector iov; } USBCombinedPacket;
typedef struct USBPacket {
    int pid;
    USBEndpoint *ep;
    QEMUIOVector iov;
    uint64_t parameter;
    %s
    int actual_length;
    USBCombinedPacket *combined;
} USBPacket;
void usb_packet_copy(USBPacket *p, void *ptr, size_t bytes);
#endif
""" % (endpoint_type, status_field)

    def callback_catalog(self):
        contracts = copy.deepcopy(self.full_catalog["contracts"][:2])
        for contract, name in zip(contracts, ("catalog_map", "catalog_unmap")):
            contract["selector"].update(
                {
                    "name": name,
                    "header": "include/hw/usb/usb.h",
                    "translation_unit": "hw/usb/bus.c",
                }
            )
        catalog = {
            "catalog_format": 5,
            "model_version": "qemu-v3-callback-resolver-test",
            "contracts": contracts,
            "callback_bindings": copy.deepcopy(
                self.full_catalog["callback_bindings"]
            ),
            "protocols": [],
        }
        catalog_tool.validate_catalog(catalog, profile="test-subset")
        return catalog

    def callback_fixture(
        self,
        directory,
        data_field="handle_data",
        data_return_type="void",
        packet_pid="int pid;",
        registration_field="class_init",
        registration_return_type="void",
        registration_variable="u2f_key_info",
        registration_initializer="u2f_key_class_init",
        registered_initializer=None,
        control_assignment_field="handle_control",
        control_assignment_target="u2f_key_handle_control",
        data_assignment_field=None,
        data_assignment_target="u2f_key_handle_data",
        include_control_assignment=True,
        include_data_assignment=True,
        include_registration_command=True,
    ):
        if registered_initializer is None:
            registered_initializer = registration_initializer
        if data_assignment_field is None:
            data_assignment_field = data_field
        root = Path(directory) / "source"
        build = Path(directory) / "build"
        usb_header = root / "include" / "hw" / "usb" / "usb.h"
        object_header = root / "include" / "qom" / "object.h"
        iov_header = root / "include" / "qemu" / "iov.h"
        bus_source = root / "hw" / "usb" / "bus.c"
        registration_source = root / "hw" / "usb" / "u2f.c"
        for path in (usb_header, object_header, iov_header, bus_source):
            path.parent.mkdir(parents=True, exist_ok=True)
        build.mkdir()
        iov_header.write_text(
            """\
#ifndef TEST_IOV_H
#define TEST_IOV_H
#include <stddef.h>
typedef struct QEMUIOVector { size_t size; } QEMUIOVector;
#endif
""",
            encoding="utf-8",
        )
        usb_header.write_text(
            """\
#ifndef TEST_USB_H
#define TEST_USB_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "include/qemu/iov.h"
typedef unsigned long hwaddr;
typedef struct AddressSpace AddressSpace;
typedef struct MemTxAttrs { unsigned value; } MemTxAttrs;
typedef struct USBDevice USBDevice;
typedef struct USBEndpoint { uint8_t nr; uint8_t type; } USBEndpoint;
typedef struct USBCombinedPacket { QEMUIOVector iov; } USBCombinedPacket;
typedef struct USBPacket {
    %s
    USBEndpoint *ep;
    QEMUIOVector iov;
    uint64_t parameter;
    USBCombinedPacket *combined;
} USBPacket;
typedef struct USBDeviceClass {
    void (*handle_control)(USBDevice *, USBPacket *, int, int, int, int,
                           uint8_t *);
    %s (*%s)(USBDevice *, USBPacket *);
    void (*alternate_data)(USBDevice *, USBPacket *);
} USBDeviceClass;
void *catalog_map(AddressSpace *as, hwaddr addr, hwaddr *plen,
                  bool is_write, MemTxAttrs attrs);
void catalog_unmap(AddressSpace *as, void *buffer, hwaddr len,
                   bool is_write, hwaddr access_len);
#endif
"""
            % (packet_pid, data_return_type, data_field),
            encoding="utf-8",
        )
        object_header.parent.mkdir(parents=True, exist_ok=True)
        object_header.write_text(
            """\
#ifndef TEST_OBJECT_H
#define TEST_OBJECT_H
typedef struct ObjectClass ObjectClass;
typedef struct TypeInfo {
    const char *name;
    %s (*%s)(ObjectClass *, const void *);
} TypeInfo;
#endif
"""
            % (registration_return_type, registration_field),
            encoding="utf-8",
        )
        bus_source.write_text(
            '#include "include/hw/usb/usb.h"\n', encoding="utf-8"
        )
        registration_source.parent.mkdir(parents=True, exist_ok=True)
        registration_source.write_text(
            '#include "include/hw/usb/usb.h"\n'
            '#include "include/qom/object.h"\n'
            'struct ObjectClass { int unused; };\n'
            'static void u2f_key_handle_control(USBDevice *dev, USBPacket *p,\n'
            '                                   int request, int value, int index,\n'
            '                                   int length, uint8_t *data) {}\n'
            'static void other_handle_control(USBDevice *dev, USBPacket *p,\n'
            '                                 int request, int value, int index,\n'
            '                                 int length, uint8_t *data) {}\n'
            'static %s u2f_key_handle_data(USBDevice *dev, USBPacket *p) {%s}\n'
            'static %s other_handle_data(USBDevice *dev, USBPacket *p) {%s}\n'
            'static %s %s(ObjectClass *klass, const void *data)\n'
            '{\n'
            '    USBDeviceClass *uc = (USBDeviceClass *)klass;\n'
            '%s'
            '%s'
            '%s'
            '}\n'
            'static void other_class_init(ObjectClass *klass, const void *data) {}\n'
            'static const TypeInfo %s = {\n'
            '    .%s = %s,\n'
            '};\n'
            % (
                data_return_type,
                ' return 0;' if data_return_type != 'void' else '',
                data_return_type,
                ' return 0;' if data_return_type != 'void' else '',
                registration_return_type,
                registration_initializer,
                (
                    '    uc->%s = %s;\n'
                    % (control_assignment_field, control_assignment_target)
                    if include_control_assignment
                    else ''
                ),
                (
                    '    uc->%s = %s;\n'
                    % (data_assignment_field, data_assignment_target)
                    if include_data_assignment
                    else ''
                ),
                '    return 0;\n' if registration_return_type != 'void' else '',
                registration_variable,
                registration_field,
                registered_initializer,
            ),
            encoding="utf-8",
        )

        def entry(source, object_name):
            return {
                "directory": str(build),
                "file": str(source),
                "arguments": [
                    self.clang,
                    "-std=c11",
                    "-I",
                    str(root),
                    "-c",
                    str(source),
                    "-o",
                    str(build / object_name),
                ],
            }

        entries = [entry(bus_source, "bus.o")]
        if include_registration_command:
            entries.append(entry(registration_source, "u2f.o"))
        compile_commands = build / "compile_commands.json"
        compile_commands.write_text(
            json.dumps(entries, indent=2) + "\n", encoding="utf-8"
        )
        return root, compile_commands

    def protocol_catalog(self, language="c"):
        contract = copy.deepcopy(
            next(
                entry
                for entry in self.full_catalog["contracts"]
                if entry["id"] == "qemu.transfer.dma-memory.read"
            )
        )
        contract["selector"].update(
            {
                "name": "catalog_transfer",
                "header": "include/test/api.h",
                "translation_unit": "probe.{}".format(
                    "cpp" if language == "c++" else "c"
                ),
            }
        )
        protocol = copy.deepcopy(self.full_catalog["protocols"][0])
        protocol["id"] = "qemu.protocol.test.queue-completion"
        protocol["family"] = "test-queue"
        protocol["scope"].update(
            {
                "name": "do_queue",
                "source": "probe.{}".format("cpp" if language == "c++" else "c"),
                "translation_unit": "probe.{}".format(
                    "cpp" if language == "c++" else "c"
                ),
                "prototype": {
                    "return_type": "void",
                    "parameters": [{"name": "device", "type": "Device *"}],
                },
            }
        )
        slot = next(
            binding for binding in protocol["bindings"] if binding["role"] == "slot"
        )
        slot["record_type"] = "Device"
        slot["field"] = "count"
        protocol["events"][0]["selectors"] = [
            {
                "kind": "transfer-call",
                "contract_id": contract["id"],
                "phase": "post-call",
                "result_path": "failure",
                "expected_count": 1,
            }
        ]
        protocol["events"][1]["selectors"] = [
            {
                "kind": "member-update",
                "record_type": "Device",
                "field": "count",
                "operation": "post-decrement",
                "phase": "bind",
                "expected_count": 1,
            }
        ]
        protocol["events"][2]["selectors"] = [
            {
                "kind": "function-call",
                "name": "publish",
                "prototype": {
                    "return_type": "void",
                    "parameters": [{"name": "device", "type": "Device *"}],
                },
                "phase": "pre-call",
                "expected_count": 1,
            }
        ]
        catalog = {
            "catalog_format": 5,
            "model_version": "qemu-v3-protocol-resolver-test",
            "contracts": [contract],
            "callback_bindings": [],
            "protocols": [protocol],
        }
        catalog_tool.validate_catalog(catalog, profile="test-subset")
        return catalog

    def protocol_header(self):
        return """\
#ifndef TEST_API_H
#define TEST_API_H
typedef unsigned long dma_addr_t;
typedef struct AddressSpace AddressSpace;
typedef struct MemTxAttrs { unsigned value; } MemTxAttrs;
typedef int MemTxResult;
MemTxResult catalog_transfer(AddressSpace *as, dma_addr_t addr, void *buf,
                             dma_addr_t len, MemTxAttrs attrs);
#endif
"""

    def protocol_source(self, body=None, publish_parameters="Device *device",
                        scope_parameters="Device *device"):
        body = body or """\
    char buffer[4];
    (void)catalog_transfer((AddressSpace *)0, 0, buffer, sizeof(buffer),
                           (MemTxAttrs){0});
    device->count--;
    publish(device);
"""
        return """\
#include "include/test/api.h"
typedef struct Device { unsigned count; unsigned other; } Device;
static void publish(%s) { (void)device; }
static void do_queue(%s)
{
%s}
""" % (publish_parameters, scope_parameters, body)

    def protocol_report(self, report):
        return report["protocols"][0]

    def contract_report(self, report, contract_id):
        return next(
            contract
            for contract in report["contracts"]
            if contract["contract_id"] == contract_id
        )

    def callback_report(self, report, binding_id):
        return next(
            callback
            for callback in report["callback_bindings"]
            if callback["binding_id"] == binding_id
        )

    def test_exact_ast_match_is_deterministic(self):
        with tempfile.TemporaryDirectory() as directory:
            root, compile_commands = self.fixture(directory, self.c_header())
            first = resolver.resolve_catalog(
                self.catalog(), self.schema, compile_commands, root
            )
            second = resolver.resolve_catalog(
                self.catalog(), self.schema, compile_commands, root
            )
            serialized = json.dumps(first, sort_keys=True)
            self.assertNotIn(directory, serialized)
        self.assertEqual(first, second)
        self.assertEqual(first["result"], "pass")
        self.assertEqual(
            [contract["status"] for contract in first["contracts"]],
            ["matched", "matched"],
        )
        self.assertEqual(first["compile_database"]["unique_command_count"], 1)
        self.assertEqual(len(first["compile_database"]["selector_filters"]), 2)
        self.assertEqual(first["compile_database"]["anchor_command_count"], 1)
        self.assertEqual(first["compile_database"]["ast_run_count"], 2)
        self.assertEqual(len(first["compilers"]), 1)
        self.assertEqual(len(first["cc1_executables"]), 1)
        self.assertEqual(
            first["compile_database"]["commands"][0][
                "cc1_executable_sha256"
            ],
            first["cc1_executables"][0]["sha256"],
        )
        self.assertEqual(
            first["tool"]["resolver_sha256"],
            resolver._sha256_file(Path(resolver.__file__).resolve()),
        )
        self.assertEqual(
            first["tool"]["catalog_generator_sha256"],
            resolver._sha256_file(Path(catalog_tool.__file__).resolve()),
        )
        self.assertTrue(serialized)

    def test_packet_member_paths_match_including_promoted_iov_size(self):
        with tempfile.TemporaryDirectory() as directory:
            root, compile_commands = self.fixture(
                directory, self.packet_header()
            )
            report = resolver.resolve_catalog(
                self.packet_catalog(), self.schema, compile_commands, root
            )
        self.assertEqual(report["result"], "pass")
        contract = self.contract_report(report, "qemu.usb.packet-copy")
        self.assertEqual(contract["status"], "matched")
        self.assertEqual(len(contract["member_paths"]), 8)
        self.assertTrue(
            all(path["status"] == "matched" for path in contract["member_paths"])
        )
        primary = next(
            path
            for path in contract["member_paths"]
            if path["role"] == "primary_capacity"
        )
        iov_definition = primary["steps"][1]["definitions"][0]
        size = next(
            field for field in iov_definition["fields"] if field["name"] == "size"
        )
        self.assertEqual(size["type"], "size_t")
        self.assertEqual(size["access"], "promoted")
        self.assertEqual(report["compile_database"]["ast_run_count"], 5)
        self.assertEqual(
            report["compile_database"]["selector_filters"],
            [
                "QEMUIOVector",
                "USBCombinedPacket",
                "USBEndpoint",
                "USBPacket",
                "usb_packet_copy",
            ],
        )

    def test_packet_member_name_and_type_drift_fail_closed(self):
        cases = (
            (
                self.packet_header(status_field="int outcome;"),
                "status",
            ),
            (
                self.packet_header(endpoint_type="unsigned short"),
                "endpoint_type",
            ),
        )
        for header, role in cases:
            with self.subTest(role=role), tempfile.TemporaryDirectory() as directory:
                root, compile_commands = self.fixture(directory, header)
                report = resolver.resolve_catalog(
                    self.packet_catalog(), self.schema, compile_commands, root
                )
            contract = self.contract_report(report, "qemu.usb.packet-copy")
            path = next(
                path for path in contract["member_paths"] if path["role"] == role
            )
            self.assertEqual(report["result"], "drift")
            self.assertEqual(contract["status"], "member-drift")
            self.assertEqual(path["status"], "drift")
            self.assertTrue(any(step["status"] == "stale" for step in path["steps"]))

    def test_packet_member_header_drift_fails_closed(self):
        catalog = self.packet_catalog()
        primary = next(
            operand
            for operand in catalog["contracts"][0]["operands"]
            if operand["role"] == "primary_capacity"
        )
        primary["path"][1]["header"] = "include/test/iov.h"
        with tempfile.TemporaryDirectory() as directory:
            root, compile_commands = self.fixture(
                directory, self.packet_header()
            )
            iov_header = root / "include" / "test" / "iov.h"
            iov_header.write_text("/* wrong member owner header */\n", encoding="utf-8")
            report = resolver.resolve_catalog(
                catalog, self.schema, compile_commands, root
            )
        contract = self.contract_report(report, "qemu.usb.packet-copy")
        primary_report = next(
            path
            for path in contract["member_paths"]
            if path["role"] == "primary_capacity"
        )
        self.assertEqual(report["result"], "drift")
        self.assertEqual(contract["status"], "member-drift")
        self.assertEqual(primary_report["steps"][1]["status"], "missing")

    def test_usb_callback_slots_registration_and_inputs_match_exactly(self):
        with tempfile.TemporaryDirectory() as directory:
            root, compile_commands = self.callback_fixture(directory)
            first = resolver.resolve_catalog(
                self.callback_catalog(), self.schema, compile_commands, root
            )
            second = resolver.resolve_catalog(
                self.callback_catalog(), self.schema, compile_commands, root
            )
            self.assertNotIn(directory, json.dumps(first, sort_keys=True))
        self.assertEqual(first, second)
        self.assertEqual(first["report_format"], 2)
        self.assertEqual(first["result"], "pass")
        self.assertEqual(
            [callback["status"] for callback in first["callback_bindings"]],
            ["matched", "matched"],
        )
        self.assertEqual(first["compile_database"]["callback_binding_count"], 2)
        self.assertEqual(first["compile_database"]["anchor_command_count"], 2)
        self.assertEqual(first["compile_database"]["ast_run_count"], 10)
        data = self.callback_report(first, "qemu.usb-device.handle-data")
        self.assertEqual(data["slot"]["status"], "matched")
        self.assertEqual(data["registration_root"]["status"], "matched")
        self.assertEqual(
            data["registration_root"]["variable_initializer"]["status"],
            "matched",
        )
        self.assertEqual(
            data["registration_root"]["class_initializer"]["status"],
            "matched",
        )
        self.assertEqual(
            data["registration_root"]["slot_assignment"]["status"],
            "matched",
        )
        self.assertTrue(
            all(entry["status"] == "matched" for entry in data["entry_inputs"])
        )
        self.assertEqual(
            data["slot"]["expected"]["type"],
            "void (*)(USBDevice *, USBPacket *)",
        )
        self.assertEqual(data["input_buffers"], [])
        control = self.callback_report(
            first, "qemu.usb-device.handle-control"
        )
        self.assertEqual(
            control["input_buffers"],
            [
                {
                    "expected": {
                        "buffer_index": 6,
                        "length_role": "control-length",
                        "active_when": {
                            "role": "control-request",
                            "mask": 32768,
                            "equals": 0,
                        },
                    },
                    "buffer_argument_index": 6,
                    "buffer_type": "uint8_t *",
                    "length_role": "control-length",
                    "length_argument_index": 5,
                    "selector_role": "control-request",
                    "selector_argument_index": 2,
                    "status": "matched",
                }
            ],
        )
        self.assertEqual(
            control["expected"]["input_buffers"],
            [control["input_buffers"][0]["expected"]],
        )

    def test_usb_callback_slot_name_and_type_drift_fail_closed(self):
        cases = (
            ({"data_field": "process_data"}, "stale"),
            ({"data_return_type": "int"}, "stale"),
        )
        for fixture_arguments, expected_slot_status in cases:
            with self.subTest(
                fixture_arguments=fixture_arguments
            ), tempfile.TemporaryDirectory() as directory:
                root, compile_commands = self.callback_fixture(
                    directory, **fixture_arguments
                )
                report = resolver.resolve_catalog(
                    self.callback_catalog(), self.schema, compile_commands, root
                )
            data = self.callback_report(report, "qemu.usb-device.handle-data")
            self.assertEqual(report["result"], "drift")
            self.assertEqual(data["status"], "slot-drift")
            self.assertEqual(data["slot"]["status"], expected_slot_status)

    def test_usb_callback_entry_member_name_and_type_drift_fail_closed(self):
        cases = (
            ("int token;", "stale"),
            ("unsigned pid;", "stale"),
        )
        for packet_pid, expected_step_status in cases:
            with self.subTest(packet_pid=packet_pid), tempfile.TemporaryDirectory() as directory:
                root, compile_commands = self.callback_fixture(
                    directory, packet_pid=packet_pid
                )
                report = resolver.resolve_catalog(
                    self.callback_catalog(), self.schema, compile_commands, root
                )
            data = self.callback_report(report, "qemu.usb-device.handle-data")
            direction = next(
                entry
                for entry in data["entry_inputs"]
                if entry["role"] == "packet-direction"
            )
            self.assertEqual(report["result"], "drift")
            self.assertEqual(data["status"], "member-drift")
            self.assertEqual(direction["status"], "drift")
            self.assertEqual(direction["steps"][0]["status"], expected_step_status)

    def test_usb_callback_registration_root_name_and_type_drift_fail_closed(self):
        cases = (
            ({"registration_field": "instance_init"}, "stale"),
            ({"registration_return_type": "int"}, "stale"),
        )
        for fixture_arguments, expected_root_status in cases:
            with self.subTest(
                fixture_arguments=fixture_arguments
            ), tempfile.TemporaryDirectory() as directory:
                root, compile_commands = self.callback_fixture(
                    directory, **fixture_arguments
                )
                report = resolver.resolve_catalog(
                    self.callback_catalog(), self.schema, compile_commands, root
                )
            self.assertEqual(report["result"], "drift")
            for callback in report["callback_bindings"]:
                self.assertEqual(callback["status"], "registration-drift")
                self.assertEqual(
                    callback["registration_root"]["field"]["status"],
                    expected_root_status,
                )

    def test_usb_callback_registration_variable_and_initializer_are_exact(self):
        cases = (
            (
                {"registration_variable": "renamed_info"},
                "variable_initializer",
                "missing",
            ),
            (
                {"registered_initializer": "other_class_init"},
                "variable_initializer",
                "stale",
            ),
            (
                {"registration_initializer": "renamed_class_init"},
                "class_initializer",
                "missing",
            ),
        )
        for fixture_arguments, component, expected_status in cases:
            with self.subTest(
                fixture_arguments=fixture_arguments
            ), tempfile.TemporaryDirectory() as directory:
                root, compile_commands = self.callback_fixture(
                    directory, **fixture_arguments
                )
                report = resolver.resolve_catalog(
                    self.callback_catalog(), self.schema, compile_commands, root
                )
            self.assertEqual(report["result"], "drift")
            for callback in report["callback_bindings"]:
                self.assertEqual(callback["status"], "registration-drift")
                self.assertEqual(
                    callback["registration_root"][component]["status"],
                    expected_status,
                )

    def test_usb_callback_slot_assignment_is_exact(self):
        cases = (
            ({"include_data_assignment": False}, "missing"),
            ({"data_assignment_field": "alternate_data"}, "missing"),
            ({"data_assignment_target": "other_handle_data"}, "stale"),
        )
        for fixture_arguments, expected_status in cases:
            with self.subTest(
                fixture_arguments=fixture_arguments
            ), tempfile.TemporaryDirectory() as directory:
                root, compile_commands = self.callback_fixture(
                    directory, **fixture_arguments
                )
                report = resolver.resolve_catalog(
                    self.callback_catalog(), self.schema, compile_commands, root
                )
            data = self.callback_report(report, "qemu.usb-device.handle-data")
            self.assertEqual(report["result"], "drift")
            self.assertEqual(data["status"], "registration-drift")
            self.assertEqual(
                data["registration_root"]["slot_assignment"]["status"],
                expected_status,
            )

    def test_usb_callback_registration_compile_command_is_required(self):
        with tempfile.TemporaryDirectory() as directory:
            root, compile_commands = self.callback_fixture(
                directory, include_registration_command=False
            )
            with self.assertRaisesRegex(
                resolver.ResolverError,
                r"callback registration translation-unit anchor|hw/usb/u2f.c.*0 distinct compile commands",
            ):
                resolver.resolve_catalog(
                    self.callback_catalog(), self.schema, compile_commands, root
                )

    def test_usb_callback_declared_header_is_required(self):
        with tempfile.TemporaryDirectory() as directory:
            root, compile_commands = self.callback_fixture(directory)
            (root / "include" / "qom" / "object.h").unlink()
            with self.assertRaisesRegex(
                resolver.ResolverError, "callback registration header is missing"
            ):
                resolver.resolve_catalog(
                    self.callback_catalog(), self.schema, compile_commands, root
                )

    def test_protocol_scope_and_events_match_deterministically(self):
        with tempfile.TemporaryDirectory() as directory:
            root, compile_commands = self.fixture(
                directory,
                self.protocol_header(),
                self.protocol_source(),
            )
            first = resolver.resolve_catalog(
                self.protocol_catalog(), self.schema, compile_commands, root
            )
            second = resolver.resolve_catalog(
                self.protocol_catalog(), self.schema, compile_commands, root
            )
            serialized = json.dumps(first, sort_keys=True)
            self.assertNotIn(directory, serialized)
        self.assertEqual(first, second)
        self.assertEqual(first["result"], "pass")
        protocol = self.protocol_report(first)
        self.assertEqual(protocol["status"], "matched")
        self.assertEqual(
            [event["status"] for event in protocol["definitions"][0]["events"]],
            ["matched", "matched", "matched"],
        )
        self.assertEqual(
            [
                selector["observed_count"]
                for event in protocol["definitions"][0]["events"]
                for selector in event["selectors"]
            ],
            [1, 1, 1],
        )
        self.assertEqual(first["compile_database"]["protocol_count"], 1)
        self.assertEqual(first["compile_database"]["ast_run_count"], 2)
        self.assertEqual(first["source"]["protocol_sources"][0]["path"], "probe.c")

    def test_protocol_location_recovers_clang_compressed_offset(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "probe.c"
            source.write_bytes(b"first line\n  event();\n")
            node = {
                "range": {
                    "begin": {
                        "offset": len(b"first line\n  "),
                        "col": 3,
                        "tokLen": 5,
                    }
                }
            }
            self.assertEqual(
                resolver._source_location(
                    node, source, Path(directory), allow_inherited=True
                ),
                (2, 3, False),
            )
            self.assertIsNone(
                resolver._source_location(
                    node, source, Path(directory), allow_inherited=False
                )
            )
            without_column = copy.deepcopy(node)
            del without_column["range"]["begin"]["col"]
            self.assertEqual(
                resolver._source_location(
                    without_column,
                    source,
                    Path(directory),
                    allow_inherited=True,
                ),
                (2, 3, False),
            )
            for offset in (-1, len(source.read_bytes()) + 1):
                invalid = copy.deepcopy(node)
                invalid["range"]["begin"]["offset"] = offset
                self.assertIsNone(
                    resolver._source_location(
                        invalid, source, Path(directory), allow_inherited=True
                    )
                )
            inconsistent_column = copy.deepcopy(node)
            inconsistent_column["range"]["begin"]["col"] = 4
            self.assertIsNone(
                resolver._source_location(
                    inconsistent_column,
                    source,
                    Path(directory),
                    allow_inherited=True,
                )
            )

    def test_identical_protocol_compile_contexts_remain_matched(self):
        with tempfile.TemporaryDirectory() as directory:
            root, compile_commands = self.fixture(
                directory, self.protocol_header(), self.protocol_source()
            )
            entries = json.loads(compile_commands.read_text(encoding="utf-8"))
            duplicate = copy.deepcopy(entries[0])
            duplicate["arguments"].insert(1, "-DUNUSED_SECOND_CONTEXT=1")
            entries.append(duplicate)
            compile_commands.write_text(
                json.dumps(entries, indent=2) + "\n", encoding="utf-8"
            )
            report = resolver.resolve_catalog(
                self.protocol_catalog(), self.schema, compile_commands, root
            )
        protocol = self.protocol_report(report)
        self.assertEqual(report["result"], "pass")
        self.assertEqual(protocol["status"], "matched")
        self.assertEqual(protocol["definitions"][0]["context_count"], 2)
        self.assertEqual(protocol["definitions"][0]["context_variant_count"], 1)

    def test_protocol_compile_context_event_variants_fail_closed(self):
        body = """\
    char buffer[4];
    (void)catalog_transfer((AddressSpace *)0, 0, buffer, sizeof(buffer),
                           (MemTxAttrs){0});
    device->count--;
#ifndef OMIT_COMPLETION_EVENT
    publish(device);
#endif
"""
        with tempfile.TemporaryDirectory() as directory:
            root, compile_commands = self.fixture(
                directory, self.protocol_header(), self.protocol_source(body)
            )
            entries = json.loads(compile_commands.read_text(encoding="utf-8"))
            duplicate = copy.deepcopy(entries[0])
            duplicate["arguments"].insert(1, "-DOMIT_COMPLETION_EVENT=1")
            entries.append(duplicate)
            compile_commands.write_text(
                json.dumps(entries, indent=2) + "\n", encoding="utf-8"
            )
            report = resolver.resolve_catalog(
                self.protocol_catalog(), self.schema, compile_commands, root
            )
        protocol = self.protocol_report(report)
        definition = protocol["definitions"][0]
        self.assertEqual(report["result"], "drift")
        self.assertEqual(protocol["status"], "context-drift")
        self.assertEqual(definition["context_count"], 2)
        self.assertEqual(definition["context_variant_count"], 2)
        self.assertEqual(
            {
                variant["events"][2]["selectors"][0]["observed_count"]
                for variant in definition["context_variants"]
            },
            {0, 1},
        )

    def test_protocol_compile_context_missing_scope_fails_closed(self):
        source = self.protocol_source().replace(
            "static void do_queue", "#ifndef OMIT_SCOPE\nstatic void do_queue"
        ) + "#endif\n"
        with tempfile.TemporaryDirectory() as directory:
            root, compile_commands = self.fixture(
                directory, self.protocol_header(), source
            )
            entries = json.loads(compile_commands.read_text(encoding="utf-8"))
            duplicate = copy.deepcopy(entries[0])
            duplicate["arguments"].insert(1, "-DOMIT_SCOPE=1")
            entries.append(duplicate)
            compile_commands.write_text(
                json.dumps(entries, indent=2) + "\n", encoding="utf-8"
            )
            report = resolver.resolve_catalog(
                self.protocol_catalog(), self.schema, compile_commands, root
            )
        protocol = self.protocol_report(report)
        self.assertEqual(report["result"], "drift")
        self.assertEqual(protocol["status"], "missing-context")
        self.assertEqual(protocol["analyzed_context_count"], 2)
        self.assertEqual(protocol["definitions"][0]["context_count"], 1)
        self.assertNotEqual(
            protocol["definitions"][0]["context_ids"],
            protocol["analyzed_context_ids"],
        )

    def test_missing_protocol_scope_is_drift(self):
        with tempfile.TemporaryDirectory() as directory:
            source = self.protocol_source().replace("do_queue", "other_queue")
            root, compile_commands = self.fixture(
                directory, self.protocol_header(), source
            )
            report = resolver.resolve_catalog(
                self.protocol_catalog(), self.schema, compile_commands, root
            )
        self.assertEqual(report["result"], "drift")
        self.assertEqual(self.protocol_report(report)["status"], "missing")

    def test_extra_transfer_call_is_cardinality_drift(self):
        body = """\
    char buffer[4];
    (void)catalog_transfer((AddressSpace *)0, 0, buffer, sizeof(buffer),
                           (MemTxAttrs){0});
    (void)catalog_transfer((AddressSpace *)0, 4, buffer, sizeof(buffer),
                           (MemTxAttrs){0});
    device->count--;
    publish(device);
"""
        with tempfile.TemporaryDirectory() as directory:
            root, compile_commands = self.fixture(
                directory, self.protocol_header(), self.protocol_source(body)
            )
            report = resolver.resolve_catalog(
                self.protocol_catalog(), self.schema, compile_commands, root
            )
        protocol = self.protocol_report(report)
        transfer = protocol["definitions"][0]["events"][0]["selectors"][0]
        self.assertEqual(protocol["status"], "event-drift")
        self.assertEqual(transfer["status"], "cardinality")
        self.assertEqual(transfer["observed_count"], 2)

    def test_wrong_member_field_is_event_drift(self):
        with tempfile.TemporaryDirectory() as directory:
            source = self.protocol_source().replace(
                "device->count--;", "device->other--;"
            )
            root, compile_commands = self.fixture(
                directory, self.protocol_header(), source
            )
            report = resolver.resolve_catalog(
                self.protocol_catalog(), self.schema, compile_commands, root
            )
        member = self.protocol_report(report)["definitions"][0]["events"][1][
            "selectors"
        ][0]
        self.assertEqual(member["status"], "missing")
        self.assertEqual(member["observed_count"], 0)

    def test_wrong_completion_prototype_is_event_drift(self):
        body = self.protocol_source(
            body="""\
    char buffer[4];
    (void)catalog_transfer((AddressSpace *)0, 0, buffer, sizeof(buffer),
                           (MemTxAttrs){0});
    device->count--;
    publish(device, 0);
""",
            publish_parameters="Device *device, int ignored",
        )
        with tempfile.TemporaryDirectory() as directory:
            root, compile_commands = self.fixture(
                directory, self.protocol_header(), body
            )
            report = resolver.resolve_catalog(
                self.protocol_catalog(), self.schema, compile_commands, root
            )
        completion = self.protocol_report(report)["definitions"][0]["events"][2][
            "selectors"
        ][0]
        self.assertEqual(completion["status"], "missing")

    def test_stale_and_ambiguous_protocol_scopes_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            stale_source = self.protocol_source(
                scope_parameters="Device *device, int ignored"
            )
            root, compile_commands = self.fixture(
                directory, self.protocol_header(), stale_source
            )
            stale = resolver.resolve_catalog(
                self.protocol_catalog(), self.schema, compile_commands, root
            )
        self.assertEqual(self.protocol_report(stale)["status"], "stale")

        with tempfile.TemporaryDirectory() as directory:
            source = self.protocol_source() + """\
static void do_queue(Device *device, int ignored)
{
    (void)device;
    (void)ignored;
}
"""
            root, compile_commands = self.fixture(
                directory,
                self.protocol_header(),
                source,
                language="c++",
            )
            ambiguous = resolver.resolve_catalog(
                self.protocol_catalog(language="c++"),
                self.schema,
                compile_commands,
                root,
            )
        self.assertEqual(self.protocol_report(ambiguous)["status"], "ambiguous")

    def test_redeclaration_is_not_ambiguous(self):
        with tempfile.TemporaryDirectory() as directory:
            header = self.c_header().replace(
                "void *catalog_map(AddressSpace *as,",
                "void *catalog_map(AddressSpace *space, hwaddr guest_address,\n"
                "                  hwaddr *mapped_length, bool write,\n"
                "                  MemTxAttrs attributes);\n"
                "void *catalog_map(AddressSpace *as,",
            )
            root, compile_commands = self.fixture(directory, header)
            report = resolver.resolve_catalog(
                self.catalog(), self.schema, compile_commands, root
            )
        self.assertEqual(report["result"], "pass")
        contract = self.contract_report(report, "qemu.dma.address-space.map")
        self.assertEqual(contract["status"], "matched")
        self.assertEqual(len(contract["declarations"]), 1)
        self.assertEqual(len(contract["declarations"][0]["sites"]), 2)
        self.assertEqual(
            len(contract["declarations"][0]["parameter_name_variants"]), 2
        )

    def test_c_block_scope_declaration_is_rejected(self):
        source = """\
void wrapper(void) {
#include "include/test/api.h"
}
"""
        with tempfile.TemporaryDirectory() as directory:
            root, compile_commands = self.fixture(
                directory, self.c_header(), source=source
            )
            report = resolver.resolve_catalog(
                self.catalog(), self.schema, compile_commands, root
            )
        self.assertEqual(report["result"], "error")
        self.assertTrue(
            any(error["kind"] == "non-global-selector" for error in report["errors"])
        )

    def test_stale_prototype_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root, compile_commands = self.fixture(
                directory,
                self.c_header("unsigned int addr, unsigned int *plen"),
            )
            report = resolver.resolve_catalog(
                self.catalog(), self.schema, compile_commands, root
            )
        self.assertEqual(report["result"], "drift")
        contract = self.contract_report(report, "qemu.dma.address-space.map")
        self.assertEqual(contract["status"], "stale")
        self.assertIn("unsigned int", contract["declarations"][0]["prototype"])

    def test_missing_selector_is_rejected(self):
        catalog = self.catalog()
        catalog["contracts"][0]["selector"]["name"] = "catalog_missing_map"
        with tempfile.TemporaryDirectory() as directory:
            root, compile_commands = self.fixture(directory, self.c_header())
            report = resolver.resolve_catalog(
                catalog, self.schema, compile_commands, root
            )
        self.assertEqual(report["result"], "drift")
        contract = self.contract_report(report, "qemu.dma.address-space.map")
        self.assertEqual(contract["status"], "missing")
        self.assertEqual(contract["declarations"], [])

    def test_same_name_outside_selected_header_does_not_match(self):
        header = self.c_header(map_name="different_map")
        source = """\
#include "include/test/api.h"
void *catalog_map(AddressSpace *as, hwaddr addr, hwaddr *plen,
                  bool is_write, MemTxAttrs attrs) {
  return 0;
}
"""
        with tempfile.TemporaryDirectory() as directory:
            root, compile_commands = self.fixture(
                directory, header, source=source
            )
            report = resolver.resolve_catalog(
                self.catalog(), self.schema, compile_commands, root
            )
        contract = self.contract_report(report, "qemu.dma.address-space.map")
        self.assertEqual(contract["status"], "missing")
        self.assertEqual(contract["declarations"], [])

    def test_compile_database_file_must_be_the_actual_driver_input(self):
        with tempfile.TemporaryDirectory() as directory:
            root, compile_commands = self.fixture(directory, self.c_header())
            other = root / "other.c"
            other.write_text('#include "include/test/api.h"\n', encoding="utf-8")
            entries = json.loads(compile_commands.read_text(encoding="utf-8"))
            source = entries[0]["file"]
            entries[0]["arguments"] = [
                str(other) if argument == source else argument
                for argument in entries[0]["arguments"]
            ]
            compile_commands.write_text(
                json.dumps(entries, indent=2) + "\n", encoding="utf-8"
            )
            with self.assertRaisesRegex(
                resolver.ResolverError, "exactly one C-family input matching"
            ):
                resolver.resolve_catalog(
                    self.catalog(), self.schema, compile_commands, root
                )

    def test_option_operand_cannot_impersonate_primary_input(self):
        with tempfile.TemporaryDirectory() as directory:
            root, compile_commands = self.fixture(directory, self.c_header())
            entries = json.loads(compile_commands.read_text(encoding="utf-8"))
            source = entries[0]["file"]
            arguments = entries[0]["arguments"]
            source_index = arguments.index(source)
            arguments[source_index:source_index + 1] = [
                "-include",
                source,
                "-x",
                "c",
                "/dev/null",
            ]
            compile_commands.write_text(
                json.dumps(entries, indent=2) + "\n", encoding="utf-8"
            )
            with self.assertRaisesRegex(
                resolver.ResolverError, "Clang selected /dev/null"
            ):
                resolver.resolve_catalog(
                    self.catalog(), self.schema, compile_commands, root
                )

    def test_language_is_taken_from_actual_driver_job(self):
        source = """\
namespace hidden {
#include "include/test/api.h"
}
"""
        with tempfile.TemporaryDirectory() as directory:
            root, compile_commands = self.fixture(
                directory, self.c_header(), source=source, language="c++"
            )
            entries = json.loads(compile_commands.read_text(encoding="utf-8"))
            entries[0]["arguments"].extend(["-x", "c"])
            compile_commands.write_text(
                json.dumps(entries, indent=2) + "\n", encoding="utf-8"
            )
            report = resolver.resolve_catalog(
                self.catalog(language="c++"), self.schema, compile_commands, root
            )
        self.assertEqual(report["result"], "error")
        self.assertEqual(report["compile_database"]["commands"][0]["language"], "c++")
        self.assertTrue(
            any(error["kind"] == "non-global-selector" for error in report["errors"])
        )

    def test_explicit_clang_config_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root, compile_commands = self.fixture(directory, self.c_header())
            config = Path(directory) / "resolver.cfg"
            config.write_text("-DRESOLVER_CONFIG=1\n", encoding="utf-8")
            entries = json.loads(compile_commands.read_text(encoding="utf-8"))
            entries[0]["arguments"].insert(1, "--config={}".format(config))
            compile_commands.write_text(
                json.dumps(entries, indent=2) + "\n", encoding="utf-8"
            )
            with self.assertRaisesRegex(
                resolver.ResolverError, "unsupported Clang configuration option"
            ):
                resolver.resolve_catalog(
                    self.catalog(), self.schema, compile_commands, root
                )

    def test_compiler_environment_is_controlled_and_attested(self):
        injected = {
            "CCC_OVERRIDE_OPTIONS": "+-DRESOLVER_INJECTED=1",
            "CLANG_CONFIG_FILE_USER_DIR": "/unattested/config",
            "HOME": "/unattested/home",
            "LD_PRELOAD": "/unattested/preload.so",
        }
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(
            os.environ, injected
        ):
            root, compile_commands = self.fixture(directory, self.c_header())
            report = resolver.resolve_catalog(
                self.catalog(), self.schema, compile_commands, root
            )
        self.assertEqual(report["result"], "pass")
        self.assertEqual(report["environment"]["semantic"]["LANG"], "C")
        self.assertEqual(report["environment"]["semantic"]["LC_ALL"], "C")
        for name in injected:
            self.assertNotIn(name, report["environment"]["semantic"])

    def test_relative_compiler_path_is_resolved_from_command_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root, compile_commands = self.fixture(directory, self.c_header())
            entries = json.loads(compile_commands.read_text(encoding="utf-8"))
            build = Path(entries[0]["directory"])
            entries[0]["arguments"][0] = os.path.relpath(
                self.clang, build.resolve()
            )
            compile_commands.write_text(
                json.dumps(entries, indent=2) + "\n", encoding="utf-8"
            )
            report = resolver.resolve_catalog(
                self.catalog(), self.schema, compile_commands, root
            )
        self.assertEqual(report["result"], "pass")

    def test_dispatching_compiler_attests_actual_cc1_executable(self):
        with tempfile.TemporaryDirectory() as directory:
            root, compile_commands = self.fixture(directory, self.c_header())
            wrapper = Path(directory) / "clang-dispatch"
            wrapper.write_text(
                "#!/bin/sh\nexec {} \"$@\"\n".format(shlex.quote(self.clang)),
                encoding="utf-8",
            )
            wrapper.chmod(0o700)
            entries = json.loads(compile_commands.read_text(encoding="utf-8"))
            entries[0]["arguments"][0] = str(wrapper)
            compile_commands.write_text(
                json.dumps(entries, indent=2) + "\n", encoding="utf-8"
            )
            report = resolver.resolve_catalog(
                self.catalog(), self.schema, compile_commands, root
            )
        self.assertEqual(report["result"], "pass")
        self.assertEqual(len(report["compilers"]), 1)
        self.assertEqual(len(report["cc1_executables"]), 1)
        frontend = Path(report["cc1_executables"][0]["resolved"])
        self.assertNotEqual(frontend, wrapper.resolve())
        self.assertTrue(frontend.is_file())
        self.assertEqual(
            report["cc1_executables"][0]["sha256"],
            resolver._sha256_file(frontend),
        )
        self.assertEqual(
            report["compile_database"]["commands"][0][
                "cc1_executable_sha256"
            ],
            report["cc1_executables"][0]["sha256"],
        )
        self.assertNotEqual(
            report["compilers"][0]["sha256"],
            report["cc1_executables"][0]["sha256"],
        )

    def test_invalid_cc1_job_plans_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root, compile_commands = self.fixture(directory, self.c_header())
            entries = json.loads(compile_commands.read_text(encoding="utf-8"))
            source = entries[0]["file"]
            command = {
                "arguments": entries[0]["arguments"],
                "directory": Path(entries[0]["directory"]),
                "file": Path(source),
            }
            not_executable = Path(directory) / "not-executable"
            not_executable.write_text("not executable\n", encoding="utf-8")
            plans = (
                (
                    '"-cc1" "-x" "c" "{}"\n'.format(source),
                    "missing or ambiguous",
                ),
                (
                    '"env" "clang" "-cc1" "-x" "c" "{}"\n'.format(
                        source
                    ),
                    "missing or ambiguous",
                ),
                (
                    '"{}" "-cc1" "-x" "c" "{}"\n'.format(
                        not_executable, source
                    ),
                    "not executable",
                ),
                (
                    '"{}" "-cc1" "-ivfsoverlay" "overlay.json" '
                    '"-x" "c" "{}"\n'.format(self.clang, source),
                    "semantic auxiliary input option",
                ),
            )
            for stderr, message in plans:
                with self.subTest(stderr=stderr), mock.patch.object(
                    resolver,
                    "_run_bounded",
                    return_value=subprocess.CompletedProcess(
                        command["arguments"], 0, "", stderr
                    ),
                ):
                    with self.assertRaisesRegex(resolver.ResolverError, message):
                        resolver._attest_driver_plan(
                            command,
                            root,
                            compile_commands.parent,
                            dict(os.environ),
                            10,
                        )

    def test_semantic_auxiliary_inputs_are_rejected(self):
        cases = (
            ["-ivfsoverlay", "overlay.json"],
            ["-vfsoverlay=overlay.json"],
            ["-fplugin=plugin.so"],
            ["-Xclang", "-load", "-Xclang", "plugin.so"],
            ["-fmodule-file=module.pcm"],
            ["-include-pch", "prefix.pch"],
            ["-remap-file", "source.h;replacement.h"],
            ["-chain-include", "prefix.h"],
            ["-ast-merge", "state.ast"],
            ["-ivfsstatcache", "stat.cache"],
            ["-iapinotes-path", "api.apinotes"],
            ["-iapinotes-modules=api-notes"],
            ["-fapinotes-swift-version=5"],
            ["-fcas-fs", "cas-tree"],
            ["-fcas-path=cas-store"],
            ["-fcas-plugin-path", "cas-plugin.so"],
            ["-fprebuilt-module-path=prebuilt-modules"],
        )
        for arguments in cases:
            with self.subTest(arguments=arguments):
                with self.assertRaisesRegex(
                    resolver.ResolverError, "semantic auxiliary input option"
                ):
                    resolver._validate_driver_command_shape(
                        {"arguments": [self.clang] + arguments}
                    )

    def test_cc1_semantic_auxiliary_inputs_are_rejected(self):
        cases = (
            ["-remap-file", "source.h;replacement.h"],
            ["-chain-include", "prefix.h"],
            ["-ast-merge", "state.ast"],
            ["-ivfsstatcache", "stat.cache"],
            ["-iapinotes-path", "api.apinotes"],
            ["-fcas-fs", "cas-tree"],
            ["-fcas-path", "cas-store"],
            ["-fcas-plugin-path", "cas-plugin.so"],
            ["-fprebuilt-module-path=prebuilt-modules"],
        )
        with tempfile.TemporaryDirectory() as directory:
            root, compile_commands = self.fixture(directory, self.c_header())
            entries = json.loads(compile_commands.read_text(encoding="utf-8"))
            source = entries[0]["file"]
            command = {
                "arguments": entries[0]["arguments"],
                "directory": Path(entries[0]["directory"]),
                "file": Path(source),
            }
            for auxiliary in cases:
                plan = shlex.join(
                    [self.clang, "-cc1"]
                    + auxiliary
                    + ["-x", "c", source]
                )
                with self.subTest(auxiliary=auxiliary), mock.patch.object(
                    resolver,
                    "_run_bounded",
                    return_value=subprocess.CompletedProcess(
                        command["arguments"], 0, "", plan + "\n"
                    ),
                ):
                    with self.assertRaisesRegex(
                        resolver.ResolverError,
                        "semantic auxiliary input option",
                    ):
                        resolver._attest_driver_plan(
                            command,
                            root,
                            compile_commands.parent,
                            dict(os.environ),
                            10,
                        )

    def test_remap_and_chain_include_are_rejected_before_replay(self):
        for auxiliary in (
            ["-Xclang", "-remap-file", "-Xclang", "source.h;replacement.h"],
            ["-Xclang", "-chain-include", "-Xclang", "prefix.h"],
        ):
            with self.subTest(auxiliary=auxiliary):
                with tempfile.TemporaryDirectory() as directory:
                    root, compile_commands = self.fixture(
                        directory, self.c_header()
                    )
                    entries = json.loads(
                        compile_commands.read_text(encoding="utf-8")
                    )
                    entries[0]["arguments"][1:1] = auxiliary
                    compile_commands.write_text(
                        json.dumps(entries, indent=2) + "\n", encoding="utf-8"
                    )
                    with mock.patch.object(resolver, "_run_bounded") as replay:
                        with self.assertRaisesRegex(
                            resolver.ResolverError,
                            "semantic auxiliary input option",
                        ):
                            resolver.resolve_catalog(
                                self.catalog(),
                                self.schema,
                                compile_commands,
                                root,
                            )
                    replay.assert_not_called()

    def test_vfs_overlay_is_rejected_before_replay(self):
        with tempfile.TemporaryDirectory() as directory:
            root, compile_commands = self.fixture(directory, self.c_header())
            overlay = Path(directory) / "overlay.json"
            overlay.write_text('{"version":0,"roots":[]}', encoding="utf-8")
            entries = json.loads(compile_commands.read_text(encoding="utf-8"))
            entries[0]["arguments"][1:1] = ["-ivfsoverlay", str(overlay)]
            compile_commands.write_text(
                json.dumps(entries, indent=2) + "\n", encoding="utf-8"
            )
            with self.assertRaisesRegex(
                resolver.ResolverError, "semantic auxiliary input option"
            ):
                resolver.resolve_catalog(
                    self.catalog(), self.schema, compile_commands, root
                )

    def test_macro_spelling_location_does_not_claim_source_declaration(self):
        header = self.c_header(map_name="different_map") + """
#define DECLARE_CATALOG_MAP(name) \\
  void *name(AddressSpace *as, hwaddr addr, hwaddr *plen, \\
             bool is_write, MemTxAttrs attrs)
"""
        source = """\
#include "include/test/api.h"
DECLARE_CATALOG_MAP(catalog_map);
"""
        with tempfile.TemporaryDirectory() as directory:
            root, compile_commands = self.fixture(directory, header, source=source)
            report = resolver.resolve_catalog(
                self.catalog(), self.schema, compile_commands, root
            )
        contract = self.contract_report(report, "qemu.dma.address-space.map")
        self.assertEqual(report["result"], "drift")
        self.assertEqual(contract["status"], "missing")

    def test_cpp_namespace_wrapping_is_rejected(self):
        source = """\
namespace hidden {
#include "include/test/api.h"
}
"""
        with tempfile.TemporaryDirectory() as directory:
            root, compile_commands = self.fixture(
                directory, self.c_header(), source=source, language="c++"
            )
            report = resolver.resolve_catalog(
                self.catalog(language="c++"), self.schema, compile_commands, root
            )
        self.assertEqual(report["result"], "error")
        self.assertTrue(
            any(error["kind"] == "non-global-selector" for error in report["errors"])
        )

    def test_command_form_with_quoted_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture_root = Path(directory) / "quoted fixture"
            root, compile_commands = self.fixture(fixture_root, self.c_header())
            entries = json.loads(compile_commands.read_text(encoding="utf-8"))
            arguments = entries[0].pop("arguments")
            arguments.insert(1, '-DQUOTED_VALUE="two words"')
            entries[0]["command"] = shlex.join(arguments)
            compile_commands.write_text(
                json.dumps(entries, indent=2) + "\n", encoding="utf-8"
            )
            report = resolver.resolve_catalog(
                self.catalog(), self.schema, compile_commands, root
            )
        self.assertEqual(report["result"], "pass")
        self.assertEqual(report["compile_database"]["entry_count"], 1)

    def test_duplicate_anchor_commands_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root, compile_commands = self.fixture(directory, self.c_header())
            entries = json.loads(compile_commands.read_text(encoding="utf-8"))
            duplicate = copy.deepcopy(entries[0])
            duplicate["arguments"].insert(1, "-DSECOND_CONTEXT=1")
            entries.append(duplicate)
            compile_commands.write_text(
                json.dumps(entries, indent=2) + "\n", encoding="utf-8"
            )
            with self.assertRaisesRegex(
                resolver.ResolverError, "has 2 distinct compile commands"
            ):
                resolver.resolve_catalog(
                    self.catalog(), self.schema, compile_commands, root
                )

    def test_ast_output_limit_is_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root, compile_commands = self.fixture(directory, self.c_header())
            with mock.patch.object(resolver, "MAX_AST_OUTPUT_BYTES", 128):
                report = resolver.resolve_catalog(
                    self.catalog(), self.schema, compile_commands, root
                )
        self.assertEqual(report["result"], "error")
        self.assertEqual(report["errors"][0]["kind"], "output-limit")

    def test_compile_database_size_limit_is_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root, compile_commands = self.fixture(directory, self.c_header())
            original_sha256_file = resolver._sha256_file
            database_hashes = []

            def record_hash(path, *args, **kwargs):
                if Path(path).resolve() == compile_commands.resolve():
                    database_hashes.append(Path(path))
                return original_sha256_file(path, *args, **kwargs)

            with mock.patch.object(
                resolver, "MAX_COMPILE_DATABASE_BYTES", 1
            ), mock.patch.object(
                resolver, "_sha256_file", side_effect=record_hash
            ):
                with self.assertRaisesRegex(
                    resolver.ResolverError, "compile_commands.json exceeds"
                ):
                    resolver.resolve_catalog(
                        self.catalog(), self.schema, compile_commands, root
                    )
            self.assertEqual(database_hashes, [])

    def test_dependency_file_size_limit_is_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root, compile_commands = self.fixture(directory, self.c_header())
            with mock.patch.object(resolver, "MAX_DEPENDENCY_FILE_BYTES", 1):
                report = resolver.resolve_catalog(
                    self.catalog(), self.schema, compile_commands, root
                )
        self.assertEqual(report["result"], "error")
        self.assertTrue(
            any(error["kind"] == "dependency" for error in report["errors"])
        )

    def test_stateful_driver_is_not_reused_after_cc1_attestation(self):
        with tempfile.TemporaryDirectory() as directory:
            original_header = self.c_header()
            root, compile_commands = self.fixture(directory, original_header)
            header = root / "include" / "test" / "api.h"
            call_count = Path(directory) / "driver-call-count"
            wrapper = Path(directory) / "stateful-clang-dispatch"
            wrapper.write_text(
                """\
#!/bin/sh
count=0
if [ -f {call_count} ]; then
    count=$(sed -n '1p' {call_count})
fi
count=$((count + 1))
printf '%s\\n' "$count" > {call_count}
if [ "$count" -gt 2 ]; then
    printf '%s\\n' 'typedef int replay_used_stateful_driver;' > {header}
    exit 97
fi
exec {clang} "$@"
""".format(
                    clang=shlex.quote(self.clang),
                    call_count=shlex.quote(str(call_count)),
                    header=shlex.quote(str(header)),
                ),
                encoding="utf-8",
            )
            wrapper.chmod(0o700)
            entries = json.loads(compile_commands.read_text(encoding="utf-8"))
            entries[0]["arguments"][0] = str(wrapper)
            compile_commands.write_text(
                json.dumps(entries, indent=2) + "\n", encoding="utf-8"
            )
            report = resolver.resolve_catalog(
                self.catalog(), self.schema, compile_commands, root
            )
            self.assertEqual(call_count.read_text(encoding="utf-8"), "2\n")
            self.assertEqual(header.read_text(encoding="utf-8"), original_header)
        self.assertEqual(report["result"], "pass")
        self.assertEqual(report["errors"], [])
        self.assertIn(
            "cc1_replay_plan_sha256",
            report["compile_database"]["commands"][0],
        )

    def test_aggregate_attestation_and_hash_deadline_are_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            first = Path(directory) / "first"
            second = Path(directory) / "second"
            first.write_bytes(b"ab")
            second.write_bytes(b"cd")
            budget = resolver._AttestationBudget(
                3, time.monotonic() + 10
            )
            resolver._file_snapshot(first, with_hash=True, budget=budget)
            with self.assertRaisesRegex(resolver.ResolverError, "aggregate limit"):
                resolver._file_snapshot(second, with_hash=True, budget=budget)
            expired = resolver._AttestationBudget(1024, time.monotonic() - 1)
            with self.assertRaisesRegex(
                resolver.ResolverError, "global deadline"
            ):
                resolver._file_snapshot(first, with_hash=True, budget=expired)

    def test_relative_path_environment_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root, compile_commands = self.fixture(directory, self.c_header())
            with mock.patch.dict(os.environ, {"PATH": "relative/bin"}):
                with self.assertRaisesRegex(
                    resolver.ResolverError, "PATH must contain only"
                ):
                    resolver.resolve_catalog(
                        self.catalog(), self.schema, compile_commands, root
                    )

    def test_overloaded_selector_is_ambiguous(self):
        header = """\
#ifndef TEST_API_H
#define TEST_API_H
using hwaddr = unsigned long;
struct AddressSpace;
struct MemTxAttrs { unsigned value; };
void *catalog_map(AddressSpace *as, hwaddr addr, hwaddr *plen,
                  bool is_write, MemTxAttrs attrs);
void *catalog_map(AddressSpace *as, unsigned int addr, unsigned int *plen,
                  bool is_write, MemTxAttrs attrs);
void catalog_unmap(AddressSpace *as, void *buffer, hwaddr len,
                   bool is_write, hwaddr access_len);
#endif
"""
        with tempfile.TemporaryDirectory() as directory:
            root, compile_commands = self.fixture(
                directory, header, language="c++"
            )
            report = resolver.resolve_catalog(
                self.catalog(language="c++"), self.schema, compile_commands, root
            )
        self.assertEqual(report["result"], "drift")
        contract = self.contract_report(report, "qemu.dma.address-space.map")
        self.assertEqual(contract["status"], "ambiguous")
        self.assertEqual(len(contract["declarations"]), 2)

    def test_compiler_failure_is_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root, compile_commands = self.fixture(
                directory,
                self.c_header(),
                source='#include "include/test/api.h"\nthis is not C;\n',
            )
            report = resolver.resolve_catalog(
                self.catalog(), self.schema, compile_commands, root
            )
        self.assertEqual(report["result"], "error")
        self.assertEqual(report["errors"][0]["kind"], "compiler")
        self.assertIn("error:", report["errors"][0]["message"])

    def test_cli_exit_status_and_report(self):
        with tempfile.TemporaryDirectory() as directory:
            root, compile_commands = self.fixture(directory, self.c_header())
            catalog_path = Path(directory) / "catalog.json"
            report_path = Path(directory) / "report.json"
            catalog_path.write_text(
                json.dumps(self.catalog(), indent=2) + "\n", encoding="utf-8"
            )
            status = resolver.main(
                [
                    "--catalog",
                    str(catalog_path),
                    "--schema",
                    str(SCHEMA_PATH),
                    "--compile-commands",
                    str(compile_commands),
                    "--source-root",
                    str(root),
                    "--output",
                    str(report_path),
                ]
            )
            report = json.loads(report_path.read_text(encoding="utf-8"))
        self.assertEqual(status, 0)
        self.assertEqual(report["result"], "pass")


class QEMUContractCatalogResolverPureTest(unittest.TestCase):
    def test_registration_variable_extracts_exact_designated_binding(self):
        source = (
            b"static const TypeInfo u2f_key_info = {\n"
            b"    .class_init = u2f_key_class_init,\n"
            b"};\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            source_path = Path(directory) / "u2f.c"
            source_path.write_bytes(source)
            node = {
                "kind": "VarDecl",
                "name": "u2f_key_info",
                "type": {"qualType": "const TypeInfo"},
                "loc": {
                    "file": str(source_path),
                    "line": 1,
                    "col": 23,
                    "offset": 22,
                },
                "range": {
                    "begin": {"offset": 0, "line": 1, "col": 1},
                    "end": {
                        "offset": len(source) - 2,
                        "line": 3,
                        "col": 1,
                        "tokLen": 1,
                    },
                },
                "inner": [
                    {
                        "kind": "InitListExpr",
                        "inner": [
                            {
                                "kind": "ImplicitCastExpr",
                                "inner": [
                                    {
                                        "kind": "DeclRefExpr",
                                        "referencedDecl": {
                                            "kind": "FunctionDecl",
                                            "name": "u2f_key_class_init",
                                            "type": {
                                                "qualType": "void (ObjectClass *, const void *)"
                                            },
                                        },
                                    }
                                ],
                            }
                        ],
                    }
                ],
            }
            observed = resolver._registration_variable(
                node, source_path.resolve(), source_path.parent.resolve(), source
            )
        self.assertEqual(
            observed["designated_bindings"],
            [{"field": "class_init", "target": "u2f_key_class_init"}],
        )
        self.assertEqual(
            observed["function_references"],
            [
                {
                    "name": "u2f_key_class_init",
                    "type": "void (ObjectClass *, const void *)",
                }
            ],
        )

        renamed = source.replace(b".class_init", b".instance_init")
        self.assertEqual(
            resolver._designated_initializer_bindings(renamed),
            [{"field": "instance_init", "target": "u2f_key_class_init"}],
        )

    def test_callback_assignment_extracts_exact_slot_and_target(self):
        source = b"uc->handle_data = u2f_key_handle_data;\n"
        with tempfile.TemporaryDirectory() as directory:
            source_path = Path(directory) / "u2f.c"
            source_path.write_bytes(source)
            node = {
                "kind": "BinaryOperator",
                "opcode": "=",
                "range": {
                    "begin": {
                        "file": str(source_path),
                        "offset": 0,
                        "line": 1,
                        "col": 1,
                    },
                    "end": {
                        "offset": len(source) - 3,
                        "line": 1,
                        "col": len(source) - 2,
                        "tokLen": 1,
                    },
                },
                "inner": [
                    {
                        "kind": "MemberExpr",
                        "name": "handle_data",
                        "type": {
                            "qualType": "void (*)(USBDevice *, USBPacket *)"
                        },
                        "inner": [
                            {
                                "kind": "ImplicitCastExpr",
                                "type": {"qualType": "USBDeviceClass *"},
                                "inner": [
                                    {
                                        "kind": "DeclRefExpr",
                                        "type": {"qualType": "USBDeviceClass *"},
                                    }
                                ],
                            }
                        ],
                    },
                    {
                        "kind": "ImplicitCastExpr",
                        "inner": [
                            {
                                "kind": "DeclRefExpr",
                                "referencedDecl": {
                                    "kind": "FunctionDecl",
                                    "name": "u2f_key_handle_data",
                                    "type": {
                                        "qualType": "void (USBDevice *, USBPacket *)"
                                    },
                                },
                            }
                        ],
                    },
                ],
            }
            observed = resolver._callback_assignment(
                node, source_path.resolve(), source_path.parent.resolve(), source
            )
        self.assertEqual(observed["field"], "handle_data")
        self.assertEqual(observed["base_type"], "USBDeviceClass *")
        self.assertEqual(observed["target"], "u2f_key_handle_data")

        wrong = copy.deepcopy(node)
        wrong["inner"][0]["name"] = "alternate_data"
        wrong["inner"][1]["inner"][0]["referencedDecl"][
            "name"
        ] = "other_handle_data"
        with tempfile.TemporaryDirectory() as directory:
            source_path = Path(directory) / "u2f.c"
            source_path.write_bytes(source)
            wrong["range"]["begin"]["file"] = str(source_path)
            observed = resolver._callback_assignment(
                wrong, source_path.resolve(), source_path.parent.resolve(), source
            )
        self.assertEqual(observed["field"], "alternate_data")
        self.assertEqual(observed["target"], "other_handle_data")


if __name__ == "__main__":
    unittest.main()
