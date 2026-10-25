#!/usr/bin/env python3

import copy
import importlib.util
import re
import tempfile
import unittest
from pathlib import Path


ANALYZER_UTILS = Path(__file__).resolve().parents[1]
MODULE_PATH = ANALYZER_UTILS / "qemu_contract_catalog.py"
SPEC = importlib.util.spec_from_file_location("qemu_contract_catalog", MODULE_PATH)
catalog_tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(catalog_tool)

CLANG_ROOT = ANALYZER_UTILS.parents[1]
CHECKER_DIR = CLANG_ROOT / "lib" / "StaticAnalyzer" / "Checkers"
CATALOG_PATH = CHECKER_DIR / "QEMUContractCatalog.json"
SCHEMA_PATH = CHECKER_DIR / "QEMUContractCatalog.schema.json"
GENERATED_PATH = CHECKER_DIR / "QEMUContractCatalog.inc"


class QEMUContractCatalogTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog = catalog_tool.load_json_strict(CATALOG_PATH)
        cls.schema = catalog_tool.load_json_strict(SCHEMA_PATH)

    def mutated_catalog(self):
        return copy.deepcopy(self.catalog)

    def assert_catalog_error(self, catalog, message):
        with self.assertRaisesRegex(catalog_tool.CatalogError, message):
            catalog_tool.validate_catalog(catalog)

    def contract(self, catalog, contract_id):
        return next(entry for entry in catalog["contracts"] if entry["id"] == contract_id)

    def callback(self, catalog, callback_id):
        return next(
            entry
            for entry in catalog["callback_bindings"]
            if entry["id"] == callback_id
        )

    def protocol(self, catalog):
        return catalog["protocols"][0]

    def test_catalog_contains_exact_dma_usb_and_iommu_lifetime_slices(self):
        catalog_tool.validate_catalog(self.catalog)
        self.assertEqual(self.catalog["catalog_format"], 5)
        self.assertEqual(self.catalog["model_version"], "qemu-v3-io-contracts-v7")
        selectors = {entry["selector"]["name"] for entry in self.catalog["contracts"]}
        self.assertEqual(
            selectors,
            {
                "address_space_read",
                "address_space_rw",
                "address_space_write",
                "address_space_map",
                "address_space_unmap",
                "dma_memory_read",
                "dma_memory_rw",
                "dma_memory_write",
                "dma_memory_map",
                "dma_memory_unmap",
                "pci_dma_map",
                "pci_dma_unmap",
                "physical_memory_map",
                "physical_memory_unmap",
                "usb_packet_copy",
                "iommu_notifier_init",
                "memory_region_register_iommu_notifier",
                "memory_region_unregister_iommu_notifier",
            },
        )
        self.assertFalse(any(name.startswith("cpu_physical_") for name in selectors))
        anchors = {
            entry["selector"]["translation_unit"]
            for entry in self.catalog["contracts"]
        }
        self.assertEqual(
            anchors,
            {
                "system/memory.c",
                "system/dma-helpers.c",
                "hw/pci/pci.c",
                "hw/usb/core.c",
                "system/physmem.c",
            },
        )

        iommu_contracts = {
            contract["kind"]: contract
            for contract in self.catalog["contracts"]
            if contract["family"] == "iommu-notifier"
        }
        self.assertEqual(
            set(iommu_contracts),
            {"initialize-resource", "register-callback", "unregister-callback"},
        )
        self.assertEqual(
            iommu_contracts["register-callback"]["predicates"]["success"],
            {"operand": "result", "operator": "eq", "rhs": {"integer": 0}},
        )
        self.assertEqual(
            iommu_contracts["register-callback"]["effects"],
            [
                {
                    "kind": "register-callback",
                    "when": "success",
                    "target": "notifier",
                    "memory_region": "memory_region",
                    "epoch": "create",
                }
            ],
        )

        transfers = [
            contract
            for contract in self.catalog["contracts"]
            if contract["kind"] == "transfer"
        ]
        self.assertEqual(len(transfers), 6)
        self.assertTrue(all(contract["pair"] is None for contract in transfers))
        self.assertEqual(
            {contract["direction_encoding"] for contract in transfers},
            {
                "bool-is-write",
                "dma-direction",
                "fixed-to-device",
                "fixed-from-device",
            },
        )
        directions = {
            contract["selector"]["name"]: contract["direction_encoding"]
            for contract in transfers
        }
        self.assertEqual(directions["address_space_read"], "fixed-to-device")
        self.assertEqual(directions["address_space_write"], "fixed-from-device")
        self.assertEqual(directions["address_space_rw"], "bool-is-write")
        self.assertEqual(directions["dma_memory_read"], "fixed-to-device")
        self.assertEqual(directions["dma_memory_write"], "fixed-from-device")
        self.assertEqual(directions["dma_memory_rw"], "dma-direction")
        self.assertTrue(
            all(
                contract["prototype"]["return_type"] == "MemTxResult"
                for contract in transfers
            )
        )
        self.assertTrue(
            selectors.isdisjoint(
                {
                    "address_space_read_full",
                    "address_space_write_rom",
                    "dma_memory_read_relaxed",
                    "dma_memory_rw_relaxed",
                    "dma_memory_write_relaxed",
                    "pci_dma_read",
                    "pci_dma_rw",
                    "pci_dma_write",
                }
            )
        )

        packet_copy = self.contract(self.catalog, "qemu.usb.packet-copy")
        self.assertEqual(packet_copy["kind"], "packet-copy")
        self.assertEqual(
            packet_copy["additional_rule_ids"], ["qemu.guest-memory.bounds"]
        )
        self.assertEqual(packet_copy["direction_encoding"], "usb-token-pid")
        self.assertIsNone(packet_copy["pair"])
        self.assertEqual(
            {
                operand["role"]
                for operand in packet_copy["operands"]
                if operand["source"] == "argument_member"
            },
            {
                "direction",
                "access_offset",
                "capacity_selector",
                "primary_capacity",
                "alternate_capacity",
                "status",
                "endpoint_type",
                "setup_parameter",
            },
        )
    def test_catalog_contains_exact_usb_callback_bindings(self):
        callbacks = {
            callback["id"]: callback
            for callback in self.catalog["callback_bindings"]
        }
        self.assertEqual(
            set(callbacks),
            {
                "qemu.usb-device.handle-control",
                "qemu.usb-device.handle-data",
            },
        )

        self.assertEqual(
            {
                callback["slot"]["field"]
                for callback in callbacks.values()
            },
            {"handle_control", "handle_data"},
        )
        for callback in callbacks.values():
            self.assertEqual(callback["slot"]["record_type"], "USBDeviceClass")
            self.assertEqual(callback["slot"]["header"], "include/hw/usb/usb.h")
            self.assertEqual(callback["slot"]["translation_unit"], "hw/usb/bus.c")
            self.assertEqual(callback["registration"]["record_type"], "TypeInfo")
            self.assertEqual(callback["registration"]["field"], "class_init")
            self.assertEqual(callback["registration"]["header"], "include/qom/object.h")
            self.assertEqual(
                callback["registration"]["translation_unit"], "hw/usb/u2f.c"
            )
            self.assertEqual(callback["registration"]["variable"], "u2f_key_info")
            self.assertEqual(
                callback["registration"]["initializer"], "u2f_key_class_init"
            )
        self.assertEqual(
            callbacks["qemu.usb-device.handle-control"]["slot"]["implementation"],
            "u2f_key_handle_control",
        )
        self.assertEqual(
            callbacks["qemu.usb-device.handle-data"]["slot"]["implementation"],
            "u2f_key_handle_data",
        )
        self.assertEqual(
            callbacks["qemu.usb-device.handle-control"]["input_buffers"],
            [
                {
                    "buffer_index": 6,
                    "length_role": "control-length",
                    "active_when": {
                        "role": "control-request",
                        "mask": 0x8000,
                        "equals": 0,
                    },
                }
            ],
        )
        self.assertEqual(
            callbacks["qemu.usb-device.handle-data"]["input_buffers"], []
        )
        self.assertEqual(
            {
                entry["role"]
                for entry in callbacks[
                    "qemu.usb-device.handle-control"
                ]["entry_inputs"]
            },
            {
                "control-request",
                "control-value",
                "control-index",
                "control-length",
            },
        )
        self.assertEqual(
            {
                entry["role"]
                for entry in callbacks[
                    "qemu.usb-device.handle-data"
                ]["entry_inputs"]
            },
            {
                "packet-direction",
                "packet-capacity-selector",
                "packet-primary-capacity",
                "packet-alternate-capacity",
                "packet-setup-parameter",
                "packet-endpoint-number",
                "packet-endpoint-type",
            },
        )

    def test_iommu_lifetime_contract_semantics_are_fail_closed(self):
        wrong_success = self.mutated_catalog()
        register = self.contract(wrong_success, "qemu.iommu.notifier-register")
        register["predicates"]["success"]["rhs"]["integer"] = 1
        self.assert_catalog_error(wrong_success, "IOMMU registration semantics")

        wrong_effect = self.mutated_catalog()
        initialize = self.contract(wrong_effect, "qemu.iommu.notifier-init")
        initialize["effects"][0]["callback"] = "notifier"
        self.assert_catalog_error(
            wrong_effect, "initialize-resource effect is not canonical"
        )

        wrong_pair = self.mutated_catalog()
        unregister = self.contract(wrong_pair, "qemu.iommu.notifier-unregister")
        unregister["pair"]["contract_id"] = "qemu.dma.address-space.map"
        self.assert_catalog_error(wrong_pair, "not reciprocal pairs")

    def test_checked_in_generation_and_hash_are_current(self):
        generated = catalog_tool.generate(self.catalog, self.schema)
        self.assertEqual(GENERATED_PATH.read_text(encoding="utf-8"), generated)
        match = re.search(r'CatalogSHA256\[\] = "([0-9a-f]{64})";', generated)
        self.assertIsNotNone(match)
        self.assertEqual(match.group(1), catalog_tool._sha256(catalog_tool._normalized_catalog(self.catalog)))

    def test_catalog_contains_exact_sdhci_completion_protocol(self):
        protocol = self.protocol(self.catalog)
        self.assertEqual(protocol["id"], "qemu.protocol.sdhci.adma-completion")
        self.assertEqual(protocol["rule_id"], "qemu.failed-completion-publication")
        self.assertEqual(protocol["scope"]["name"], "sdhci_do_adma")
        self.assertEqual(protocol["scope"]["source"], "hw/sd/sdhci.c")
        self.assertEqual(
            [event["stage"] for event in protocol["events"]],
            list(catalog_tool.PROTOCOL_STAGES),
        )
        self.assertEqual(
            {
                selector["contract_id"]
                for selector in protocol["events"][0]["selectors"]
            },
            {
                "qemu.transfer.dma-memory.read",
                "qemu.transfer.dma-memory.write",
            },
        )
        self.assertEqual(protocol["events"][1]["selectors"][0]["field"], "blkcnt")
        self.assertEqual(
            protocol["events"][2]["selectors"][0]["name"],
            "sdhci_end_transfer",
        )

    def test_contract_order_does_not_change_output(self):
        reordered = self.mutated_catalog()
        reordered["contracts"].reverse()
        reordered["callback_bindings"].reverse()
        reordered["protocols"].reverse()
        self.assertEqual(
            catalog_tool.generate(self.catalog, self.schema),
            catalog_tool.generate(reordered, self.schema),
        )

    def test_set_like_record_order_does_not_change_output(self):
        reordered = self.mutated_catalog()
        for contract in reordered["contracts"]:
            contract.get("additional_rule_ids", []).reverse()
            contract["operands"].reverse()
            contract["effects"].reverse()
        for callback in reordered["callback_bindings"]:
            callback["rule_ids"].reverse()
            callback["entry_inputs"].reverse()
            callback["input_buffers"].reverse()
        for protocol in reordered["protocols"]:
            protocol["bindings"].reverse()
            for event in protocol["events"]:
                event["selectors"].reverse()
        self.assertEqual(
            catalog_tool.generate(self.catalog, self.schema),
            catalog_tool.generate(reordered, self.schema),
        )

    def test_duplicate_json_members_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "duplicate.json"
            path.write_text('{"catalog_format":1,"catalog_format":1}\n', encoding="utf-8")
            with self.assertRaisesRegex(catalog_tool.CatalogError, "duplicate JSON member"):
                catalog_tool.load_json_strict(path)

    def test_unknown_fields_are_rejected_at_each_level(self):
        mutations = []
        root = self.mutated_catalog()
        root["surprise"] = True
        mutations.append((root, "unknown field"))

        contract = self.mutated_catalog()
        contract["contracts"][0]["surprise"] = True
        mutations.append((contract, "unknown field"))

        operand = self.mutated_catalog()
        operand["contracts"][0]["operands"][0]["surprise"] = True
        mutations.append((operand, "unknown field"))

        member_step = self.mutated_catalog()
        packet_copy = self.contract(member_step, "qemu.usb.packet-copy")
        member_operand = next(
            operand
            for operand in packet_copy["operands"]
            if operand["source"] == "argument_member"
        )
        member_operand["path"][0]["surprise"] = True
        mutations.append((member_step, "unknown field"))

        predicate = self.mutated_catalog()
        predicate["contracts"][0]["predicates"]["success"]["surprise"] = True
        mutations.append((predicate, "unknown field"))

        callback = self.mutated_catalog()
        callback["callback_bindings"][0]["surprise"] = True
        mutations.append((callback, "unknown field"))

        callback_slot = self.mutated_catalog()
        callback_slot["callback_bindings"][0]["slot"]["surprise"] = True
        mutations.append((callback_slot, "unknown field"))

        callback_registration = self.mutated_catalog()
        callback_registration["callback_bindings"][0]["registration"][
            "surprise"
        ] = True
        mutations.append((callback_registration, "unknown field"))

        callback_input = self.mutated_catalog()
        callback_input["callback_bindings"][0]["entry_inputs"][0][
            "surprise"
        ] = True
        mutations.append((callback_input, "unknown field"))

        callback_buffer = self.mutated_catalog()
        self.callback(
            callback_buffer, "qemu.usb-device.handle-control"
        )["input_buffers"][0]["surprise"] = True
        mutations.append((callback_buffer, "unknown field"))

        callback_condition = self.mutated_catalog()
        self.callback(
            callback_condition, "qemu.usb-device.handle-control"
        )["input_buffers"][0]["active_when"]["surprise"] = True
        mutations.append((callback_condition, "unknown field"))

        protocol = self.mutated_catalog()
        protocol["protocols"][0]["surprise"] = True
        mutations.append((protocol, "unknown field"))

        scope = self.mutated_catalog()
        scope["protocols"][0]["scope"]["surprise"] = True
        mutations.append((scope, "unknown field"))

        binding = self.mutated_catalog()
        binding["protocols"][0]["bindings"][0]["surprise"] = True
        mutations.append((binding, "unknown field"))

        event = self.mutated_catalog()
        event["protocols"][0]["events"][0]["surprise"] = True
        mutations.append((event, "unknown field"))

        selector = self.mutated_catalog()
        selector["protocols"][0]["events"][0]["selectors"][0]["surprise"] = True
        mutations.append((selector, "unknown field"))

        for catalog, message in mutations:
            with self.subTest(catalog=catalog["contracts"][0].get("id", "root")):
                self.assert_catalog_error(catalog, message)

    def test_translation_unit_anchor_must_be_normalized(self):
        catalog = self.mutated_catalog()
        catalog["contracts"][0]["selector"]["translation_unit"] = "../memory.c"
        self.assert_catalog_error(catalog, "normalized relative path")

        catalog = self.mutated_catalog()
        catalog["protocols"][0]["scope"]["source"] = "../sdhci.c"
        self.assert_catalog_error(catalog, "normalized relative path")

        catalog = self.mutated_catalog()
        catalog["callback_bindings"][0]["slot"]["translation_unit"] = "../bus.c"
        self.assert_catalog_error(catalog, "normalized relative path")

        catalog = self.mutated_catalog()
        catalog["callback_bindings"][0]["registration"][
            "translation_unit"
        ] = "../u2f.c"
        self.assert_catalog_error(catalog, "normalized relative path")

    def test_duplicate_contract_ids_and_selectors_are_rejected(self):
        duplicate_id = self.mutated_catalog()
        duplicate_id["contracts"][1]["id"] = duplicate_id["contracts"][0]["id"]
        self.assert_catalog_error(duplicate_id, "duplicate contract id")

        duplicate_selector = self.mutated_catalog()
        duplicate_selector["contracts"][1]["selector"] = copy.deepcopy(
            duplicate_selector["contracts"][0]["selector"]
        )
        self.assert_catalog_error(duplicate_selector, "duplicate function selector")

        duplicate_global_id = self.mutated_catalog()
        duplicate_global_id["protocols"][0]["id"] = duplicate_global_id["contracts"][0]["id"]
        self.assert_catalog_error(duplicate_global_id, "duplicate catalog id")

    def test_callback_ids_slots_and_rule_ids_are_unique(self):
        empty = self.mutated_catalog()
        empty["callback_bindings"] = []
        self.assert_catalog_error(empty, "exact USB callback set")

        missing_one = self.mutated_catalog()
        missing_one["callback_bindings"].pop()
        self.assert_catalog_error(missing_one, "exact USB callback set")

        catalog_tool.validate_catalog(empty, profile="test-subset")
        with self.assertRaisesRegex(catalog_tool.CatalogError, "unknown.*profile"):
            catalog_tool.validate_catalog(empty, profile="typo")

        duplicate_id = self.mutated_catalog()
        duplicate_id["callback_bindings"][1]["id"] = duplicate_id[
            "callback_bindings"
        ][0]["id"]
        self.assert_catalog_error(duplicate_id, "duplicate catalog id")

        duplicate_slot = self.mutated_catalog()
        duplicate_slot["callback_bindings"][1]["slot"]["field"] = "handle_control"
        self.assert_catalog_error(duplicate_slot, "duplicate callback slot")

        duplicate_rule = self.mutated_catalog()
        duplicate_rule["callback_bindings"][0]["rule_ids"].append(
            duplicate_rule["callback_bindings"][0]["rule_ids"][0]
        )
        self.assert_catalog_error(duplicate_rule, "duplicate rule id")

    def test_callback_prototypes_roots_and_entry_inputs_are_exact(self):
        bad_prototype = self.mutated_catalog()
        control = self.callback(bad_prototype, "qemu.usb-device.handle-control")
        control["prototype"]["parameters"][6]["type"] = "void *"
        self.assert_catalog_error(
            bad_prototype, "buffer_index must select a uint8_t \\* parameter"
        )

        bad_slot_header = self.mutated_catalog()
        control = self.callback(bad_slot_header, "qemu.usb-device.handle-control")
        control["slot"]["header"] = "include/hw/usb/other.h"
        self.assert_catalog_error(bad_slot_header, "invalid USBDeviceClass callback slot")

        bad_registration = self.mutated_catalog()
        control = self.callback(bad_registration, "qemu.usb-device.handle-control")
        control["registration"]["field"] = "instance_init"
        self.assert_catalog_error(bad_registration, "invalid TypeInfo.class_init root")

        bad_registration_prototype = self.mutated_catalog()
        control = self.callback(
            bad_registration_prototype, "qemu.usb-device.handle-control"
        )
        control["registration"]["prototype"]["parameters"][1][
            "type"
        ] = "void *"
        self.assert_catalog_error(
            bad_registration_prototype, "invalid TypeInfo.class_init root"
        )

        bad_registration_variable = self.mutated_catalog()
        control = self.callback(
            bad_registration_variable, "qemu.usb-device.handle-control"
        )
        control["registration"]["variable"] = "other_info"
        self.assert_catalog_error(
            bad_registration_variable, "invalid TypeInfo.class_init root"
        )

        bad_registration_initializer = self.mutated_catalog()
        control = self.callback(
            bad_registration_initializer, "qemu.usb-device.handle-control"
        )
        control["registration"]["initializer"] = "other_class_init"
        self.assert_catalog_error(
            bad_registration_initializer, "invalid TypeInfo.class_init root"
        )

        bad_implementation = self.mutated_catalog()
        control = self.callback(bad_implementation, "qemu.usb-device.handle-control")
        control["slot"]["implementation"] = "other_handle_control"
        self.assert_catalog_error(bad_implementation, "callback implementation")

        bad_index = self.mutated_catalog()
        control = self.callback(bad_index, "qemu.usb-device.handle-control")
        control["entry_inputs"][0]["index"] = 99
        self.assert_catalog_error(bad_index, "outside the prototype")

        bad_role_index = self.mutated_catalog()
        control = self.callback(bad_role_index, "qemu.usb-device.handle-control")
        control["entry_inputs"][0]["index"] = 3
        self.assert_catalog_error(bad_role_index, "invalid control-request entry input")

        missing_path = self.mutated_catalog()
        data = self.callback(missing_path, "qemu.usb-device.handle-data")
        data["entry_inputs"][0].pop("path")
        self.assert_catalog_error(missing_path, "argument_member input requires path")

        wrong_path_root = self.mutated_catalog()
        data = self.callback(wrong_path_root, "qemu.usb-device.handle-data")
        data["entry_inputs"][0]["path"][0]["record_type"] = "OtherPacket"
        self.assert_catalog_error(wrong_path_root, "does not follow 'USBPacket'")

        bad_rule_set = self.mutated_catalog()
        control = self.callback(bad_rule_set, "qemu.usb-device.handle-control")
        control["rule_ids"][0] = "qemu.other.rule"
        self.assert_catalog_error(
            bad_rule_set,
            "input_buffers and qemu.callback-buffer.bounds must be present together",
        )

        same_typed_callback_swaps = (
            ("packet-direction", "status"),
            ("packet-setup-parameter", "id"),
            ("packet-endpoint-number", "type"),
        )
        for role, replacement in same_typed_callback_swaps:
            with self.subTest(role=role, replacement=replacement):
                swapped = self.mutated_catalog()
                data = self.callback(swapped, "qemu.usb-device.handle-data")
                entry = next(
                    item for item in data["entry_inputs"] if item["role"] == role
                )
                entry["path"][-1]["field"] = replacement
                self.assert_catalog_error(swapped, "invalid .* member path")

    def test_callback_input_buffer_relations_are_strict(self):
        missing = self.mutated_catalog()
        self.callback(missing, "qemu.usb-device.handle-control").pop(
            "input_buffers"
        )
        self.assert_catalog_error(missing, "missing field.*input_buffers")

        not_array = self.mutated_catalog()
        self.callback(
            not_array, "qemu.usb-device.handle-control"
        )["input_buffers"] = {}
        self.assert_catalog_error(not_array, "input_buffers must be an array")

        missing_rule = self.mutated_catalog()
        control = self.callback(
            missing_rule, "qemu.usb-device.handle-control"
        )
        control["rule_ids"].remove("qemu.callback-buffer.bounds")
        self.assert_catalog_error(
            missing_rule,
            "input_buffers and qemu.callback-buffer.bounds must be present together",
        )

        rule_without_buffer = self.mutated_catalog()
        data = self.callback(rule_without_buffer, "qemu.usb-device.handle-data")
        data["rule_ids"][1] = "qemu.callback-buffer.bounds"
        self.assert_catalog_error(
            rule_without_buffer,
            "input_buffers and qemu.callback-buffer.bounds must be present together",
        )

        out_of_range = self.mutated_catalog()
        self.callback(
            out_of_range, "qemu.usb-device.handle-control"
        )["input_buffers"][0]["buffer_index"] = 7
        self.assert_catalog_error(out_of_range, "buffer_index is outside the prototype")

        wrong_buffer_type = self.mutated_catalog()
        self.callback(
            wrong_buffer_type, "qemu.usb-device.handle-control"
        )["input_buffers"][0]["buffer_index"] = 1
        self.assert_catalog_error(
            wrong_buffer_type, "buffer_index must select a uint8_t \\* parameter"
        )

        missing_length_role = self.mutated_catalog()
        self.callback(
            missing_length_role, "qemu.usb-device.handle-control"
        )["input_buffers"][0]["length_role"] = "no-such-role"
        self.assert_catalog_error(
            missing_length_role, "length_role must name a direct argument entry input"
        )

        missing_selector_role = self.mutated_catalog()
        self.callback(
            missing_selector_role, "qemu.usb-device.handle-control"
        )["input_buffers"][0]["active_when"]["role"] = "no-such-role"
        self.assert_catalog_error(
            missing_selector_role,
            "active_when.role must name a direct argument entry input",
        )

        overlapping_roles = self.mutated_catalog()
        self.callback(
            overlapping_roles, "qemu.usb-device.handle-control"
        )["input_buffers"][0]["active_when"]["role"] = "control-length"
        self.assert_catalog_error(
            overlapping_roles, "buffer, length, and selector parameters must be distinct"
        )

        duplicate_buffer = self.mutated_catalog()
        control = self.callback(
            duplicate_buffer, "qemu.usb-device.handle-control"
        )
        control["input_buffers"].append(copy.deepcopy(control["input_buffers"][0]))
        self.assert_catalog_error(duplicate_buffer, "duplicate input-buffer parameter")

        for field, value, message in (
            ("mask", 0, "mask must be a nonzero uint64 value"),
            ("mask", True, "mask must be a nonzero uint64 value"),
            ("mask", 1 << 64, "mask must be a nonzero uint64 value"),
            ("equals", -1, "equals must be a uint64 value"),
            ("equals", True, "equals must be a uint64 value"),
            ("equals", 1 << 64, "equals must be a uint64 value"),
            ("equals", 1, "equals sets bits outside mask"),
        ):
            with self.subTest(field=field, value=value):
                malformed = self.mutated_catalog()
                condition = self.callback(
                    malformed, "qemu.usb-device.handle-control"
                )["input_buffers"][0]["active_when"]
                condition[field] = value
                self.assert_catalog_error(malformed, message)

        wrong_exact_relation = self.mutated_catalog()
        self.callback(
            wrong_exact_relation, "qemu.usb-device.handle-control"
        )["input_buffers"][0]["active_when"]["mask"] = 0x4000
        self.assert_catalog_error(
            wrong_exact_relation, "invalid conditional input-buffer relation"
        )

        unexpected_data_buffer = self.mutated_catalog()
        data = self.callback(
            unexpected_data_buffer, "qemu.usb-device.handle-data"
        )
        data["input_buffers"] = copy.deepcopy(
            self.callback(
                unexpected_data_buffer, "qemu.usb-device.handle-control"
            )["input_buffers"]
        )
        self.assert_catalog_error(unexpected_data_buffer, "outside the prototype")

    def test_protocol_bindings_are_exact(self):
        wrong_source = self.mutated_catalog()
        self.protocol(wrong_source)["bindings"][0]["source"] = "transfer-result"
        self.protocol(wrong_source)["bindings"][0].pop("index")
        self.assert_catalog_error(wrong_source, "role 'owner' must use source")

        duplicate_role = self.mutated_catalog()
        self.protocol(duplicate_role)["bindings"][1]["role"] = "owner"
        self.protocol(duplicate_role)["bindings"][1]["source"] = "scope-argument"
        self.protocol(duplicate_role)["bindings"][1].pop("value")
        self.protocol(duplicate_role)["bindings"][1]["index"] = 0
        self.assert_catalog_error(duplicate_role, "duplicate binding role")

        out_of_range = self.mutated_catalog()
        owner = next(
            binding
            for binding in self.protocol(out_of_range)["bindings"]
            if binding["role"] == "owner"
        )
        owner["index"] = 1
        self.assert_catalog_error(out_of_range, "outside the scope prototype")

        stale_member_shape = self.mutated_catalog()
        slot = next(
            binding
            for binding in self.protocol(stale_member_shape)["bindings"]
            if binding["role"] == "slot"
        )
        slot["value"] = 0
        self.assert_catalog_error(stale_member_shape, "requires exactly record_type and field")

        wrong_attempt = self.mutated_catalog()
        attempt = next(
            binding
            for binding in self.protocol(wrong_attempt)["bindings"]
            if binding["role"] == "attempt"
        )
        attempt["source"] = "integer-constant"
        attempt["value"] = 0
        self.assert_catalog_error(wrong_attempt, "role 'attempt' must use source")

        wrong_result = self.mutated_catalog()
        result = next(
            binding
            for binding in self.protocol(wrong_result)["bindings"]
            if binding["role"] == "result"
        )
        result["source"] = "scope-argument"
        result["index"] = 0
        self.assert_catalog_error(wrong_result, "role 'result' must use source")

        wrong_owner_record = self.mutated_catalog()
        self.protocol(wrong_owner_record)["scope"]["prototype"]["parameters"][0][
            "type"
        ] = "OtherState *"
        self.assert_catalog_error(wrong_owner_record, "owner pointee record type")

    def test_protocol_event_order_and_selectors_are_exact(self):
        reversed_events = self.mutated_catalog()
        self.protocol(reversed_events)["events"].reverse()
        self.assert_catalog_error(reversed_events, "stage must be")

        missing_event = self.mutated_catalog()
        self.protocol(missing_event)["events"].pop()
        self.assert_catalog_error(missing_event, "ordered failed-publication stages")

        duplicate_selector = self.mutated_catalog()
        selectors = self.protocol(duplicate_selector)["events"][0]["selectors"]
        selectors.append(copy.deepcopy(selectors[0]))
        self.assert_catalog_error(duplicate_selector, "duplicate protocol selector")

        bad_count = self.mutated_catalog()
        self.protocol(bad_count)["events"][1]["selectors"][0]["expected_count"] = 0
        self.assert_catalog_error(bad_count, "integer from 1 to 64")

        mismatched_ring = self.mutated_catalog()
        self.protocol(mismatched_ring)["events"][1]["selectors"][0][
            "field"
        ] = "other_count"
        self.assert_catalog_error(mismatched_ring, "must match slot binding")

    def test_protocol_integer_constants_fit_signed_long_long(self):
        below = self.mutated_catalog()
        queue = next(
            binding
            for binding in self.protocol(below)["bindings"]
            if binding["role"] == "queue"
        )
        queue["value"] = catalog_tool.SIGNED_LONG_LONG_MIN - 1
        self.assert_catalog_error(below, "outside signed long long range")

        above = self.mutated_catalog()
        queue = next(
            binding
            for binding in self.protocol(above)["bindings"]
            if binding["role"] == "queue"
        )
        queue["value"] = catalog_tool.SIGNED_LONG_LONG_MAX + 1
        self.assert_catalog_error(above, "outside signed long long range")

        minimum = self.mutated_catalog()
        queue = next(
            binding
            for binding in self.protocol(minimum)["bindings"]
            if binding["role"] == "queue"
        )
        queue["value"] = catalog_tool.SIGNED_LONG_LONG_MIN
        generated = catalog_tool.generate(minimum, self.schema)
        self.assertIn("(-9223372036854775807LL - 1LL)", generated)

    def test_empty_protocol_catalog_generates_standard_cpp_sentinels(self):
        catalog = self.mutated_catalog()
        catalog["protocols"] = []
        generated = catalog_tool.generate(catalog, self.schema)
        for table, count in (
            ("ProtocolBindings", "ProtocolBindingRecordCount"),
            ("ProtocolSelectors", "ProtocolSelectorRecordCount"),
            ("ProtocolEvents", "ProtocolEventRecordCount"),
            ("Protocols", "ProtocolRecordCount"),
        ):
            self.assertRegex(
                generated,
                r"{}\[\] = \{{\n  \{{\}},\n\}};".format(table),
            )
            self.assertIn(
                "inline constexpr unsigned {} = 0;".format(count), generated
            )

    def test_generated_protocol_ranges_are_contiguous(self):
        generated = catalog_tool.generate(self.catalog, self.schema)
        self.assertIn("ProtocolBindingRecordCount = 6;", generated)
        self.assertIn("ProtocolSelectorRecordCount = 4;", generated)
        self.assertIn("ProtocolEventRecordCount = 3;", generated)
        self.assertIn("ProtocolRecordCount = 1;", generated)
        self.assertIn('"descriptor-failed", 0, 2', generated)
        self.assertIn('"ring-advanced", 2, 1', generated)
        self.assertIn('"interrupt-published", 3, 1', generated)
        self.assertIn('"void (SDHCIState *)", 0, 6, 0, 3', generated)

    def test_protocol_selector_kinds_fail_closed(self):
        missing_contract = self.mutated_catalog()
        transfer = self.protocol(missing_contract)["events"][0]["selectors"][0]
        transfer["contract_id"] = "qemu.transfer.missing"
        self.assert_catalog_error(missing_contract, "missing or non-transfer contract")

        wrong_transfer_phase = self.mutated_catalog()
        transfer = self.protocol(wrong_transfer_phase)["events"][0]["selectors"][0]
        transfer["phase"] = "pre-call"
        self.assert_catalog_error(wrong_transfer_phase, "post-call failure")

        wrong_member_operation = self.mutated_catalog()
        member = self.protocol(wrong_member_operation)["events"][1]["selectors"][0]
        member["operation"] = "assign"
        self.assert_catalog_error(wrong_member_operation, "operation has invalid value")

        extra_function_field = self.mutated_catalog()
        function = self.protocol(extra_function_field)["events"][2]["selectors"][0]
        function["field"] = "blkcnt"
        self.assert_catalog_error(extra_function_field, "function-call fields are not canonical")

    def test_duplicate_parameters_and_operands_are_rejected(self):
        duplicate_parameter = self.mutated_catalog()
        parameters = duplicate_parameter["contracts"][0]["prototype"]["parameters"]
        parameters[1]["name"] = parameters[0]["name"]
        self.assert_catalog_error(duplicate_parameter, "duplicate parameter name")

        duplicate_operand = self.mutated_catalog()
        operands = duplicate_operand["contracts"][0]["operands"]
        operands[1]["role"] = operands[0]["role"]
        self.assert_catalog_error(duplicate_operand, "duplicate operand role")

    def test_operand_range_and_signature_drift_are_rejected(self):
        out_of_range = self.mutated_catalog()
        out_of_range["contracts"][0]["operands"][0]["index"] = 99
        self.assert_catalog_error(out_of_range, "outside the prototype")

        unmodeled_parameter = self.mutated_catalog()
        del unmodeled_parameter["contracts"][0]["operands"][5]
        self.assert_catalog_error(unmodeled_parameter, "prototype parameter.*unmodeled")

        wrong_return = self.mutated_catalog()
        wrong_return["contracts"][0]["prototype"]["return_type"] = "int"
        self.assert_catalog_error(wrong_return, "map prototype must return void")

        non_pointer_pointee = self.mutated_catalog()
        non_pointer_pointee["contracts"][0]["prototype"]["parameters"][2]["type"] = "hwaddr"
        self.assert_catalog_error(non_pointer_pointee, "requires a pointer parameter")

    def test_direction_encoding_must_match_prototype(self):
        catalog = self.mutated_catalog()
        catalog["contracts"][0]["direction_encoding"] = "dma-direction"
        self.assert_catalog_error(catalog, "direction encoding does not match type")

    def test_map_operands_must_have_usable_source_phases(self):
        catalog = self.mutated_catalog()
        contract = self.contract(catalog, "qemu.dma.address-space.map")
        direction = next(
            operand for operand in contract["operands"] if operand["role"] == "direction"
        )
        direction["phase"] = "post"
        self.assert_catalog_error(catalog, "direction must be a pre-call argument")

        catalog = self.mutated_catalog()
        contract = self.contract(catalog, "qemu.dma.address-space.map")
        owner = next(
            operand for operand in contract["operands"] if operand["role"] == "owner"
        )
        owner["phase"] = "post"
        self.assert_catalog_error(catalog, "owner must be a pre-call argument")

    def test_pair_must_exist_and_be_reciprocal(self):
        missing = self.mutated_catalog()
        missing["contracts"][0]["pair"]["contract_id"] = "qemu.dma.missing.unmap"
        self.assert_catalog_error(missing, "pairs with missing contract")

        asymmetric = self.mutated_catalog()
        asymmetric["contracts"][1]["pair"]["contract_id"] = "qemu.dma.dma-memory.map"
        self.assert_catalog_error(asymmetric, "not reciprocal pairs")

        transfer_pair = self.mutated_catalog()
        transfer_pair["contracts"][0]["pair"][
            "contract_id"
        ] = "qemu.transfer.address-space.read"
        self.assert_catalog_error(transfer_pair, "unpaired contract")

    def test_pair_signature_asymmetry_is_rejected(self):
        catalog = self.mutated_catalog()
        unmap = self.contract(catalog, "qemu.dma.address-space.unmap")
        unmap["prototype"]["parameters"][2]["type"] = "dma_addr_t"
        unmap["prototype"]["parameters"][4]["type"] = "dma_addr_t"
        self.assert_catalog_error(catalog, "disagree on mapped_length type")

    def test_effect_shape_and_pairing_are_rejected(self):
        duplicate_effect = self.mutated_catalog()
        duplicate_effect["contracts"][0]["effects"].append(
            copy.deepcopy(duplicate_effect["contracts"][0]["effects"][0])
        )
        self.assert_catalog_error(duplicate_effect, "duplicate effect kind")

        missing_invalidation = self.mutated_catalog()
        missing_invalidation["contracts"][1]["effects"] = [
            missing_invalidation["contracts"][1]["effects"][0]
        ]
        self.assert_catalog_error(missing_invalidation, "unmap and invalidate effects")

        extra_map_field = self.mutated_catalog()
        extra_map_field["contracts"][0]["effects"][0][
            "access_extent"
        ] = "mapped_length"
        self.assert_catalog_error(extra_map_field, "map effect is not canonical")

        extra_unmap_field = self.mutated_catalog()
        unmap = self.contract(extra_unmap_field, "qemu.dma.address-space.unmap")
        unmap_effect = next(
            effect for effect in unmap["effects"] if effect["kind"] == "unmap"
        )
        unmap_effect["requested_extent"] = "mapped_length"
        self.assert_catalog_error(extra_unmap_field, "unmap effect is not canonical")

    def test_transfer_result_semantics_are_exact(self):
        wrong_return = self.mutated_catalog()
        transfer = self.contract(wrong_return, "qemu.transfer.address-space.read")
        transfer["prototype"]["return_type"] = "int"
        self.assert_catalog_error(wrong_return, "must return MemTxResult")

        inverted_success = self.mutated_catalog()
        transfer = self.contract(inverted_success, "qemu.transfer.address-space.read")
        transfer["predicates"]["success"]["operator"] = "ne"
        self.assert_catalog_error(inverted_success, "MemTxResult semantics")

        partial_success = self.mutated_catalog()
        transfer = self.contract(partial_success, "qemu.transfer.address-space.read")
        transfer["predicates"]["partial_success"] = {
            "operand": "result",
            "operator": "eq",
            "rhs": {"integer": 0},
        }
        self.assert_catalog_error(partial_success, "MemTxResult semantics")

    def test_transfer_direction_and_effect_are_exact(self):
        dynamic_without_operand = self.mutated_catalog()
        transfer = self.contract(
            dynamic_without_operand, "qemu.transfer.address-space.read"
        )
        transfer["direction_encoding"] = "bool-is-write"
        self.assert_catalog_error(dynamic_without_operand, "direction operand")

        wrong_constness = self.mutated_catalog()
        transfer = self.contract(
            wrong_constness, "qemu.transfer.address-space.write"
        )
        transfer["prototype"]["parameters"][3]["type"] = "void *"
        self.assert_catalog_error(wrong_constness, "buffer type")

        failure_effect = self.mutated_catalog()
        transfer = self.contract(failure_effect, "qemu.transfer.dma-memory.read")
        transfer["effects"][0]["when"] = "failure"
        self.assert_catalog_error(failure_effect, "transfer effect is not canonical")

        paired_transfer = self.mutated_catalog()
        transfer = self.contract(paired_transfer, "qemu.transfer.dma-memory.read")
        transfer["pair"] = {
            "contract_id": "qemu.transfer.dma-memory.write",
            "relation": "map-to-unmap",
        }
        self.assert_catalog_error(paired_transfer, "pair must be null")

    def test_packet_copy_member_paths_and_semantics_are_exact(self):
        packet_copy = self.contract(self.catalog, "qemu.usb.packet-copy")
        operands = {operand["role"]: operand for operand in packet_copy["operands"]}
        self.assertEqual(
            operands["primary_capacity"]["path"],
            [
                {
                    "record_type": "USBPacket",
                    "field": "iov",
                    "type": "QEMUIOVector",
                    "header": "include/hw/usb/usb.h",
                },
                {
                    "record_type": "QEMUIOVector",
                    "field": "size",
                    "type": "size_t",
                    "header": "include/qemu/iov.h",
                },
            ],
        )
        self.assertEqual(
            [step["field"] for step in operands["alternate_capacity"]["path"]],
            ["combined", "iov", "size"],
        )
        self.assertEqual(
            [step["field"] for step in operands["endpoint_type"]["path"]],
            ["ep", "type"],
        )
        self.assertEqual(
            operands["status"]["path"][0]["field"],
            "status",
        )
        self.assertEqual(
            operands["setup_parameter"]["path"][0]["field"],
            "parameter",
        )

        missing_path = self.mutated_catalog()
        packet_copy = self.contract(missing_path, "qemu.usb.packet-copy")
        next(
            operand
            for operand in packet_copy["operands"]
            if operand["role"] == "direction"
        ).pop("path")
        self.assert_catalog_error(missing_path, "requires path")

        path_on_argument = self.mutated_catalog()
        packet_copy = self.contract(path_on_argument, "qemu.usb.packet-copy")
        owner = next(
            operand
            for operand in packet_copy["operands"]
            if operand["role"] == "owner"
        )
        owner["path"] = [copy.deepcopy(operands["direction"]["path"][0])]
        self.assert_catalog_error(path_on_argument, "only for argument_member")

        wrong_root = self.mutated_catalog()
        packet_copy = self.contract(wrong_root, "qemu.usb.packet-copy")
        direction = next(
            operand
            for operand in packet_copy["operands"]
            if operand["role"] == "direction"
        )
        direction["path"][0]["record_type"] = "OtherPacket"
        self.assert_catalog_error(wrong_root, "does not follow 'USBPacket'")

        broken_chain = self.mutated_catalog()
        packet_copy = self.contract(broken_chain, "qemu.usb.packet-copy")
        primary = next(
            operand
            for operand in packet_copy["operands"]
            if operand["role"] == "primary_capacity"
        )
        primary["path"][0]["type"] = "OtherVector"
        self.assert_catalog_error(broken_chain, "does not follow 'OtherVector'")

        wrong_field_type = self.mutated_catalog()
        packet_copy = self.contract(wrong_field_type, "qemu.usb.packet-copy")
        direction = next(
            operand
            for operand in packet_copy["operands"]
            if operand["role"] == "direction"
        )
        direction["path"][0]["type"] = "size_t"
        self.assert_catalog_error(wrong_field_type, "direction encoding does not match")

        stale_header = self.mutated_catalog()
        packet_copy = self.contract(stale_header, "qemu.usb.packet-copy")
        direction = next(
            operand
            for operand in packet_copy["operands"]
            if operand["role"] == "direction"
        )
        direction["path"][0]["header"] = "../usb.h"
        self.assert_catalog_error(stale_header, "invalid value")

        same_typed_packet_swaps = (
            ("direction", "status"),
            ("access_offset", "pid"),
            ("setup_parameter", "id"),
            ("endpoint_type", "nr"),
        )
        for role, replacement in same_typed_packet_swaps:
            with self.subTest(role=role, replacement=replacement):
                swapped = self.mutated_catalog()
                packet_copy = self.contract(swapped, "qemu.usb.packet-copy")
                operand = next(
                    item for item in packet_copy["operands"] if item["role"] == role
                )
                operand["path"][-1]["field"] = replacement
                self.assert_catalog_error(swapped, "member path is not canonical")

        wrong_predicate = self.mutated_catalog()
        packet_copy = self.contract(wrong_predicate, "qemu.usb.packet-copy")
        packet_copy["predicates"]["success"] = {"constant": False}
        self.assert_catalog_error(wrong_predicate, "packet-copy semantics")

        wrong_effect = self.mutated_catalog()
        packet_copy = self.contract(wrong_effect, "qemu.usb.packet-copy")
        packet_copy["effects"][0]["offset"] = "transfer_length"
        self.assert_catalog_error(wrong_effect, "packet-copy effect is not canonical")

        paired_packet_copy = self.mutated_catalog()
        packet_copy = self.contract(paired_packet_copy, "qemu.usb.packet-copy")
        packet_copy["pair"] = {
            "contract_id": "qemu.transfer.dma-memory.write",
            "relation": "map-to-unmap",
        }
        self.assert_catalog_error(paired_packet_copy, "pair must be null")

    def test_packet_copy_additional_rule_binding_is_exact(self):
        missing = self.mutated_catalog()
        self.contract(missing, "qemu.usb.packet-copy").pop("additional_rule_ids")
        self.assert_catalog_error(missing, "additional_rule_ids must be")

        duplicate_primary = self.mutated_catalog()
        packet_copy = self.contract(duplicate_primary, "qemu.usb.packet-copy")
        packet_copy["additional_rule_ids"] = [packet_copy["rule_id"]]
        self.assert_catalog_error(duplicate_primary, "duplicate diagnostic rule")

        unrelated = self.mutated_catalog()
        self.contract(unrelated, "qemu.dma.address-space.map")[
            "additional_rule_ids"
        ] = ["qemu.guest-memory.bounds"]
        self.assert_catalog_error(unrelated, "additional_rule_ids must be")

    def test_generated_member_path_ranges_are_contiguous(self):
        generated = catalog_tool.generate(self.catalog, self.schema)
        self.assertIn("struct MemberStepRecord", generated)
        self.assertIn("inline constexpr unsigned MemberStepRecordCount = 12;", generated)
        self.assertIn(
            '"qemu.usb.packet-copy", "primary_capacity", "USBPacket", "iov", '
            '"QEMUIOVector", "include/hw/usb/usb.h"',
            generated,
        )

    def test_generated_callback_and_additional_rule_ranges_are_contiguous(self):
        generated = catalog_tool.generate(self.catalog, self.schema)
        self.assertIn("ContractAdditionalRuleRecordCount = 1;", generated)
        self.assertIn(
            '"qemu.usb.packet-copy", "qemu.guest-memory.bounds"', generated
        )
        self.assertIn("CallbackRuleRecordCount = 4;", generated)
        self.assertIn("CallbackParameterRecordCount = 9;", generated)
        self.assertIn("CallbackMemberStepRecordCount = 12;", generated)
        self.assertIn("CallbackEntryInputRecordCount = 11;", generated)
        self.assertIn("CallbackInputBufferRecordCount = 1;", generated)
        self.assertIn("CallbackBindingRecordCount = 2;", generated)
        self.assertIn(
            '"qemu.usb-device.handle-control", 6, 5, 2, 32768ULL, 0ULL',
            generated,
        )
        self.assertIn(
            '"qemu.usb-device.handle-control", "usb", "USBDeviceClass", '
            '"handle_control", "include/hw/usb/usb.h", "hw/usb/bus.c", '
            '"u2f_key_handle_control", '
            '"void (USBDevice *, USBPacket *, int, int, int, int, uint8_t *)"',
            generated,
        )
        self.assertIn(
            '"TypeInfo", "class_init", "include/qom/object.h", "hw/usb/u2f.c", '
            '"u2f_key_info", "u2f_key_class_init"',
            generated,
        )
        self.assertIn(
            '"qemu.usb-device.handle-data", "packet-primary-capacity", '
            '"argument_member", 1',
            generated,
        )
        self.assertIn(
            '"qemu.usb.packet-copy", "alternate_capacity", "USBCombinedPacket", '
            '"iov", "QEMUIOVector", "include/hw/usb/usb.h"',
            generated,
        )
        self.assertIn(
            '"packet-copy", "success", "host_buffer", "transfer_length", "", '
            '"", "direction", "owner", "", "", "", "access_offset", '
            '"capacity_selector", "primary_capacity", "alternate_capacity"',
            generated,
        )

    def test_schema_and_generator_field_sets_stay_in_lockstep(self):
        catalog_tool.validate_schema_document(self.schema)
        schema = copy.deepcopy(self.schema)
        schema["$defs"]["contract"]["properties"]["stale_field"] = {"type": "string"}
        with self.assertRaisesRegex(catalog_tool.CatalogError, "do not match generator fields"):
            catalog_tool.validate_schema_document(schema)

        schema = copy.deepcopy(self.schema)
        schema["$defs"]["operand"]["properties"]["role"]["enum"].remove("owner")
        with self.assertRaisesRegex(catalog_tool.CatalogError, "values do not match"):
            catalog_tool.validate_schema_document(schema)

        schema = copy.deepcopy(self.schema)
        schema["$defs"]["parameter"]["properties"]["type"]["pattern"] = ".*"
        with self.assertRaisesRegex(catalog_tool.CatalogError, "type patterns"):
            catalog_tool.validate_schema_document(schema)

        schema = copy.deepcopy(self.schema)
        schema["$defs"]["operand"]["properties"]["path"]["maxItems"] = 9
        with self.assertRaisesRegex(catalog_tool.CatalogError, "member paths"):
            catalog_tool.validate_schema_document(schema)

        schema = copy.deepcopy(self.schema)
        schema["$defs"]["callback_binding"]["properties"]["stale_field"] = {
            "type": "string"
        }
        with self.assertRaisesRegex(catalog_tool.CatalogError, "do not match generator fields"):
            catalog_tool.validate_schema_document(schema)

        schema = copy.deepcopy(self.schema)
        schema["properties"]["callback_bindings"]["items"] = {
            "$ref": "#/$defs/contract"
        }
        with self.assertRaisesRegex(catalog_tool.CatalogError, "callback_bindings.*semantics"):
            catalog_tool.validate_schema_document(schema)

        schema = copy.deepcopy(self.schema)
        schema["properties"]["callback_bindings"]["minItems"] = 0
        with self.assertRaisesRegex(catalog_tool.CatalogError, "callback_bindings.*semantics"):
            catalog_tool.validate_schema_document(schema)

        schema = copy.deepcopy(self.schema)
        schema["$defs"]["contract"]["properties"]["additional_rule_ids"][
            "uniqueItems"
        ] = False
        with self.assertRaisesRegex(catalog_tool.CatalogError, "additional_rule_ids.*semantics"):
            catalog_tool.validate_schema_document(schema)

        schema = copy.deepcopy(self.schema)
        schema["$defs"]["callback_binding"]["properties"]["rule_ids"][
            "uniqueItems"
        ] = False
        with self.assertRaisesRegex(catalog_tool.CatalogError, "rule_ids.*semantics"):
            catalog_tool.validate_schema_document(schema)

        schema = copy.deepcopy(self.schema)
        schema["$defs"]["callback_binding"]["properties"]["entry_inputs"][
            "items"
        ] = {"$ref": "#/$defs/operand"}
        with self.assertRaisesRegex(catalog_tool.CatalogError, "entry_inputs.*semantics"):
            catalog_tool.validate_schema_document(schema)

        schema = copy.deepcopy(self.schema)
        schema["$defs"]["callback_binding"]["properties"]["input_buffers"][
            "maxItems"
        ] = 5
        with self.assertRaisesRegex(catalog_tool.CatalogError, "input_buffers.*semantics"):
            catalog_tool.validate_schema_document(schema)

        schema = copy.deepcopy(self.schema)
        schema["$defs"]["callback_input_buffer_condition"]["properties"][
            "mask"
        ]["minimum"] = 0
        with self.assertRaisesRegex(
            catalog_tool.CatalogError,
            "callback_input_buffer_condition property semantics",
        ):
            catalog_tool.validate_schema_document(schema)

        schema = copy.deepcopy(self.schema)
        schema["$defs"]["callback_binding"]["properties"]["entry_inputs"][
            "maxItems"
        ] = 8
        with self.assertRaisesRegex(catalog_tool.CatalogError, "entry_inputs.*semantics"):
            catalog_tool.validate_schema_document(schema)

        schema = copy.deepcopy(self.schema)
        schema["$defs"]["callback_entry_input"]["properties"]["path"][
            "maxItems"
        ] = 9
        with self.assertRaisesRegex(
            catalog_tool.CatalogError, "callback_entry_input.path.*semantics"
        ):
            catalog_tool.validate_schema_document(schema)

        schema = copy.deepcopy(self.schema)
        schema["$defs"]["callback_entry_input"]["properties"]["source"][
            "enum"
        ].remove("argument_member")
        with self.assertRaisesRegex(catalog_tool.CatalogError, "values do not match"):
            catalog_tool.validate_schema_document(schema)

        schema = copy.deepcopy(self.schema)
        schema["$defs"]["callback_slot"]["properties"]["header"]["pattern"] = ".*"
        with self.assertRaisesRegex(catalog_tool.CatalogError, "callback_slot.*semantics"):
            catalog_tool.validate_schema_document(schema)

        schema = copy.deepcopy(self.schema)
        schema["$defs"]["callback_binding"]["properties"]["slot"] = {
            "$ref": "#/$defs/member_step"
        }
        with self.assertRaisesRegex(catalog_tool.CatalogError, "callback_binding.slot"):
            catalog_tool.validate_schema_document(schema)

        schema = copy.deepcopy(self.schema)
        schema["$defs"]["callback_registration"]["properties"]["prototype"] = {
            "$ref": "#/$defs/member_step"
        }
        with self.assertRaisesRegex(
            catalog_tool.CatalogError, "callback_registration.*semantics"
        ):
            catalog_tool.validate_schema_document(schema)

        schema = copy.deepcopy(self.schema)
        schema["$defs"]["callback_entry_input"]["properties"]["index"][
            "minimum"
        ] = -10
        with self.assertRaisesRegex(catalog_tool.CatalogError, "entry_input.index"):
            catalog_tool.validate_schema_document(schema)

        schema = copy.deepcopy(self.schema)
        schema["$defs"]["callback_slot"]["properties"]["record_type"][
            "type"
        ] = "integer"
        with self.assertRaisesRegex(catalog_tool.CatalogError, "callback_slot.*semantics"):
            catalog_tool.validate_schema_document(schema)

        for mutate in (
            lambda value: value["$defs"]["callback_binding"].__setitem__(
                "not", {}
            ),
            lambda value: value["$defs"]["callback_slot"].__setitem__("not", {}),
            lambda value: value["$defs"]["callback_registration"].update(
                minProperties=99
            ),
            lambda value: value["$defs"]["callback_entry_input"].update(
                allOf=[False]
            ),
            lambda value: value["$defs"]["member_step"]["properties"][
                "record_type"
            ].update(type="integer"),
            lambda value: value["$defs"]["parameter"]["properties"]["type"].update(
                type="integer"
            ),
            lambda value: value["$defs"]["prototype"].__setitem__("not", {}),
            lambda value: value["$defs"].update(stale_definition={}),
            lambda value: value["$defs"]["callback_binding"]["required"].append(
                "id"
            ),
        ):
            schema = copy.deepcopy(self.schema)
            mutate(schema)
            with self.assertRaisesRegex(catalog_tool.CatalogError, "canonical identity"):
                catalog_tool.validate_schema_document(schema)

        schema = copy.deepcopy(self.schema)
        schema["$defs"]["contract"]["properties"]["additional_rule_ids"][
            "items"
        ]["pattern"] = ".*"
        with self.assertRaisesRegex(catalog_tool.CatalogError, "additional_rule_ids.*semantics"):
            catalog_tool.validate_schema_document(schema)

        schema = copy.deepcopy(self.schema)
        schema["$defs"]["protocol_selector"]["properties"]["kind"]["enum"].remove(
            "member-update"
        )
        with self.assertRaisesRegex(catalog_tool.CatalogError, "values do not match"):
            catalog_tool.validate_schema_document(schema)

        schema = copy.deepcopy(self.schema)
        schema["$defs"]["protocol_binding"]["properties"]["stale_field"] = {
            "type": "string"
        }
        with self.assertRaisesRegex(catalog_tool.CatalogError, "do not match generator fields"):
            catalog_tool.validate_schema_document(schema)

        schema = copy.deepcopy(self.schema)
        schema["$defs"]["protocol_binding"]["properties"]["value"][
            "minimum"
        ] += 1
        with self.assertRaisesRegex(catalog_tool.CatalogError, "bounds do not match"):
            catalog_tool.validate_schema_document(schema)

        schema = copy.deepcopy(self.schema)
        comparison = next(
            alternative
            for alternative in schema["$defs"]["predicate"]["oneOf"]
            if "operator" in alternative.get("properties", {})
        )
        comparison["properties"]["operator"]["enum"].remove("ge")
        with self.assertRaisesRegex(catalog_tool.CatalogError, "predicate operators"):
            catalog_tool.validate_schema_document(schema)

        schema = copy.deepcopy(self.schema)
        schema["$defs"]["contract"]["properties"]["pair"] = {
            "$ref": "#/$defs/pair"
        }
        with self.assertRaisesRegex(catalog_tool.CatalogError, "pair object or null"):
            catalog_tool.validate_schema_document(schema)


if __name__ == "__main__":
    unittest.main()
