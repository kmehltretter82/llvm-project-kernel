#!/usr/bin/env python3
"""Validate and generate the QEMU analyzer contract catalog.

The JSON schema is the public format description.  This program deliberately
performs the semantic checks itself so generation has no third-party Python
dependency and cannot silently accept a catalog that the future checker table
cannot represent.

The initial transfer slice deliberately covers only address_space_{read,write,rw}
and dma_memory_{read,write,rw}.  Relaxed DMA accessors, PCI convenience
wrappers, cached/ROM/set operations, and typed load/store helpers are deferred:
their barrier, implicit-attribute, or specialized side-effect semantics need
separate contract fields rather than name-based approximation.  USB packet
copying is represented separately because its direction, offset, and effective
capacity are fields reachable from the packet argument rather than direct
arguments.  The packet contract source-attests the raw 64-bit setup parameter;
the ``(parameter >> 48) & 0xffff`` wLength projection remains a separate
follow-on relation rather than being hidden in a selector-specific
implementation.  USB callback slots, registration roots, entry inputs, and
direction-conditioned logical input buffers are described by top-level
callback bindings so indirect callback discovery can also fail closed against
source drift.  For a packet-copy effect, a
null ``capacity_selector`` selects ``primary_capacity`` and a nonnull selector
selects ``alternate_capacity``; spelling that relation in the generated effect
record keeps the checker independent of concrete field names.

For MemTxResult transfers, zero is the only success result and every nonzero
bitmask is a failure.  A failed composite access may nevertheless have
completed a prefix.  Accordingly, the catalog asserts a transfer effect only
on success; ``partial_success: false`` means that the API exposes no distinct,
reliably detectable partial-success result, not that failure is atomic.

The IOMMU-notifier slice records initialization separately from successful
registration.  Only a zero return from
``memory_region_register_iommu_notifier`` activates the exact
``(MemoryRegion, IOMMUNotifier)`` pair; unregistering retires that exact pair.
"""

import argparse
import copy
import difflib
import hashlib
import json
import re
import sys
from pathlib import Path


# This deliberately pins every transitive JSON-Schema semantic keyword.  The
# structural checks below provide useful errors; this identity prevents an
# unreviewed schema broadening/narrowing through a keyword they do not name.
EXPECTED_SCHEMA_SHA256 = "09a169d61f4b526431cb22ab6c219adcbf263aa7f5f3abfd46701731cbee166d"


CATALOG_KEYS = {
    "catalog_format",
    "model_version",
    "contracts",
    "callback_bindings",
    "protocols",
}
CONTRACT_KEYS = {
    "id",
    "rule_id",
    "additional_rule_ids",
    "family",
    "kind",
    "selector",
    "prototype",
    "direction_encoding",
    "operands",
    "predicates",
    "effects",
    "pair",
}
SELECTOR_KEYS = {"kind", "name", "header", "translation_unit"}
PROTOTYPE_KEYS = {"return_type", "parameters"}
PARAMETER_KEYS = {"name", "type"}
OPERAND_KEYS = {"role", "source", "index", "phase", "path"}
MEMBER_STEP_KEYS = {"record_type", "field", "type", "header"}
PREDICATE_NAMES = {"success", "partial_success", "failure"}
EFFECT_KEYS = {
    "kind",
    "when",
    "target",
    "extent",
    "requested_extent",
    "access_extent",
    "direction",
    "owner",
    "callback",
    "memory_region",
    "epoch",
    "offset",
    "capacity_selector",
    "primary_capacity",
    "alternate_capacity",
}
PAIR_KEYS = {"contract_id", "relation"}
PROTOCOL_KEYS = {"id", "rule_id", "family", "scope", "bindings", "events"}
PROTOCOL_SCOPE_KEYS = {
    "kind",
    "name",
    "source",
    "translation_unit",
    "prototype",
}
PROTOCOL_BINDING_KEYS = {
    "role",
    "source",
    "index",
    "record_type",
    "field",
    "value",
}
PROTOCOL_EVENT_KEYS = {"stage", "selectors"}
PROTOCOL_SELECTOR_KEYS = {
    "kind",
    "contract_id",
    "name",
    "prototype",
    "record_type",
    "field",
    "operation",
    "phase",
    "result_path",
    "expected_count",
}
CALLBACK_BINDING_KEYS = {
    "id",
    "rule_ids",
    "family",
    "slot",
    "prototype",
    "registration",
    "entry_inputs",
    "input_buffers",
}
CALLBACK_SLOT_KEYS = {
    "record_type",
    "field",
    "header",
    "translation_unit",
    "implementation",
}
CALLBACK_REGISTRATION_KEYS = {
    "record_type",
    "field",
    "header",
    "translation_unit",
    "prototype",
    "variable",
    "initializer",
}
CALLBACK_ENTRY_INPUT_KEYS = {"role", "source", "index", "path"}
CALLBACK_INPUT_BUFFER_KEYS = {"buffer_index", "length_role", "active_when"}
CALLBACK_INPUT_BUFFER_CONDITION_KEYS = {"role", "mask", "equals"}

OPERAND_ROLES = {
    "owner",
    "guest_address",
    "requested_length",
    "mapped_buffer",
    "mapped_length",
    "direction",
    "attributes",
    "access_length",
    "host_buffer",
    "transfer_length",
    "result",
    "access_offset",
    "capacity_selector",
    "primary_capacity",
    "alternate_capacity",
    "status",
    "endpoint_type",
    "setup_parameter",
    "notifier",
    "callback",
    "memory_region",
    "flags",
    "range_start",
    "range_end",
    "iommu_index",
    "error",
}
OPERAND_SOURCES = {
    "argument",
    "argument_pointee",
    "argument_member",
    "return",
}
OPERAND_PHASES = {"pre", "post"}
PREDICATE_OPERATORS = {
    "is_null",
    "not_null",
    "eq",
    "ne",
    "lt",
    "le",
    "gt",
    "ge",
}
EFFECT_KINDS = {
    "map",
    "unmap",
    "invalidate",
    "transfer",
    "packet-copy",
    "initialize-resource",
    "register-callback",
    "unregister-callback",
}
DIRECTION_ENCODINGS = {
    "bool-is-write",
    "dma-direction",
    "fixed-to-device",
    "fixed-from-device",
    "usb-token-pid",
    "none",
}
PROTOCOL_BINDING_ROLES = {"owner", "queue", "attempt", "slot", "vector", "result"}
PROTOCOL_BINDING_SOURCES = {
    "scope-argument",
    "transfer-result",
    "member-value-pre",
    "integer-constant",
}
PROTOCOL_STAGES = (
    "descriptor-failed",
    "ring-advanced",
    "interrupt-published",
)
PROTOCOL_SELECTOR_KINDS = {"transfer-call", "member-update", "function-call"}
PROTOCOL_SELECTOR_PHASES = {"post-call", "bind", "pre-call"}
PROTOCOL_MEMBER_OPERATIONS = {
    "pre-decrement",
    "post-decrement",
    "pre-increment",
    "post-increment",
    "add-assign",
    "subtract-assign",
}
CALLBACK_ENTRY_INPUT_SOURCES = {"argument", "argument_member"}
CALLBACK_ENTRY_INPUT_ROLES = {
    "control-request",
    "control-value",
    "control-index",
    "control-length",
    "packet-direction",
    "packet-capacity-selector",
    "packet-primary-capacity",
    "packet-alternate-capacity",
    "packet-setup-parameter",
    "packet-endpoint-number",
    "packet-endpoint-type",
}
VALIDATION_PROFILES = {"production", "test-subset"}


def _path_signature(path):
    return tuple(
        (step["record_type"], step["field"], step["type"], step["header"])
        for step in path
    )


USB_PACKET_MEMBER_PATHS = {
    "direction": (
        ("USBPacket", "pid", "int", "include/hw/usb/usb.h"),
    ),
    "access_offset": (
        ("USBPacket", "actual_length", "int", "include/hw/usb/usb.h"),
    ),
    "capacity_selector": (
        (
            "USBPacket",
            "combined",
            "USBCombinedPacket *",
            "include/hw/usb/usb.h",
        ),
    ),
    "primary_capacity": (
        ("USBPacket", "iov", "QEMUIOVector", "include/hw/usb/usb.h"),
        ("QEMUIOVector", "size", "size_t", "include/qemu/iov.h"),
    ),
    "alternate_capacity": (
        (
            "USBPacket",
            "combined",
            "USBCombinedPacket *",
            "include/hw/usb/usb.h",
        ),
        (
            "USBCombinedPacket",
            "iov",
            "QEMUIOVector",
            "include/hw/usb/usb.h",
        ),
        ("QEMUIOVector", "size", "size_t", "include/qemu/iov.h"),
    ),
    "status": (
        ("USBPacket", "status", "int", "include/hw/usb/usb.h"),
    ),
    "endpoint_type": (
        ("USBPacket", "ep", "USBEndpoint *", "include/hw/usb/usb.h"),
        ("USBEndpoint", "type", "uint8_t", "include/hw/usb/usb.h"),
    ),
    "setup_parameter": (
        ("USBPacket", "parameter", "uint64_t", "include/hw/usb/usb.h"),
    ),
}

USB_CALLBACK_MEMBER_PATHS = {
    "packet-direction": USB_PACKET_MEMBER_PATHS["direction"],
    "packet-capacity-selector": USB_PACKET_MEMBER_PATHS["capacity_selector"],
    "packet-primary-capacity": USB_PACKET_MEMBER_PATHS["primary_capacity"],
    "packet-alternate-capacity": USB_PACKET_MEMBER_PATHS["alternate_capacity"],
    "packet-setup-parameter": USB_PACKET_MEMBER_PATHS["setup_parameter"],
    "packet-endpoint-number": (
        ("USBPacket", "ep", "USBEndpoint *", "include/hw/usb/usb.h"),
        ("USBEndpoint", "nr", "uint8_t", "include/hw/usb/usb.h"),
    ),
    "packet-endpoint-type": USB_PACKET_MEMBER_PATHS["endpoint_type"],
}
SIGNED_LONG_LONG_MIN = -(1 << 63)
SIGNED_LONG_LONG_MAX = (1 << 63) - 1
UNSIGNED_LONG_LONG_MAX = (1 << 64) - 1

ID_RE = re.compile(r"^qemu\.[a-z0-9][a-z0-9.-]*$")
MODEL_RE = re.compile(r"^qemu-v3-[a-z0-9][a-z0-9.-]*$")
FAMILY_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")
IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
HEADER_RE = re.compile(r"^include/[A-Za-z0-9_./-]+\.h$")
TRANSLATION_UNIT_RE = re.compile(
    r"^(?:[A-Za-z0-9_.+-]+/)*[A-Za-z0-9_.+-]+\.(?:c|cc|cpp|cxx)$"
)
TYPE_RE = re.compile(r"^(?:const )?[A-Za-z_][A-Za-z0-9_]*(?: \*+)?$")


class CatalogError(ValueError):
    """A deterministic, user-actionable catalog validation failure."""


def _object_from_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise CatalogError("duplicate JSON member {!r}".format(key))
        result[key] = value
    return result


def load_json_strict(path):
    try:
        with Path(path).open("r", encoding="utf-8") as stream:
            return json.load(stream, object_pairs_hook=_object_from_pairs)
    except CatalogError:
        raise
    except (OSError, json.JSONDecodeError) as error:
        raise CatalogError("{}: {}".format(path, error)) from error


def _expect_object(value, allowed, required, where):
    if not isinstance(value, dict):
        raise CatalogError("{} must be an object".format(where))
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise CatalogError(
            "{} has unknown field(s): {}".format(where, ", ".join(unknown))
        )
    missing = sorted(required - set(value))
    if missing:
        raise CatalogError(
            "{} is missing field(s): {}".format(where, ", ".join(missing))
        )


def _expect_string(value, where, pattern=None):
    if not isinstance(value, str) or not value:
        raise CatalogError("{} must be a non-empty string".format(where))
    if pattern is not None and pattern.fullmatch(value) is None:
        raise CatalogError("{} has invalid value {!r}".format(where, value))


def _validate_type(type_name, where):
    _expect_string(type_name, where)
    if TYPE_RE.fullmatch(type_name) is None:
        raise CatalogError("{} is not a canonical C type: {!r}".format(where, type_name))


def _is_pointer(type_name):
    return type_name.endswith("*")


def _pointee(type_name):
    if not _is_pointer(type_name):
        raise CatalogError("cannot take pointee type of {!r}".format(type_name))
    return type_name[:-1].rstrip()


def _pointer_record_name(type_name):
    pointee = _pointee(type_name)
    if pointee.startswith("const "):
        pointee = pointee[len("const ") :]
    return pointee


def _record_name(type_name):
    value = type_name
    if value.startswith("const "):
        value = value[len("const ") :]
    return value.rstrip(" *")


def _validate_relative_source_path(value, where):
    _expect_string(value, where, TRANSLATION_UNIT_RE)
    if any(component in {"", ".", ".."} for component in value.split("/")):
        raise CatalogError("{} must be a normalized relative path".format(where))


def _validate_header_path(value, where):
    _expect_string(value, where, HEADER_RE)
    if any(component in {"", ".", ".."} for component in value.split("/")):
        raise CatalogError("{} must be a normalized header path".format(where))


def _validate_prototype(prototype, where):
    _expect_object(prototype, PROTOTYPE_KEYS, PROTOTYPE_KEYS, where)
    _validate_type(prototype["return_type"], where + ".return_type")
    parameters = prototype["parameters"]
    if not isinstance(parameters, list) or not parameters:
        raise CatalogError("{}.parameters must be a non-empty array".format(where))
    parameter_names = set()
    for parameter_index, parameter in enumerate(parameters):
        parameter_where = "{}.parameters[{}]".format(where, parameter_index)
        _expect_object(parameter, PARAMETER_KEYS, PARAMETER_KEYS, parameter_where)
        _expect_string(parameter["name"], parameter_where + ".name", IDENTIFIER_RE)
        _validate_type(parameter["type"], parameter_where + ".type")
        if parameter["name"] in parameter_names:
            raise CatalogError(
                "{} has duplicate parameter name {!r}".format(
                    where, parameter["name"]
                )
            )
        parameter_names.add(parameter["name"])
    return parameters


def _prototype_type_string(prototype):
    return "{} ({})".format(
        prototype["return_type"],
        ", ".join(parameter["type"] for parameter in prototype["parameters"]),
    )


def _function_pointer_type_string(prototype):
    return "{} (*)({})".format(
        prototype["return_type"],
        ", ".join(parameter["type"] for parameter in prototype["parameters"]),
    )


def _operand_type(contract, operand):
    prototype = contract["prototype"]
    if operand["source"] == "return":
        return prototype["return_type"]
    parameter_type = prototype["parameters"][operand["index"]]["type"]
    if operand["source"] == "argument_pointee":
        return _pointee(parameter_type)
    if operand["source"] == "argument_member":
        return operand["path"][-1]["type"]
    return parameter_type


def _validate_member_path(parameter_type, path, where):
    if not _is_pointer(parameter_type):
        raise CatalogError("{} requires a pointer parameter".format(where))
    if not isinstance(path, list) or not path:
        raise CatalogError("{}.path must be a non-empty array".format(where))
    if len(path) > 8:
        raise CatalogError("{}.path exceeds eight member steps".format(where))

    expected_record = _pointer_record_name(parameter_type)
    for index, step in enumerate(path):
        step_where = "{}.path[{}]".format(where, index)
        _expect_object(step, MEMBER_STEP_KEYS, MEMBER_STEP_KEYS, step_where)
        _expect_string(step["record_type"], step_where + ".record_type", IDENTIFIER_RE)
        _expect_string(step["field"], step_where + ".field", IDENTIFIER_RE)
        _validate_type(step["type"], step_where + ".type")
        _validate_header_path(step["header"], step_where + ".header")
        if step["record_type"] != expected_record:
            raise CatalogError(
                "{} record_type {!r} does not follow {!r}".format(
                    step_where, step["record_type"], expected_record
                )
            )
        if index + 1 < len(path):
            expected_record = _record_name(step["type"])


def _validate_predicate(node, roles, role_types, where):
    if not isinstance(node, dict):
        raise CatalogError("{} must be an object".format(where))

    if "constant" in node:
        _expect_object(node, {"constant"}, {"constant"}, where)
        if type(node["constant"]) is not bool:
            raise CatalogError("{}.constant must be a boolean".format(where))
        return

    compound = [name for name in ("all", "any", "not") if name in node]
    if compound:
        if len(compound) != 1:
            raise CatalogError("{} has more than one predicate combinator".format(where))
        name = compound[0]
        _expect_object(node, {name}, {name}, where)
        if name == "not":
            _validate_predicate(node[name], roles, role_types, where + ".not")
            return
        children = node[name]
        if not isinstance(children, list) or not children:
            raise CatalogError("{}.{} must be a non-empty array".format(where, name))
        for index, child in enumerate(children):
            _validate_predicate(
                child, roles, role_types, "{}.{}[{}]".format(where, name, index)
            )
        return

    _expect_object(node, {"operand", "operator", "rhs"}, {"operand", "operator"}, where)
    operand = node["operand"]
    operator = node["operator"]
    if operand not in roles:
        raise CatalogError("{}.operand references unknown role {!r}".format(where, operand))
    if operator not in PREDICATE_OPERATORS:
        raise CatalogError("{}.operator has invalid value {!r}".format(where, operator))

    unary = operator in {"is_null", "not_null"}
    if unary:
        if "rhs" in node:
            raise CatalogError("{} unary predicate must not have rhs".format(where))
        if not _is_pointer(role_types[operand]):
            raise CatalogError("{} null predicate requires a pointer operand".format(where))
        return

    if "rhs" not in node:
        raise CatalogError("{} comparison predicate requires rhs".format(where))
    rhs = node["rhs"]
    _expect_object(rhs, {"operand", "integer"}, set(), where + ".rhs")
    if set(rhs) == {"operand"}:
        rhs_operand = rhs["operand"]
        if rhs_operand not in roles:
            raise CatalogError(
                "{}.rhs references unknown role {!r}".format(where, rhs_operand)
            )
        if role_types[operand] != role_types[rhs_operand]:
            raise CatalogError(
                "{} compares incompatible operand types {!r} and {!r}".format(
                    where, role_types[operand], role_types[rhs_operand]
                )
            )
    elif set(rhs) == {"integer"}:
        if type(rhs["integer"]) is not int:
            raise CatalogError("{}.rhs.integer must be an integer".format(where))
        if _is_pointer(role_types[operand]) and operator not in {"eq", "ne"}:
            raise CatalogError("{} orders a pointer against an integer".format(where))
    else:
        raise CatalogError("{}.rhs must contain exactly one value".format(where))


def _validate_effects(contract, roles, where):
    effects = contract["effects"]
    if not isinstance(effects, list) or not effects:
        raise CatalogError("{}.effects must be a non-empty array".format(where))
    seen_kinds = set()
    for index, effect in enumerate(effects):
        effect_where = "{}.effects[{}]".format(where, index)
        _expect_object(effect, EFFECT_KEYS, {"kind", "when", "target"}, effect_where)
        kind = effect["kind"]
        if kind not in EFFECT_KINDS:
            raise CatalogError("{}.kind has invalid value {!r}".format(effect_where, kind))
        if kind in seen_kinds:
            raise CatalogError("{} has duplicate effect kind {!r}".format(where, kind))
        seen_kinds.add(kind)
        if effect["when"] not in PREDICATE_NAMES:
            raise CatalogError("{}.when names an unknown predicate".format(effect_where))
        for field in (
            "target",
            "extent",
            "requested_extent",
            "access_extent",
            "direction",
            "owner",
            "callback",
            "memory_region",
            "offset",
            "capacity_selector",
            "primary_capacity",
            "alternate_capacity",
        ):
            if field in effect and effect[field] not in roles:
                raise CatalogError(
                    "{}.{} references unknown role {!r}".format(
                        effect_where, field, effect[field]
                    )
                )
        if "epoch" in effect and effect["epoch"] not in {"create", "retire"}:
            raise CatalogError("{}.epoch has invalid value".format(effect_where))

    effect_by_kind = {effect["kind"]: effect for effect in effects}
    has_owner = "owner" in roles
    if contract["kind"] == "map":
        if set(effect_by_kind) != {"map"}:
            raise CatalogError("{} map contract must have exactly one map effect".format(where))
        effect = effect_by_kind["map"]
        expected = {
            "kind": "map",
            "when": "success",
            "target": "mapped_buffer",
            "extent": "mapped_length",
            "requested_extent": "requested_length",
            "direction": "direction",
            "epoch": "create",
        }
        if has_owner:
            expected["owner"] = "owner"
        if effect != expected:
            raise CatalogError("{}.effects map effect is not canonical".format(where))
    elif contract["kind"] == "unmap":
        if set(effect_by_kind) != {"unmap", "invalidate"}:
            raise CatalogError(
                "{} unmap contract must have unmap and invalidate effects".format(where)
            )
        unmap = effect_by_kind["unmap"]
        expected = {
            "kind": "unmap",
            "when": "success",
            "target": "mapped_buffer",
            "extent": "mapped_length",
            "access_extent": "access_length",
            "direction": "direction",
        }
        if has_owner:
            expected["owner"] = "owner"
        if unmap != expected:
            raise CatalogError("{}.effects unmap effect is not canonical".format(where))
        invalidate = effect_by_kind["invalidate"]
        if invalidate != {
            "kind": "invalidate",
            "when": "success",
            "target": "mapped_buffer",
            "epoch": "retire",
        }:
            raise CatalogError("{}.effects invalidate effect is not canonical".format(where))
    elif contract["kind"] == "transfer":
        if set(effect_by_kind) != {"transfer"}:
            raise CatalogError(
                "{} transfer contract must have exactly one transfer effect".format(
                    where
                )
            )
        expected = {
            "kind": "transfer",
            "when": "success",
            "target": "host_buffer",
            "extent": "transfer_length",
            "owner": "owner",
        }
        if contract["direction_encoding"] in {"bool-is-write", "dma-direction"}:
            expected["direction"] = "direction"
        if effect_by_kind["transfer"] != expected:
            raise CatalogError("{}.effects transfer effect is not canonical".format(where))
    elif contract["kind"] == "packet-copy":
        if set(effect_by_kind) != {"packet-copy"}:
            raise CatalogError(
                "{} packet-copy contract must have exactly one packet-copy effect".format(
                    where
                )
            )
        expected = {
            "kind": "packet-copy",
            "when": "success",
            "target": "host_buffer",
            "extent": "transfer_length",
            "direction": "direction",
            "owner": "owner",
            "offset": "access_offset",
            "capacity_selector": "capacity_selector",
            "primary_capacity": "primary_capacity",
            "alternate_capacity": "alternate_capacity",
        }
        if effect_by_kind["packet-copy"] != expected:
            raise CatalogError(
                "{}.effects packet-copy effect is not canonical".format(where)
            )
    elif contract["kind"] == "initialize-resource":
        expected = {
            "kind": "initialize-resource",
            "when": "success",
            "target": "notifier",
            "callback": "callback",
            "epoch": "create",
        }
        if set(effect_by_kind) != {"initialize-resource"} or effect_by_kind[
            "initialize-resource"
        ] != expected:
            raise CatalogError(
                "{}.effects initialize-resource effect is not canonical".format(where)
            )
    elif contract["kind"] == "register-callback":
        expected = {
            "kind": "register-callback",
            "when": "success",
            "target": "notifier",
            "memory_region": "memory_region",
            "epoch": "create",
        }
        if set(effect_by_kind) != {"register-callback"} or effect_by_kind[
            "register-callback"
        ] != expected:
            raise CatalogError(
                "{}.effects register-callback effect is not canonical".format(where)
            )
    else:
        expected = {
            "kind": "unregister-callback",
            "when": "success",
            "target": "notifier",
            "memory_region": "memory_region",
            "epoch": "retire",
        }
        if set(effect_by_kind) != {"unregister-callback"} or effect_by_kind[
            "unregister-callback"
        ] != expected:
            raise CatalogError(
                "{}.effects unregister-callback effect is not canonical".format(where)
            )


def _validate_contract(contract, index, require_exact_qemu=True):
    where = "contracts[{}]".format(index)
    _expect_object(
        contract, CONTRACT_KEYS, CONTRACT_KEYS - {"additional_rule_ids"}, where
    )
    _expect_string(contract["id"], where + ".id", ID_RE)
    _expect_string(contract["rule_id"], where + ".rule_id", ID_RE)
    additional_rules = contract.get("additional_rule_ids", [])
    if not isinstance(additional_rules, list):
        raise CatalogError("{}.additional_rule_ids must be an array".format(where))
    seen_rules = {contract["rule_id"]}
    for rule_index, rule_id in enumerate(additional_rules):
        _expect_string(
            rule_id,
            "{}.additional_rule_ids[{}]".format(where, rule_index),
            ID_RE,
        )
        if rule_id in seen_rules:
            raise CatalogError("{} has duplicate diagnostic rule {!r}".format(where, rule_id))
        seen_rules.add(rule_id)
    _expect_string(contract["family"], where + ".family", FAMILY_RE)
    if contract["kind"] not in {
        "map",
        "unmap",
        "transfer",
        "packet-copy",
        "initialize-resource",
        "register-callback",
        "unregister-callback",
    }:
        raise CatalogError(
            "{}.kind has an unsupported contract kind".format(where)
        )
    expected_rule = {
        "map": "qemu.direct-dma-map",
        "unmap": "qemu.direct-dma-unmap",
        "transfer": "qemu.dma-transfer-result",
        "packet-copy": "qemu.initialized-bytes.disclosure",
        "initialize-resource": "qemu.iommu-notifier-lifetime",
        "register-callback": "qemu.iommu-notifier-lifetime",
        "unregister-callback": "qemu.iommu-notifier-lifetime",
    }[contract["kind"]]
    if contract["rule_id"] != expected_rule:
        raise CatalogError("{}.rule_id must be {!r}".format(where, expected_rule))
    expected_additional_rules = (
        {"qemu.guest-memory.bounds"}
        if contract["kind"] == "packet-copy"
        else set()
    )
    if set(additional_rules) != expected_additional_rules:
        raise CatalogError(
            "{}.additional_rule_ids must be {}".format(
                where, sorted(expected_additional_rules)
            )
        )

    selector = contract["selector"]
    _expect_object(selector, SELECTOR_KEYS, SELECTOR_KEYS, where + ".selector")
    if selector["kind"] != "function":
        raise CatalogError("{}.selector.kind must be function".format(where))
    _expect_string(selector["name"], where + ".selector.name", IDENTIFIER_RE)
    _validate_header_path(selector["header"], where + ".selector.header")
    _validate_relative_source_path(
        selector["translation_unit"], where + ".selector.translation_unit"
    )

    prototype = contract["prototype"]
    parameters = _validate_prototype(prototype, where + ".prototype")

    if contract["direction_encoding"] not in DIRECTION_ENCODINGS:
        raise CatalogError("{}.direction_encoding has invalid value".format(where))

    operands = contract["operands"]
    if not isinstance(operands, list) or not operands:
        raise CatalogError("{}.operands must be a non-empty array".format(where))
    roles = {}
    referenced_parameters = set()
    for operand_index, operand in enumerate(operands):
        operand_where = "{}.operands[{}]".format(where, operand_index)
        _expect_object(operand, OPERAND_KEYS, {"role", "source", "phase"}, operand_where)
        role = operand["role"]
        source = operand["source"]
        phase = operand["phase"]
        if role not in OPERAND_ROLES:
            raise CatalogError("{}.role has invalid value {!r}".format(operand_where, role))
        if role in roles:
            raise CatalogError("{} has duplicate operand role {!r}".format(where, role))
        if source not in OPERAND_SOURCES:
            raise CatalogError("{}.source has invalid value {!r}".format(operand_where, source))
        if phase not in OPERAND_PHASES:
            raise CatalogError("{}.phase has invalid value {!r}".format(operand_where, phase))
        if source == "return":
            if "index" in operand or "path" in operand:
                raise CatalogError(
                    "{} return operand must not have index or path".format(
                        operand_where
                    )
                )
            if phase != "post" or prototype["return_type"] == "void":
                raise CatalogError("{} has an invalid return operand".format(operand_where))
        else:
            if "index" not in operand or type(operand["index"]) is not int:
                raise CatalogError("{} argument operand requires integer index".format(operand_where))
            argument_index = operand["index"]
            if argument_index < 0 or argument_index >= len(parameters):
                raise CatalogError("{}.index is outside the prototype".format(operand_where))
            referenced_parameters.add(argument_index)
            if source == "argument_pointee" and not _is_pointer(
                parameters[argument_index]["type"]
            ):
                raise CatalogError("{} requires a pointer parameter".format(operand_where))
            if source == "argument_member":
                if "path" not in operand:
                    raise CatalogError(
                        "{} argument_member operand requires path".format(
                            operand_where
                        )
                    )
                _validate_member_path(
                    parameters[argument_index]["type"],
                    operand["path"],
                    operand_where,
                )
            elif "path" in operand:
                raise CatalogError(
                    "{} path is valid only for argument_member".format(
                        operand_where
                    )
                )
        roles[role] = operand

    if referenced_parameters != set(range(len(parameters))):
        missing = sorted(set(range(len(parameters))) - referenced_parameters)
        raise CatalogError(
            "{} prototype parameter(s) are unmodeled: {}".format(
                where, ", ".join(str(value) for value in missing)
            )
        )

    required_map = {
        "guest_address",
        "requested_length",
        "mapped_buffer",
        "mapped_length",
        "direction",
    }
    required_unmap = {"mapped_buffer", "mapped_length", "direction", "access_length"}
    required_transfer = {
        "owner",
        "guest_address",
        "host_buffer",
        "transfer_length",
        "attributes",
        "result",
    }
    required_packet_copy = {
        "owner",
        "host_buffer",
        "transfer_length",
        "direction",
        "access_offset",
        "capacity_selector",
        "primary_capacity",
        "alternate_capacity",
        "status",
        "endpoint_type",
        "setup_parameter",
    }
    required_initialize_resource = {
        "notifier",
        "callback",
        "flags",
        "range_start",
        "range_end",
        "iommu_index",
    }
    required_register_callback = {
        "memory_region",
        "notifier",
        "error",
        "result",
    }
    required_unregister_callback = {"memory_region", "notifier"}
    if contract["kind"] == "map":
        if not required_map.issubset(roles) or "access_length" in roles:
            raise CatalogError("{} has invalid map operand roles".format(where))
        if prototype["return_type"] != "void *":
            raise CatalogError("{} map prototype must return void *".format(where))
        if roles["mapped_buffer"]["source"] != "return":
            raise CatalogError("{} mapped_buffer must be the return value".format(where))
        requested = roles["requested_length"]
        mapped = roles["mapped_length"]
        if (
            requested["source"] != "argument_pointee"
            or requested["phase"] != "pre"
            or mapped["source"] != "argument_pointee"
            or mapped["phase"] != "post"
            or requested["index"] != mapped["index"]
        ):
            raise CatalogError("{} length in/out operands are not paired".format(where))
        for role in ("guest_address", "direction"):
            if roles[role]["source"] != "argument" or roles[role]["phase"] != "pre":
                raise CatalogError("{} {} must be a pre-call argument".format(where, role))
        for role in ("owner", "attributes"):
            if role in roles and (
                roles[role]["source"] != "argument" or roles[role]["phase"] != "pre"
            ):
                raise CatalogError("{} {} must be a pre-call argument".format(where, role))
    elif contract["kind"] == "unmap":
        if set(roles) - (required_unmap | {"owner"}) or not required_unmap.issubset(roles):
            raise CatalogError("{} has invalid unmap operand roles".format(where))
        if prototype["return_type"] != "void":
            raise CatalogError("{} unmap prototype must return void".format(where))
        for role in required_unmap:
            if roles[role]["source"] != "argument" or roles[role]["phase"] != "pre":
                raise CatalogError("{} {} must be a pre-call argument".format(where, role))
        if "owner" in roles and (
            roles["owner"]["source"] != "argument"
            or roles["owner"]["phase"] != "pre"
        ):
            raise CatalogError("{} owner must be a pre-call argument".format(where))
    elif contract["kind"] == "transfer":
        allowed_transfer = required_transfer | {"direction"}
        if set(roles) - allowed_transfer or not required_transfer.issubset(roles):
            raise CatalogError("{} has invalid transfer operand roles".format(where))
        if prototype["return_type"] != "MemTxResult":
            raise CatalogError("{} transfer prototype must return MemTxResult".format(where))
        dynamic_direction = contract["direction_encoding"] in {
            "bool-is-write",
            "dma-direction",
        }
        if dynamic_direction != ("direction" in roles):
            raise CatalogError(
                "{} transfer direction operand does not match encoding".format(where)
            )
        for role in required_transfer - {"result"}:
            if roles[role]["source"] != "argument" or roles[role]["phase"] != "pre":
                raise CatalogError("{} {} must be a pre-call argument".format(where, role))
        if roles["result"]["source"] != "return" or roles["result"]["phase"] != "post":
            raise CatalogError("{} result must be the post-call return value".format(where))
        if "direction" in roles and (
            roles["direction"]["source"] != "argument"
            or roles["direction"]["phase"] != "pre"
        ):
            raise CatalogError("{} direction must be a pre-call argument".format(where))
    elif contract["kind"] == "packet-copy":
        if set(roles) != required_packet_copy:
            raise CatalogError("{} has invalid packet-copy operand roles".format(where))
        if prototype["return_type"] != "void":
            raise CatalogError("{} packet-copy prototype must return void".format(where))
        for role in ("owner", "host_buffer", "transfer_length"):
            if roles[role]["source"] != "argument" or roles[role]["phase"] != "pre":
                raise CatalogError(
                    "{} {} must be a pre-call argument".format(where, role)
                )
        for role in (
            "direction",
            "access_offset",
            "capacity_selector",
            "primary_capacity",
            "alternate_capacity",
            "status",
            "endpoint_type",
            "setup_parameter",
        ):
            if (
                roles[role]["source"] != "argument_member"
                or roles[role]["phase"] != "pre"
                or roles[role]["index"] != roles["owner"]["index"]
            ):
                raise CatalogError(
                    "{} {} must be a pre-call member of owner".format(where, role)
                )
    elif contract["kind"] == "initialize-resource":
        if set(roles) != required_initialize_resource:
            raise CatalogError(
                "{} has invalid initialize-resource operand roles".format(where)
            )
        if prototype["return_type"] != "void":
            raise CatalogError(
                "{} initialize-resource prototype must return void".format(where)
            )
        for role in required_initialize_resource:
            if roles[role]["source"] != "argument" or roles[role]["phase"] != "pre":
                raise CatalogError(
                    "{} {} must be a pre-call argument".format(where, role)
                )
    elif contract["kind"] == "register-callback":
        if set(roles) != required_register_callback:
            raise CatalogError(
                "{} has invalid register-callback operand roles".format(where)
            )
        if prototype["return_type"] != "int":
            raise CatalogError(
                "{} register-callback prototype must return int".format(where)
            )
        for role in required_register_callback - {"result"}:
            if roles[role]["source"] != "argument" or roles[role]["phase"] != "pre":
                raise CatalogError(
                    "{} {} must be a pre-call argument".format(where, role)
                )
        if roles["result"]["source"] != "return" or roles["result"]["phase"] != "post":
            raise CatalogError("{} result must be the post-call return value".format(where))
    else:
        if set(roles) != required_unregister_callback:
            raise CatalogError(
                "{} has invalid unregister-callback operand roles".format(where)
            )
        if prototype["return_type"] != "void":
            raise CatalogError(
                "{} unregister-callback prototype must return void".format(where)
            )
        for role in required_unregister_callback:
            if roles[role]["source"] != "argument" or roles[role]["phase"] != "pre":
                raise CatalogError(
                    "{} {} must be a pre-call argument".format(where, role)
                )

    role_types = {role: _operand_type(contract, operand) for role, operand in roles.items()}
    if "direction" in roles:
        expected_direction_type = {
            "bool-is-write": "bool",
            "dma-direction": "DMADirection",
            "usb-token-pid": "int",
        }.get(contract["direction_encoding"])
        if expected_direction_type is None:
            raise CatalogError(
                "{} fixed direction encoding must not have an operand".format(where)
            )
        if role_types["direction"] != expected_direction_type:
            raise CatalogError(
                "{} direction encoding does not match type {!r}".format(
                    where, role_types["direction"]
                )
            )
    elif contract["kind"] in {
        "initialize-resource",
        "register-callback",
        "unregister-callback",
    }:
        if contract["direction_encoding"] != "none":
            raise CatalogError(
                "{} callback-lifetime contract direction must be none".format(where)
            )
    elif contract["direction_encoding"] not in {"fixed-to-device", "fixed-from-device"}:
        raise CatalogError("{} dynamic direction encoding requires an operand".format(where))
    if contract["kind"] in {"map", "unmap"} and contract[
        "direction_encoding"
    ] not in {"bool-is-write", "dma-direction"}:
        raise CatalogError("{} map/unmap direction must be dynamic".format(where))
    if "mapped_buffer" in roles and role_types["mapped_buffer"] != "void *":
        raise CatalogError("{} mapped_buffer must have type void *".format(where))
    if "owner" in roles and not _is_pointer(role_types["owner"]):
        raise CatalogError("{} owner must have pointer type".format(where))
    if "attributes" in roles and role_types["attributes"] != "MemTxAttrs":
        raise CatalogError("{} attributes must have type MemTxAttrs".format(where))
    if contract["kind"] == "map":
        length_type = role_types["mapped_length"]
        if role_types["requested_length"] != length_type or role_types["guest_address"] != length_type:
            raise CatalogError("{} address and length types do not match".format(where))
    elif contract["kind"] == "unmap" and role_types["access_length"] != role_types["mapped_length"]:
        raise CatalogError("{} access and mapped length types do not match".format(where))
    elif contract["kind"] == "transfer":
        if role_types["result"] != "MemTxResult":
            raise CatalogError("{} result must have type MemTxResult".format(where))
        if role_types["guest_address"] != role_types["transfer_length"]:
            raise CatalogError("{} address and transfer length types do not match".format(where))
        expected_buffer_type = (
            "const void *"
            if contract["direction_encoding"] == "fixed-from-device"
            else "void *"
        )
        if role_types["host_buffer"] != expected_buffer_type:
            raise CatalogError(
                "{} host buffer type does not match transfer direction".format(where)
            )
    elif contract["kind"] == "packet-copy":
        if contract["direction_encoding"] != "usb-token-pid":
            raise CatalogError(
                "{} packet-copy direction must use usb-token-pid".format(where)
            )
        if role_types["owner"] != "USBPacket *":
            raise CatalogError("{} packet-copy owner must be USBPacket *".format(where))
        if role_types["host_buffer"] != "void *":
            raise CatalogError("{} packet-copy host buffer must be void *".format(where))
        if role_types["transfer_length"] != "size_t":
            raise CatalogError("{} packet-copy length must be size_t".format(where))
        if role_types["access_offset"] != "int":
            raise CatalogError("{} packet-copy offset must be int".format(where))
        if role_types["status"] != "int":
            raise CatalogError("{} packet-copy status must be int".format(where))
        if role_types["endpoint_type"] != "uint8_t":
            raise CatalogError(
                "{} packet-copy endpoint type must be uint8_t".format(where)
            )
        if role_types["setup_parameter"] != "uint64_t":
            raise CatalogError(
                "{} packet-copy setup parameter must be uint64_t".format(where)
            )
        if role_types["capacity_selector"] != "USBCombinedPacket *":
            raise CatalogError(
                "{} packet-copy capacity selector must be USBCombinedPacket *".format(
                    where
                )
            )
        for role in ("primary_capacity", "alternate_capacity"):
            if role_types[role] != "size_t":
                raise CatalogError(
                    "{} packet-copy {} must be size_t".format(where, role)
                )
        if require_exact_qemu:
            for role, expected_path in USB_PACKET_MEMBER_PATHS.items():
                if _path_signature(roles[role]["path"]) != expected_path:
                    raise CatalogError(
                        "{} packet-copy {} member path is not canonical".format(
                            where, role
                        )
                    )
    elif contract["kind"] == "initialize-resource":
        expected_types = {
            "notifier": "IOMMUNotifier *",
            "callback": "IOMMUNotify",
            "flags": "IOMMUNotifierFlag",
            "range_start": "hwaddr",
            "range_end": "hwaddr",
            "iommu_index": "int",
        }
        if any(role_types[role] != expected for role, expected in expected_types.items()):
            raise CatalogError("{} has noncanonical IOMMU init operand types".format(where))
    elif contract["kind"] == "register-callback":
        expected_types = {
            "memory_region": "MemoryRegion *",
            "notifier": "IOMMUNotifier *",
            "error": "Error **",
            "result": "int",
        }
        if any(role_types[role] != expected for role, expected in expected_types.items()):
            raise CatalogError(
                "{} has noncanonical IOMMU register operand types".format(where)
            )
    elif contract["kind"] == "unregister-callback":
        if role_types != {
            "memory_region": "MemoryRegion *",
            "notifier": "IOMMUNotifier *",
        }:
            raise CatalogError(
                "{} has noncanonical IOMMU unregister operand types".format(where)
            )

    predicates = contract["predicates"]
    _expect_object(predicates, PREDICATE_NAMES, PREDICATE_NAMES, where + ".predicates")
    for name in sorted(PREDICATE_NAMES):
        _validate_predicate(
            predicates[name], roles, role_types, "{}.predicates.{}".format(where, name)
        )
    if contract["kind"] == "transfer":
        expected_predicates = {
            "success": {
                "operand": "result",
                "operator": "eq",
                "rhs": {"integer": 0},
            },
            "partial_success": {"constant": False},
            "failure": {
                "operand": "result",
                "operator": "ne",
                "rhs": {"integer": 0},
            },
        }
        if predicates != expected_predicates:
            raise CatalogError(
                "{}.predicates do not encode MemTxResult semantics".format(where)
            )
    elif contract["kind"] == "packet-copy":
        expected_predicates = {
            "success": {"constant": True},
            "partial_success": {"constant": False},
            "failure": {"constant": False},
        }
        if predicates != expected_predicates:
            raise CatalogError(
                "{}.predicates do not encode packet-copy semantics".format(where)
            )
    elif contract["kind"] == "register-callback":
        expected_predicates = {
            "success": {
                "operand": "result",
                "operator": "eq",
                "rhs": {"integer": 0},
            },
            "partial_success": {"constant": False},
            "failure": {
                "operand": "result",
                "operator": "ne",
                "rhs": {"integer": 0},
            },
        }
        if predicates != expected_predicates:
            raise CatalogError(
                "{}.predicates do not encode IOMMU registration semantics".format(where)
            )
    elif contract["kind"] in {"initialize-resource", "unregister-callback"}:
        expected_predicates = {
            "success": {"constant": True},
            "partial_success": {"constant": False},
            "failure": {"constant": False},
        }
        if predicates != expected_predicates:
            raise CatalogError(
                "{}.predicates do not encode infallible callback semantics".format(where)
            )

    _validate_effects(contract, roles, where)
    pair = contract["pair"]
    if contract["kind"] in {"transfer", "packet-copy", "initialize-resource"}:
        if pair is not None:
            raise CatalogError(
                "{}.pair must be null for a {}".format(where, contract["kind"])
            )
        return roles, role_types
    _expect_object(pair, PAIR_KEYS, PAIR_KEYS, where + ".pair")
    _expect_string(pair["contract_id"], where + ".pair.contract_id", ID_RE)
    paired_kind = {
        "map": "unmap",
        "unmap": "map",
        "register-callback": "unregister-callback",
        "unregister-callback": "register-callback",
    }[contract["kind"]]
    expected_relation = "{}-to-{}".format(contract["kind"], paired_kind)
    if pair["relation"] != expected_relation:
        raise CatalogError("{}.pair.relation must be {!r}".format(where, expected_relation))
    return roles, role_types


def _validate_protocol_binding(binding, protocol, index, where):
    binding_where = "{}.bindings[{}]".format(where, index)
    _expect_object(
        binding,
        PROTOCOL_BINDING_KEYS,
        {"role", "source"},
        binding_where,
    )
    role = binding["role"]
    source = binding["source"]
    if role not in PROTOCOL_BINDING_ROLES:
        raise CatalogError("{}.role has invalid value {!r}".format(binding_where, role))
    if source not in PROTOCOL_BINDING_SOURCES:
        raise CatalogError(
            "{}.source has invalid value {!r}".format(binding_where, source)
        )

    expected_source = {
        "owner": "scope-argument",
        "queue": "integer-constant",
        "attempt": "transfer-result",
        "slot": "member-value-pre",
        "vector": "integer-constant",
        "result": "transfer-result",
    }[role]
    if source != expected_source:
        raise CatalogError(
            "{} role {!r} must use source {!r}".format(
                binding_where, role, expected_source
            )
        )

    extra_fields = set(binding) - {"role", "source"}
    if source == "scope-argument":
        if extra_fields != {"index"} or type(binding["index"]) is not int:
            raise CatalogError(
                "{} scope-argument requires exactly an integer index".format(
                    binding_where
                )
            )
        parameters = protocol["scope"]["prototype"]["parameters"]
        argument_index = binding["index"]
        if argument_index < 0 or argument_index >= len(parameters):
            raise CatalogError("{}.index is outside the scope prototype".format(binding_where))
        if not _is_pointer(parameters[argument_index]["type"]):
            raise CatalogError("{} owner argument must have pointer type".format(binding_where))
    elif source == "transfer-result":
        if extra_fields:
            raise CatalogError(
                "{} transfer-result must not have source fields".format(binding_where)
            )
    elif source == "member-value-pre":
        if extra_fields != {"record_type", "field"}:
            raise CatalogError(
                "{} member-value-pre requires exactly record_type and field".format(
                    binding_where
                )
            )
        _expect_string(
            binding["record_type"], binding_where + ".record_type", IDENTIFIER_RE
        )
        _expect_string(binding["field"], binding_where + ".field", IDENTIFIER_RE)
    else:
        if extra_fields != {"value"} or type(binding["value"]) is not int:
            raise CatalogError(
                "{} integer-constant requires exactly an integer value".format(
                    binding_where
                )
            )
        if not SIGNED_LONG_LONG_MIN <= binding["value"] <= SIGNED_LONG_LONG_MAX:
            raise CatalogError(
                "{}.value is outside signed long long range".format(binding_where)
            )
    return role


def _validate_protocol_selector(selector, stage, index, contracts_by_id, where):
    selector_where = "{}.selectors[{}]".format(where, index)
    _expect_object(
        selector,
        PROTOCOL_SELECTOR_KEYS,
        {"kind", "phase", "expected_count"},
        selector_where,
    )
    kind = selector["kind"]
    phase = selector["phase"]
    if kind not in PROTOCOL_SELECTOR_KINDS:
        raise CatalogError("{}.kind has invalid value {!r}".format(selector_where, kind))
    if phase not in PROTOCOL_SELECTOR_PHASES:
        raise CatalogError("{}.phase has invalid value {!r}".format(selector_where, phase))
    if type(selector["expected_count"]) is not int or not (
        1 <= selector["expected_count"] <= 64
    ):
        raise CatalogError("{}.expected_count must be an integer from 1 to 64".format(selector_where))

    if kind == "transfer-call":
        expected_fields = {
            "kind",
            "contract_id",
            "phase",
            "result_path",
            "expected_count",
        }
        if set(selector) != expected_fields:
            raise CatalogError(
                "{} transfer-call fields are not canonical".format(selector_where)
            )
        contract_id = selector["contract_id"]
        _expect_string(contract_id, selector_where + ".contract_id", ID_RE)
        contract = contracts_by_id.get(contract_id)
        if contract is None or contract["kind"] != "transfer":
            raise CatalogError(
                "{} references missing or non-transfer contract {!r}".format(
                    selector_where, contract_id
                )
            )
        if phase != "post-call" or selector["result_path"] != "failure":
            raise CatalogError(
                "{} transfer-call must select post-call failure".format(
                    selector_where
                )
            )
        key = (kind, contract_id)
    elif kind == "member-update":
        expected_fields = {
            "kind",
            "record_type",
            "field",
            "operation",
            "phase",
            "expected_count",
        }
        if set(selector) != expected_fields:
            raise CatalogError(
                "{} member-update fields are not canonical".format(selector_where)
            )
        _expect_string(
            selector["record_type"], selector_where + ".record_type", IDENTIFIER_RE
        )
        _expect_string(selector["field"], selector_where + ".field", IDENTIFIER_RE)
        if selector["operation"] not in PROTOCOL_MEMBER_OPERATIONS:
            raise CatalogError("{}.operation has invalid value".format(selector_where))
        if phase != "bind":
            raise CatalogError("{} member-update phase must be bind".format(selector_where))
        key = (
            kind,
            selector["record_type"],
            selector["field"],
            selector["operation"],
        )
    else:
        expected_fields = {
            "kind",
            "name",
            "prototype",
            "phase",
            "expected_count",
        }
        if set(selector) != expected_fields:
            raise CatalogError(
                "{} function-call fields are not canonical".format(selector_where)
            )
        _expect_string(selector["name"], selector_where + ".name", IDENTIFIER_RE)
        _validate_prototype(selector["prototype"], selector_where + ".prototype")
        if phase != "pre-call":
            raise CatalogError("{} function-call phase must be pre-call".format(selector_where))
        key = (kind, selector["name"], _prototype_string(selector))

    expected_kind = {
        "descriptor-failed": "transfer-call",
        "ring-advanced": "member-update",
        "interrupt-published": "function-call",
    }[stage]
    if kind != expected_kind:
        raise CatalogError(
            "{} stage {!r} requires selector kind {!r}".format(
                selector_where, stage, expected_kind
            )
        )
    return key


def _validate_protocol(protocol, index, contracts_by_id):
    where = "protocols[{}]".format(index)
    _expect_object(protocol, PROTOCOL_KEYS, PROTOCOL_KEYS, where)
    _expect_string(protocol["id"], where + ".id", ID_RE)
    _expect_string(protocol["rule_id"], where + ".rule_id", ID_RE)
    if protocol["rule_id"] != "qemu.failed-completion-publication":
        raise CatalogError(
            "{}.rule_id must be 'qemu.failed-completion-publication'".format(where)
        )
    _expect_string(protocol["family"], where + ".family", FAMILY_RE)

    scope = protocol["scope"]
    _expect_object(scope, PROTOCOL_SCOPE_KEYS, PROTOCOL_SCOPE_KEYS, where + ".scope")
    if scope["kind"] != "function-definition":
        raise CatalogError("{}.scope.kind must be function-definition".format(where))
    _expect_string(scope["name"], where + ".scope.name", IDENTIFIER_RE)
    _validate_relative_source_path(scope["source"], where + ".scope.source")
    _validate_relative_source_path(
        scope["translation_unit"], where + ".scope.translation_unit"
    )
    _validate_prototype(scope["prototype"], where + ".scope.prototype")

    bindings = protocol["bindings"]
    if not isinstance(bindings, list) or len(bindings) != len(PROTOCOL_BINDING_ROLES):
        raise CatalogError(
            "{}.bindings must contain exactly {} entries".format(
                where, len(PROTOCOL_BINDING_ROLES)
            )
        )
    roles = set()
    bindings_by_role = {}
    for binding_index, binding in enumerate(bindings):
        role = _validate_protocol_binding(binding, protocol, binding_index, where)
        if role in roles:
            raise CatalogError("{} has duplicate binding role {!r}".format(where, role))
        roles.add(role)
        bindings_by_role[role] = binding
    if roles != PROTOCOL_BINDING_ROLES:
        missing = sorted(PROTOCOL_BINDING_ROLES - roles)
        raise CatalogError("{} is missing binding role(s): {}".format(where, ", ".join(missing)))
    owner_binding = bindings_by_role["owner"]
    owner_type = scope["prototype"]["parameters"][owner_binding["index"]]["type"]
    slot_binding = bindings_by_role["slot"]
    if _pointer_record_name(owner_type) != slot_binding["record_type"]:
        raise CatalogError(
            "{} owner pointee record type must match slot record_type".format(where)
        )

    events = protocol["events"]
    if not isinstance(events, list) or len(events) != len(PROTOCOL_STAGES):
        raise CatalogError(
            "{}.events must contain exactly the ordered failed-publication stages".format(
                where
            )
        )
    for event_index, (event, expected_stage) in enumerate(
        zip(events, PROTOCOL_STAGES)
    ):
        event_where = "{}.events[{}]".format(where, event_index)
        _expect_object(event, PROTOCOL_EVENT_KEYS, PROTOCOL_EVENT_KEYS, event_where)
        if event["stage"] != expected_stage:
            raise CatalogError(
                "{}.stage must be {!r}".format(event_where, expected_stage)
            )
        selectors = event["selectors"]
        if not isinstance(selectors, list) or not selectors:
            raise CatalogError("{}.selectors must be a non-empty array".format(event_where))
        seen = set()
        for selector_index, selector in enumerate(selectors):
            key = _validate_protocol_selector(
                selector,
                expected_stage,
                selector_index,
                contracts_by_id,
                event_where,
            )
            if key in seen:
                raise CatalogError(
                    "{} has duplicate protocol selector".format(event_where)
                )
            seen.add(key)
            if expected_stage == "ring-advanced" and (
                selector["record_type"] != slot_binding["record_type"]
                or selector["field"] != slot_binding["field"]
            ):
                raise CatalogError(
                    "{} ring-advanced member must match slot binding".format(
                        event_where
                    )
                )


def _validate_callback_binding(binding, index):
    where = "callback_bindings[{}]".format(index)
    _expect_object(binding, CALLBACK_BINDING_KEYS, CALLBACK_BINDING_KEYS, where)
    _expect_string(binding["id"], where + ".id", ID_RE)
    _expect_string(binding["family"], where + ".family", FAMILY_RE)

    rule_ids = binding["rule_ids"]
    if not isinstance(rule_ids, list) or not rule_ids:
        raise CatalogError("{}.rule_ids must be a non-empty array".format(where))
    seen_rules = set()
    for rule_index, rule_id in enumerate(rule_ids):
        _expect_string(rule_id, "{}.rule_ids[{}]".format(where, rule_index), ID_RE)
        if rule_id in seen_rules:
            raise CatalogError("{} has duplicate rule id {!r}".format(where, rule_id))
        seen_rules.add(rule_id)

    slot = binding["slot"]
    _expect_object(slot, CALLBACK_SLOT_KEYS, CALLBACK_SLOT_KEYS, where + ".slot")
    _expect_string(slot["record_type"], where + ".slot.record_type", IDENTIFIER_RE)
    _expect_string(slot["field"], where + ".slot.field", IDENTIFIER_RE)
    _expect_string(
        slot["implementation"], where + ".slot.implementation", IDENTIFIER_RE
    )
    _validate_header_path(slot["header"], where + ".slot.header")
    _validate_relative_source_path(
        slot["translation_unit"], where + ".slot.translation_unit"
    )

    parameters = _validate_prototype(binding["prototype"], where + ".prototype")

    registration = binding["registration"]
    _expect_object(
        registration,
        CALLBACK_REGISTRATION_KEYS,
        CALLBACK_REGISTRATION_KEYS,
        where + ".registration",
    )
    _expect_string(
        registration["record_type"],
        where + ".registration.record_type",
        IDENTIFIER_RE,
    )
    _expect_string(
        registration["field"], where + ".registration.field", IDENTIFIER_RE
    )
    _expect_string(
        registration["variable"],
        where + ".registration.variable",
        IDENTIFIER_RE,
    )
    _expect_string(
        registration["initializer"],
        where + ".registration.initializer",
        IDENTIFIER_RE,
    )
    _validate_header_path(
        registration["header"], where + ".registration.header"
    )
    _validate_relative_source_path(
        registration["translation_unit"],
        where + ".registration.translation_unit",
    )
    _validate_prototype(
        registration["prototype"], where + ".registration.prototype"
    )

    entry_inputs = binding["entry_inputs"]
    if not isinstance(entry_inputs, list) or not entry_inputs:
        raise CatalogError("{}.entry_inputs must be a non-empty array".format(where))
    roles = set()
    inputs_by_role = {}
    for input_index, entry_input in enumerate(entry_inputs):
        input_where = "{}.entry_inputs[{}]".format(where, input_index)
        _expect_object(
            entry_input,
            CALLBACK_ENTRY_INPUT_KEYS,
            {"role", "source", "index"},
            input_where,
        )
        role = entry_input["role"]
        source = entry_input["source"]
        _expect_string(role, input_where + ".role")
        if role not in CALLBACK_ENTRY_INPUT_ROLES:
            raise CatalogError("{}.role has invalid value {!r}".format(input_where, role))
        if role in roles:
            raise CatalogError("{} has duplicate entry-input role {!r}".format(where, role))
        roles.add(role)
        inputs_by_role[role] = entry_input
        if source not in CALLBACK_ENTRY_INPUT_SOURCES:
            raise CatalogError("{}.source has invalid value {!r}".format(input_where, source))
        argument_index = entry_input["index"]
        if type(argument_index) is not int or not 0 <= argument_index < len(parameters):
            raise CatalogError("{}.index is outside the prototype".format(input_where))
        if source == "argument_member":
            if "path" not in entry_input:
                raise CatalogError("{} argument_member input requires path".format(input_where))
            _validate_member_path(
                parameters[argument_index]["type"], entry_input["path"], input_where
            )
        elif "path" in entry_input:
            raise CatalogError("{} path is valid only for argument_member".format(input_where))

    input_buffers = binding["input_buffers"]
    if not isinstance(input_buffers, list):
        raise CatalogError("{}.input_buffers must be an array".format(where))
    seen_buffer_indices = set()
    for buffer_index, input_buffer in enumerate(input_buffers):
        buffer_where = "{}.input_buffers[{}]".format(where, buffer_index)
        _expect_object(
            input_buffer,
            CALLBACK_INPUT_BUFFER_KEYS,
            CALLBACK_INPUT_BUFFER_KEYS,
            buffer_where,
        )
        parameter_index = input_buffer["buffer_index"]
        if type(parameter_index) is not int or not 0 <= parameter_index < len(parameters):
            raise CatalogError("{}.buffer_index is outside the prototype".format(buffer_where))
        if parameter_index in seen_buffer_indices:
            raise CatalogError("{} has duplicate input-buffer parameter {}".format(where, parameter_index))
        seen_buffer_indices.add(parameter_index)
        if parameters[parameter_index]["type"] != "uint8_t *":
            raise CatalogError("{}.buffer_index must select a uint8_t * parameter".format(buffer_where))

        length_role = input_buffer["length_role"]
        _expect_string(length_role, buffer_where + ".length_role")
        length_input = inputs_by_role.get(length_role)
        if length_input is None or length_input["source"] != "argument":
            raise CatalogError(
                "{}.length_role must name a direct argument entry input".format(
                    buffer_where
                )
            )
        length_index = length_input["index"]
        if _is_pointer(parameters[length_index]["type"]):
            raise CatalogError("{}.length_role must select a scalar parameter".format(buffer_where))

        active_when = input_buffer["active_when"]
        _expect_object(
            active_when,
            CALLBACK_INPUT_BUFFER_CONDITION_KEYS,
            CALLBACK_INPUT_BUFFER_CONDITION_KEYS,
            buffer_where + ".active_when",
        )
        selector_role = active_when["role"]
        _expect_string(selector_role, buffer_where + ".active_when.role")
        selector_input = inputs_by_role.get(selector_role)
        if selector_input is None or selector_input["source"] != "argument":
            raise CatalogError(
                "{}.active_when.role must name a direct argument entry input".format(
                    buffer_where
                )
            )
        selector_index = selector_input["index"]
        if _is_pointer(parameters[selector_index]["type"]):
            raise CatalogError(
                "{}.active_when.role must select a scalar parameter".format(
                    buffer_where
                )
            )
        if len({parameter_index, length_index, selector_index}) != 3:
            raise CatalogError(
                "{} buffer, length, and selector parameters must be distinct".format(
                    buffer_where
                )
            )
        mask = active_when["mask"]
        equals = active_when["equals"]
        if type(mask) is not int or not 1 <= mask <= UNSIGNED_LONG_LONG_MAX:
            raise CatalogError(
                "{}.active_when.mask must be a nonzero uint64 value".format(
                    buffer_where
                )
            )
        if type(equals) is not int or not 0 <= equals <= UNSIGNED_LONG_LONG_MAX:
            raise CatalogError(
                "{}.active_when.equals must be a uint64 value".format(
                    buffer_where
                )
            )
        if equals & ~mask:
            raise CatalogError(
                "{}.active_when.equals sets bits outside mask".format(buffer_where)
            )

    has_buffer_rule = "qemu.callback-buffer.bounds" in seen_rules
    if has_buffer_rule != bool(input_buffers):
        raise CatalogError(
            "{}.input_buffers and qemu.callback-buffer.bounds must be present "
            "together".format(where)
        )

    return (slot["record_type"], slot["field"]), roles


def validate_catalog(catalog, profile="production"):
    # ``test-subset`` exists only so resolver unit fixtures can isolate one
    # selector family without fabricating every production anchor.  Generation
    # and the resolver CLI always use the fail-closed production profile.
    if profile not in VALIDATION_PROFILES:
        raise CatalogError("unknown catalog validation profile {!r}".format(profile))
    require_exact_qemu = profile == "production"
    _expect_object(catalog, CATALOG_KEYS, CATALOG_KEYS, "catalog")
    if type(catalog["catalog_format"]) is not int or catalog["catalog_format"] != 5:
        raise CatalogError("catalog.catalog_format must be integer 5")
    _expect_string(catalog["model_version"], "catalog.model_version", MODEL_RE)
    contracts = catalog["contracts"]
    if not isinstance(contracts, list) or not contracts:
        raise CatalogError("catalog.contracts must be a non-empty array")

    by_id = {}
    selectors = {}
    details = {}
    for index, contract in enumerate(contracts):
        roles, role_types = _validate_contract(
            contract, index, require_exact_qemu=require_exact_qemu
        )
        contract_id = contract["id"]
        if contract_id in by_id:
            raise CatalogError("duplicate contract id {!r}".format(contract_id))
        by_id[contract_id] = contract
        selector = contract["selector"]["name"]
        if selector in selectors:
            raise CatalogError("duplicate function selector {!r}".format(selector))
        selectors[selector] = contract_id
        details[contract_id] = (roles, role_types)

    for contract_id, contract in by_id.items():
        if contract["kind"] in {"transfer", "packet-copy", "initialize-resource"}:
            continue
        pair_id = contract["pair"]["contract_id"]
        if pair_id not in by_id:
            raise CatalogError("{} pairs with missing contract {}".format(contract_id, pair_id))
        pair = by_id[pair_id]
        if pair["kind"] in {"transfer", "packet-copy", "initialize-resource"} or pair["pair"] is None:
            raise CatalogError("{} pairs with an unpaired contract {}".format(contract_id, pair_id))
        if pair["pair"]["contract_id"] != contract_id:
            raise CatalogError("{} and {} are not reciprocal pairs".format(contract_id, pair_id))
        if pair["kind"] == contract["kind"]:
            raise CatalogError("{} and {} have the same contract kind".format(contract_id, pair_id))
        if pair["family"] != contract["family"]:
            raise CatalogError("{} and {} have different families".format(contract_id, pair_id))
        if pair["direction_encoding"] != contract["direction_encoding"]:
            raise CatalogError("{} and {} have different direction encodings".format(contract_id, pair_id))

        roles, role_types = details[contract_id]
        pair_roles, pair_role_types = details[pair_id]
        if contract["kind"] in {"map", "unmap"}:
            for role in ("mapped_buffer", "mapped_length", "direction"):
                if role_types[role] != pair_role_types[role]:
                    raise CatalogError(
                        "{} and {} disagree on {} type".format(contract_id, pair_id, role)
                    )
            if ("owner" in roles) != ("owner" in pair_roles):
                raise CatalogError("{} and {} disagree on owner presence".format(contract_id, pair_id))
            if "owner" in roles and role_types["owner"] != pair_role_types["owner"]:
                raise CatalogError("{} and {} disagree on owner type".format(contract_id, pair_id))
        else:
            for role in ("memory_region", "notifier"):
                if role_types[role] != pair_role_types[role]:
                    raise CatalogError(
                        "{} and {} disagree on {} type".format(contract_id, pair_id, role)
                    )

    callbacks = catalog["callback_bindings"]
    if not isinstance(callbacks, list):
        raise CatalogError("catalog.callback_bindings must be an array")
    callback_ids = set()
    callback_slots = set()
    callback_roles = {}
    for index, callback in enumerate(callbacks):
        slot, roles = _validate_callback_binding(callback, index)
        callback_id = callback["id"]
        if callback_id in by_id or callback_id in callback_ids:
            raise CatalogError("duplicate catalog id {!r}".format(callback_id))
        if slot in callback_slots:
            raise CatalogError(
                "duplicate callback slot {}.{}".format(slot[0], slot[1])
            )
        callback_ids.add(callback_id)
        callback_slots.add(slot)
        callback_roles[callback_id] = roles

    expected_callbacks = {
        "qemu.usb-device.handle-control": {
            "field": "handle_control",
            "prototype": (
                "void (USBDevice *, USBPacket *, int, int, int, int, uint8_t *)"
            ),
            "rules": {
                "qemu.callback-buffer.bounds",
                "qemu.guest-memory.bounds",
            },
            "roles": {
                "control-request",
                "control-value",
                "control-index",
                "control-length",
            },
            "input_buffers": [
                {
                    "buffer_index": 6,
                    "length_role": "control-length",
                    "active_when": {
                        "role": "control-request",
                        "mask": 32768,
                        "equals": 0,
                    },
                }
            ],
        },
        "qemu.usb-device.handle-data": {
            "field": "handle_data",
            "prototype": "void (USBDevice *, USBPacket *)",
            "rules": {
                "qemu.guest-memory.bounds",
                "qemu.initialized-bytes.disclosure",
            },
            "roles": {
                "packet-direction",
                "packet-capacity-selector",
                "packet-primary-capacity",
                "packet-alternate-capacity",
                "packet-setup-parameter",
                "packet-endpoint-number",
                "packet-endpoint-type",
            },
            "input_buffers": [],
        },
    }
    if require_exact_qemu and set(callback_roles) != set(expected_callbacks):
        raise CatalogError("catalog.callback_bindings must contain the exact USB callback set")
    for callback in callbacks:
        callback_id = callback["id"]
        if callback_id not in expected_callbacks:
            if require_exact_qemu:
                raise CatalogError(
                    "catalog.callback_bindings must contain the exact USB callback set"
                )
            continue
        if callback["family"] != "usb":
            raise CatalogError("{} must belong to USB family".format(callback_id))
        expected = expected_callbacks[callback_id]
        if callback_roles[callback_id] != expected["roles"]:
            raise CatalogError("{} has an incomplete entry-input role set".format(callback_id))
        if callback["input_buffers"] != expected["input_buffers"]:
            raise CatalogError(
                "{} has an invalid conditional input-buffer relation".format(
                    callback_id
                )
            )
        slot = callback["slot"]
        if (
            slot["record_type"] != "USBDeviceClass"
            or slot["field"] != expected["field"]
            or slot["header"] != "include/hw/usb/usb.h"
            or slot["translation_unit"] != "hw/usb/bus.c"
            or _prototype_type_string(callback["prototype"])
            != expected["prototype"]
            or set(callback["rule_ids"]) != expected["rules"]
        ):
            raise CatalogError(
                "{} has an invalid USBDeviceClass callback slot".format(callback_id)
            )
        inputs_by_role = {
            entry_input["role"]: entry_input
            for entry_input in callback["entry_inputs"]
        }
        expected_inputs = {
            "qemu.usb-device.handle-control": {
                "control-request": ("argument", 2, "int"),
                "control-value": ("argument", 3, "int"),
                "control-index": ("argument", 4, "int"),
                "control-length": ("argument", 5, "int"),
            },
            "qemu.usb-device.handle-data": {
                "packet-direction": ("argument_member", 1, "int"),
                "packet-capacity-selector": (
                    "argument_member",
                    1,
                    "USBCombinedPacket *",
                ),
                "packet-primary-capacity": ("argument_member", 1, "size_t"),
                "packet-alternate-capacity": ("argument_member", 1, "size_t"),
                "packet-setup-parameter": ("argument_member", 1, "uint64_t"),
                "packet-endpoint-number": ("argument_member", 1, "uint8_t"),
                "packet-endpoint-type": ("argument_member", 1, "uint8_t"),
            },
        }[callback_id]
        for role, (source, argument_index, expected_type) in expected_inputs.items():
            entry_input = inputs_by_role[role]
            actual_type = (
                callback["prototype"]["parameters"][argument_index]["type"]
                if source == "argument"
                else entry_input["path"][-1]["type"]
            )
            if (
                entry_input["source"] != source
                or entry_input["index"] != argument_index
                or actual_type != expected_type
            ):
                raise CatalogError(
                    "{} has an invalid {} entry input".format(callback_id, role)
                )
            expected_path = USB_CALLBACK_MEMBER_PATHS.get(role)
            if require_exact_qemu and expected_path is not None and (
                _path_signature(entry_input["path"]) != expected_path
            ):
                raise CatalogError(
                    "{} has an invalid {} member path".format(callback_id, role)
                )
        registration = callback["registration"]
        if (
            registration["record_type"] != "TypeInfo"
            or registration["field"] != "class_init"
            or registration["header"] != "include/qom/object.h"
            or registration["translation_unit"] != "hw/usb/u2f.c"
            or registration["variable"] != "u2f_key_info"
            or registration["initializer"] != "u2f_key_class_init"
            or _prototype_type_string(registration["prototype"])
            != "void (ObjectClass *, const void *)"
        ):
            raise CatalogError("{} has an invalid TypeInfo.class_init root".format(callback_id))
        expected_implementation = {
            "qemu.usb-device.handle-control": "u2f_key_handle_control",
            "qemu.usb-device.handle-data": "u2f_key_handle_data",
        }[callback_id]
        if slot["implementation"] != expected_implementation:
            raise CatalogError(
                "{} has an invalid USBDeviceClass callback implementation".format(
                    callback_id
                )
            )

    protocols = catalog["protocols"]
    if not isinstance(protocols, list):
        raise CatalogError("catalog.protocols must be an array")
    protocol_ids = set()
    for index, protocol in enumerate(protocols):
        _validate_protocol(protocol, index, by_id)
        protocol_id = protocol["id"]
        if protocol_id in by_id or protocol_id in callback_ids or protocol_id in protocol_ids:
            raise CatalogError("duplicate catalog id {!r}".format(protocol_id))
        protocol_ids.add(protocol_id)
    return catalog


def validate_schema_document(schema):
    if not isinstance(schema, dict):
        raise CatalogError("schema must be an object")
    if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
        raise CatalogError("schema must use JSON Schema draft 2020-12")
    if schema.get("type") != "object":
        raise CatalogError("schema root must describe an object")
    if schema.get("additionalProperties") is not False:
        raise CatalogError("schema root must reject unknown fields")
    root_fields = set(schema.get("properties", {}))
    root_required = set(schema.get("required", []))
    if root_fields != CATALOG_KEYS or root_required != CATALOG_KEYS:
        raise CatalogError("schema root fields do not match generator fields")
    if schema["properties"]["catalog_format"].get("const") != 5:
        raise CatalogError("schema catalog_format does not match generator format")
    if schema["properties"]["model_version"].get("pattern") != MODEL_RE.pattern:
        raise CatalogError("schema model_version pattern does not match generator")

    expected_root_arrays = {
        "contracts": {
            "type": "array",
            "minItems": 1,
            "items": {"$ref": "#/$defs/contract"},
        },
        "callback_bindings": {
            "type": "array",
            "minItems": 2,
            "maxItems": 2,
            "uniqueItems": True,
            "items": {"$ref": "#/$defs/callback_binding"},
        },
        "protocols": {
            "type": "array",
            "items": {"$ref": "#/$defs/protocol"},
        },
    }
    for field, expected in expected_root_arrays.items():
        if schema["properties"].get(field) != expected:
            raise CatalogError(
                "schema {} array/cardinality/ref semantics do not match generator".format(
                    field
                )
            )

    definitions = schema.get("$defs")
    expected_definitions = {
        "selector",
        "parameter",
        "prototype",
        "operand",
        "member_step",
        "rhs",
        "predicate",
        "predicates",
        "effect",
        "pair",
        "contract",
        "callback_slot",
        "callback_registration",
        "callback_entry_input",
        "callback_input_buffer_condition",
        "callback_input_buffer",
        "callback_binding",
        "protocol_scope",
        "protocol_binding",
        "protocol_selector",
        "protocol_event",
        "protocol",
    }
    if not isinstance(definitions, dict) or not expected_definitions.issubset(definitions):
        raise CatalogError("schema is missing a generator definition")

    object_definitions = {
        "selector": (SELECTOR_KEYS, SELECTOR_KEYS),
        "parameter": (PARAMETER_KEYS, PARAMETER_KEYS),
        "prototype": (PROTOTYPE_KEYS, PROTOTYPE_KEYS),
        "operand": (OPERAND_KEYS, {"role", "source", "phase"}),
        "member_step": (MEMBER_STEP_KEYS, MEMBER_STEP_KEYS),
        "predicates": (PREDICATE_NAMES, PREDICATE_NAMES),
        "effect": (EFFECT_KEYS, {"kind", "when", "target"}),
        "pair": (PAIR_KEYS, PAIR_KEYS),
        "contract": (CONTRACT_KEYS, CONTRACT_KEYS - {"additional_rule_ids"}),
        "callback_slot": (CALLBACK_SLOT_KEYS, CALLBACK_SLOT_KEYS),
        "callback_registration": (
            CALLBACK_REGISTRATION_KEYS,
            CALLBACK_REGISTRATION_KEYS,
        ),
        "callback_entry_input": (
            CALLBACK_ENTRY_INPUT_KEYS,
            {"role", "source", "index"},
        ),
        "callback_input_buffer_condition": (
            CALLBACK_INPUT_BUFFER_CONDITION_KEYS,
            CALLBACK_INPUT_BUFFER_CONDITION_KEYS,
        ),
        "callback_input_buffer": (
            CALLBACK_INPUT_BUFFER_KEYS,
            CALLBACK_INPUT_BUFFER_KEYS,
        ),
        "callback_binding": (CALLBACK_BINDING_KEYS, CALLBACK_BINDING_KEYS),
        "protocol_scope": (PROTOCOL_SCOPE_KEYS, PROTOCOL_SCOPE_KEYS),
        "protocol_binding": (
            PROTOCOL_BINDING_KEYS,
            {"role", "source"},
        ),
        "protocol_selector": (
            PROTOCOL_SELECTOR_KEYS,
            {"kind", "phase", "expected_count"},
        ),
        "protocol_event": (PROTOCOL_EVENT_KEYS, PROTOCOL_EVENT_KEYS),
        "protocol": (PROTOCOL_KEYS, PROTOCOL_KEYS),
    }
    for name, (fields, required) in object_definitions.items():
        definition = definitions[name]
        if not isinstance(definition, dict) or definition.get("type") != "object":
            raise CatalogError("schema {} must describe an object".format(name))
        if definition.get("additionalProperties") is not False:
            raise CatalogError("schema {} must reject unknown fields".format(name))
        if set(definition.get("properties", {})) != fields or set(
            definition.get("required", [])
        ) != required:
            raise CatalogError(
                "schema {} fields do not match generator fields".format(name)
            )

    expected_array_fields = {
        ("prototype", "parameters"): {
            "type": "array",
            "minItems": 1,
            "items": {"$ref": "#/$defs/parameter"},
        },
        ("contract", "additional_rule_ids"): {
            "type": "array",
            "maxItems": 1,
            "uniqueItems": True,
            "items": {"type": "string", "pattern": ID_RE.pattern},
        },
        ("callback_binding", "rule_ids"): {
            "type": "array",
            "minItems": 1,
            "maxItems": 2,
            "uniqueItems": True,
            "items": {"type": "string", "pattern": ID_RE.pattern},
        },
        ("callback_binding", "entry_inputs"): {
            "type": "array",
            "minItems": 1,
            "maxItems": 7,
            "uniqueItems": True,
            "items": {"$ref": "#/$defs/callback_entry_input"},
        },
        ("callback_binding", "input_buffers"): {
            "type": "array",
            "maxItems": 4,
            "uniqueItems": True,
            "items": {"$ref": "#/$defs/callback_input_buffer"},
        },
    }
    for (definition, field), expected in expected_array_fields.items():
        if definitions[definition]["properties"].get(field) != expected:
            raise CatalogError(
                "schema {}.{} array/cardinality/ref semantics do not match generator".format(
                    definition, field
                )
            )

    expected_callback_properties = {
        "callback_slot": {
            "record_type": {"type": "string", "pattern": IDENTIFIER_RE.pattern},
            "field": {"type": "string", "pattern": IDENTIFIER_RE.pattern},
            "header": {"type": "string", "pattern": HEADER_RE.pattern},
            "translation_unit": {
                "type": "string",
                "pattern": TRANSLATION_UNIT_RE.pattern,
            },
            "implementation": {
                "type": "string",
                "pattern": IDENTIFIER_RE.pattern,
            },
        },
        "callback_registration": {
            "record_type": {"type": "string", "pattern": IDENTIFIER_RE.pattern},
            "field": {"type": "string", "pattern": IDENTIFIER_RE.pattern},
            "header": {"type": "string", "pattern": HEADER_RE.pattern},
            "translation_unit": {
                "type": "string",
                "pattern": TRANSLATION_UNIT_RE.pattern,
            },
            "variable": {"type": "string", "pattern": IDENTIFIER_RE.pattern},
            "initializer": {
                "type": "string",
                "pattern": IDENTIFIER_RE.pattern,
            },
            "prototype": {"$ref": "#/$defs/prototype"},
        },
    }
    for definition, expected in expected_callback_properties.items():
        if definitions[definition]["properties"] != expected:
            raise CatalogError(
                "schema {} property semantics do not match generator".format(
                    definition
                )
            )

    callback_input_properties = definitions["callback_entry_input"]["properties"]
    if callback_input_properties.get("index") != {
        "type": "integer",
        "minimum": 0,
    }:
        raise CatalogError(
            "schema callback_entry_input.index semantics do not match generator"
        )
    for field in ("role", "source"):
        if set(callback_input_properties[field]) != {"enum"}:
            raise CatalogError(
                "schema callback_entry_input.{} semantics do not match generator".format(
                    field
                )
            )
    if callback_input_properties.get("path") != {
        "type": "array",
        "minItems": 1,
        "maxItems": 8,
        "items": {"$ref": "#/$defs/member_step"},
    }:
        raise CatalogError(
            "schema callback_entry_input.path semantics do not match generator"
        )

    callback_binding_properties = definitions["callback_binding"]["properties"]
    expected_callback_binding_scalars = {
        "id": {"type": "string", "pattern": ID_RE.pattern},
        "family": {"type": "string", "pattern": FAMILY_RE.pattern},
        "slot": {"$ref": "#/$defs/callback_slot"},
        "prototype": {"$ref": "#/$defs/prototype"},
        "registration": {"$ref": "#/$defs/callback_registration"},
    }
    for field, expected in expected_callback_binding_scalars.items():
        if callback_binding_properties.get(field) != expected:
            raise CatalogError(
                "schema callback_binding.{} semantics do not match generator".format(
                    field
                )
            )

    callback_input_buffer_properties = definitions["callback_input_buffer"][
        "properties"
    ]
    if callback_input_buffer_properties != {
        "buffer_index": {"type": "integer", "minimum": 0},
        "length_role": {
            "type": "string",
            "pattern": IDENTIFIER_RE.pattern,
        },
        "active_when": {
            "$ref": "#/$defs/callback_input_buffer_condition"
        },
    }:
        raise CatalogError(
            "schema callback_input_buffer property semantics do not match generator"
        )
    callback_condition_properties = definitions[
        "callback_input_buffer_condition"
    ]["properties"]
    expected_uint64 = {
        "type": "integer",
        "minimum": 0,
        "maximum": UNSIGNED_LONG_LONG_MAX,
    }
    if callback_condition_properties != {
        "role": {"type": "string", "pattern": IDENTIFIER_RE.pattern},
        "mask": {
            "type": "integer",
            "minimum": 1,
            "maximum": UNSIGNED_LONG_LONG_MAX,
        },
        "equals": expected_uint64,
    }:
        raise CatalogError(
            "schema callback_input_buffer_condition property semantics do not match generator"
        )

    def require_enum(definition, field, expected):
        actual = definitions[definition]["properties"][field].get("enum")
        if not isinstance(actual, list) or set(actual) != expected or len(actual) != len(
            expected
        ):
            raise CatalogError(
                "schema {}.{} values do not match generator values".format(
                    definition, field
                )
            )

    selector_kind = definitions["selector"]["properties"]["kind"].get("const")
    if selector_kind != "function":
        raise CatalogError("schema selector.kind does not match generator")
    require_enum("operand", "role", OPERAND_ROLES)
    require_enum("operand", "source", OPERAND_SOURCES)
    require_enum("operand", "phase", OPERAND_PHASES)
    require_enum("effect", "kind", EFFECT_KINDS)
    require_enum("effect", "when", PREDICATE_NAMES)
    require_enum("callback_entry_input", "role", CALLBACK_ENTRY_INPUT_ROLES)
    require_enum("callback_entry_input", "source", CALLBACK_ENTRY_INPUT_SOURCES)
    require_enum("effect", "epoch", {"create", "retire"})
    require_enum(
        "pair",
        "relation",
        {
            "map-to-unmap",
            "unmap-to-map",
            "register-callback-to-unregister-callback",
            "unregister-callback-to-register-callback",
        },
    )
    require_enum(
        "contract",
        "kind",
        {
            "map",
            "unmap",
            "transfer",
            "packet-copy",
            "initialize-resource",
            "register-callback",
            "unregister-callback",
        },
    )
    require_enum("contract", "direction_encoding", DIRECTION_ENCODINGS)
    require_enum("protocol_binding", "role", PROTOCOL_BINDING_ROLES)
    require_enum("protocol_binding", "source", PROTOCOL_BINDING_SOURCES)
    require_enum("protocol_selector", "kind", PROTOCOL_SELECTOR_KINDS)
    require_enum("protocol_selector", "phase", PROTOCOL_SELECTOR_PHASES)
    require_enum("protocol_selector", "operation", PROTOCOL_MEMBER_OPERATIONS)
    require_enum("protocol_event", "stage", set(PROTOCOL_STAGES))

    member_path = definitions["operand"]["properties"]["path"]
    if (
        member_path.get("type") != "array"
        or member_path.get("minItems") != 1
        or member_path.get("maxItems") != 8
        or member_path.get("items") != {"$ref": "#/$defs/member_step"}
    ):
        raise CatalogError("schema operand.path does not match generator member paths")
    callback_member_path = definitions["callback_entry_input"]["properties"]["path"]
    if (
        callback_member_path.get("type") != "array"
        or callback_member_path.get("minItems") != 1
        or callback_member_path.get("maxItems") != 8
        or callback_member_path.get("items") != {"$ref": "#/$defs/member_step"}
    ):
        raise CatalogError(
            "schema callback_entry_input.path does not match generator member paths"
        )

    scope_kind = definitions["protocol_scope"]["properties"]["kind"].get(
        "const"
    )
    if scope_kind != "function-definition":
        raise CatalogError("schema protocol_scope.kind does not match generator")
    result_path = definitions["protocol_selector"]["properties"][
        "result_path"
    ].get("const")
    if result_path != "failure":
        raise CatalogError("schema protocol_selector.result_path does not match generator")
    integer_value = definitions["protocol_binding"]["properties"]["value"]
    if (
        integer_value.get("minimum") != SIGNED_LONG_LONG_MIN
        or integer_value.get("maximum") != SIGNED_LONG_LONG_MAX
    ):
        raise CatalogError(
            "schema protocol_binding.value bounds do not match generator"
        )

    predicate_alternatives = definitions["predicate"].get("oneOf")
    if not isinstance(predicate_alternatives, list):
        raise CatalogError("schema predicate must describe alternatives")
    required_alternatives = {
        frozenset(alternative.get("required", []))
        for alternative in predicate_alternatives
        if isinstance(alternative, dict)
    }
    expected_alternatives = {
        frozenset({"constant"}),
        frozenset({"operand", "operator"}),
        frozenset({"all"}),
        frozenset({"any"}),
        frozenset({"not"}),
    }
    if required_alternatives != expected_alternatives or len(
        predicate_alternatives
    ) != len(expected_alternatives):
        raise CatalogError("schema predicate alternatives do not match generator")
    comparison = next(
        alternative
        for alternative in predicate_alternatives
        if set(alternative.get("required", [])) == {"operand", "operator"}
    )
    operators = comparison.get("properties", {}).get("operator", {}).get("enum")
    if not isinstance(operators, list) or set(operators) != PREDICATE_OPERATORS or len(
        operators
    ) != len(PREDICATE_OPERATORS):
        raise CatalogError("schema predicate operators do not match generator")

    rhs_alternatives = definitions["rhs"].get("oneOf")
    rhs_required = {
        frozenset(alternative.get("required", []))
        for alternative in rhs_alternatives or []
        if isinstance(alternative, dict)
    }
    if rhs_required != {frozenset({"operand"}), frozenset({"integer"})} or len(
        rhs_alternatives or []
    ) != 2:
        raise CatalogError("schema predicate rhs alternatives do not match generator")

    parameter_type = definitions["parameter"]["properties"]["type"]
    return_type = definitions["prototype"]["properties"]["return_type"]
    if parameter_type.get("pattern") != TYPE_RE.pattern or return_type.get(
        "pattern"
    ) != TYPE_RE.pattern:
        raise CatalogError("schema C type patterns do not match generator")
    if definitions["contract"]["properties"]["id"].get("pattern") != ID_RE.pattern:
        raise CatalogError("schema contract.id pattern does not match generator")
    if definitions["contract"]["properties"]["rule_id"].get("pattern") != ID_RE.pattern:
        raise CatalogError("schema contract.rule_id pattern does not match generator")
    additional_rule_items = definitions["contract"]["properties"][
        "additional_rule_ids"
    ].get("items", {})
    if additional_rule_items.get("pattern") != ID_RE.pattern:
        raise CatalogError(
            "schema contract.additional_rule_ids pattern does not match generator"
        )
    if definitions["contract"]["properties"]["family"].get(
        "pattern"
    ) != FAMILY_RE.pattern:
        raise CatalogError("schema contract.family pattern does not match generator")
    if definitions["selector"]["properties"]["name"].get(
        "pattern"
    ) != IDENTIFIER_RE.pattern or definitions["parameter"]["properties"]["name"].get(
        "pattern"
    ) != IDENTIFIER_RE.pattern:
        raise CatalogError("schema identifier patterns do not match generator")
    if definitions["selector"]["properties"]["header"].get(
        "pattern"
    ) != HEADER_RE.pattern:
        raise CatalogError("schema header pattern does not match generator")
    if definitions["member_step"]["properties"]["header"].get(
        "pattern"
    ) != HEADER_RE.pattern:
        raise CatalogError("schema member_step.header pattern does not match generator")
    if definitions["member_step"]["properties"]["type"].get(
        "pattern"
    ) != TYPE_RE.pattern:
        raise CatalogError("schema member_step.type pattern does not match generator")
    for field in ("record_type", "field"):
        if definitions["member_step"]["properties"][field].get(
            "pattern"
        ) != IDENTIFIER_RE.pattern:
            raise CatalogError(
                "schema member_step.{} pattern does not match generator".format(
                    field
                )
            )
    if definitions["selector"]["properties"]["translation_unit"].get(
        "pattern"
    ) != TRANSLATION_UNIT_RE.pattern:
        raise CatalogError("schema translation-unit pattern does not match generator")
    if definitions["pair"]["properties"]["contract_id"].get(
        "pattern"
    ) != ID_RE.pattern:
        raise CatalogError("schema pair.contract_id pattern does not match generator")
    for definition, field in (
        ("protocol", "id"),
        ("protocol", "rule_id"),
        ("protocol_selector", "contract_id"),
    ):
        if definitions[definition]["properties"][field].get("pattern") != ID_RE.pattern:
            raise CatalogError(
                "schema {}.{} pattern does not match generator".format(
                    definition, field
                )
            )
    if definitions["protocol"]["properties"]["family"].get(
        "pattern"
    ) != FAMILY_RE.pattern:
        raise CatalogError("schema protocol.family pattern does not match generator")
    if definitions["callback_binding"]["properties"]["id"].get(
        "pattern"
    ) != ID_RE.pattern:
        raise CatalogError("schema callback_binding.id pattern does not match generator")
    callback_rule_items = definitions["callback_binding"]["properties"][
        "rule_ids"
    ].get("items", {})
    if callback_rule_items.get("pattern") != ID_RE.pattern:
        raise CatalogError(
            "schema callback_binding.rule_ids pattern does not match generator"
        )
    if definitions["callback_binding"]["properties"]["family"].get(
        "pattern"
    ) != FAMILY_RE.pattern:
        raise CatalogError(
            "schema callback_binding.family pattern does not match generator"
        )
    for definition, identifier_fields in (
        ("callback_slot", ("record_type", "field", "implementation")),
        (
            "callback_registration",
            ("record_type", "field", "variable", "initializer"),
        ),
    ):
        for field in identifier_fields:
            if (
                definitions[definition]["properties"][field].get("pattern")
                != IDENTIFIER_RE.pattern
            ):
                raise CatalogError(
                    "schema {}.{} pattern does not match generator".format(
                        definition, field
                    )
                )
        if (
            definitions[definition]["properties"]["header"].get("pattern")
            != HEADER_RE.pattern
        ):
            raise CatalogError(
                "schema {}.header pattern does not match generator".format(
                    definition
                )
            )
        if (
            definitions[definition]["properties"]["translation_unit"].get(
                "pattern"
            )
            != TRANSLATION_UNIT_RE.pattern
        ):
            raise CatalogError(
                "schema {}.translation_unit pattern does not match generator".format(
                    definition
                )
            )
    for definition, fields in (
        ("protocol_scope", ("name",)),
        ("protocol_binding", ("record_type", "field")),
        ("protocol_selector", ("name", "record_type", "field")),
    ):
        for field in fields:
            if (
                definitions[definition]["properties"][field].get("pattern")
                != IDENTIFIER_RE.pattern
            ):
                raise CatalogError(
                    "schema {}.{} pattern does not match generator".format(
                        definition, field
                    )
                )
    for field in ("source", "translation_unit"):
        if definitions["protocol_scope"]["properties"][field].get(
            "pattern"
        ) != TRANSLATION_UNIT_RE.pattern:
            raise CatalogError(
                "schema protocol_scope.{} pattern does not match generator".format(
                    field
                )
            )
    contract_pair = definitions["contract"]["properties"]["pair"].get("oneOf")
    if (
        not isinstance(contract_pair, list)
        or len(contract_pair) != 2
        or not all(isinstance(alternative, dict) for alternative in contract_pair)
        or {"$ref": "#/$defs/pair"} not in contract_pair
        or {"type": "null"} not in contract_pair
    ):
        raise CatalogError("schema contract.pair must be a pair object or null")
    if _sha256(schema) != EXPECTED_SCHEMA_SHA256:
        raise CatalogError(
            "schema canonical identity does not match the generator's exact schema"
        )


def _normalized_catalog(catalog):
    normalized = copy.deepcopy(catalog)
    normalized["contracts"].sort(key=lambda contract: contract["id"])
    for contract in normalized["contracts"]:
        if "additional_rule_ids" in contract:
            contract["additional_rule_ids"].sort()
        contract["operands"].sort(
            key=lambda operand: (
                operand["role"],
                operand["source"],
                operand.get("index", -1),
                operand["phase"],
            )
        )
        contract["effects"].sort(key=lambda effect: effect["kind"])
    normalized["callback_bindings"].sort(key=lambda callback: callback["id"])
    for callback in normalized["callback_bindings"]:
        callback["rule_ids"].sort()
        callback["entry_inputs"].sort(
            key=lambda entry_input: (
                entry_input["role"],
                entry_input["source"],
                entry_input["index"],
            )
        )
        callback["input_buffers"].sort(
            key=lambda input_buffer: (
                input_buffer["buffer_index"],
                input_buffer["length_role"],
                input_buffer["active_when"]["role"],
                input_buffer["active_when"]["mask"],
                input_buffer["active_when"]["equals"],
            )
        )
    normalized["protocols"].sort(key=lambda protocol: protocol["id"])
    for protocol in normalized["protocols"]:
        protocol["bindings"].sort(key=lambda binding: binding["role"])
        for event in protocol["events"]:
            event["selectors"].sort(
                key=lambda selector: _canonical_json(selector)
            )
    return normalized


def _canonical_json(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def _sha256(value):
    return hashlib.sha256((_canonical_json(value) + "\n").encode("utf-8")).hexdigest()


def _cpp_string(value):
    return json.dumps(value, ensure_ascii=True)


def _cpp_signed_long_long(value):
    if value == SIGNED_LONG_LONG_MIN:
        return "(-9223372036854775807LL - 1LL)"
    return "{}LL".format(value)


def _prototype_string(contract):
    return _prototype_type_string(contract["prototype"])


def generate(catalog, schema):
    validate_catalog(catalog)
    validate_schema_document(schema)
    catalog = _normalized_catalog(catalog)
    catalog_hash = _sha256(catalog)
    schema_hash = _sha256(schema)

    parameters = []
    operands = []
    member_steps = []
    effects = []
    additional_rules = []
    contracts = []
    for contract in catalog["contracts"]:
        additional_rule_begin = len(additional_rules)
        for rule_id in contract.get("additional_rule_ids", []):
            additional_rules.append((contract["id"], rule_id))
        parameter_begin = len(parameters)
        for index, parameter in enumerate(contract["prototype"]["parameters"]):
            parameters.append((contract["id"], index, parameter["name"], parameter["type"]))
        operand_begin = len(operands)
        for operand in contract["operands"]:
            member_begin = len(member_steps)
            for step in operand.get("path", []):
                member_steps.append(
                    (
                        contract["id"],
                        operand["role"],
                        step["record_type"],
                        step["field"],
                        step["type"],
                        step["header"],
                    )
                )
            operands.append(
                (
                    contract["id"],
                    operand["role"],
                    operand["source"],
                    operand.get("index", -1),
                    operand["phase"],
                    member_begin,
                    len(operand.get("path", [])),
                )
            )
        effect_begin = len(effects)
        for effect in contract["effects"]:
            effects.append(
                (
                    contract["id"],
                    effect["kind"],
                    effect["when"],
                    effect["target"],
                    effect.get("extent", ""),
                    effect.get("requested_extent", ""),
                    effect.get("access_extent", ""),
                    effect.get("direction", ""),
                    effect.get("owner", ""),
                    effect.get("callback", ""),
                    effect.get("memory_region", ""),
                    effect.get("epoch", ""),
                    effect.get("offset", ""),
                    effect.get("capacity_selector", ""),
                    effect.get("primary_capacity", ""),
                    effect.get("alternate_capacity", ""),
                )
            )
        contracts.append(
            (
                contract,
                parameter_begin,
                len(contract["prototype"]["parameters"]),
                operand_begin,
                len(contract["operands"]),
                effect_begin,
                len(contract["effects"]),
                additional_rule_begin,
                len(contract.get("additional_rule_ids", [])),
            )
        )

    callback_rules = []
    callback_parameters = []
    callback_member_steps = []
    callback_entry_inputs = []
    callback_input_buffers = []
    callback_bindings = []
    for callback in catalog["callback_bindings"]:
        rule_begin = len(callback_rules)
        for rule_id in callback["rule_ids"]:
            callback_rules.append((callback["id"], rule_id))
        parameter_begin = len(callback_parameters)
        for index, parameter in enumerate(callback["prototype"]["parameters"]):
            callback_parameters.append(
                (callback["id"], index, parameter["name"], parameter["type"])
            )
        input_begin = len(callback_entry_inputs)
        for entry_input in callback["entry_inputs"]:
            member_begin = len(callback_member_steps)
            for step in entry_input.get("path", []):
                callback_member_steps.append(
                    (
                        callback["id"],
                        entry_input["role"],
                        step["record_type"],
                        step["field"],
                        step["type"],
                        step["header"],
                    )
                )
            callback_entry_inputs.append(
                (
                    callback["id"],
                    entry_input["role"],
                    entry_input["source"],
                    entry_input["index"],
                    member_begin,
                    len(entry_input.get("path", [])),
                )
            )
        inputs_by_role = {
            entry_input["role"]: entry_input
            for entry_input in callback["entry_inputs"]
        }
        input_buffer_begin = len(callback_input_buffers)
        for input_buffer in callback["input_buffers"]:
            active_when = input_buffer["active_when"]
            callback_input_buffers.append(
                (
                    callback["id"],
                    input_buffer["buffer_index"],
                    inputs_by_role[input_buffer["length_role"]]["index"],
                    inputs_by_role[active_when["role"]]["index"],
                    active_when["mask"],
                    active_when["equals"],
                )
            )
        callback_bindings.append(
            (
                callback,
                rule_begin,
                len(callback["rule_ids"]),
                parameter_begin,
                len(callback["prototype"]["parameters"]),
                input_begin,
                len(callback["entry_inputs"]),
                input_buffer_begin,
                len(callback["input_buffers"]),
            )
        )

    protocol_bindings = []
    protocol_events = []
    protocol_selectors = []
    protocols = []
    for protocol in catalog["protocols"]:
        binding_begin = len(protocol_bindings)
        for binding in protocol["bindings"]:
            protocol_bindings.append(
                (
                    protocol["id"],
                    binding["role"],
                    binding["source"],
                    binding.get("index", -1),
                    binding.get("record_type", ""),
                    binding.get("field", ""),
                    binding.get("value", 0),
                    "value" in binding,
                )
            )
        event_begin = len(protocol_events)
        for event in protocol["events"]:
            selector_begin = len(protocol_selectors)
            for selector in event["selectors"]:
                protocol_selectors.append(
                    (
                        protocol["id"],
                        event["stage"],
                        selector["kind"],
                        selector.get("contract_id", ""),
                        selector.get("name", ""),
                        _prototype_string(selector)
                        if "prototype" in selector
                        else "",
                        selector.get("record_type", ""),
                        selector.get("field", ""),
                        selector.get("operation", ""),
                        selector["phase"],
                        selector.get("result_path", ""),
                        selector["expected_count"],
                    )
                )
            protocol_events.append(
                (
                    protocol["id"],
                    event["stage"],
                    selector_begin,
                    len(event["selectors"]),
                )
            )
        protocols.append(
            (
                protocol,
                binding_begin,
                len(protocol["bindings"]),
                event_begin,
                len(protocol["events"]),
            )
        )

    lines = [
        "//===-- QEMUContractCatalog.inc - generated QEMU API contracts -----===//",
        "//",
        "// Generated by clang/utils/analyzer/qemu_contract_catalog.py.",
        "// Do not edit: update QEMUContractCatalog.json and regenerate.",
        "//",
        "//===----------------------------------------------------------------------===//",
        "",
        "namespace clang::ento::qemu_contracts_generated {",
        "",
        "inline constexpr unsigned CatalogFormat = {};".format(catalog["catalog_format"]),
        "inline constexpr char ModelVersion[] = {};".format(
            _cpp_string(catalog["model_version"])
        ),
        "inline constexpr char CatalogSHA256[] = {};".format(_cpp_string(catalog_hash)),
        "inline constexpr char SchemaSHA256[] = {};".format(_cpp_string(schema_hash)),
        "",
        "struct ParameterRecord {",
        "  const char *ContractID;",
        "  unsigned Index;",
        "  const char *Name;",
        "  const char *Type;",
        "};",
        "",
        "struct OperandRecord {",
        "  const char *ContractID;",
        "  const char *Role;",
        "  const char *Source;",
        "  int ArgumentIndex;",
        "  const char *Phase;",
        "  unsigned MemberStepBegin;",
        "  unsigned MemberStepCount;",
        "};",
        "",
        "struct MemberStepRecord {",
        "  const char *ContractID;",
        "  const char *OperandRole;",
        "  const char *RecordType;",
        "  const char *Field;",
        "  const char *Type;",
        "  const char *Header;",
        "};",
        "",
        "struct EffectRecord {",
        "  const char *ContractID;",
        "  const char *Kind;",
        "  const char *When;",
        "  const char *Target;",
        "  const char *Extent;",
        "  const char *RequestedExtent;",
        "  const char *AccessExtent;",
        "  const char *Direction;",
        "  const char *Owner;",
        "  const char *Callback;",
        "  const char *MemoryRegion;",
        "  const char *Epoch;",
        "  const char *Offset;",
        "  const char *CapacitySelector;",
        "  const char *PrimaryCapacity;",
        "  const char *AlternateCapacity;",
        "};",
        "",
        "struct ContractAdditionalRuleRecord {",
        "  const char *ContractID;",
        "  const char *RuleID;",
        "};",
        "",
        "struct ContractRecord {",
        "  const char *ID;",
        "  const char *RuleID;",
        "  unsigned AdditionalRuleBegin;",
        "  unsigned AdditionalRuleCount;",
        "  const char *Family;",
        "  const char *Kind;",
        "  const char *SelectorName;",
        "  const char *SelectorHeader;",
        "  const char *SelectorTranslationUnit;",
        "  const char *Prototype;",
        "  const char *ReturnType;",
        "  const char *DirectionEncoding;",
        "  const char *PairID;",
        "  const char *PairRelation;",
        "  unsigned ParameterBegin;",
        "  unsigned ParameterCount;",
        "  unsigned OperandBegin;",
        "  unsigned OperandCount;",
        "  unsigned EffectBegin;",
        "  unsigned EffectCount;",
        "  const char *SuccessPredicateJSON;",
        "  const char *PartialSuccessPredicateJSON;",
        "  const char *FailurePredicateJSON;",
        "};",
        "",
        "struct CallbackRuleRecord {",
        "  const char *CallbackID;",
        "  const char *RuleID;",
        "};",
        "",
        "struct CallbackParameterRecord {",
        "  const char *CallbackID;",
        "  unsigned Index;",
        "  const char *Name;",
        "  const char *Type;",
        "};",
        "",
        "struct CallbackMemberStepRecord {",
        "  const char *CallbackID;",
        "  const char *InputRole;",
        "  const char *RecordType;",
        "  const char *Field;",
        "  const char *Type;",
        "  const char *Header;",
        "};",
        "",
        "struct CallbackEntryInputRecord {",
        "  const char *CallbackID;",
        "  const char *Role;",
        "  const char *Source;",
        "  unsigned ArgumentIndex;",
        "  unsigned MemberStepBegin;",
        "  unsigned MemberStepCount;",
        "};",
        "",
        "struct CallbackInputBufferRecord {",
        "  const char *CallbackID;",
        "  unsigned BufferArgumentIndex;",
        "  unsigned LengthArgumentIndex;",
        "  unsigned SelectorArgumentIndex;",
        "  unsigned long long SelectorMask;",
        "  unsigned long long SelectorValue;",
        "};",
        "",
        "struct CallbackBindingRecord {",
        "  const char *ID;",
        "  const char *Family;",
        "  const char *SlotRecordType;",
        "  const char *SlotField;",
        "  const char *SlotHeader;",
        "  const char *SlotTranslationUnit;",
        "  const char *SlotImplementation;",
        "  const char *Prototype;",
        "  const char *RegistrationRecordType;",
        "  const char *RegistrationField;",
        "  const char *RegistrationHeader;",
        "  const char *RegistrationTranslationUnit;",
        "  const char *RegistrationVariable;",
        "  const char *RegistrationInitializer;",
        "  const char *RegistrationPrototype;",
        "  unsigned RuleBegin;",
        "  unsigned RuleCount;",
        "  unsigned ParameterBegin;",
        "  unsigned ParameterCount;",
        "  unsigned EntryInputBegin;",
        "  unsigned EntryInputCount;",
        "  unsigned InputBufferBegin;",
        "  unsigned InputBufferCount;",
        "};",
        "",
        "struct ProtocolBindingRecord {",
        "  const char *ProtocolID;",
        "  const char *Role;",
        "  const char *Source;",
        "  int ArgumentIndex;",
        "  const char *RecordType;",
        "  const char *Field;",
        "  long long IntegerValue;",
        "  bool HasIntegerValue;",
        "};",
        "",
        "struct ProtocolSelectorRecord {",
        "  const char *ProtocolID;",
        "  const char *Stage;",
        "  const char *Kind;",
        "  const char *ContractID;",
        "  const char *Name;",
        "  const char *Prototype;",
        "  const char *RecordType;",
        "  const char *Field;",
        "  const char *Operation;",
        "  const char *Phase;",
        "  const char *ResultPath;",
        "  unsigned ExpectedCount;",
        "};",
        "",
        "struct ProtocolEventRecord {",
        "  const char *ProtocolID;",
        "  const char *Stage;",
        "  unsigned SelectorBegin;",
        "  unsigned SelectorCount;",
        "};",
        "",
        "struct ProtocolRecord {",
        "  const char *ID;",
        "  const char *RuleID;",
        "  const char *Family;",
        "  const char *ScopeName;",
        "  const char *ScopeSource;",
        "  const char *ScopeTranslationUnit;",
        "  const char *ScopePrototype;",
        "  unsigned BindingBegin;",
        "  unsigned BindingCount;",
        "  unsigned EventBegin;",
        "  unsigned EventCount;",
        "};",
        "",
        "inline constexpr ParameterRecord Parameters[] = {",
    ]
    for contract_id, index, name, type_name in parameters:
        lines.append(
            "  {{{}, {}, {}, {}}},".format(
                _cpp_string(contract_id), index, _cpp_string(name), _cpp_string(type_name)
            )
        )
    lines.extend(
        [
            "};",
            "inline constexpr unsigned ParameterRecordCount =",
            "    sizeof(Parameters) / sizeof(Parameters[0]);",
            "",
            "inline constexpr OperandRecord Operands[] = {",
        ]
    )
    for contract_id, role, source, index, phase, member_begin, member_count in operands:
        lines.append(
            "  {{{}, {}, {}, {}, {}, {}, {}}},".format(
                _cpp_string(contract_id),
                _cpp_string(role),
                _cpp_string(source),
                index,
                _cpp_string(phase),
                member_begin,
                member_count,
            )
        )
    lines.extend(
        [
            "};",
            "inline constexpr unsigned OperandRecordCount =",
            "    sizeof(Operands) / sizeof(Operands[0]);",
            "",
            "inline constexpr MemberStepRecord MemberSteps[] = {",
        ]
    )
    for member_step in member_steps:
        lines.append(
            "  {{{}}},".format(
                ", ".join(_cpp_string(value) for value in member_step)
            )
        )
    if not member_steps:
        lines.append("  {},")
    lines.extend(
        [
            "};",
            "inline constexpr unsigned MemberStepRecordCount = {};".format(
                len(member_steps)
            ),
            "",
            "inline constexpr EffectRecord Effects[] = {",
        ]
    )
    for effect in effects:
        lines.append("  {{{}}},".format(", ".join(_cpp_string(value) for value in effect)))
    lines.extend(
        [
            "};",
            "inline constexpr unsigned EffectRecordCount =",
            "    sizeof(Effects) / sizeof(Effects[0]);",
            "",
            "inline constexpr ContractAdditionalRuleRecord ContractAdditionalRules[] = {",
        ]
    )
    for contract_id, rule_id in additional_rules:
        lines.append(
            "  {{{}, {}}},".format(
                _cpp_string(contract_id), _cpp_string(rule_id)
            )
        )
    if not additional_rules:
        lines.append("  {},")
    lines.extend(
        [
            "};",
            "inline constexpr unsigned ContractAdditionalRuleRecordCount = {};".format(
                len(additional_rules)
            ),
            "",
            "inline constexpr ContractRecord Contracts[] = {",
        ]
    )
    for (
        contract,
        parameter_begin,
        parameter_count,
        operand_begin,
        operand_count,
        effect_begin,
        effect_count,
        additional_rule_begin,
        additional_rule_count,
    ) in contracts:
        predicates = contract["predicates"]
        pair = contract["pair"]
        fields = [
            _cpp_string(contract["id"]),
            _cpp_string(contract["rule_id"]),
            str(additional_rule_begin),
            str(additional_rule_count),
            _cpp_string(contract["family"]),
            _cpp_string(contract["kind"]),
            _cpp_string(contract["selector"]["name"]),
            _cpp_string(contract["selector"]["header"]),
            _cpp_string(contract["selector"]["translation_unit"]),
            _cpp_string(_prototype_string(contract)),
            _cpp_string(contract["prototype"]["return_type"]),
            _cpp_string(contract["direction_encoding"]),
            _cpp_string(pair["contract_id"] if pair is not None else ""),
            _cpp_string(pair["relation"] if pair is not None else ""),
            str(parameter_begin),
            str(parameter_count),
            str(operand_begin),
            str(operand_count),
            str(effect_begin),
            str(effect_count),
            _cpp_string(_canonical_json(predicates["success"])),
            _cpp_string(_canonical_json(predicates["partial_success"])),
            _cpp_string(_canonical_json(predicates["failure"])),
        ]
        lines.append("  {{{}}},".format(", ".join(fields)))
    lines.extend(
        [
            "};",
            "inline constexpr unsigned ContractRecordCount =",
            "    sizeof(Contracts) / sizeof(Contracts[0]);",
            "",
            "inline constexpr CallbackRuleRecord CallbackRules[] = {",
        ]
    )
    for callback_id, rule_id in callback_rules:
        lines.append(
            "  {{{}, {}}},".format(
                _cpp_string(callback_id), _cpp_string(rule_id)
            )
        )
    if not callback_rules:
        lines.append("  {},")
    lines.extend(
        [
            "};",
            "inline constexpr unsigned CallbackRuleRecordCount = {};".format(
                len(callback_rules)
            ),
            "",
            "inline constexpr CallbackParameterRecord CallbackParameters[] = {",
        ]
    )
    for callback_id, index, name, type_name in callback_parameters:
        lines.append(
            "  {{{}, {}, {}, {}}},".format(
                _cpp_string(callback_id),
                index,
                _cpp_string(name),
                _cpp_string(type_name),
            )
        )
    if not callback_parameters:
        lines.append("  {},")
    lines.extend(
        [
            "};",
            "inline constexpr unsigned CallbackParameterRecordCount = {};".format(
                len(callback_parameters)
            ),
            "",
            "inline constexpr CallbackMemberStepRecord CallbackMemberSteps[] = {",
        ]
    )
    for member_step in callback_member_steps:
        lines.append(
            "  {{{}}},".format(
                ", ".join(_cpp_string(value) for value in member_step)
            )
        )
    if not callback_member_steps:
        lines.append("  {},")
    lines.extend(
        [
            "};",
            "inline constexpr unsigned CallbackMemberStepRecordCount = {};".format(
                len(callback_member_steps)
            ),
            "",
            "inline constexpr CallbackEntryInputRecord CallbackEntryInputs[] = {",
        ]
    )
    for entry_input in callback_entry_inputs:
        fields = [_cpp_string(value) for value in entry_input[:3]] + [
            str(value) for value in entry_input[3:]
        ]
        lines.append("  {{{}}},".format(", ".join(fields)))
    if not callback_entry_inputs:
        lines.append("  {},")
    lines.extend(
        [
            "};",
            "inline constexpr unsigned CallbackEntryInputRecordCount = {};".format(
                len(callback_entry_inputs)
            ),
            "",
            "inline constexpr CallbackInputBufferRecord CallbackInputBuffers[] = {",
        ]
    )
    for input_buffer in callback_input_buffers:
        fields = [
            _cpp_string(input_buffer[0]),
            str(input_buffer[1]),
            str(input_buffer[2]),
            str(input_buffer[3]),
            "{}ULL".format(input_buffer[4]),
            "{}ULL".format(input_buffer[5]),
        ]
        lines.append("  {{{}}},".format(", ".join(fields)))
    if not callback_input_buffers:
        lines.append("  {},")
    lines.extend(
        [
            "};",
            "inline constexpr unsigned CallbackInputBufferRecordCount = {};".format(
                len(callback_input_buffers)
            ),
            "",
            "inline constexpr CallbackBindingRecord CallbackBindings[] = {",
        ]
    )
    for (
        callback,
        rule_begin,
        rule_count,
        parameter_begin,
        parameter_count,
        input_begin,
        input_count,
        input_buffer_begin,
        input_buffer_count,
    ) in callback_bindings:
        slot = callback["slot"]
        registration = callback["registration"]
        fields = [
            _cpp_string(callback["id"]),
            _cpp_string(callback["family"]),
            _cpp_string(slot["record_type"]),
            _cpp_string(slot["field"]),
            _cpp_string(slot["header"]),
            _cpp_string(slot["translation_unit"]),
            _cpp_string(slot["implementation"]),
            _cpp_string(_prototype_string(callback)),
            _cpp_string(registration["record_type"]),
            _cpp_string(registration["field"]),
            _cpp_string(registration["header"]),
            _cpp_string(registration["translation_unit"]),
            _cpp_string(registration["variable"]),
            _cpp_string(registration["initializer"]),
            _cpp_string(_prototype_string(registration)),
            str(rule_begin),
            str(rule_count),
            str(parameter_begin),
            str(parameter_count),
            str(input_begin),
            str(input_count),
            str(input_buffer_begin),
            str(input_buffer_count),
        ]
        lines.append("  {{{}}},".format(", ".join(fields)))
    if not callback_bindings:
        lines.append("  {},")
    lines.extend(
        [
            "};",
            "inline constexpr unsigned CallbackBindingRecordCount = {};".format(
                len(callback_bindings)
            ),
            "",
            "inline constexpr ProtocolBindingRecord ProtocolBindings[] = {",
        ]
    )
    for (
        protocol_id,
        role,
        source,
        argument_index,
        record_type,
        field,
        integer_value,
        has_integer_value,
    ) in protocol_bindings:
        lines.append(
            "  {{{}, {}, {}, {}, {}, {}, {}, {}}},".format(
                _cpp_string(protocol_id),
                _cpp_string(role),
                _cpp_string(source),
                argument_index,
                _cpp_string(record_type),
                _cpp_string(field),
                _cpp_signed_long_long(integer_value),
                "true" if has_integer_value else "false",
            )
        )
    if not protocol_bindings:
        lines.append("  {},")
    lines.extend(
        [
            "};",
            "inline constexpr unsigned ProtocolBindingRecordCount = {};".format(
                len(protocol_bindings)
            ),
            "",
            "inline constexpr ProtocolSelectorRecord ProtocolSelectors[] = {",
        ]
    )
    for selector in protocol_selectors:
        fields = [_cpp_string(value) for value in selector[:-1]] + [
            str(selector[-1])
        ]
        lines.append("  {{{}}},".format(", ".join(fields)))
    if not protocol_selectors:
        lines.append("  {},")
    lines.extend(
        [
            "};",
            "inline constexpr unsigned ProtocolSelectorRecordCount = {};".format(
                len(protocol_selectors)
            ),
            "",
            "inline constexpr ProtocolEventRecord ProtocolEvents[] = {",
        ]
    )
    for protocol_id, stage, selector_begin, selector_count in protocol_events:
        lines.append(
            "  {{{}, {}, {}, {}}},".format(
                _cpp_string(protocol_id),
                _cpp_string(stage),
                selector_begin,
                selector_count,
            )
        )
    if not protocol_events:
        lines.append("  {},")
    lines.extend(
        [
            "};",
            "inline constexpr unsigned ProtocolEventRecordCount = {};".format(
                len(protocol_events)
            ),
            "",
            "inline constexpr ProtocolRecord Protocols[] = {",
        ]
    )
    for protocol, binding_begin, binding_count, event_begin, event_count in protocols:
        scope = protocol["scope"]
        fields = [
            _cpp_string(protocol["id"]),
            _cpp_string(protocol["rule_id"]),
            _cpp_string(protocol["family"]),
            _cpp_string(scope["name"]),
            _cpp_string(scope["source"]),
            _cpp_string(scope["translation_unit"]),
            _cpp_string(_prototype_string(scope)),
            str(binding_begin),
            str(binding_count),
            str(event_begin),
            str(event_count),
        ]
        lines.append("  {{{}}},".format(", ".join(fields)))
    if not protocols:
        lines.append("  {},")
    lines.extend(
        [
            "};",
            "inline constexpr unsigned ProtocolRecordCount = {};".format(
                len(protocols)
            ),
            "",
            "} // namespace clang::ento::qemu_contracts_generated",
            "",
        ]
    )
    return "\n".join(lines)


def _default_paths():
    clang_root = Path(__file__).resolve().parents[2]
    checker_dir = clang_root / "lib" / "StaticAnalyzer" / "Checkers"
    return (
        checker_dir / "QEMUContractCatalog.json",
        checker_dir / "QEMUContractCatalog.schema.json",
        checker_dir / "QEMUContractCatalog.inc",
    )


def main(argv=None):
    default_catalog, default_schema, default_output = _default_paths()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", type=Path, default=default_catalog)
    parser.add_argument("--schema", type=Path, default=default_schema)
    parser.add_argument("--output", type=Path, default=default_output)
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail if the checked-in generated file is absent or stale",
    )
    arguments = parser.parse_args(argv)
    try:
        catalog = load_json_strict(arguments.catalog)
        schema = load_json_strict(arguments.schema)
        output = generate(catalog, schema)
        if arguments.check:
            try:
                current = arguments.output.read_text(encoding="utf-8")
            except OSError as error:
                raise CatalogError("{}: {}".format(arguments.output, error)) from error
            if current != output:
                difference = difflib.unified_diff(
                    current.splitlines(True),
                    output.splitlines(True),
                    fromfile=str(arguments.output),
                    tofile="generated",
                )
                sys.stderr.write("".join(difference))
                return 1
            print("{} is current".format(arguments.output))
            return 0
        arguments.output.write_text(output, encoding="utf-8")
        print("generated {}".format(arguments.output))
        return 0
    except CatalogError as error:
        print("error: {}".format(error), file=sys.stderr)
        return 1
    except OSError as error:
        print("error: {}".format(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
