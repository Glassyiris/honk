#!/usr/bin/env python3
"""Local raw-BPF differential check and paired microbenchmark."""

import argparse
import ctypes
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import platform
import random
import re
import statistics
import struct
import sys
import time

BPF_SYSCALL_X86_64 = 321
BPF_MAP_CREATE = 0
BPF_MAP_LOOKUP_ELEM = 1
BPF_MAP_UPDATE_ELEM = 2
BPF_MAP_DELETE_ELEM = 3
BPF_PROG_LOAD = 5
BPF_PROG_TEST_RUN = 10
BPF_OBJ_GET_INFO_BY_FD = 15
BPF_MAP_TYPE_HASH = 1
BPF_MAP_TYPE_ARRAY = 2
BPF_MAP_TYPE_LPM_TRIE = 11
BPF_PROG_TYPE_SCHED_CLS = 3
BPF_F_NO_PREALLOC = 1
MAP_LOOKUP_ELEM = 1
CATEGORIES = ("destination", "source", "mac", "domain")
DECISION_FIELDS = ("outbound", "mark", "must", "domain_final", "rule_id")
BASELINE_COMMIT = "ac7cf6a5ab6d7c4229a0c6230a6415965d953403"
BASELINE_SHA256 = "477f81f42c422783d5a2790b6d98e34372e23a4c51a1777357dfbf1497543d3a"
BASELINE_METADATA_SHA256 = "9ff8a368f80f4d5dec99837a489d58e8943234fbf15fa64629c5194971bb09bc"
LIBC = ctypes.CDLL(None, use_errno=True)
LIBC.syscall.restype = ctypes.c_long
OPEN_FDS = []


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def bpf(command, raw, *, missing_ok=False):
    attr = ctypes.create_string_buffer(raw, max(144, len(raw)))
    result = LIBC.syscall(BPF_SYSCALL_X86_64, command, ctypes.byref(attr), len(attr))
    if result < 0:
        error = ctypes.get_errno()
        if missing_ok and error == 2:
            return None, attr.raw
        raise OSError(error, os.strerror(error))
    return result, attr.raw


def create_map(kind, key_size, value_size, entries, flags=0):
    fd, _ = bpf(
        BPF_MAP_CREATE,
        struct.pack("<6I", kind, key_size, value_size, entries, flags, 0),
    )
    OPEN_FDS.append(fd)
    return fd


def update_map(fd, key, value):
    key_buffer = ctypes.create_string_buffer(key)
    value_buffer = ctypes.create_string_buffer(value)
    bpf(
        BPF_MAP_UPDATE_ELEM,
        struct.pack(
            "<IIQQQ",
            fd,
            0,
            ctypes.addressof(key_buffer),
            ctypes.addressof(value_buffer),
            0,
        ),
    )


def lookup_map(fd, key, value_size):
    key_buffer = ctypes.create_string_buffer(key)
    value_buffer = ctypes.create_string_buffer(value_size)
    result, _ = bpf(
        BPF_MAP_LOOKUP_ELEM,
        struct.pack(
            "<IIQQQ",
            fd,
            0,
            ctypes.addressof(key_buffer),
            ctypes.addressof(value_buffer),
            0,
        ),
        missing_ok=True,
    )
    return None if result is None else value_buffer.raw


def delete_map(fd, key):
    key_buffer = ctypes.create_string_buffer(key)
    bpf(
        BPF_MAP_DELETE_ELEM,
        struct.pack("<IIQ", fd, 0, ctypes.addressof(key_buffer)),
        missing_ok=True,
    )


def insn(code, dst=0, src=0, off=0, imm=0):
    return struct.pack("<BBhi", code, dst | (src << 4), off, imm)


def fixed_wrapper(fixture_fd):
    return b"".join(
        [
            insn(0x62, 10, off=-4),
            insn(0x18, 1, 1, imm=fixture_fd),
            insn(0),
            insn(0xBF, 2, 10),
            insn(0x07, 2, imm=-4),
            insn(0x85, imm=MAP_LOOKUP_ELEM),
            insn(0x55, off=2),
            insn(0xB7, 0, imm=2),
            insn(0x95),
            insn(0xBF, 1, 0),
            insn(0xBF, 2, 0),
            insn(0x07, 2, imm=128),
            insn(0x85, src=1, imm=1),
            insn(0x95),
        ]
    )


def stream_wrapper(fixture_fd, counter_fd, working_set):
    if working_set < 2 or working_set & (working_set - 1):
        raise ValueError("working set must be a power of two")
    return b"".join(
        [
            insn(0x62, 10, off=-4),
            insn(0x18, 1, 1, imm=counter_fd),
            insn(0),
            insn(0xBF, 2, 10),
            insn(0x07, 2, imm=-4),
            insn(0x85, imm=MAP_LOOKUP_ELEM),
            insn(0x55, off=2),
            insn(0xB7, 0, imm=2),
            insn(0x95),
            insn(0x61, 3, 0),
            insn(0xBF, 4, 3),
            insn(0x07, 4, imm=1),
            insn(0x63, 0, 4),
            insn(0x57, 3, imm=working_set - 1),
            insn(0x63, 10, 3, off=-4),
            insn(0x18, 1, 1, imm=fixture_fd),
            insn(0),
            insn(0xBF, 2, 10),
            insn(0x07, 2, imm=-4),
            insn(0x85, imm=MAP_LOOKUP_ELEM),
            insn(0x55, off=2),
            insn(0xB7, 0, imm=2),
            insn(0x95),
            insn(0xBF, 1, 0),
            insn(0xBF, 2, 0),
            insn(0x07, 2, imm=128),
            insn(0x85, src=1, imm=1),
            insn(0x95),
        ]
    )


def patch_map_fds(body, actual_fds):
    patched = bytearray(body)
    for offset in range(0, len(patched), 8):
        code, registers, _, immediate = struct.unpack_from("<BBhi", patched, offset)
        if code == 0x18 and registers >> 4 == 1:
            if immediate not in actual_fds:
                raise AssertionError(f"unknown emitted map sentinel {immediate}")
            struct.pack_into("<i", patched, offset + 4, actual_fds[immediate])
    return bytes(patched)


def load_program(body, actual_fds, wrapper, label):
    body = patch_map_fds(body, actual_fds)
    payload_bytes = wrapper + body
    payload = ctypes.create_string_buffer(payload_bytes)
    license_buffer = ctypes.create_string_buffer(b"GPL\0")
    verifier_buffer = ctypes.create_string_buffer(2 * 1024 * 1024)
    attr = struct.pack(
        "<IIQQIIQ",
        BPF_PROG_TYPE_SCHED_CLS,
        len(payload_bytes) // 8,
        ctypes.addressof(payload),
        ctypes.addressof(license_buffer),
        4,
        len(verifier_buffer),
        ctypes.addressof(verifier_buffer),
    )
    started = time.perf_counter_ns()
    try:
        fd, _ = bpf(BPF_PROG_LOAD, attr)
    except OSError as error:
        log = verifier_buffer.value.decode(errors="replace")
        raise RuntimeError(f"load {label}: {error}\n{log}") from error
    load_duration = time.perf_counter_ns() - started
    OPEN_FDS.append(fd)
    info = ctypes.create_string_buffer(256)
    bpf(
        BPF_OBJ_GET_INFO_BY_FD,
        struct.pack("<IIQ", fd, len(info), ctypes.addressof(info)),
    )
    verifier_log = verifier_buffer.value.decode(errors="replace").strip()
    summary = re.search(
        r"processed (\d+) insns .*?max_states_per_insn (\d+) total_states (\d+) peak_states (\d+)",
        verifier_log,
    )
    stack = re.search(r"stack depth ([0-9+]+)(?: max (\d+))?", verifier_log)
    stack_depth = (
        int(stack.group(2) or stack.group(1))
        if stack and (stack.group(2) or "+" not in stack.group(1))
        else None
    )
    if summary is None:
        raise RuntimeError(f"{label}: verifier statistics missing from log: {verifier_log!r}")
    metadata = {
        "label": label,
        "static_bytes": len(body),
        "static_instruction_slots": len(body) // 8,
        "wrapper_bytes": len(wrapper),
        "wrapper_instruction_slots": len(wrapper) // 8,
        "load_duration_ns": load_duration,
        "jit_bytes": struct.unpack_from("<I", info.raw, 16)[0],
        "xlated_bytes": struct.unpack_from("<I", info.raw, 20)[0],
        "kernel_processed_instructions": int(summary.group(1)),
        "stack_depth_bytes": stack_depth,
        "verifier_log": verifier_log,
        "verifier": {
            "processed_instructions": int(summary.group(1)),
            "max_states_per_instruction": int(summary.group(2)),
            "total_states": int(summary.group(3)),
            "peak_states": int(summary.group(4)),
            "stack_depth_bytes": stack_depth,
            "stack_depth_by_subprogram": [int(n) for n in stack.group(1).split("+")] if stack else None,
            "stack_depth_note": None if stack_depth is not None else "kernel did not report aggregate maximum stack depth",
        },
    }
    if metadata["jit_bytes"] == 0:
        raise RuntimeError(f"{label}: kernel did not report JIT code")
    return fd, metadata


def test_run(fd, repeat):
    packet = ctypes.create_string_buffer(64)
    attr = bytearray(80)
    struct.pack_into(
        "<IIIIQQII",
        attr,
        0,
        fd,
        0,
        len(packet),
        0,
        ctypes.addressof(packet),
        0,
        repeat,
        0,
    )
    _, result = bpf(BPF_PROG_TEST_RUN, bytes(attr))
    return struct.unpack_from("<I", result, 4)[0], struct.unpack_from("<I", result, 36)[0]


def ipv4_mapped(value):
    return b"\0" * 10 + b"\xff\xff" + int(value).to_bytes(4, "big")


def address(family, index=1, *, source=False, miss=False):
    if family == 1:
        base = 0xC6120000 if miss else (0x0A600000 if source else 0x0A400000)
        return ipv4_mapped(base + index)
    if family == 2:
        base = int(ipaddress.IPv6Address("2001:db8:ffff::" if miss else ("2001:db8:2::" if source else "2001:db8:1::")))
        return (base + index).to_bytes(16, "big")
    return bytes(16)


def mac_value(index=1):
    return bytes(10) + bytes([0x02, 0, 0, (index >> 16) & 0xFF, (index >> 8) & 0xFF, index & 0xFF])


def routing_input(
    family,
    index=1,
    *,
    miss=False,
    mac_present=True,
    destination_port=443,
    protocol=1,
):
    value = bytearray(128)
    value[0:16] = address(family, index, source=True)
    value[16:32] = address(family, index, miss=miss)
    value[32:48] = mac_value(index)
    struct.pack_into(
        "<8I",
        value,
        96,
        12345,
        destination_port,
        protocol,
        family,
        0,
        0,
        0,
        int(mac_present),
    )
    return bytes(value)


def decision(raw):
    return dict(zip(DECISION_FIELDS, struct.unpack("<5I", raw)))


def bitmap(*bits):
    value = 0
    for bit in bits:
        value |= 1 << bit
    return value.to_bytes(32, "little")


def lpm_key(prefix, data):
    return struct.pack("<I", prefix) + data


def fact_key(category, family, input_value):
    if category == "destination":
        data = input_value[28:32] + bytes(12) if family == 1 else input_value[16:32]
        return lpm_key(32 if family == 1 else 128, data)
    if category == "source":
        data = input_value[12:16] + bytes(12) if family == 1 else input_value[0:16]
        return lpm_key(32 if family == 1 else 128, data)
    if category == "mac":
        return lpm_key(128, input_value[32:48])
    if category == "domain":
        return input_value[16:32]
    raise AssertionError(category)


class MapModel:
    def __init__(self, kind, key_size):
        self.kind = kind
        self.key_size = key_size
        self.entries = {}

    def put(self, key, value):
        self.entries[key] = value

    def lookup(self, key):
        if self.kind == "hash":
            return self.entries.get(key)
        query = key[4:20]
        best = None
        best_prefix = -1
        for stored, value in self.entries.items():
            prefix = struct.unpack_from("<I", stored)[0]
            if prefix <= best_prefix:
                continue
            whole, remainder = divmod(prefix, 8)
            matches = stored[4 : 4 + whole] == query[:whole]
            if matches and remainder:
                mask = 0xFF << (8 - remainder) & 0xFF
                matches = stored[4 + whole] & mask == query[whole] & mask
            if matches:
                best, best_prefix = value, prefix
        return best


def model_maps(sentinels):
    return {
        sentinels["destination_v4"]: MapModel("lpm", 20),
        sentinels["destination_v6"]: MapModel("lpm", 20),
        sentinels["source_v4"]: MapModel("lpm", 20),
        sentinels["source_v6"]: MapModel("lpm", 20),
        sentinels["mac"]: MapModel("lpm", 20),
        sentinels["domain"]: MapModel("hash", 16),
    }


def sentinel_for(sentinels, category, family):
    if category in ("destination", "source"):
        return sentinels[f"{category}_{'v4' if family == 1 else 'v6'}"]
    return sentinels[category]


class KernelMaps:
    def __init__(self, sentinels, max_entries, shape):
        self.sentinels = sentinels
        self.shape = shape
        self.fds = {
            sentinels[name]: create_map(
                BPF_MAP_TYPE_HASH if name == "domain" else BPF_MAP_TYPE_LPM_TRIE,
                16 if name == "domain" else 20,
                32,
                max_entries,
                0 if name == "domain" else BPF_F_NO_PREALLOC,
            )
            for name in sentinels
        }
        self.keys = {sentinel: set() for sentinel in self.fds}

    def put(self, category, family, key, value):
        sentinel = sentinel_for(self.sentinels, category, family)
        update_map(self.fds[sentinel], key, value)
        self.keys[sentinel].add(key)

    def clear(self):
        for sentinel, keys in self.keys.items():
            for key in keys:
                delete_map(self.fds[sentinel], key)
            keys.clear()


class Memory:
    def __init__(self):
        self.regions = []
        self.max_stack_depth = 0

    def add(self, start, size, initial=None, initialized=False):
        data = bytearray(size if initial is None else initial)
        state = bytearray([int(initialized)] * size)
        self.regions.append((start, data, state))

    def region(self, address, size):
        for start, data, state in self.regions:
            if start <= address and address + size <= start + len(data):
                if start == 0x300000:
                    self.max_stack_depth = max(self.max_stack_depth, 0x300200 - address)
                return address - start, data, state
        raise AssertionError(f"invalid memory access {address:#x}+{size}")

    def load(self, address, size):
        offset, data, state = self.region(address, size)
        if not all(state[offset : offset + size]):
            raise AssertionError(f"uninitialized memory read {address:#x}+{size}")
        return int.from_bytes(data[offset : offset + size], "little")

    def bytes(self, address, size):
        offset, data, state = self.region(address, size)
        if not all(state[offset : offset + size]):
            raise AssertionError(f"uninitialized memory read {address:#x}+{size}")
        return bytes(data[offset : offset + size])

    def store(self, address, size, value):
        offset, data, state = self.region(address, size)
        data[offset : offset + size] = (value & ((1 << (size * 8)) - 1)).to_bytes(size, "little")
        state[offset : offset + size] = b"\x01" * size


SUPPORTED_OPCODES = {
    0x00,
    0x07,
    0x0F,
    0x17,
    0x1F,
    0x18,
    0x47,
    0x4F,
    0x57,
    0x5F,
    0x61,
    0x62,
    0x63,
    0x67,
    0x6F,
    0x71,
    0x72,
    0x73,
    0x77,
    0x79,
    0x7A,
    0x7B,
    0x7F,
    0x85,
    0x95,
    0xB7,
    0xBF,
    0x05,
    0x15,
    0x1D,
    0x25,
    0x2D,
    0x35,
    0x3D,
    0x55,
    0x5D,
}


def decoded(body):
    if len(body) % 8:
        raise AssertionError("instruction stream length is not divisible by eight")
    return [struct.unpack_from("<BBhi", body, offset) for offset in range(0, len(body), 8)]


def validate_opcodes(body):
    instructions = decoded(body)
    encountered = set()
    continuation = False
    for index, (code, registers, _, immediate) in enumerate(instructions):
        if continuation:
            if code != 0:
                raise AssertionError(f"malformed ldimm64 continuation at instruction {index}")
            continuation = False
            continue
        encountered.add(code)
        if code not in SUPPORTED_OPCODES:
            raise AssertionError(f"unsupported opcode {code:#04x} at instruction {index}")
        if code == 0x18:
            continuation = True
        if code == 0x85 and (registers >> 4 != 0 or immediate != MAP_LOOKUP_ELEM):
            raise AssertionError(f"unsupported call at instruction {index}")
    if continuation:
        raise AssertionError("truncated ldimm64")
    return sorted(encountered)


def interpret(body, input_value, maps):
    instructions = decoded(body)
    memory = Memory()
    memory.add(0x100000, len(input_value), input_value, True)
    memory.add(0x200000, 20)
    memory.add(0x300000, 512)
    registers = [None] * 11
    registers[1], registers[2], registers[10] = 0x100000, 0x200000, 0x300200
    lookups = dict.fromkeys(CATEGORIES, 0)
    map_categories = {}
    for sentinel in maps:
        map_categories[sentinel] = (
            "destination"
            if sentinel in (101, 102)
            else "source"
            if sentinel in (103, 104)
            else "mac"
            if sentinel == 105
            else "domain"
        )
    pc = 0
    steps = 0
    next_map_value = 0x400000

    def reg(index):
        value = registers[index]
        if value is None:
            raise AssertionError(f"read clobbered/uninitialized r{index} at instruction {pc}")
        return value

    while True:
        steps += 1
        if steps > 1_000_000 or not 0 <= pc < len(instructions):
            raise AssertionError(f"interpreter escaped at instruction {pc}")
        code, register_byte, offset, immediate = instructions[pc]
        dst, src = register_byte & 0xF, register_byte >> 4
        if code == 0x18:
            if pc + 1 >= len(instructions) or instructions[pc + 1][0] != 0:
                raise AssertionError(f"bad ldimm64 at instruction {pc}")
            high = instructions[pc + 1][3] & 0xFFFFFFFF
            registers[dst] = (immediate & 0xFFFFFFFF) | (high << 32)
            pc += 2
            continue
        if code in (0xB7, 0xBF):
            registers[dst] = (immediate & 0xFFFFFFFFFFFFFFFF) if code == 0xB7 else reg(src)
        elif code in (0x07, 0x0F, 0x17, 0x1F, 0x47, 0x4F, 0x57, 0x5F, 0x67, 0x6F, 0x77, 0x7F):
            right = reg(src) if code & 0x08 else immediate & 0xFFFFFFFFFFFFFFFF
            left = reg(dst)
            operation = code & 0xF0
            if operation == 0x00:
                value = left + right
            elif operation == 0x10:
                value = left - right
            elif operation == 0x40:
                value = left | right
            elif operation == 0x50:
                value = left & right
            elif operation == 0x60:
                value = left << right
            elif operation == 0x70:
                value = left >> right
            else:
                raise AssertionError(f"unsupported ALU opcode {code:#x}")
            registers[dst] = value & 0xFFFFFFFFFFFFFFFF
        elif code in (0x61, 0x71, 0x79):
            size = {0x61: 4, 0x71: 1, 0x79: 8}[code]
            registers[dst] = memory.load(reg(src) + offset, size)
        elif code in (0x62, 0x72, 0x7A):
            size = {0x62: 4, 0x72: 1, 0x7A: 8}[code]
            memory.store(reg(dst) + offset, size, immediate)
        elif code in (0x63, 0x73, 0x7B):
            size = {0x63: 4, 0x73: 1, 0x7B: 8}[code]
            memory.store(reg(dst) + offset, size, reg(src))
        elif code == 0x05:
            pc += offset + 1
            continue
        elif code in (0x15, 0x1D, 0x25, 0x2D, 0x35, 0x3D, 0x55, 0x5D):
            left = reg(dst)
            right = reg(src) if code & 0x08 else immediate & 0xFFFFFFFFFFFFFFFF
            operation = code & 0xF0
            take = (
                left == right
                if operation == 0x10
                else left > right
                if operation == 0x20
                else left >= right
                if operation == 0x30
                else left != right
            )
            if take:
                pc += offset + 1
                continue
        elif code == 0x85:
            if src != 0 or immediate != MAP_LOOKUP_ELEM:
                raise AssertionError(f"unsupported helper call at instruction {pc}")
            map_reference = reg(1)
            if map_reference not in maps:
                raise AssertionError(f"unknown map reference {map_reference} at instruction {pc}")
            model = maps[map_reference]
            key = memory.bytes(reg(2), model.key_size)
            value = model.lookup(key)
            category = map_categories[map_reference]
            lookups[category] += 1
            for index in range(1, 6):
                registers[index] = None
            if value is None:
                registers[0] = 0
            else:
                memory.add(next_map_value, len(value), value, True)
                registers[0] = next_map_value
                next_map_value += 0x100
        elif code == 0x95:
            return {
                "return": reg(0) if registers[0] is not None else None,
                "decision": decision(memory.bytes(0x200000, 20)),
                "lookups": lookups,
                "executed_instructions": steps,
                "stack_depth_bytes": memory.max_stack_depth,
            }
        elif code == 0:
            raise AssertionError(f"orphan instruction continuation at {pc}")
        else:
            raise AssertionError(f"unsupported opcode {code:#04x} at instruction {pc}")
        pc += 1


def bit_matches(value, bit):
    return value is not None and bool(value[bit // 8] & (1 << (bit % 8)))


def golden(plan, input_value, maps, sentinels):
    family = struct.unpack_from("<I", input_value, 108)[0]
    used = set()
    domain_value = None
    domain_final = int(not plan["has_domain_rules"] or plan["features"] & 2 == 0)
    if plan["has_domain_rules"]:
        used.add("domain")
        domain_value = maps[sentinels["domain"]].lookup(input_value[16:32])
        if domain_value is not None:
            domain_final = 1

    def predicate(condition):
        kind = condition["kind"]
        if kind in ("destination_ip", "source_ip"):
            category = kind.removesuffix("_ip")
            used.add(category)
            if family not in (1, 2):
                return False
            key = fact_key(category, family, input_value)
            value = maps[sentinel_for(sentinels, category, family)].lookup(key)
            return bit_matches(value, condition["id"])
        if kind == "mac":
            used.add("mac")
            if struct.unpack_from("<I", input_value, 124)[0] == 0:
                return False
            value = maps[sentinels["mac"]].lookup(fact_key("mac", family, input_value))
            return bit_matches(value, condition["id"])
        if kind == "domain":
            return bit_matches(domain_value, condition["id"])
        if kind in ("destination_port", "source_port"):
            offset = 100 if kind == "destination_port" else 96
            value = struct.unpack_from("<I", input_value, offset)[0]
            return any(start <= value <= end for start, end in condition["ranges"])
        if kind in ("protocol", "ip_version"):
            offset = 104 if kind == "protocol" else 108
            return bool(struct.unpack_from("<I", input_value, offset)[0] & condition["mask"])
        if kind == "dscp":
            return struct.unpack_from("<I", input_value, 112)[0] in condition["values"]
        if kind == "process_name":
            length = min(struct.unpack_from("<I", input_value, 120)[0], 48)
            name = input_value[48 : 48 + length]
            return any(candidate in name for candidate in map(bytes, condition["names"]))
        raise AssertionError(kind)

    selected = None
    for rule in plan["rules"]:
        matched = True
        for condition in rule["conditions"]:
            result = predicate(condition)
            if condition["not"]:
                result = not result
            if not result:
                matched = False
                break
        if matched:
            selected = rule
            break
    if selected is None:
        result = {
            "outbound": plan["fallback"],
            "mark": 0,
            "must": 0,
            "domain_final": domain_final,
            "rule_id": 0xFFFFFFFF,
        }
    else:
        result = {
            "outbound": selected["outbound"],
            "mark": selected["mark"],
            "must": int(selected["must"]),
            "domain_final": domain_final,
            "rule_id": selected["id"],
        }
    return result, used


def put_fact(models, kernel_maps, sentinels, category, family, input_value, value):
    key = fact_key(category, family, input_value)
    sentinel = sentinel_for(sentinels, category, family)
    models[sentinel].put(key, value)
    kernel_maps.put(category, family, key, value)


def configure_case(case, kernel_maps, sentinels):
    kernel_maps.clear()
    models = model_maps(sentinels)
    family = case["family"]
    scenario = case["scenario"]
    variant = case["variant"]
    destination_port = (
        8443
        if scenario == "early-port"
        else 9
        if scenario in ("hit", "dominated-hit", "match", "ready-positive", "ready-zero", "ready-null")
        else 443
    )
    input_value = routing_input(
        family,
        miss=scenario == "miss",
        mac_present=scenario not in ("mac-absent", "invalid"),
        destination_port=destination_port,
        protocol=2 if variant in ("domain-gated-repeated", "mixed3categories") and scenario == "match" else 1,
    )
    if variant.startswith("dst-"):
        count = int(variant.split("-")[1])
        if count and scenario in ("first", "middle", "late", "multi"):
            selected = 0 if scenario == "first" else count // 2 if scenario == "middle" else count - 1
            bits = (0, count - 1) if scenario == "multi" else (selected,)
            put_fact(models, kernel_maps, sentinels, "destination", family, input_value, bitmap(*bits))
        elif count and scenario == "zero":
            put_fact(models, kernel_maps, sentinels, "destination", family, input_value, bytes(32))
    elif variant in ("short-circuit-dst", "post-lookup-fail"):
        put_fact(models, kernel_maps, sentinels, "destination", family, input_value, bitmap(0, 1))
    elif variant == "dominated-dst-chain":
        if scenario in ("dominated-hit", "hit", "reuse-hit"):
            put_fact(models, kernel_maps, sentinels, "destination", family, input_value, bitmap(0))
        elif scenario == "zero":
            put_fact(models, kernel_maps, sentinels, "destination", family, input_value, bytes(32))
    elif variant == "domain-gated-repeated":
        if scenario in ("match", "reuse-hit", "destination-null", "destination-zero"):
            put_fact(models, kernel_maps, sentinels, "domain", family, input_value, bitmap(0))
            if scenario != "destination-null":
                value = bytes(32) if scenario == "destination-zero" else bitmap(0)
                put_fact(models, kernel_maps, sentinels, "destination", family, input_value, value)
        elif scenario == "zero":
            put_fact(models, kernel_maps, sentinels, "domain", family, input_value, bytes(32))
            put_fact(models, kernel_maps, sentinels, "destination", family, input_value, bytes(32))
    elif variant == "mixed3categories":
        categories = ("destination", "source", "mac")
        if scenario in ("all", "match", "source-null", "mac-null", "mac-absent"):
            for category in categories:
                if (category == "source" and scenario == "source-null") or (
                    category == "mac" and scenario in ("source-null", "mac-null", "mac-absent")
                ):
                    continue
                put_fact(models, kernel_maps, sentinels, category, family, input_value, bitmap(0))
        elif scenario == "zero":
            for category in categories:
                put_fact(models, kernel_maps, sentinels, category, family, input_value, bytes(32))
    elif variant == "conditional-first-use-merge":
        bits = (1,) if scenario == "ready-positive" else (0, 1, 2, 3) if scenario in ("all", "match", "first-fail") else (3,)
        if scenario not in ("null", "ready-null"):
            value = bytes(32) if scenario == "ready-zero" else bitmap(*bits)
            put_fact(models, kernel_maps, sentinels, "destination", family, input_value, value)
    elif variant == "seeded-adversarial-0x484f4e4b":
        categories = ("destination", "source", "mac")
        if scenario == "all":
            for category in categories:
                put_fact(models, kernel_maps, sentinels, category, family, input_value, bitmap(*range(32)))
        elif scenario in ("zero", "mac-absent"):
            for category in categories:
                if category != "mac" or scenario != "mac-absent":
                    put_fact(models, kernel_maps, sentinels, category, family, input_value, bytes(32))
    elif variant == "mixed":
        if scenario == "all":
            for category in ("destination", "source", "mac", "domain"):
                put_fact(models, kernel_maps, sentinels, category, family, input_value, bitmap(0, 1))
        elif scenario in ("zero", "mac-absent"):
            for category in ("destination", "source", "domain"):
                put_fact(models, kernel_maps, sentinels, category, family, input_value, bytes(32))
            if scenario != "mac-absent":
                put_fact(models, kernel_maps, sentinels, "mac", family, input_value, bytes(32))
    return input_value, models


FACT_SCENARIOS = (
    ("dominated-dst-chain", ("dominated-hit", "reuse-hit", "zero", "miss")),
    ("domain-gated-repeated", ("match", "reuse-hit", "destination-null", "destination-zero", "zero", "null")),
    ("mixed3categories", ("all", "match", "source-null", "mac-null", "null", "zero", "mac-absent")),
    ("conditional-first-use-merge", ("match", "first-fail", "merge-miss", "null", "ready-positive", "ready-zero", "ready-null")),
    ("seeded-adversarial-0x484f4e4b", ("all", "null", "zero", "mac-absent")),
)


def correctness_cases():
    cases = [
        {"variant": "dst-0", "family": family, "scenario": "fallback"}
        for family in (1, 2)
    ]
    for count in (1, 4, 16, 64, 256):
        for family in (1, 2):
            for scenario in ("first", "middle", "late", "zero", "miss"):
                cases.append({"variant": f"dst-{count}", "family": family, "scenario": scenario})
    cases.extend(
        [{"variant": "dst-256", "family": family, "scenario": "multi"} for family in (1, 2)]
    )
    cases.append({"variant": "dst-4", "family": 0, "scenario": "invalid"})
    for variant, scenario in (
        ("early-dst-16", "early-port"),
        ("short-circuit-dst", "short-circuit"),
        ("post-lookup-fail", "post-lookup-fail"),
    ):
        for family in (1, 2):
            cases.append({"variant": variant, "family": family, "scenario": scenario})
    for variant, scenarios in FACT_SCENARIOS:
        for family in (1, 2):
            for scenario in scenarios:
                cases.append({"variant": variant, "family": family, "scenario": scenario})
    for family in (1, 2):
        for scenario in ("all", "null", "zero", "mac-absent"):
            cases.append({"variant": "mixed", "family": family, "scenario": scenario})
    cases.extend(
        [
            {"variant": "mixed3categories", "family": 0, "scenario": "invalid"},
            {"variant": "seeded-adversarial-0x484f4e4b", "family": 0, "scenario": "invalid"},
        ]
    )
    return cases


def set_fixture(fixture_fd, input_value, index=0):
    update_map(fixture_fd, struct.pack("<I", index), input_value + bytes(20))


def kernel_decision(program_fd, fixture_fd):
    result, _ = test_run(program_fd, 1)
    if result != 0:
        raise AssertionError(f"BPF program returned {result}")
    value = lookup_map(fixture_fd, bytes(4), 148)
    if value is None:
        raise AssertionError("fixture vanished")
    return decision(value[128:148])


def dispersion(samples):
    median = statistics.median(samples)
    deviations = [abs(value - median) for value in samples]
    ordered = sorted(samples)
    return {
        "median_ns_per_evaluation": median,
        "mad_ns_per_evaluation": statistics.median(deviations),
        "min_ns_per_evaluation": ordered[0],
        "max_ns_per_evaluation": ordered[-1],
        "p25_ns_per_evaluation": ordered[(len(ordered) - 1) // 4],
        "p75_ns_per_evaluation": ordered[(len(ordered) - 1) * 3 // 4],
    }


class ProgramCache:
    def __init__(self, bodies, sentinels, metadata):
        self.bodies = bodies
        self.sentinels = sentinels
        self.metadata = metadata
        self.cache = {}

    def get(self, variant, emitter, maps, fixture_fd, mode="fixed", counter_fd=None, working_set=None):
        key = (variant, emitter, maps.shape, fixture_fd, mode)
        if key not in self.cache:
            wrapper = (
                fixed_wrapper(fixture_fd)
                if mode == "fixed"
                else stream_wrapper(fixture_fd, counter_fd, working_set)
            )
            body = self.bodies[variant][emitter]
            label = f"{maps.shape}/{mode}/{variant}/{emitter}/fixture-{fixture_fd}"
            fd, meta = load_program(body, maps.fds, wrapper, label)
            meta["body_sha256"] = hashlib.sha256(body).hexdigest()
            meta["map_shape"] = maps.shape
            meta["input_mode"] = mode
            self.metadata.append(meta)
            self.cache[key] = fd
        return self.cache[key]


def paired_measure(programs, repeat, rounds, warmups, *, counter_fd=None, working_set=None):
    for _ in range(warmups):
        for emitter in ("old", "new"):
            if counter_fd is not None:
                update_map(counter_fd, bytes(4), bytes(4))
            result, _ = test_run(programs[emitter], repeat)
            if result != 0:
                raise AssertionError(f"warmup returned {result}")
    samples = []
    by_emitter = {"old": [], "new": []}
    for round_index in range(rounds):
        order = ("old", "new") if round_index % 2 == 0 else ("new", "old")
        row = {"round": round_index, "order": list(order)}
        start = (round_index * repeat) & (working_set - 1) if working_set else 0
        for emitter in order:
            if counter_fd is not None:
                update_map(counter_fd, bytes(4), struct.pack("<I", start))
            result, duration = test_run(programs[emitter], repeat)
            if result != 0:
                raise AssertionError(f"measurement returned {result}")
            per_evaluation = duration
            row[emitter] = {
                "bpf_test_run_duration_ns": duration,
                "ns_per_evaluation": per_evaluation,
            }
            by_emitter[emitter].append(per_evaluation)
        samples.append(row)
    return {
        "raw_samples": samples,
        "dispersion": {emitter: dispersion(values) for emitter, values in by_emitter.items()},
    }




def benchmark_row(cache, maps, fixture_fd, variant, family, scenario, config, *, mode="fixed", counter_fd=None, working_set=None):
    programs = {
        emitter: cache.get(
            variant,
            emitter,
            maps,
            fixture_fd,
            mode,
            counter_fd,
            working_set,
        )
        for emitter in ("old", "new")
    }
    measured = paired_measure(
        programs,
        config.repeat,
        config.rounds,
        config.warmups,
        counter_fd=counter_fd,
        working_set=working_set,
    )
    return {
        "variant": variant,
        "family": family,
        "scenario": scenario,
        "map_shape": maps.shape,
        "input_mode": mode,
        "repeat": config.repeat,
        **measured,
    }


def run(args):
    root = Path(__file__).resolve().parent
    generated = args.generated.resolve()
    manifest_path = generated / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    if manifest.get("schema_version") != 1:
        raise AssertionError("unsupported generator manifest schema")
    if manifest["baseline"]["commit"] != BASELINE_COMMIT:
        raise AssertionError("wrong baseline commit")
    if sha256(root / "baseline-codegen.rs") != BASELINE_SHA256:
        raise AssertionError("frozen baseline emitter changed")
    baseline_metadata = json.loads((root / "baseline.json").read_text())
    if sha256(root / "baseline.json") != BASELINE_METADATA_SHA256:
        raise AssertionError("frozen baseline metadata changed")
    if baseline_metadata.get("head") != BASELINE_COMMIT:
        raise AssertionError("baseline metadata names the wrong commit")
    if manifest["baseline"].get("metadata_sha256") != BASELINE_METADATA_SHA256:
        raise AssertionError("generator manifest names the wrong baseline metadata")
    candidate_source = Path(manifest["candidate"]["source"])
    candidate_source_sha256 = sha256(candidate_source)
    if manifest["candidate"].get("source_sha256") != candidate_source_sha256:
        raise AssertionError("candidate emitter changed after bytecode generation")
    sentinels = manifest["map_fd_sentinels"]
    if set(sentinels.values()) != {101, 102, 103, 104, 105, 106}:
        raise AssertionError("unexpected map sentinel set")
    variants = {variant["name"]: variant for variant in manifest["variants"]}
    bodies = {
        name: {
            emitter: (generated / variant["emitters"][emitter]["file"]).read_bytes()
            for emitter in ("old", "new")
        }
        for name, variant in variants.items()
    }
    for name, emitters in bodies.items():
        for emitter, body in emitters.items():
            expected_hash = variants[name]["emitters"][emitter]["bytecode_sha256"]
            if hashlib.sha256(body).hexdigest() != expected_hash:
                raise AssertionError(f"{name}/{emitter}: emitted bytecode differs from compiled manifest")
    opcode_coverage = {
        name: {emitter: validate_opcodes(body) for emitter, body in emitters.items()}
        for name, emitters in bodies.items()
    }

    small = KernelMaps(sentinels, 64, "small")
    large = KernelMaps(sentinels, args.large_entries + 16, "large")
    fixed_fixture = create_map(BPF_MAP_TYPE_ARRAY, 4, 148, 1)
    counter = create_map(BPF_MAP_TYPE_ARRAY, 4, 4, 1)
    metadata = []
    cache = ProgramCache(bodies, sentinels, metadata)
    comparisons = []
    measurements = []
    lookup_assertions = 0
    for case in correctness_cases():
        input_value, models = configure_case(case, small, sentinels)
        plan = variants[case["variant"]]["plan"]
        expected, used = golden(plan, input_value, models, sentinels)
        interpreted = {
            emitter: interpret(bodies[case["variant"]][emitter], input_value, models)
            for emitter in ("old", "new")
        }
        set_fixture(fixed_fixture, input_value)
        observed_kernel = {
            emitter: kernel_decision(
                cache.get(case["variant"], emitter, small, fixed_fixture), fixed_fixture
            )
            for emitter in ("old", "new")
        }
        for emitter in ("old", "new"):
            if interpreted[emitter]["return"] != 0:
                raise AssertionError((case, emitter, interpreted[emitter]["return"]))
            if interpreted[emitter]["decision"] != expected or observed_kernel[emitter] != expected:
                raise AssertionError((case, emitter, expected, interpreted[emitter], observed_kernel[emitter]))
        for category in CATEGORIES:
            count = interpreted["new"]["lookups"][category]
            if category not in used and count != 0:
                raise AssertionError((case, category, "unused category looked up", count))
            if category in used and count > 1:
                raise AssertionError((case, category, "lookup budget exceeded", count))
            lookup_assertions += 1
        comparisons.append(
            {
                **case,
                "expected_decision": expected,
                "used_categories": sorted(used),
                "old": {
                    "decision": interpreted["old"]["decision"],
                    "lookup_counts": interpreted["old"]["lookups"],
                    "executed_instructions": interpreted["old"]["executed_instructions"],
                    "stack_depth_bytes": interpreted["old"]["stack_depth_bytes"],
                    "kernel_decision": observed_kernel["old"],
                },
                "new": {
                    "decision": interpreted["new"]["decision"],
                    "lookup_counts": interpreted["new"]["lookups"],
                    "executed_instructions": interpreted["new"]["executed_instructions"],
                    "stack_depth_bytes": interpreted["new"]["stack_depth_bytes"],
                    "kernel_decision": observed_kernel["new"],
                },
            }
        )
        # Keep the checked fixture installed: rebuilding it let timing labels drift.
        measurements.append({
            **benchmark_row(
                cache, small, fixed_fixture,
                case["variant"], case["family"], case["scenario"], args,
            ),
            "checked_case_index": len(comparisons) - 1,
        })

    alternating = []
    for index, scenario in enumerate(("all", "null", "all", "zero", "null", "all")):
        case = {"variant": "mixed", "family": 1 if index % 2 == 0 else 2, "scenario": scenario}
        input_value, models = configure_case(case, small, sentinels)
        expected, _ = golden(variants["mixed"]["plan"], input_value, models, sentinels)
        set_fixture(fixed_fixture, input_value)
        row = {"step": index, **case, "expected_decision": expected}
        for emitter in ("old", "new"):
            interpreted = interpret(bodies["mixed"][emitter], input_value, models)
            observed = kernel_decision(cache.get("mixed", emitter, small, fixed_fixture), fixed_fixture)
            if interpreted["decision"] != expected or observed != expected:
                raise AssertionError(("alternating", row, emitter, interpreted, observed))
            row[emitter] = {"lookup_counts": interpreted["lookups"], "kernel_decision": observed}
        alternating.append(row)


    for family in (1, 2):
        for address_index in range(args.large_entries):
            input_value = routing_input(family, address_index)
            large.put(
                "destination",
                family,
                fact_key("destination", family, input_value),
                bytes(32),
            )

    for family in (1, 2):
        for count in (16, 256):
            for scenario in ("late", "zero", "miss"):
                input_value = routing_input(family, miss=scenario == "miss")
                if scenario != "miss":
                    large.put(
                        "destination",
                        family,
                        fact_key("destination", family, input_value),
                        bytes(32) if scenario == "zero" else bitmap(count - 1),
                    )
                set_fixture(fixed_fixture, input_value)
                measurements.append(
                    benchmark_row(cache, large, fixed_fixture, f"dst-{count}", family, scenario, args)
                )

    working_set = args.working_set
    random_config = argparse.Namespace(**vars(args))
    random_config.repeat = max(args.repeat, working_set)
    stream_fixtures = {}
    order = list(range(working_set))
    random.Random(args.seed).shuffle(order)
    for family in (1, 2):
        fixture = create_map(BPF_MAP_TYPE_ARRAY, 4, 148, working_set)
        stream_fixtures[family] = fixture
        for slot, address_index in enumerate(order):
            input_value = routing_input(family, address_index)
            set_fixture(fixture, input_value, slot)
            large.put(
                "destination",
                family,
                fact_key("destination", family, input_value),
                bitmap(255),
            )
        measurements.append(
            benchmark_row(
                cache,
                large,
                fixture,
                "dst-256",
                family,
                "late",
                random_config,
                mode="randomized-working-set",
                counter_fd=counter,
                working_set=working_set,
            )
        )

    return {
        "schema_version": 1,
        "generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "invocation": [sys.executable, *sys.argv],
        "baseline": {
            "commit": BASELINE_COMMIT,
            "source_sha256": BASELINE_SHA256,
            "metadata_sha256": BASELINE_METADATA_SHA256,
        },
        "candidate": {
            "source": str(candidate_source),
            "source_sha256": candidate_source_sha256,
        },
        "generator": {
            "manifest": str(manifest_path),
            "manifest_sha256": sha256(manifest_path),
            "inputs": manifest,
            "opcode_coverage": opcode_coverage,
        },
        "host": {
            "kernel": platform.release(),
            "machine": platform.machine(),
            "python": platform.python_version(),
            "cpu": args.cpu,
        },
        "configuration": {
            "repeat": args.repeat,
            "rounds": args.rounds,
            "warmups": args.warmups,
            "large_entries": args.large_entries,
            "working_set": working_set,
            "random_repeat": random_config.repeat,
            "working_set_input_bytes_minimum": working_set * 148,
            "random_seed": args.seed,
            "generator_adversarial_seed": 0x484F4E4B,
        },
        "scope": {
            "program_type": "SCHED_CLS",
            "program_form": "standalone subprogram wrapper",
            "production_root": False,
            "freplace": False,
            "publication": False,
            "network_or_cgroup_attachment": False,
        },
        "syscall_side_effects": {
            "maps": "private unpinned ARRAY, HASH, and LPM_TRIE maps",
            "programs": "private unpinned SCHED_CLS programs",
            "pins": [],
            "attachments": [],
            "network_changes": [],
            "cleanup": "all file descriptors closed and original CPU affinity restored in finally",
        },
        "metric_definitions": {
            "static_bytes": "emitted body byte length",
            "kernel_processed_instructions": "verifier processed-insns statistic",
            "jit_bytes": "kernel JIT image length",
            "stack_depth_bytes": "reported verifier stack depth, when present",
            "bpf_test_run_duration_ns": "kernel-reported average duration; used directly without division",
        },
        "program_loads": metadata,
        "correctness": {
            "complete_decision_fields": list(DECISION_FIELDS),
            "cases": comparisons,
            "alternating_invocations": alternating,
            "comparison_count": len(comparisons) * 4 + len(alternating) * 4,
            "lookup_budget_assertion_count": lookup_assertions,
            "lookup_budget": "new emitter: zero for an unexecuted category and at most one for every executed category, including NULL, invalid-family, and absent-MAC paths",
        },
        "measurements": measurements,
        "limitations": [
            "This is a local SCHED_CLS subprogram wrapper, not production freplace/root/publication or packet traffic.",
            "The randomized working-set mode changes input in-kernel through ARRAY lookup plus a counter, amortizing syscalls but adding the same wrapper cost to both emitters.",
            "It is not an authentic cache-cold measurement: this wrapper cannot flush CPU, JIT, or kernel map caches between evaluations. The large randomized working set is reported only as cache-pressure evidence.",
            "Static bytes, verifier processing, JIT bytes, and stack depth are separate budgets; emitted size alone does not imply verifier cost.",
            "JIT and verifier results apply only to the recorded local kernel and architecture.",
        ],
    }


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--generated", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cpu", type=int)
    parser.add_argument("--repeat", type=int, default=5000)
    parser.add_argument("--rounds", type=int, default=11)
    parser.add_argument("--warmups", type=int, default=3)
    parser.add_argument("--large-entries", type=int, default=16384)
    parser.add_argument("--working-set", type=int, default=16384)
    parser.add_argument("--seed", type=int, default=0x484F4E4B)
    args = parser.parse_args()
    if min(args.repeat, args.rounds, args.large_entries, args.working_set) <= 0:
        parser.error("repeat, rounds, and entry counts must be positive")
    if args.working_set & (args.working_set - 1):
        parser.error("--working-set must be a power of two")
    if args.working_set > args.large_entries:
        parser.error("--working-set cannot exceed --large-entries")
    return args


def main():
    if platform.machine() != "x86_64":
        raise SystemExit("measure.py uses the x86_64 raw bpf syscall number")
    if os.geteuid() != 0:
        raise SystemExit("measure.py requires root for BPF_PROG_LOAD and JIT metadata")
    args = parse_args()
    original_affinity = os.sched_getaffinity(0)
    if not original_affinity:
        raise SystemExit("empty CPU affinity")
    args.cpu = min(original_affinity) if args.cpu is None else args.cpu
    if args.cpu not in original_affinity:
        raise SystemExit(f"CPU {args.cpu} is outside current affinity {sorted(original_affinity)}")
    result = None
    cleanup_errors = []
    try:
        os.sched_setaffinity(0, {args.cpu})
        result = run(args)
    finally:
        try:
            os.sched_setaffinity(0, original_affinity)
        except OSError as error:
            cleanup_errors.append(f"restore affinity: {error}")
        for fd in reversed(OPEN_FDS):
            try:
                os.close(fd)
            except OSError as error:
                cleanup_errors.append(f"close fd {fd}: {error}")
    if cleanup_errors:
        raise RuntimeError("; ".join(cleanup_errors))
    result["cleanup"] = {
        "closed_fd_count": len(OPEN_FDS),
        "affinity_restored": True,
        "errors": [],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.output.with_suffix(args.output.suffix + ".tmp")
    temporary.write_text(json.dumps(result, indent=2) + "\n")
    os.replace(temporary, args.output)
    print(
        f"PASS: {result['correctness']['comparison_count']} complete-decision observations; "
        f"{result['correctness']['lookup_budget_assertion_count']} lookup-budget assertions; "
        f"{len(result['measurements'])} paired measurements"
    )


if __name__ == "__main__":
    main()
