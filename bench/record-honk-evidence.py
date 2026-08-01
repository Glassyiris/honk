#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///

# ─── How to run ───
# 1. Install uv (if not installed):
#      curl -LsSf https://astral.sh/uv/install.sh | sh
# 2. Run: uv run bench/record-honk-evidence.py self-test
# 3. Or: chmod +x bench/record-honk-evidence.py && ./bench/record-honk-evidence.py --help
# ─────────────────
from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import tempfile
from typing import Final, TypedDict

SLUG: Final = "udp-group-latency-stability-optimization"
ROOT: Final = Path(__file__).resolve().parent.parent
DEFAULT_PLAN: Final = ROOT / ".omo" / "plans" / f"{SLUG}.md"
TASK_PATTERN: Final = re.compile(r"^- \[ \] (\d+)\. ")
type JsonScalar = None | bool | int | float | str
type JsonValue = JsonScalar | list[JsonValue] | dict[str, JsonValue]


class ArtifactInput(TypedDict):
    path: str
    kind: str


@dataclass(frozen=True, slots=True)
class PlanBinding:
    path: Path
    data: bytes
    sha256: str


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(value: dict[str, JsonValue]) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def regular_bytes(path: Path) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(descriptor)
        if not os.path.isfile(f"/proc/self/fd/{descriptor}"):
            raise SystemExit(f"evidence: not a regular file: {path}")
        return os.read(descriptor, info.st_size + 1)
    finally:
        os.close(descriptor)


def plan_binding(expected: str) -> PlanBinding:
    configured = os.environ.get("HONK_REVIEWED_PLAN_PATH")
    configured_path = Path(configured) if configured else DEFAULT_PLAN
    if configured_path.is_symlink():
        raise SystemExit(f"evidence: plan must not be a symlink: {configured_path}")
    path = configured_path.resolve(strict=False)
    data = regular_bytes(path)
    actual = digest(data)
    if actual != expected:
        raise SystemExit(f"evidence: reviewed plan SHA mismatch: {actual}")
    return PlanBinding(path=path, data=data, sha256=actual)


def atomic_json(path: Path, value: dict[str, JsonValue]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = canonical(value)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def attest(attempt: Path, expected: str) -> PlanBinding:
    binding = plan_binding(expected)
    reviewed = attempt / "reviewed-plan.md"
    if reviewed.exists() or reviewed.is_symlink():
        if reviewed.is_symlink() or digest(regular_bytes(reviewed)) != expected:
            raise SystemExit("evidence: reviewed-plan.md is not the approved regular file")
    else:
        reviewed.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(reviewed, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(binding.data)
    return binding


def approve(args: argparse.Namespace) -> int:
    binding = attest(args.attempt_dir.resolve(), args.reviewed_plan_sha)
    atomic_json(args.attempt_dir.resolve() / "reviewed-plan-approval.json", {
        "schema": 1, "slug": SLUG, "planPath": str(binding.path), "planSha256": binding.sha256,
    })
    return 0


def git_text(*argv: str) -> str:
    return subprocess.run(["git", "-C", str(ROOT), *argv], check=True, text=True, capture_output=True).stdout.strip()


def references(plan: bytes, task: int) -> list[str]:
    active = False
    for line in plan.decode().splitlines():
        match = TASK_PATTERN.match(line)
        if match:
            active = int(match.group(1)) == task
        if active and line.startswith("  References: "):
            return [line.removeprefix("  References: ")]
    raise SystemExit(f"evidence: task {task} references not found")


def command_version(argv: list[str]) -> str:
    result = subprocess.run(argv, check=False, text=True, capture_output=True)
    return (result.stdout or result.stderr).splitlines()[0] if result.stdout or result.stderr else "unavailable"


def begin(args: argparse.Namespace) -> int:
    attempt = args.attempt_dir.resolve()
    binding = attest(attempt, args.reviewed_plan_sha)
    tree = git_text("rev-parse", f"{args.pre_task_commit}^{{tree}}")
    task_dir = attempt / f"task-{args.task}-{SLUG}"
    task_dir.mkdir(parents=True, exist_ok=True)
    declared_references: list[JsonValue] = [item for item in references(binding.data, args.task)]
    input_value: dict[str, JsonValue] = {
        "schema": 1, "taskId": args.task, "reviewedPlanSha256": binding.sha256,
        "preTaskCommit": args.pre_task_commit, "preTaskTree": tree,
        "declaredReferences": declared_references,
    }
    atomic_json(task_dir / "input.json", input_value)
    os_release_path = Path("/etc/os-release")
    os_release = regular_bytes(os_release_path.resolve()) if os_release_path.exists() else b""
    tool_hash = digest(regular_bytes(Path(__file__).resolve()))
    uname = platform.uname()
    uname_value: dict[str, JsonValue] = {"system": uname.system, "node": uname.node, "release": uname.release, "version": uname.version, "machine": uname.machine, "processor": uname.processor}
    environment: dict[str, JsonValue] = {
        "uname": uname_value, "osReleaseSha256": digest(os_release),
        "bootId": regular_bytes(Path("/proc/sys/kernel/random/boot_id")).decode().strip(),
        "cpuModel": next((line.split(":", 1)[1].strip() for line in Path("/proc/cpuinfo").read_text().splitlines() if line.startswith("model name")), "unknown"),
        "governor": Path("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor").read_text().strip() if Path("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor").exists() else "unavailable",
        "rustc": command_version(["rustc", "--version"]), "cargo": command_version(["cargo", "--version"]),
        "just": command_version(["just", "--version"]), "toolSha256": tool_hash,
    }
    atomic_json(task_dir / "environment.json", environment)
    return 0


def load_commands(path: Path) -> list[dict[str, JsonValue]]:
    if not path.is_file() or path.is_symlink() or path.stat().st_size == 0:
        raise SystemExit("evidence: commands.jsonl is missing or empty")
    rows = [json.loads(line) for line in path.read_text().splitlines() if line]
    for row in rows:
        status = row.get("exitStatus")
        expected = row.get("expectedNegative")
        if (expected is True and status == 0) or (expected is not True and status != 0):
            raise SystemExit("evidence: command outcome violates its expected-negative contract")
        for key in ("stdoutPath", "stderrPath"):
            data = regular_bytes(Path(str(row[key])))
            if digest(data) != row[key.replace("Path", "Sha256")]:
                raise SystemExit("evidence: command output hash mismatch")
    return rows


def end(args: argparse.Namespace) -> int:
    attempt = args.attempt_dir.resolve()
    binding = attest(attempt, args.reviewed_plan_sha)
    task_dir = attempt / f"task-{args.task}-{SLUG}"
    commands = load_commands(task_dir / "commands.jsonl")
    artifact_inputs: list[ArtifactInput] = json.loads(regular_bytes(args.artifacts_json.resolve()))
    artifacts: list[dict[str, JsonValue]] = []
    for item in artifact_inputs:
        supplied_path = Path(item["path"])
        if supplied_path.is_symlink():
            raise SystemExit(f"evidence: artifact is a symlink: {supplied_path}")
        path = supplied_path.resolve()
        if not path.is_file():
            raise SystemExit(f"evidence: artifact is not a regular file: {path}")
        if item["kind"] == "external" and not path.is_relative_to(attempt):
            raise SystemExit(f"evidence: external artifact escapes attempt dir: {path}")
        if item["kind"] == "git" and subprocess.run(["git", "-C", str(ROOT), "cat-file", "-e", f"{args.execution_commit}:{path.relative_to(ROOT)}"], check=False).returncode != 0:
            raise SystemExit(f"evidence: git artifact absent from execution tree: {path}")
        artifacts.append({"path": str(path), "kind": item["kind"], "sha256": digest(regular_bytes(path)), "size": path.stat().st_size})
    input_path, environment_path = task_dir / "input.json", task_dir / "environment.json"
    command_values: list[JsonValue] = [row for row in commands]
    artifact_values: list[JsonValue] = [item for item in artifacts]
    receipt: dict[str, JsonValue] = {
        "schema": 1, "taskId": args.task, "reviewedPlanSha256": binding.sha256,
        "executionCommit": args.execution_commit, "executionTree": git_text("rev-parse", f"{args.execution_commit}^{{tree}}"),
        "commitCreated": args.commit_created, "inputSha256": digest(regular_bytes(input_path)),
        "environmentSha256": digest(regular_bytes(environment_path)), "commands": command_values, "artifacts": artifact_values,
    }
    atomic_json(task_dir / "receipt.json", receipt)
    return 0


def self_test() -> int:
    with tempfile.TemporaryDirectory(prefix="honk-evidence-") as raw:
        path = Path(raw) / "value.json"
        atomic_json(path, {"z": 2, "a": 1})
        if path.read_bytes() != b'{"a":1,"z":2}\n':
            return 1
    print("record-honk-evidence self-test passed")
    return 0


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description="Create descriptor-bound honk evidence receipts.")
    sub = root.add_subparsers(dest="action", required=True)
    sub.add_parser("self-test")
    for name in ("approve", "begin", "end"):
        command = sub.add_parser(name)
        command.add_argument("--attempt-dir", type=Path, required=True)
        command.add_argument("--reviewed-plan-sha", required=True)
        if name in ("begin", "end"):
            command.add_argument("--task", type=int, required=True)
        if name == "begin":
            command.add_argument("--pre-task-commit", required=True)
        if name == "end":
            command.add_argument("--execution-commit", required=True)
            command.add_argument("--commit-created", choices=("yes", "no"), required=True)
            command.add_argument("--artifacts-json", type=Path, required=True)
    return root


def main() -> int:
    args = parser().parse_args()
    if args.action == "self-test":
        return self_test()
    if args.action == "approve":
        return approve(args)
    if args.action == "begin":
        return begin(args)
    if args.action == "end":
        return end(args)
    raise AssertionError(args.action)


if __name__ == "__main__":
    raise SystemExit(main())
