from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import time

from .errors import HarnessError
from .jsonio import JsonValue


@dataclass(frozen=True, slots=True)
class CommandSpec:
    argv: tuple[str, ...]
    cwd: Path
    timeout_seconds: int
    env: dict[str, str] | None = None


@dataclass(frozen=True, slots=True)
class CommandResult:
    argv: tuple[str, ...]
    exit_code: int
    stdout: bytes
    stderr: bytes
    duration_ns: int
    timed_out: bool

    def record(self) -> dict[str, JsonValue]:
        return {
            "argv": list(self.argv),
            "durationNs": self.duration_ns,
            "exit": self.exit_code,
            "stderrSha256": hashlib.sha256(self.stderr).hexdigest(),
            "stdoutSha256": hashlib.sha256(self.stdout).hexdigest(),
            "timedOut": self.timed_out,
        }


def run_command(spec: CommandSpec) -> CommandResult:
    if not spec.argv:
        raise HarnessError("COMMAND_EMPTY", "argv")
    started = time.monotonic_ns()
    try:
        process = subprocess.Popen(
            spec.argv,
            cwd=spec.cwd,
            env=spec.env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
    except OSError as error:
        raise HarnessError("COMMAND_START", str(error)) from error
    timed_out = False
    try:
        stdout, stderr = process.communicate(timeout=spec.timeout_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        os.killpg(process.pid, signal.SIGTERM)
        try:
            stdout, stderr = process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            stdout, stderr = process.communicate()
    return CommandResult(
        argv=spec.argv,
        exit_code=124 if timed_out else process.returncode,
        stdout=stdout,
        stderr=stderr,
        duration_ns=time.monotonic_ns() - started,
        timed_out=timed_out,
    )


def append_command(path: Path, result: CommandResult) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(result.record(), sort_keys=True, separators=(",", ":")).encode()
    descriptor = os.open(path, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
    try:
        os.write(descriptor, payload + b"\n")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
