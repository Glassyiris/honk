from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import tempfile
from typing import Final, TypeAlias

from .errors import HarnessError

MAX_BYTES: Final = 256 * 1024
MAX_DEPTH: Final = 8
MAX_STRING: Final = 512
JsonScalar: TypeAlias = None | bool | int | str
JsonValue: TypeAlias = JsonScalar | list["JsonValue"] | dict[str, "JsonValue"]


def sha256_path(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _reject_float(raw: str) -> None:
    raise HarnessError("JSON_FLOAT", raw[:32])


def _pairs(items: list[tuple[str, JsonValue]]) -> dict[str, JsonValue]:
    result: dict[str, JsonValue] = {}
    for key, value in items:
        if key in result:
            raise HarnessError("JSON_DUPLICATE_KEY", key[:MAX_STRING])
        result[key] = value
    return result


def _bounded(value: JsonValue, depth: int = 0) -> None:
    if depth > MAX_DEPTH:
        raise HarnessError("JSON_DEPTH", str(depth))
    match value:
        case None | bool() | int():
            return
        case str() as text:
            if len(text) > MAX_STRING:
                raise HarnessError("JSON_STRING", str(len(text)))
        case list() as values:
            for item in values:
                _bounded(item, depth + 1)
        case dict() as values:
            for key, item in values.items():
                if len(key) > MAX_STRING:
                    raise HarnessError("JSON_KEY", str(len(key)))
                _bounded(item, depth + 1)


def read_json(path: Path, *, root: Path | None = None) -> JsonValue:
    if path.is_symlink() or not path.is_file():
        raise HarnessError("INPUT_REGULAR", str(path))
    resolved = path.resolve(strict=True)
    if root is not None:
        try:
            resolved.relative_to(root.resolve(strict=True))
        except ValueError as error:
            raise HarnessError("INPUT_CONTAINMENT", str(path)) from error
    size = resolved.stat().st_size
    if size > MAX_BYTES:
        raise HarnessError("INPUT_SIZE", str(size))
    try:
        value: JsonValue = json.loads(
            resolved.read_text(encoding="utf-8"),
            parse_float=_reject_float,
            parse_constant=_reject_float,
            object_pairs_hook=_pairs,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise HarnessError("JSON_SYNTAX", str(error)) from error
    _bounded(value)
    return value


def write_json(path: Path, value: JsonValue, *, exclusive: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    if exclusive:
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        return
    descriptor, raw = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(raw)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def expect_object(value: JsonValue, context: str) -> dict[str, JsonValue]:
    match value:
        case dict() as result:
            return result
        case _:
            raise HarnessError("JSON_TYPE", f"{context}: object required")


def exact_keys(value: dict[str, JsonValue], keys: set[str], context: str) -> None:
    actual = set(value)
    if actual != keys:
        raise HarnessError(
            "SCHEMA_KEYS",
            f"{context}: missing={sorted(keys - actual)} extra={sorted(actual - keys)}",
        )


def text_field(value: JsonValue, context: str) -> str:
    match value:
        case str() as result if result:
            return result
        case _:
            raise HarnessError("SCHEMA_TEXT", context)


def int_field(value: JsonValue, context: str, *, minimum: int = 0) -> int:
    match value:
        case bool():
            raise HarnessError("SCHEMA_INTEGER", context)
        case int() as result if result >= minimum:
            return result
        case _:
            raise HarnessError("SCHEMA_INTEGER", context)


def string_list(value: JsonValue, context: str, *, maximum: int) -> tuple[str, ...]:
    match value:
        case list() as raw if len(raw) <= maximum:
            results: list[str] = []
            for index, item in enumerate(raw):
                results.append(text_field(item, f"{context}[{index}]"))
            return tuple(results)
        case _:
            raise HarnessError("SCHEMA_LIST", context)
