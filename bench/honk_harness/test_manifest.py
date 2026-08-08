from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
import os
from pathlib import Path
import re
from typing import Final, Literal, assert_never

from .errors import HarnessError
from .jsonio import (
    JsonValue,
    exact_keys,
    expect_object,
    int_field,
    read_json,
    sha256_path,
    string_list,
    text_field,
    write_json,
)
from .process import CommandResult, CommandSpec, run_command

MAX_TESTS: Final = 256
SHA40: Final = re.compile(r"[0-9a-f]{40}\Z")


class Category(StrEnum):
    CODEC = "codec"
    TOKEN = "token"
    CAPS = "caps"
    OVERFLOW = "overflow"
    CRASH = "crash"
    HOOK = "hook"
    DNS = "dns"


class Package(StrEnum):
    CORE = "honk-core"
    OUTBOUND = "honk-outbound"


@dataclass(frozen=True, slots=True)
class ExactTest:
    category: Category
    package: Package
    features: tuple[str, ...]
    name: str


@dataclass(frozen=True, slots=True)
class TestManifest:
    tests: tuple[ExactTest, ...]


@dataclass(frozen=True, slots=True)
class RunOptions:
    root: Path
    report: Path
    target_dir: Path | None
    timeout_seconds: int
    execute: bool


def _category(value: JsonValue) -> Category:
    raw = text_field(value, "test.category")
    try:
        return Category(raw)
    except ValueError as error:
        raise HarnessError("MANIFEST_CATEGORY", raw) from error


def _package(value: JsonValue) -> Package:
    raw = text_field(value, "test.package")
    try:
        return Package(raw)
    except ValueError as error:
        raise HarnessError("MANIFEST_PACKAGE", raw) from error


def load_manifest(path: Path, root: Path) -> TestManifest:
    data = expect_object(read_json(path, root=root), "manifest")
    exact_keys(data, {"schema", "tests"}, "manifest")
    if int_field(data["schema"], "manifest.schema", minimum=1) != 1:
        raise HarnessError("MANIFEST_SCHEMA", "expected 1")
    match data["tests"]:
        case list() as rows if 24 <= len(rows) <= MAX_TESTS:
            tests: list[ExactTest] = []
            for index, row in enumerate(rows):
                item = expect_object(row, f"tests[{index}]")
                exact_keys(item, {"category", "features", "name", "package"}, f"tests[{index}]")
                features = string_list(item["features"], "features", maximum=4)
                if set(features) - {"honk-test-hooks"}:
                    raise HarnessError("MANIFEST_FEATURE", ",".join(features))
                tests.append(
                    ExactTest(
                        category=_category(item["category"]),
                        package=_package(item["package"]),
                        features=features,
                        name=text_field(item["name"], "test.name"),
                    )
                )
        case _:
            raise HarnessError("MANIFEST_COUNT", "expected 24..256 tests")
    identities = {(test.package, test.features, test.name) for test in tests}
    if len(identities) != len(tests):
        raise HarnessError("MANIFEST_DUPLICATE", "package/features/name")
    if {test.category for test in tests} != set(Category):
        raise HarnessError("MANIFEST_CATEGORIES", "all seven categories required")
    return TestManifest(tests=tuple(tests))


def _cargo_argv(test: ExactTest, *, list_only: bool) -> tuple[str, ...]:
    argv = ["cargo", "test", "-p", test.package.value, "--lib"]
    if test.features:
        argv.extend(("--features", ",".join(test.features)))
    if list_only:
        argv.extend(("--", "--list"))
    else:
        argv.extend((test.name, "--", "--exact", "--nocapture"))
    return tuple(argv)


def _run(argv: tuple[str, ...], options: RunOptions) -> CommandResult:
    env = os.environ.copy()
    if options.target_dir is not None:
        env["CARGO_TARGET_DIR"] = str(options.target_dir)
    result = run_command(CommandSpec(argv, options.root, options.timeout_seconds, env))
    if result.exit_code != 0:
        raise HarnessError("TEST_COMMAND", f"exit={result.exit_code} argv={list(argv)}")
    return result


def run_manifest(manifest_path: Path, options: RunOptions) -> None:
    manifest = load_manifest(manifest_path, options.root)
    grouped: dict[tuple[Package, tuple[str, ...]], list[ExactTest]] = {}
    for test in manifest.tests:
        grouped.setdefault((test.package, test.features), []).append(test)
    inventories: dict[tuple[Package, tuple[str, ...]], set[str]] = {}
    command_rows: list[JsonValue] = []
    for tests in grouped.values():
        result = _run(_cargo_argv(tests[0], list_only=True), options)
        command_rows.append(result.record())
        names = [line.removesuffix(": test") for line in result.stdout.decode().splitlines() if line.endswith(": test")]
        if not names:
            raise HarnessError("TEST_ZERO_INVENTORY", tests[0].package.value)
        if len(names) != len(set(names)):
            raise HarnessError("TEST_DUPLICATE_INVENTORY", tests[0].package.value)
        inventories[(tests[0].package, tests[0].features)] = set(names)
    for test in manifest.tests:
        if test.name not in inventories[(test.package, test.features)]:
            raise HarnessError("TEST_MISSING", test.name)
        if options.execute:
            result = _run(_cargo_argv(test, list_only=False), options)
            command_rows.append(result.record())
            output = (result.stdout + result.stderr).decode(errors="replace")
            if not re.search(r"test result: ok\. 1 passed", output):
                raise HarnessError("TEST_ZERO_SELECTION", test.name)
    head = _git(options.root, "rev-parse", "HEAD")
    tree = _git(options.root, "rev-parse", "HEAD^{tree}")
    if SHA40.fullmatch(head) is None or SHA40.fullmatch(tree) is None:
        raise HarnessError("GIT_IDENTITY", "invalid HEAD/tree")
    categories: list[JsonValue] = sorted(category.value for category in Category)
    test_names: list[JsonValue] = [test.name for test in manifest.tests]
    report: dict[str, JsonValue] = {
            "categories": categories,
            "commands": command_rows,
            "executed": options.execute,
            "head": head,
            "manifestSha256": sha256_path(manifest_path),
            "schema": 1,
            "testCount": len(manifest.tests),
            "tests": test_names,
            "tree": tree,
        }
    write_json(options.report, report)


def _git(root: Path, *args: str) -> str:
    result = run_command(CommandSpec(("git", *args), root, 30))
    if result.exit_code != 0:
        raise HarnessError("GIT_COMMAND", " ".join(args))
    return result.stdout.decode().strip()


def action_to_execute(action: Literal["list", "run"]) -> bool:
    match action:
        case "list":
            return False
        case "run":
            return True
        case unreachable:
            assert_never(unreachable)
