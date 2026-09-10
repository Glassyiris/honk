#!/usr/bin/env python3
"""Check scenario meaning at the real timing boundary; requires local x86 root."""

import struct
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

import measure


FALLBACK = 0xFFFFFFFF
EXPECTED = {
    ("domain-gated-repeated", "destination-null"): (
        {"domain": measure.bitmap(0), "destination": None}, FALLBACK,
    ),
    ("domain-gated-repeated", "destination-zero"): (
        {"domain": measure.bitmap(0), "destination": bytes(32)}, FALLBACK,
    ),
    ("mixed3categories", "source-null"): (
        {"destination": measure.bitmap(0), "source": None}, FALLBACK,
    ),
    ("mixed3categories", "mac-null"): (
        {"destination": measure.bitmap(0), "source": measure.bitmap(0), "mac": None}, FALLBACK,
    ),
    ("mixed3categories", "mac-absent"): (
        {"destination": measure.bitmap(0), "source": measure.bitmap(0), "mac": None},
        FALLBACK,
    ),
    ("mixed3categories", "match"): ({}, 12000),
    ("conditional-first-use-merge", "ready-positive"): ({"destination": measure.bitmap(1)}, 13001),
    ("conditional-first-use-merge", "ready-zero"): ({"destination": bytes(32)}, FALLBACK),
    ("conditional-first-use-merge", "ready-null"): ({"destination": None}, FALLBACK),
}


def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: test_measure.py GENERATED_DIRECTORY")
    generated = str(Path(sys.argv[1]).resolve())
    original = measure.benchmark_row
    seen = set()

    def observe(cache, maps, fixture_fd, variant, family, scenario, config, **options):
        expected = EXPECTED.get((variant, scenario))
        if maps.shape == "small" and expected is not None:
            context = (variant, family, scenario)
            fixture = measure.lookup_map(fixture_fd, bytes(4), 148)
            assert fixture is not None, context
            input_value = fixture[:128]
            facts, rule_id = expected
            for category, value in facts.items():
                sentinel = measure.sentinel_for(maps.sentinels, category, family)
                observed = measure.lookup_map(
                    maps.fds[sentinel], measure.fact_key(category, family, input_value), 32
                )
                assert observed == value, (context, category, value, observed)
            if variant == "conditional-first-use-merge":
                assert struct.unpack_from("<I", input_value, 100)[0] == 9, context
            if scenario == "mac-absent":
                assert struct.unpack_from("<I", input_value, 124)[0] == 0, context
            for emitter in ("old", "new"):
                result = measure.kernel_decision(
                    cache.get(variant, emitter, maps, fixture_fd), fixture_fd
                )
                assert result["rule_id"] == rule_id, (context, emitter, result)
            seen.add(context)
        return original(cache, maps, fixture_fd, variant, family, scenario, config, **options)

    with tempfile.TemporaryDirectory(prefix="honk-timing-regression-") as directory:
        arguments = [
            "measure.py", "--generated", generated, "--output", str(Path(directory) / "result.json"),
            "--repeat", "1", "--rounds", "1", "--warmups", "0",
            "--large-entries", "64", "--working-set", "64",
        ]
        with patch.object(measure, "benchmark_row", observe), patch.object(sys, "argv", arguments):
            measure.main()
    assert seen == {(variant, family, scenario) for variant, scenario in EXPECTED for family in (1, 2)}
    print(f"PASS: {len(seen)} timed fixtures matched their real map/input/decision contracts")


if __name__ == "__main__":
    main()
