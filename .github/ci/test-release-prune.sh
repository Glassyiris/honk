#!/usr/bin/env bash
set -euo pipefail

ci_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)

releases=$(jq -n '[
  range(1; 13) as $i
  | {
      tagName: "debug.2026.9.\($i)",
      publishedAt: "2026-09-\(if $i < 10 then "0" else "" end)\($i)T00:00:00Z"
    }
] + [
  {tagName: "debug", publishedAt: "2026-09-13T00:00:00Z"},
  {tagName: "v0.1.0", publishedAt: "2026-09-14T00:00:00Z"}
]')
few=$(jq -n '[range(1; 4) as $i | {tagName: "debug.2026.9.\($i)", publishedAt: "2026-09-0\($i)T00:00:00Z"}]')

# The rolling Debug and formal releases never appear in the selected set.
expect_pruned() {
  local input=$1 current=$2 expected=$3 actual
  actual=$(GITHUB_REF_NAME=$current bash "$ci_dir/release-prune.sh" <<< "$input" | sort)
  if [[ "$actual" != "$expected" ]]; then
    printf 'Pruning with %s expected:\n%s\ngot:\n%s\n' "$current" "$expected" "$actual" >&2
    exit 1
  fi
}

# A re-run of an old tag keeps that tag; the nine newest others stay beside it.
expect_pruned "$releases" debug.2026.9.2 $'debug.2026.9.1\ndebug.2026.9.3'
# A fresh tag prunes the two oldest.
expect_pruned "$releases" debug.2026.9.12 $'debug.2026.9.1\ndebug.2026.9.2'
# Fewer than ten releases prune nothing.
expect_pruned "$few" debug.2026.9.3 ''

printf 'Debug release pruning regression passed\n'
