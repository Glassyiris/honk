#!/usr/bin/env bash
# Runs an exact, non-empty set of ignored tests: a missing or added selection
# fails before anything runs, so an interop case cannot silently stop running.
set -euo pipefail

usage() {
    echo "usage: $0 [--lib | --test <name>] <test> [<test>...]" >&2
    exit 2
}

target=()
while [[ ${1:-} == --lib || ${1:-} == --test ]]; do
    case $1 in
        --lib) target+=(--lib); shift ;;
        --test) [[ $# -ge 2 ]] || usage; target+=(--test "$2"); shift 2 ;;
    esac
done
[[ $# -ge 1 && ${#target[@]} -gt 0 ]] || usage

filter=''
for test in "$@"; do
    if [[ -n $filter ]]; then
        filter+=' or '
    fi
    filter+="test(=$test)"
done

run=(cargo nextest run -p honk-outbound --features rprx "${target[@]}" --profile ci
    --run-ignored only -E "$filter" --no-tests fail)

echo "==> ${run[*]}"
list=$(cargo nextest list -p honk-outbound --features rprx "${target[@]}" --profile ci \
    --run-ignored only -E "$filter" --message-format json)
jq -e --args '
    [."rust-suites"[].testcases | to_entries[]
      | select(.value["filter-match"].status == "matches" and .value.ignored) | .key]
    | sort == ($ARGS.positional | sort)
' <<<"$list" "$@" || {
    echo "selection does not match the requested ignored tests exactly" >&2
    exit 1
}

"${run[@]}"
