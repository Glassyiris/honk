#!/usr/bin/env bash
set -euo pipefail

for artifact in dist/honk-core-debug-{x86_64,aarch64}-unknown-linux-{gnu,musl}{,-stock}.tar.gz; do
  if [[ ! -f "$artifact" || ! -s "$artifact" ]]; then
    printf '::error::Missing or empty Debug artifact: %s. Re-run all jobs to rebuild the complete set.\n' "$artifact" >&2
    exit 1
  fi
done
