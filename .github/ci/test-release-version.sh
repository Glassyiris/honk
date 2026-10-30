#!/usr/bin/env bash
set -euo pipefail

ci_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
printf '[workspace]\nmembers = []\n\n[workspace.package]\nversion = "1.2.0"\nedition = "2024"\n\n[package]\nversion = "9.9.9"\n' > "$work/Cargo.toml"

check() {
  bash "$ci_dir/check-release-version.sh" "$1" "$work/Cargo.toml" > /dev/null 2>&1
}

for tag in v1.2.0 v1.2.0-alpha.1 v1.2.0-beta.2 v1.2.0-rc.3; do
  check "$tag" || { printf 'Expected %s to pass\n' "$tag" >&2; exit 1; }
done
for tag in v1.2.1 v1.3.0-rc.1 v1.2.0.rc.3 v1.2.0-preview.1 v01.2.0-rc.3 1.2.0-rc.3 v9.9.9; do
  if check "$tag"; then
    printf 'Expected %s to be rejected\n' "$tag" >&2
    exit 1
  fi
done

printf '[workspace.package]\nversion = "1.2.0-rc.3"\n' > "$work/Cargo.toml"
if check v1.2.0-rc.3; then
  echo 'Expected a suffixed manifest version to be rejected' >&2
  exit 1
fi

echo "release version check: ok"
