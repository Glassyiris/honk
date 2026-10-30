#!/usr/bin/env bash
# Fail unless a formal release tag is SemVer and its MAJOR.MINOR.PATCH equals the workspace
# version. The manifest carries the release it builds towards; a -alpha.N, -beta.N or -rc.N
# suffix lives on the tag alone.
# Usage: check-release-version.sh <tag> [Cargo.toml]
set -euo pipefail

tag=${1:?usage: check-release-version.sh <tag> [Cargo.toml]}
manifest=${2:-Cargo.toml}

semver='^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-(alpha|beta|rc)\.(0|[1-9][0-9]*))?$'
if [[ ! $tag =~ $semver ]]; then
  printf '::error::Release tag %s is not vMAJOR.MINOR.PATCH or vMAJOR.MINOR.PATCH-{alpha|beta|rc}.N\n' "$tag" >&2
  exit 1
fi

version=$(awk '
  /^\[/ { section = $0 }
  section == "[workspace.package]" && $1 == "version" { gsub(/[" ]/, "", $3); print $3; exit }
' "$manifest")
if [[ ! $version =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
  printf '::error::[workspace.package] version %s in %s must be MAJOR.MINOR.PATCH without a suffix\n' "${version:-<missing>}" "$manifest" >&2
  exit 1
fi
if [[ "v$version" != "${tag%%-*}" ]]; then
  printf '::error::Release tag %s does not match [workspace.package] version %s in %s\n' "$tag" "$version" "$manifest" >&2
  exit 1
fi
