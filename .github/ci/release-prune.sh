#!/usr/bin/env bash
# Prints the per-tag Debug releases to delete from the `gh release list
# --json tagName,publishedAt` output on stdin. The tag just published is
# excluded, so re-running an older tag keeps the release that run updated.
set -euo pipefail

jq -r --arg current "${GITHUB_REF_NAME:?GITHUB_REF_NAME must name the published tag}" '
  [.[] | select((.tagName | startswith("debug.")) and .tagName != $current)]
  | sort_by(.publishedAt)
  | reverse
  | .[9:]
  | .[].tagName'
