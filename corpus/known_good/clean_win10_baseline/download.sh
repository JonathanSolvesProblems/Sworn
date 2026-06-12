#!/usr/bin/env bash
# Optional fetch script for the clean Win10 baseline. Fill in on the day
# of the acquisition. The eval harness does not require this script;
# manual placement of disk.E01 in this directory is also fine.

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
TARGET="$HERE/disk.E01"
EXPECTED_SHA256="TODO_FILL_IN_ON_DAY_OF_ACQUISITION"

if [ -f "$TARGET" ]; then
  echo "disk.E01 already present at $TARGET"
  exit 0
fi

echo "Place disk.E01 at: $TARGET"
echo "Then update ground_truth.json with the actual SHA-256:"
echo "  sha256sum '$TARGET'"
exit 1
