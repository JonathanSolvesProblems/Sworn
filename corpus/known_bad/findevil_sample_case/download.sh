#!/usr/bin/env bash
# Optional manual download script. The Egnyte URL below is from the Find Evil!
# resources panel; the actual files may require a one-time browser login.

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
echo "Fetch the case files from:"
echo "  https://sansorg.egnyte.com/fl/HhH7crTYT4JK"
echo ""
echo "Place the resulting disk image, memory capture, and any extracted"
echo "artifact files into: $HERE"
echo ""
echo "Then update ground_truth.json with the actual SHA-256 of each file:"
echo "  sha256sum '$HERE'/*"
