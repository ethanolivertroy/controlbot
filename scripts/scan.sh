#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCAN_DIR="${1:-$ROOT/fixtures/terraform}"
OUTPUT="${2:-$ROOT/findings.json}"

if ! command -v checkov >/dev/null 2>&1; then
  echo "checkov is required. Install: pip install checkov" >&2
  exit 1
fi

echo "Scanning Terraform in: $SCAN_DIR"

# Checkov exits 0 when clean, 1 when findings exist — both are success for us.
set +e
checkov \
  --directory "$SCAN_DIR" \
  --framework terraform \
  --output json \
  --quiet \
  --compact \
  > "$OUTPUT"
exit_code=$?
set -e

if [ "$exit_code" -gt 1 ]; then
  echo "checkov failed with exit code $exit_code" >&2
  exit "$exit_code"
fi

echo "Wrote $OUTPUT (${exit_code} = findings present)"
