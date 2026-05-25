#!/usr/bin/env bash
# Resolve Terraform scan directories from changed files or profile defaults.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CHANGED_FILES="${1:-}"
DEFAULT="${2:-fixtures/terraform}"

if [ -z "$CHANGED_FILES" ] || [ "$CHANGED_FILES" = "null" ]; then
  echo "$DEFAULT"
  exit 0
fi

# One directory per changed .tf file (unique, newline-separated)
echo "$CHANGED_FILES" | tr ' ' '\n' | grep '\.tf$' | xargs -I{} dirname {} | sort -u | while read -r dir; do
  [ -n "$dir" ] && echo "$dir"
done
