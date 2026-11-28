#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

python3 "$SCRIPT_DIR/ipfilter.py" aggregate \
  --db-dir "$ROOT_DIR/db" \
  --out-dir "$ROOT_DIR" \
  --config "$ROOT_DIR/config/bogons.ipv4" \
  --config "$ROOT_DIR/config/whitelist.txt" \
  --retention-days 30 \
  --readme "$ROOT_DIR/README.md"
