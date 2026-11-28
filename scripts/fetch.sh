#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

FORCE_FETCH=0
for arg in "$@"; do
  case "$arg" in
    --force) FORCE_FETCH=1 ;;
    *)
      echo "Unknown argument: $arg" >&2
      echo "Usage: $0 [--force]" >&2
      exit 1
      ;;
  esac
done

# Load .env for local testing if ABUSEIPDB_TOKEN is not already set
if [[ -z "${ABUSEIPDB_TOKEN:-}" && -f "$ROOT_DIR/.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$ROOT_DIR/.env"
  set +a
fi

if [[ -z "${ABUSEIPDB_TOKEN:-}" ]]; then
  echo "[fetch] Error: ABUSEIPDB_TOKEN is not set." >&2
  exit 1
fi

API_URL="${ABUSEIPDB_API_URL:-https://api.abuseipdb.com/api/v2/blacklist}"
MIN_VALID_IPS="${MIN_VALID_IPS:-1000}"
CACHE_TTL_SECONDS="${CACHE_TTL_SECONDS:-14400}"

CACHE_DIR="$ROOT_DIR/.cache"
CACHE_FILE="$CACHE_DIR/blacklist-latest.txt"
TODAY_UTC="$(date -u +%Y-%m-%d)"
DB_FILE="$ROOT_DIR/db/${TODAY_UTC}.ipv4"

mkdir -p "$CACHE_DIR" "$ROOT_DIR/db"

USE_CACHE=0
if [[ "$FORCE_FETCH" -eq 0 && "$CACHE_TTL_SECONDS" -gt 0 && -f "$CACHE_FILE" ]]; then
  CACHE_AGE="$(python3 -c 'import os, sys, time; print(int(time.time() - os.path.getmtime(sys.argv[1])))' "$CACHE_FILE")"
  if [[ "$CACHE_AGE" -lt "$CACHE_TTL_SECONDS" ]]; then
    USE_CACHE=1
    echo "[fetch] Using local cache ($CACHE_FILE, age ${CACHE_AGE}s < TTL ${CACHE_TTL_SECONDS}s)."
  fi
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

RAW_INPUT="$TMP_DIR/raw.txt"
HEADER_TMP="$TMP_DIR/headers.txt"

if [[ "$USE_CACHE" -eq 1 ]]; then
  cp "$CACHE_FILE" "$RAW_INPUT"
else
  echo "[fetch] Requesting AbuseIPDB blacklist (UTC date: $TODAY_UTC)..."
  HTTP_CODE="$(curl -sS -G -D "$HEADER_TMP" -o "$RAW_INPUT" -w "%{http_code}" \
    -d "limit=10000" \
    -d "ipVersion=4" \
    -H "Key: $ABUSEIPDB_TOKEN" \
    -H "Accept: text/plain" \
    "$API_URL")"

  REMAINING="$(grep -i '^x-ratelimit-remaining:' "$HEADER_TMP" | awk '{print $2}' | tr -d '\r' || true)"
  if [[ -n "$REMAINING" ]]; then
    echo "[fetch] X-RateLimit-Remaining: $REMAINING"
  fi

  if [[ "$HTTP_CODE" == "429" ]]; then
    echo "[fetch] Received HTTP 429 (Rate Limit Exceeded). Gracefully skipping without modifying existing lists."
    if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
      echo "skipped=true" >> "$GITHUB_OUTPUT"
    fi
    exit 0
  fi

  if [[ "$HTTP_CODE" != "200" ]]; then
    echo "[fetch] Error: AbuseIPDB API returned HTTP $HTTP_CODE" >&2
    head -n 10 "$RAW_INPUT" >&2 || true
    exit 1
  fi
fi

# Clean, validate threshold, and union with today's UTC archive
python3 "$SCRIPT_DIR/ipfilter.py" filter \
  --input "$RAW_INPUT" \
  --existing "$DB_FILE" \
  --output "$DB_FILE" \
  --config "$ROOT_DIR/config/bogons.ipv4" \
  --config "$ROOT_DIR/config/whitelist.txt" \
  --min-lines "$MIN_VALID_IPS"

# Save to cache only after validation succeeded
if [[ "$USE_CACHE" -eq 0 ]]; then
  cp "$RAW_INPUT" "$CACHE_FILE"
fi

if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  echo "skipped=false" >> "$GITHUB_OUTPUT"
fi
