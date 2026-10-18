#!/usr/bin/env bash
#
# run-labs.sh — execute the book's self-contained labs once, capturing
# transcript, exit code, and duration for the report generator.
#
# Usage: run-labs.sh [labs-dir] [results-dir]
# Defaults: /opt/pqc/labs  /opt/pqc/results  (container layout)

set -u
LABS="${1:-/opt/pqc/labs}"
OUT="${2:-/opt/pqc/results}"
mkdir -p "$OUT"

# Self-contained labs, auto-run at container start (order = page order).
AUTORUN="test-session-reuse.sh test-revocation.sh test-crl-checking.sh test-ocsp-stapling.sh test-renegotiation.sh"

# Environment snapshot for the report header
{
  echo "date=$(date -u '+%Y-%m-%d %H:%M UTC')"
  echo "openssl=$(openssl version)"
  echo "pqc=$(openssl list -signature-algorithms 2>/dev/null | grep -qi ML-DSA && echo native || echo 'fallback (classical)')"
  echo "host=$(uname -sm)"
} > "$OUT/env.txt"

for lab in $AUTORUN; do
  name="${lab%.sh}"
  echo ">> running $lab"
  start=$(date +%s)
  bash "$LABS/$lab" > "$OUT/$name.txt" 2>&1
  rc=$?
  dur=$(( $(date +%s) - start ))
  echo "rc=$rc" >  "$OUT/$name.meta"
  echo "dur=$dur" >> "$OUT/$name.meta"
done
echo ">> done"
