#!/usr/bin/env bash
#
# test-session-reuse.sh — TLS session resumption lab
#
# Companion to book chapter "Testing TLS Session Reuse".
# Stands up a local openssl s_server, then demonstrates:
#
#   1. The naive -reconnect probe and why it reports false negatives on TLS 1.3
#   2. Correct resumption testing with -sess_out / -sess_in  (New -> Reused)
#   3. Inspection of the saved session file (Resumption PSK = live key material)
#   4. PQC group check on the resumed connection (requires OpenSSL 3.5+;
#      falls back to classical X25519 with a notice on older builds)
#   5. Negative control: server with -num_tickets 0 must NOT resume
#
# Usage:   ./test-session-reuse.sh [port]
# Safe to re-run; everything lives in a temp dir and is cleaned on exit.

set -u
PORT="${1:-14434}"
PORT2=$((PORT + 1))
WORK="$(mktemp -d /tmp/pqc-sessreuse.XXXXXX)"
PASS=0; FAIL=0

say()  { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
ok()   { printf '   PASS: %s\n' "$*"; PASS=$((PASS+1)); }
bad()  { printf '   FAIL: %s\n' "$*"; FAIL=$((FAIL+1)); }

cleanup() {
  pkill -f "s_server.*-accept $PORT" 2>/dev/null
  pkill -f "s_server.*-accept $PORT2" 2>/dev/null
  rm -rf "$WORK"
}
trap cleanup EXIT

# ---------------------------------------------------------------- probe check
say "Probe capability"
openssl version
if openssl list -tls-groups 2>/dev/null | grep -qi MLKEM; then
  GROUPS_ARG="X25519MLKEM768"
  echo "   ML-KEM hybrid groups available: using $GROUPS_ARG"
else
  GROUPS_ARG="X25519"
  echo "   NOTE: this OpenSSL has no ML-KEM groups (pre-3.5)."
  echo "   Resumption mechanics are identical; PQC group check will use $GROUPS_ARG."
fi

# ---------------------------------------------------------------- test server
say "Starting test server on :$PORT"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
    -keyout "$WORK/srv.key" -out "$WORK/srv.crt" -days 2 -nodes \
    -subj "/CN=localhost" 2>/dev/null
openssl s_server -cert "$WORK/srv.crt" -key "$WORK/srv.key" \
    -accept "$PORT" -quiet >/dev/null 2>&1 &
sleep 1

# ------------------------------------------------- 1. the naive probe (lies)
say "Test 1: naive -reconnect probe (expected to show the false negative)"
echo | openssl s_client -connect "localhost:$PORT" -reconnect 2>/dev/null \
  | grep -E "^(New|Reused)," | sed 's/^/   /'
echo "   ^ All 'New' despite a resumption-capable server: stdin closed"
echo "     before the TLS 1.3 NewSessionTicket arrived. Probe defect, not server defect."

# ------------------------------------- 2. correct probe: explicit session file
say "Test 2: correct probe with -sess_out / -sess_in"
L1=$( (sleep 1; echo Q) | openssl s_client -connect "localhost:$PORT" \
        -sess_out "$WORK/t.sess" 2>/dev/null | grep -E "^(New|Reused)," )
L2=$( (sleep 1; echo Q) | openssl s_client -connect "localhost:$PORT" \
        -sess_in  "$WORK/t.sess" 2>/dev/null | grep -E "^(New|Reused)," )
echo "   conn 1: $L1"
echo "   conn 2: $L2"
case "$L1" in New,*)    ok "first connection was a full handshake";; *) bad "first connection: expected New";; esac
case "$L2" in Reused,*) ok "second connection resumed";;             *) bad "second connection: expected Reused";; esac

# ---------------------------------------------------- 3. session file contents
say "Test 3: session file inspection (note the Resumption PSK — key material!)"
openssl sess_id -in "$WORK/t.sess" -noout -text 2>/dev/null | head -6 | sed 's/^/   /'

# ------------------------------------------- 4. group freshness on resumption
say "Test 4: key-exchange group on the RESUMED connection (psk_dhe_ke check)"
# Version note: OpenSSL 3.5 prints "Negotiated TLS1.3 group: <name>"; older
# builds print only "Server Temp Key: <alg>". Either proves a fresh key
# exchange happened alongside the PSK (psk_dhe_ke). Neither line = psk_ke.
OUT=$( (sleep 1; echo Q) | openssl s_client -connect "localhost:$PORT" \
        -sess_in "$WORK/t.sess" -groups "$GROUPS_ARG" 2>/dev/null \
      | grep -E "^Reused,|Negotiated TLS1.3 group|Server Temp Key" )
echo "$OUT" | sed 's/^/   /'
if echo "$OUT" | grep -q "^Reused," ; then
  if echo "$OUT" | grep -Eq "Negotiated TLS1.3 group: $GROUPS_ARG|Server Temp Key"; then
    ok "resumed WITH fresh key exchange — psk_dhe_ke confirmed"
  else
    bad "resumed WITHOUT fresh key exchange — psk_ke mode; forward secrecy waived (policy finding)"
  fi
else
  bad "session did not resume in group test"
fi

# ------------------------------------------------------- 5. negative control
say "Test 5: negative control — server with -num_tickets 0 must not resume"
openssl s_server -cert "$WORK/srv.crt" -key "$WORK/srv.key" \
    -accept "$PORT2" -num_tickets 0 -quiet >/dev/null 2>&1 &
sleep 1
(sleep 1; echo Q) | openssl s_client -connect "localhost:$PORT2" \
    -sess_out "$WORK/t0.sess" 2>/dev/null >/dev/null
N=$( (sleep 1; echo Q) | openssl s_client -connect "localhost:$PORT2" \
       -sess_in "$WORK/t0.sess" 2>/dev/null | grep -E "^(New|Reused)," )
echo "   conn 2 vs no-ticket server: ${N:-<no session line>}"
case "$N" in
  Reused,*) bad "resumed against a server that issues no tickets — probe is unreliable";;
  *)        ok "no resumption without tickets — probe correctly detects non-resumption";;
esac

# ---------------------------------------------------------------------- wrap
say "Summary"
echo "   PASS=$PASS FAIL=$FAIL"
echo "   Session files are deleted on exit (they contain live PSKs)."
[ "$FAIL" -eq 0 ]
