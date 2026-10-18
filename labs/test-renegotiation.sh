#!/usr/bin/env bash
#
# test-renegotiation.sh — TLS renegotiation lab
#
# Companion to book chapter "Testing Renegotiation". Proves, live:
#
#   1. TLS 1.2: client reports "Secure Renegotiation IS supported" (RFC 5746)
#   2. TLS 1.2: server-triggered renegotiation mid-connection actually happens
#      (s_server -www treats "GET /reneg" as a renegotiation trigger:
#       observe HelloRequest + TWO ClientHellos in one connection, then 200 OK)
#   3. TLS 1.3: "Secure Renegotiation IS NOT supported" — and that is CORRECT,
#      not a vulnerability: renegotiation was removed from the protocol
#   4. TLS 1.3: the same /reneg trigger produces exactly ONE ClientHello —
#      there is no renegotiation to perform
#
# Automation note (kept per house rules): s_client's interactive command
# letters (R = renegotiate, k/K = TLS 1.3 KeyUpdate) could not be driven
# through pipes or a pty in our test environment — they appear to require a
# genuine interactive terminal. The /reneg URL of `s_server -www` is the
# deterministic, scriptable trigger; use the command letters manually when
# exploring. KeyUpdate is therefore demonstrated in the chapter as a manual
# exercise + the SSL_key_update() API note.
#
# Algorithm auto-detect: ML-DSA cert on OpenSSL 3.5+, EC P-256 fallback.
# Usage: ./test-renegotiation.sh [port]

set -u
PORT="${1:-16443}"
WORK="$(mktemp -d /tmp/pqc-reneg.XXXXXX)"
PASS=0; FAIL=0
say() { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
ok()  { printf '   PASS: %s\n' "$*"; PASS=$((PASS+1)); }
bad() { printf '   FAIL: %s\n' "$*"; FAIL=$((FAIL+1)); }
cleanup() { [ -n "${SRV_PID:-}" ] && kill "$SRV_PID" 2>/dev/null; rm -rf "$WORK"; }
trap cleanup EXIT

say "Probe capability"
openssl version
# The renegotiation tests REQUIRE a classical certificate: ML-DSA signature
# codepoints exist only in TLS 1.3, so an ML-DSA cert cannot complete any
# TLS 1.2 handshake — discovered live on the first PQC-native run, when the
# auto-selected ML-DSA cert silently killed every TLS 1.2 test. That
# incompatibility is now asserted as its own test (Test 5) when PQC exists.
HAVE_PQC=0
openssl list -signature-algorithms 2>/dev/null | grep -qi ML-DSA && HAVE_PQC=1
echo "   EC P-256 server certificate for TLS 1.2 tests (required — see comment)"
[ $HAVE_PQC -eq 1 ] && echo "   ML-DSA available: Test 5 will assert TLS 1.2/ML-DSA incompatibility"
openssl genpkey -algorithm ec -pkeyopt ec_paramgen_curve:P-256 -out "$WORK/srv.key" 2>/dev/null
openssl req -x509 -key "$WORK/srv.key" -out "$WORK/srv.crt" -days 2 \
    -subj "/CN=localhost" 2>/dev/null

openssl s_server -cert "$WORK/srv.crt" -key "$WORK/srv.key" \
    -accept "$PORT" -www >/dev/null 2>&1 &
SRV_PID=$!
sleep 1

probe() { # $1=protocol flag  $2=path  -> full -msg transcript on stdout
  (sleep 1; printf 'GET %s HTTP/1.0\r\n\r\n' "$2"; sleep 2) \
    | openssl s_client -connect "localhost:$PORT" "$1" -msg 2>&1
}

# ---------------------------------------------- 1. RFC 5746 indicator, 1.2
say "Test 1: TLS 1.2 secure renegotiation indicator (RFC 5746)"
# Indicator probes deliberately fetch NO page: the -www HTML echoes its own
# copy of the line, which polluted the grep — caught live on 3.5.7.
I12=$(echo | timeout 8 openssl s_client -connect "localhost:$PORT" -tls1_2 2>&1 \
      | grep -a "^Secure Renegotiation" | head -1)
echo "   $I12"
echo "$I12" | grep -q "IS supported" \
  && ok "extension present — connection is protected against CVE-2009-3555 splicing" \
  || bad "secure renegotiation extension missing on TLS 1.2"

# ------------------------------- 2. live renegotiation mid-connection, 1.2
say "Test 2: TLS 1.2 mid-connection renegotiation (GET /reneg)"
T12=$(probe -tls1_2 /reneg)
CH12=$(echo "$T12" | grep -ac "ClientHello")
HR12=$(echo "$T12" | grep -ac "HelloRequest")
OK12=$(echo "$T12" | grep -ac "HTTP/1.0 200")
echo "   ClientHello count: $CH12   HelloRequest: $HR12   HTTP 200 after: $OK12"
[ "$CH12" -eq 2 ] && [ "$HR12" -ge 1 ] && [ "$OK12" -ge 1 ] \
  && ok "server sent HelloRequest, full second handshake completed, data resumed" \
  || bad "expected 2 ClientHellos + HelloRequest + 200 (got CH=$CH12 HR=$HR12 OK=$OK12)"

# ------------------------------------------------- 3. indicator on TLS 1.3
say "Test 3: TLS 1.3 indicator — 'NOT supported' (or absent) is correct"
# Version dialects, caught live: 3.0.x prints "Secure Renegotiation IS NOT
# supported" on TLS 1.3; 3.5.x omits the line entirely (it is meaningless
# in 1.3). Either is a pass; only "IS supported" would be anomalous.
I13=$(echo | timeout 8 openssl s_client -connect "localhost:$PORT" -tls1_3 2>&1 \
      | grep -a "^Secure Renegotiation" | head -1)
echo "   ${I13:-<no indicator line — this OpenSSL omits it on TLS 1.3>}"
if echo "$I13" | grep -q "IS supported"; then
  bad "unexpected 'IS supported' renegotiation indicator on TLS 1.3"
else
  ok "TLS 1.3 shows no renegotiation support — the mechanism was removed from the protocol"
fi

# ------------------------------------- 4. /reneg on 1.3: nothing to trigger
say "Test 4: TLS 1.3 GET /reneg — exactly one ClientHello, no second handshake"
T13=$(probe -tls1_3 /reneg)
CH13=$(echo "$T13" | grep -ac "ClientHello")
echo "   ClientHello count: $CH13"
[ "$CH13" -eq 1 ] \
  && ok "no renegotiation occurred — TLS 1.3 removed it; rekeying is KeyUpdate's job" \
  || bad "expected exactly 1 ClientHello on TLS 1.3 (got $CH13)"

# --------------------------- 5. (PQC only) ML-DSA certs are TLS 1.3-only
if [ $HAVE_PQC -eq 1 ]; then
  say "Test 5: an ML-DSA certificate cannot negotiate TLS 1.2"
  PORT5=$((PORT + 1))
  openssl genpkey -algorithm ML-DSA-65 -out "$WORK/pq.key" 2>/dev/null
  openssl req -x509 -key "$WORK/pq.key" -out "$WORK/pq.crt" -days 2 \
      -subj "/CN=localhost" 2>/dev/null
  openssl s_server -cert "$WORK/pq.crt" -key "$WORK/pq.key" \
      -accept "$PORT5" -www >/dev/null 2>&1 &
  SRV5_PID=$!
  sleep 1
  R12=$(echo | timeout 8 openssl s_client -connect "localhost:$PORT5" -tls1_2 2>&1 \
        | grep -cE "^New, TLSv1.2")
  # Version dialects: 3.5.x -brief prints "Signature type: mldsa65";
  # other releases may use the full name. Accept either spelling.
  R13=$(echo | timeout 8 openssl s_client -connect "localhost:$PORT5" -tls1_3 -brief 2>&1 \
        | grep -icE "Signature type: (ML-DSA-65|mldsa65)")
  echo "   TLS 1.2 handshakes completed: $R12   TLS 1.3 with ML-DSA-65 signature: $R13"
  [ "$R12" -eq 0 ] && ok "TLS 1.2 handshake fails with ML-DSA cert (codepoints are 1.3-only)" \
                   || bad "TLS 1.2 unexpectedly completed with an ML-DSA certificate"
  [ "$R13" -ge 1 ] && ok "same certificate serves TLS 1.3 (Signature type: ML-DSA-65)" \
                   || bad "TLS 1.3 did not authenticate with the ML-DSA certificate"
  kill "$SRV5_PID" 2>/dev/null
fi

say "Summary"
echo "   PASS=$PASS FAIL=$FAIL"
echo "   PQC notes: (1) KeyUpdate ratchets traffic keys from the existing"
echo "   secret — it does NOT perform a fresh ML-KEM exchange; for fresh"
echo "   quantum-resistant entropy use a new connection or psk_dhe_ke"
echo "   resumption. (2) ML-DSA certificates serve TLS 1.3 only — a TLS 1.2"
echo "   estate cannot present them at all."
[ "$FAIL" -eq 0 ]
