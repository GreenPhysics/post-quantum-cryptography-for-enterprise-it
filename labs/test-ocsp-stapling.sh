#!/usr/bin/env bash
#
# test-ocsp-stapling.sh — OCSP stapling lab
#
# Companion to book chapter "OCSP Stapling". Builds a throwaway CA, obtains
# a real OCSP response from a live responder, staples it into a TLS server,
# and proves from the client side:
#
#   1. Baseline: a server WITHOUT stapling sends no OCSP response
#      (client sees "no response sent" even when it asks with -status)
#   2. A server started with -status_file staples the response:
#      client sees OCSP Response Status: successful + Cert Status: good
#   3. After revocation + fresh responder fetch, the staple says: revoked
#      (the server is now serving proof of its own revocation)
#
# Algorithm auto-detect: ML-DSA on OpenSSL 3.5+, EC P-256 fallback otherwise.
# Usage: ./test-ocsp-stapling.sh [base-port]   (uses base, +1, +2)

set -u
BASE="${1:-19100}"
OCSP_PORT=$BASE; TLS1=$((BASE+1)); TLS2=$((BASE+2))
WORK="$(mktemp -d /tmp/pqc-staple.XXXXXX)"
PASS=0; FAIL=0

say() { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
ok()  { printf '   PASS: %s\n' "$*"; PASS=$((PASS+1)); }
bad() { printf '   FAIL: %s\n' "$*"; FAIL=$((FAIL+1)); }
cleanup() {
  pkill -f "ocsp.*-port $OCSP_PORT" 2>/dev/null
  pkill -f "s_server.*-accept $TLS1" 2>/dev/null
  pkill -f "s_server.*-accept $TLS2" 2>/dev/null
  rm -rf "$WORK"
}
trap cleanup EXIT

# ------------------------------------------------------------ algorithm pick
say "Probe capability"
openssl version
if openssl list -signature-algorithms 2>/dev/null | grep -qi ML-DSA; then
  echo "   Using ML-DSA (CA: ML-DSA-65, leaf: ML-DSA-65)"
  genkey() { openssl genpkey -algorithm ML-DSA-65 -out "$1" 2>/dev/null; }
else
  echo "   Using EC P-256 fallback (no ML-DSA on this build; stapling mechanics identical)"
  genkey() { openssl genpkey -algorithm ec -pkeyopt ec_paramgen_curve:P-256 -out "$1" 2>/dev/null; }
fi

# ------------------------------------------------------------- mini CA setup
say "Building throwaway CA + leaf in $WORK"
mkdir -p "$WORK/newcerts"; touch "$WORK/index.txt"
echo 1000 > "$WORK/serial"; echo 1000 > "$WORK/crlnumber"
cat > "$WORK/ca.cnf" <<EOF
[ ca ]
default_ca = CA_default
[ CA_default ]
dir = $WORK
database = \$dir/index.txt
new_certs_dir = \$dir/newcerts
serial = \$dir/serial
crlnumber = \$dir/crlnumber
private_key = \$dir/ca.key
certificate = \$dir/ca.crt
default_md = sha512
default_days = 365
default_crl_days = 7
policy = policy_any
x509_extensions = srv_cert
[ policy_any ]
commonName = supplied
[ srv_cert ]
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
authorityInfoAccess = OCSP;URI:http://127.0.0.1:$OCSP_PORT
[ req ]
distinguished_name = dn
prompt = no
[ dn ]
CN = Stapling Lab CA
EOF

genkey "$WORK/ca.key"
openssl req -config "$WORK/ca.cnf" -key "$WORK/ca.key" -new -x509 -days 2 \
    -subj "/CN=Stapling Lab CA" \
    -addext "basicConstraints=critical,CA:true" \
    -addext "keyUsage=critical,keyCertSign,cRLSign,digitalSignature" \
    -out "$WORK/ca.crt" 2>/dev/null

genkey "$WORK/srv.key"
openssl req -new -key "$WORK/srv.key" -subj "/CN=localhost" -out "$WORK/srv.csr" 2>/dev/null
openssl ca -config "$WORK/ca.cnf" -batch -notext \
    -in "$WORK/srv.csr" -out "$WORK/srv.crt" 2>/dev/null
[ -s "$WORK/srv.crt" ] && ok "server certificate issued (AIA -> http://127.0.0.1:$OCSP_PORT)" \
  || bad "issuance failed"

# --------------------------------------------------------- responder + fetch
say "Starting OCSP responder and fetching a stapleable response"
openssl ocsp -index "$WORK/index.txt" -port "$OCSP_PORT" \
    -rsigner "$WORK/ca.crt" -rkey "$WORK/ca.key" -CA "$WORK/ca.crt" >/dev/null 2>&1 &
sleep 1
openssl ocsp -CAfile "$WORK/ca.crt" -issuer "$WORK/ca.crt" \
    -cert "$WORK/srv.crt" -url "http://127.0.0.1:$OCSP_PORT" \
    -respout "$WORK/staple-good.der" >/dev/null 2>&1
[ -s "$WORK/staple-good.der" ] \
  && ok "OCSP response saved to DER ($(stat -c%s "$WORK/staple-good.der" 2>/dev/null || wc -c < "$WORK/staple-good.der") bytes)" \
  || bad "could not fetch OCSP response"

# ----------------------------------------- 1. baseline: no stapling offered
say "Test 1: server WITHOUT stapling — client asks, gets nothing"
openssl s_server -cert "$WORK/srv.crt" -key "$WORK/srv.key" \
    -accept "$TLS1" -quiet >/dev/null 2>&1 &
sleep 1
R1=$( (sleep 1; echo Q) | openssl s_client -connect "localhost:$TLS1" \
        -CAfile "$WORK/ca.crt" -status 2>/dev/null | grep -i "OCSP response" | head -1 )
echo "   ${R1:-<no OCSP line>}"
echo "$R1" | grep -qi "no response sent" \
  && ok "no staple sent — baseline confirmed" \
  || bad "expected 'no response sent'"

# ------------------------------------------------ 2. stapled 'good' response
say "Test 2: server WITH -status_file — staple arrives in the handshake"
openssl s_server -cert "$WORK/srv.crt" -key "$WORK/srv.key" \
    -accept "$TLS2" -status_file "$WORK/staple-good.der" -quiet >/dev/null 2>&1 &
sleep 1
R2=$( (sleep 1; echo Q) | openssl s_client -connect "localhost:$TLS2" \
        -CAfile "$WORK/ca.crt" -status 2>/dev/null \
      | grep -Ei "OCSP Response Status|Cert Status|This Update" )
echo "$R2" | sed 's/^ */   /'
echo "$R2" | grep -q "successful" && echo "$R2" | grep -q "good" \
  && ok "stapled response delivered: status successful, cert good" \
  || bad "staple missing or not 'good'"

# --------------------------------- 3. revoke, refetch, staple says 'revoked'
say "Test 3: revoke the server cert — the staple now proves its own revocation"
pkill -f "s_server.*-accept $TLS2" 2>/dev/null
openssl ca -config "$WORK/ca.cnf" -revoke "$WORK/srv.crt" \
    -crl_reason keyCompromise 2>/dev/null
# CAUGHT LIVE IN TESTING: `openssl ocsp` loads index.txt at STARTUP, not per
# query. A responder started before the revocation keeps answering 'good'
# from its stale in-memory copy — the same trap module 05 solves by
# restarting the systemd service after every index sync. Restart it:
pkill -f "ocsp.*-port $OCSP_PORT" 2>/dev/null; sleep 1
openssl ocsp -index "$WORK/index.txt" -port "$OCSP_PORT" \
    -rsigner "$WORK/ca.crt" -rkey "$WORK/ca.key" -CA "$WORK/ca.crt" >/dev/null 2>&1 &
sleep 1
openssl ocsp -CAfile "$WORK/ca.crt" -issuer "$WORK/ca.crt" \
    -cert "$WORK/srv.crt" -url "http://127.0.0.1:$OCSP_PORT" \
    -respout "$WORK/staple-revoked.der" >/dev/null 2>&1
openssl s_server -cert "$WORK/srv.crt" -key "$WORK/srv.key" \
    -accept "$TLS2" -status_file "$WORK/staple-revoked.der" -quiet >/dev/null 2>&1 &
sleep 1
R3=$( (sleep 1; echo Q) | openssl s_client -connect "localhost:$TLS2" \
        -CAfile "$WORK/ca.crt" -status 2>/dev/null \
      | grep -Ei "Cert Status|Reason|Revocation Time" )
echo "$R3" | sed 's/^ */   /'
echo "$R3" | grep -qi "revoked" \
  && ok "staple carries 'revoked' — client can reject before sending a byte of data" \
  || bad "revoked status not stapled"

# --------------------------------------------------------------------- wrap
say "Summary"
echo "   PASS=$PASS FAIL=$FAIL"
echo "   Note: production servers refresh staples automatically (nginx"
echo "   ssl_stapling, HAProxy, F5); s_server -status_file is a static demo."
[ "$FAIL" -eq 0 ]
