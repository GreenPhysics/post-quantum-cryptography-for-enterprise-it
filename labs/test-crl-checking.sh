#!/usr/bin/env bash
#
# test-crl-checking.sh — client-side CRL failure-mode lab
#
# Companion to book chapter "Certificate Revocation" (CRL failure modes
# section). The revocation lab proved the CA-side mechanics; this lab proves
# the CLIENT-side ways a revoked certificate slips back into trust:
#
#   1. Verification WITHOUT -crl_check accepts a revoked cert
#      (revocation checking is opt-in; the MITM window of lazy clients)
#   2. Verification with a STALE (pre-revocation) CRL accepts a revoked cert
#      (the cached-CRL window — CRL analog of the stale-OCSP-responder trap)
#   3. Verification with the FRESH CRL rejects it (error 23)
#   4. Verification with an EXPIRED CRL fails closed (error 12)
#      (freshness is enforced — an old list is not silently trusted forever)
#
# Algorithm auto-detect: ML-DSA on OpenSSL 3.5+, EC P-256 fallback otherwise.
# Usage: ./test-crl-checking.sh

set -u
WORK="$(mktemp -d /tmp/pqc-crlcheck.XXXXXX)"
PASS=0; FAIL=0
say() { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
ok()  { printf '   PASS: %s\n' "$*"; PASS=$((PASS+1)); }
bad() { printf '   FAIL: %s\n' "$*"; FAIL=$((FAIL+1)); }
trap 'rm -rf "$WORK"' EXIT

say "Probe capability"
openssl version
if openssl list -signature-algorithms 2>/dev/null | grep -qi ML-DSA; then
  echo "   Using ML-DSA-65"
  genkey() { openssl genpkey -algorithm ML-DSA-65 -out "$1" 2>/dev/null; }
else
  echo "   Using EC P-256 fallback (checking mechanics identical)"
  genkey() { openssl genpkey -algorithm ec -pkeyopt ec_paramgen_curve:P-256 -out "$1" 2>/dev/null; }
fi

# ------------------------------------------------------------- mini CA setup
say "Building throwaway CA, issuing victim cert"
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
x509_extensions = usr_cert
[ policy_any ]
commonName = supplied
[ usr_cert ]
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature
[ req ]
distinguished_name = dn
prompt = no
[ dn ]
CN = CRL Lab CA
EOF
genkey "$WORK/ca.key"
openssl req -config "$WORK/ca.cnf" -key "$WORK/ca.key" -new -x509 -days 2 \
    -subj "/CN=CRL Lab CA" \
    -addext "basicConstraints=critical,CA:true" \
    -addext "keyUsage=critical,keyCertSign,cRLSign,digitalSignature" \
    -out "$WORK/ca.crt" 2>/dev/null
genkey "$WORK/victim.key"
openssl req -new -key "$WORK/victim.key" -subj "/CN=victim" -out "$WORK/victim.csr" 2>/dev/null
openssl ca -config "$WORK/ca.cnf" -batch -notext \
    -in "$WORK/victim.csr" -out "$WORK/victim.crt" 2>/dev/null
[ -s "$WORK/victim.crt" ] && ok "victim cert issued" || bad "issuance failed"

# CRL v1: BEFORE revocation (this is the 'stale cache' artifact)
openssl ca -config "$WORK/ca.cnf" -gencrl -out "$WORK/crl-stale.pem" 2>/dev/null

# Revoke, then CRL v2: AFTER revocation
openssl ca -config "$WORK/ca.cnf" -revoke "$WORK/victim.crt" \
    -crl_reason keyCompromise 2>/dev/null
openssl ca -config "$WORK/ca.cnf" -gencrl -out "$WORK/crl-fresh.pem" 2>/dev/null
echo "   victim revoked (keyCompromise); crl-stale (pre) and crl-fresh (post) generated"

# --------------------------- 1. no -crl_check: revoked cert sails through
say "Test 1: verify WITHOUT -crl_check — revocation checking is opt-in"
V=$(openssl verify -CAfile "$WORK/ca.crt" "$WORK/victim.crt" 2>&1)
echo "$V" | sed 's/^/   /'
echo "$V" | grep -q ": OK" \
  && ok "revoked cert ACCEPTED without -crl_check — proves checking is opt-in" \
  || bad "unexpected rejection"

# --------------------------- 2. stale CRL: revoked cert still sails through
say "Test 2: verify with STALE pre-revocation CRL — the cached-CRL window"
V=$(openssl verify -crl_check -CAfile "$WORK/ca.crt" \
      -CRLfile "$WORK/crl-stale.pem" "$WORK/victim.crt" 2>&1)
echo "$V" | sed 's/^/   /'
echo "$V" | grep -q ": OK" \
  && ok "revoked cert ACCEPTED via stale CRL — cache window demonstrated" \
  || bad "unexpected result with stale CRL"

# ------------------------------------- 3. fresh CRL: rejected with error 23
say "Test 3: verify with FRESH CRL — revocation finally bites"
V=$(openssl verify -crl_check -CAfile "$WORK/ca.crt" \
      -CRLfile "$WORK/crl-fresh.pem" "$WORK/victim.crt" 2>&1)
echo "$V" | sed 's/^/   /'
echo "$V" | grep -q "certificate revoked" \
  && ok "revoked cert rejected (error 23) with fresh CRL" \
  || bad "fresh CRL did not reject revoked cert"

# ----------------------------------- 4. expired CRL: fails closed (error 12)
say "Test 4: verify with EXPIRED CRL — freshness is enforced, fails closed"
# Note: -crldays/-crlhours/-crlsec take a POSITIVE integer (0 is rejected,
# and the failure is silent if stderr is discarded — caught live in testing).
openssl ca -config "$WORK/ca.cnf" -gencrl -crlsec 1 \
    -out "$WORK/crl-expired.pem" 2>/dev/null
sleep 2
V=$(openssl verify -crl_check -CAfile "$WORK/ca.crt" \
      -CRLfile "$WORK/crl-expired.pem" "$WORK/victim.crt" 2>&1)
echo "$V" | sed 's/^/   /'
echo "$V" | grep -qi "CRL has expired" \
  && ok "expired CRL rejected (error 12) — client refuses stale-forever lists" \
  || bad "expired CRL was not flagged"

say "Summary"
echo "   PASS=$PASS FAIL=$FAIL"
echo "   Lesson: tests 1-2 are the MITM window. A client must (a) enable"
echo "   revocation checking AND (b) refresh CRLs faster than the CA revokes."
[ "$FAIL" -eq 0 ]
