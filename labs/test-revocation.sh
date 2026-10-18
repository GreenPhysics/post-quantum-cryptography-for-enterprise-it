#!/usr/bin/env bash
#
# test-revocation.sh — CRL and OCSP revocation lab
#
# Companion to book chapter "Certificate Revocation" (lab: fipsqs module 05).
# Builds a throwaway one-tier CA, issues two certs, revokes one, then proves:
#
#   1. Revocation flips the CA database entry V -> R
#   2. The regenerated CRL carries the serial + reason code
#   3. `openssl verify -crl_check` fails the revoked cert (error 23)
#      and still passes the valid cert
#   4. CRL signature verifies against the CA
#   5. A live `openssl ocsp` responder answers: good / revoked (+reason)
#
# Algorithm auto-detect: ML-DSA on OpenSSL 3.5+, EC P-256 fallback otherwise
# (revocation mechanics are identical; only the signatures differ).
#
# Usage: ./test-revocation.sh [ocsp-port]

set -u
PORT="${1:-18888}"
WORK="$(mktemp -d /tmp/pqc-revoke.XXXXXX)"
PASS=0; FAIL=0

say() { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
ok()  { printf '   PASS: %s\n' "$*"; PASS=$((PASS+1)); }
bad() { printf '   FAIL: %s\n' "$*"; FAIL=$((FAIL+1)); }
cleanup() { pkill -f "ocsp.*-port $PORT" 2>/dev/null; rm -rf "$WORK"; }
trap cleanup EXIT

# ------------------------------------------------------------ algorithm pick
say "Probe capability"
openssl version
if openssl list -signature-algorithms 2>/dev/null | grep -qi ML-DSA; then
  CA_ALG="ML-DSA-65"; LEAF_ALG="ML-DSA-44"
  # $1 is a role selector (CA|LEAF), not an algorithm name. Passing it to
  # -algorithm directly was a latent bug, unreachable until the first run
  # on a PQC-native OpenSSL — caught live when 3.5.7 arrived.
  genkey() { local a; [ "$1" = "CA" ] && a="$CA_ALG" || a="$LEAF_ALG"
             openssl genpkey -algorithm "$a" -out "$2" 2>/dev/null; }
else
  CA_ALG="EC-P256 (fallback: no ML-DSA on this build)"; LEAF_ALG="$CA_ALG"
  genkey() { openssl genpkey -algorithm ec -pkeyopt ec_paramgen_curve:P-256 -out "$2" 2>/dev/null; }
fi
echo "   CA algorithm:   $CA_ALG"
echo "   Leaf algorithm: $LEAF_ALG"

# ------------------------------------------------------------- mini CA setup
say "Building throwaway CA in $WORK"
mkdir -p "$WORK"/{newcerts,crl}
touch "$WORK/index.txt"
echo 1000 > "$WORK/serial"
echo 1000 > "$WORK/crlnumber"

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
crl_extensions = crl_ext
[ policy_any ]
commonName = supplied
[ usr_cert ]
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature
[ crl_ext ]
authorityKeyIdentifier = keyid:always
[ req ]
distinguished_name = dn
prompt = no
[ dn ]
CN = Revocation Lab CA
EOF

genkey CA "$WORK/ca.key"
openssl req -config "$WORK/ca.cnf" -key "$WORK/ca.key" -new -x509 -days 2 \
    -subj "/CN=Revocation Lab CA" \
    -addext "basicConstraints=critical,CA:true" \
    -addext "keyUsage=critical,keyCertSign,cRLSign,digitalSignature" \
    -out "$WORK/ca.crt" 2>/dev/null

issue() { # $1=name
  genkey LEAF "$WORK/$1.key"
  openssl req -new -key "$WORK/$1.key" -subj "/CN=$1" -out "$WORK/$1.csr" 2>/dev/null
  openssl ca -config "$WORK/ca.cnf" -batch -notext \
      -in "$WORK/$1.csr" -out "$WORK/$1.crt" 2>/dev/null
}
issue good-cert
issue revoke-me
[ -s "$WORK/good-cert.crt" ] && [ -s "$WORK/revoke-me.crt" ] \
  && ok "issued good-cert and revoke-me" || bad "certificate issuance failed"

# --------------------------------------------------------- 1. revoke: V -> R
say "Test 1: revocation flips the database entry V -> R"
echo "   before: $(grep revoke-me "$WORK/index.txt" | cut -c1)"
openssl ca -config "$WORK/ca.cnf" -revoke "$WORK/revoke-me.crt" \
    -crl_reason keyCompromise 2>/dev/null
ST=$(grep revoke-me "$WORK/index.txt" | cut -c1)
echo "   after:  $ST"
[ "$ST" = "R" ] && ok "database shows R (revoked)" || bad "expected R, got '$ST'"

# ----------------------------------------------------- 2. CRL carries reason
say "Test 2: regenerated CRL lists the serial with reason code"
openssl ca -config "$WORK/ca.cnf" -gencrl -out "$WORK/crl/ca.crl" 2>/dev/null
openssl crl -in "$WORK/crl/ca.crl" -noout -text \
  | grep -E "Signature Algorithm|Serial Number|CRL Reason|Key Compromise" \
  | sort -u | sed 's/^ *//;s/^/   /'
openssl crl -in "$WORK/crl/ca.crl" -noout -text | grep -q "Key Compromise" \
  && ok "CRL carries keyCompromise reason" || bad "reason code missing from CRL"

# ------------------------------------------- 3. verify -crl_check both certs
say "Test 3: openssl verify -crl_check"
V1=$(openssl verify -crl_check -CAfile "$WORK/ca.crt" \
       -CRLfile "$WORK/crl/ca.crl" "$WORK/revoke-me.crt" 2>&1)
echo "$V1" | sed 's/^/   /'
echo "$V1" | grep -q "certificate revoked" \
  && ok "revoked cert fails verification (error 23)" || bad "revoked cert was not rejected"

V2=$(openssl verify -crl_check -CAfile "$WORK/ca.crt" \
       -CRLfile "$WORK/crl/ca.crl" "$WORK/good-cert.crt" 2>&1)
echo "$V2" | sed 's/^/   /'
echo "$V2" | grep -q ": OK" \
  && ok "valid cert still verifies" || bad "valid cert failed verification"

# ------------------------------------------------------- 4. CRL is signed
say "Test 4: CRL signature verifies against the CA"
V3=$(openssl crl -in "$WORK/crl/ca.crl" -CAfile "$WORK/ca.crt" -verify -noout 2>&1)
echo "$V3" | sed 's/^/   /'
echo "$V3" | grep -q "verify OK" && ok "CRL signature valid" || bad "CRL signature invalid"

# --------------------------------------------------------- 5. live OCSP
say "Test 5: live OCSP responder (port $PORT)"
openssl ocsp -index "$WORK/index.txt" -port "$PORT" \
    -rsigner "$WORK/ca.crt" -rkey "$WORK/ca.key" \
    -CA "$WORK/ca.crt" >/dev/null 2>&1 &
sleep 1

Q1=$(openssl ocsp -CAfile "$WORK/ca.crt" -issuer "$WORK/ca.crt" \
       -cert "$WORK/good-cert.crt" -url "http://127.0.0.1:$PORT" 2>&1 \
     | grep -E "good-cert.crt:|Response verify")
echo "$Q1" | sed 's/^/   /'
echo "$Q1" | grep -q ": good" && ok "OCSP answers 'good' for valid cert" \
  || bad "OCSP did not answer good"

Q2=$(openssl ocsp -CAfile "$WORK/ca.crt" -issuer "$WORK/ca.crt" \
       -cert "$WORK/revoke-me.crt" -url "http://127.0.0.1:$PORT" 2>&1 \
     | grep -E "revoke-me.crt:|Reason|Revocation Time")
echo "$Q2" | sed 's/^/   /'
echo "$Q2" | grep -q ": revoked" && ok "OCSP answers 'revoked' with reason" \
  || bad "OCSP did not answer revoked"

# Note: production responders use a dedicated OCSPSigning-EKU cert (see the
# private-CA chapter); this lab signs with the CA key directly for brevity.

# --------------------------------------------------------------------- wrap
say "Summary"
echo "   PASS=$PASS FAIL=$FAIL"
[ "$FAIL" -eq 0 ]
