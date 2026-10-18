#!/usr/bin/env bash
#
# PQC Apache entrypoint.
#   (no args)  start httpd and serve PQC TLS on 8443/8444/8445
#   verify     start httpd, run the proof probes, print PASS/FAIL, exit
#   ca         emit the browser (EC) CA certificate     — for 8444
#   ca-pqc     emit the ML-DSA-87 CA certificate        — for 8443/8445
#
# The verify mode demonstrates, on the reader's own hardware, that a stock
# Apache httpd — built against OpenSSL 3.5.x and nothing else — serves fully
# post-quantum TLS, and can be configured to REFUSE classical parameters,
# which is what the CNSA 2.0 TLS profile actually requires.

set -u

case "${1:-}" in
  ca|ca-ec)  exec cat /opt/pki-ec/ca.crt ;;
  ca-pqc)    exec cat /opt/pki/ca.crt    ;;
esac

PASS=0; FAIL=0
say() { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
ok()  { printf '   PASS: %s\n' "$*"; PASS=$((PASS+1)); }
bad() { printf '   FAIL: %s\n' "$*"; FAIL=$((FAIL+1)); }

say "Environment"
openssl version
echo "   ML-DSA signature algorithms: $(openssl list -signature-algorithms | grep -c ML-DSA)"
echo "   ML-KEM groups: $(openssl list -tls-groups | tr ':' '\n' | grep -ci mlkem)"
/opt/httpd/bin/httpd -v | sed 's/^/   /'
echo "   certificate chain (8443/8445):"
openssl x509 -in /opt/pki/server.crt -noout -text | \
  grep -E "Signature Algorithm|Public Key Algorithm" | sort -u | sed 's/^ */     /'

say "Proof 1: mod_ssl is bound to OUR OpenSSL, not a system library"
# The same mod_ssl.so binds whatever libssl.so.3 the loader resolves. On a
# host with a system OpenSSL 3.0 this starts cleanly and serves classical TLS
# with no post-quantum support — silently. The RPATH burned in at build time
# is what pins it; ldd is how you check it.
LDD_OUT=$(ldd /opt/httpd/modules/mod_ssl.so | grep -E 'libssl|libcrypto')
echo "$LDD_OUT" | sed 's/^/   /'
echo "$LDD_OUT" | grep -q "/opt/openssl/lib" \
  && ok "mod_ssl resolves /opt/openssl (3.5.x) — the library that has ML-KEM and ML-DSA" \
  || bad "mod_ssl resolved a different libssl — PQC support cannot be assumed"

say "Starting httpd"
/opt/httpd/bin/httpd
for i in $(seq 1 15); do
  grep -q "resuming normal operations" /opt/httpd/logs/error_log 2>/dev/null && break
  sleep 1
done
grep "resuming normal operations" /opt/httpd/logs/error_log | tail -1 | sed 's/^/   /'
if grep -q "Apache.*OpenSSL/3\.5" /opt/httpd/logs/error_log; then
  ok "startup banner names the library: $(grep -o 'OpenSSL/[0-9.]*' /opt/httpd/logs/error_log | head -1)"
else
  bad "startup banner does not show OpenSSL 3.5.x — check error_log"
fi

if [ "${1:-}" != "verify" ]; then
  cat <<'BANNER'

  Three listeners are serving:

    https://localhost:8443   CNSA 2.0 algorithms, interoperable — ML-DSA-87
                             chain, ML-KEM-1024 preferred, hybrids accepted,
                             AES-256-GCM only.

    https://localhost:8444   browser-compatible — classical ECDSA chain
                             + ML-KEM hybrid key exchange. A real padlock
                             plus post-quantum confidentiality.

    https://localhost:8445   CNSA 2.0 STRICT — ML-KEM-1024 or nothing.
                             Classical clients are refused (alert 40),
                             which is what the profile requires.

  Trust the browser CA on your host:

    docker run --rm pqc-apache ca > pqc-lab-ec-ca.crt
    # macOS:  sudo security add-trusted-cert -d -r trustRoot \
    #           -k /Library/Keychains/System.keychain pqc-lab-ec-ca.crt
    # Remove it when finished — a trusted root can vouch for any hostname.

  Then open https://localhost:8444 — padlock present, key exchange ML-KEM.

BANNER
  exec tail -f /opt/httpd/logs/error_log
fi

say "Proof 2: full post-quantum handshake (ML-DSA-87 chain + ML-KEM)"
OUT=$(echo | openssl s_client -connect 127.0.0.1:8443 -brief \
        -CAfile /opt/pki/ca.crt 2>&1)
echo "$OUT" | grep -E "Protocol version|Ciphersuite|Signature type|Verification|group|Hash" | sed 's/^/   /'
echo "$OUT" | grep -q "Verification: OK" && echo "$OUT" | grep -qi "mldsa87" \
  && ok "ML-DSA-87 chain verified; note 'Hash used: UNDEF' — ML-DSA hashes internally" \
  || bad "PQC handshake on 8443 did not complete as expected"

say "Proof 3: pure ML-KEM-1024 negotiated (CNSA 2.0 key establishment)"
OUT=$(echo | openssl s_client -connect 127.0.0.1:8443 -brief \
        -groups MLKEM1024 -CAfile /opt/pki/ca.crt 2>&1)
echo "$OUT" | grep -E "Negotiated TLS1.3 group|Ciphersuite" | sed 's/^/   /'
echo "$OUT" | grep -q "MLKEM1024" \
  && ok "negotiated MLKEM1024 — set in the vhost via SSLOpenSSLConfCmd, no openssl.cnf needed" \
  || bad "MLKEM1024 not negotiated"

say "Proof 4: browser-compatible listener (classical chain + ML-KEM)"
OUT=$(echo | openssl s_client -connect 127.0.0.1:8444 -brief \
        -CAfile /opt/pki-ec/ca.crt 2>&1)
echo "$OUT" | grep -E "Protocol version|Signature type|Verification|group" | sed 's/^/   /'
echo "$OUT" | grep -q "Verification: OK" && echo "$OUT" | grep -q "MLKEM" \
  && ok "8444: classical authentication + post-quantum confidentiality (what browsers do today)" \
  || bad "8444 did not complete as expected"

say "Proof 5: strict listener REFUSES a classical-only client"
# The CNSA 2.0 TLS profile requires that non-compliant parameters be
# rejected, not merely deprioritized. A client offering only X25519 must
# fail. Audit with a restricted client, never a cooperative one.
OUT=$(echo | openssl s_client -connect 127.0.0.1:8445 -brief \
        -groups X25519 -CAfile /opt/pki/ca.crt 2>&1)
echo "$OUT" | grep -E "alert|error" | head -2 | sed 's/^/   /'
if echo "$OUT" | grep -q "alert number 40\|handshake failure"; then
  ok "classical-only client refused (alert 40) — exclusion, not preference"
else
  echo "$OUT" | grep -q "CONNECTION ESTABLISHED" \
    && bad "strict listener accepted a classical client — profile violated" \
    || bad "unexpected result on 8445 refusal probe"
fi

say "Proof 6: strict listener completes a fully compliant handshake"
OUT=$(echo | openssl s_client -connect 127.0.0.1:8445 -brief \
        -groups MLKEM1024 -CAfile /opt/pki/ca.crt 2>&1)
echo "$OUT" | grep -E "Ciphersuite|Signature type|Verification|group" | sed 's/^/   /'
echo "$OUT" | grep -q "MLKEM1024" && echo "$OUT" | grep -q "TLS_AES_256_GCM_SHA384" \
    && echo "$OUT" | grep -q "Verification: OK" \
  && ok "MLKEM1024 + AES-256-GCM + ML-DSA-87, chain verified — every CNSA 2.0 algorithm" \
  || bad "compliant handshake on 8445 failed"

say "Proof 7: real HTTP served over post-quantum TLS"
OUT=$(printf 'GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n' | \
      openssl s_client -connect 127.0.0.1:8443 -quiet -CAfile /opt/pki/ca.crt 2>/dev/null)
echo "$OUT" | grep -m1 "HTTP/" | sed 's/^/   /'
echo "$OUT" | grep -q "200 OK" \
  && ok "HTTP 200 over the ML-DSA + ML-KEM session" \
  || bad "no HTTP response over the PQC session"
echo "   Apache's own record of the session (logs/pqc_ssl_log):"
tail -1 /opt/httpd/logs/pqc_ssl_log 2>/dev/null | sed 's/^/   /'

say "Summary"
echo "   PASS=$PASS FAIL=$FAIL"
echo "   The same httpd binary on a system OpenSSL 3.0 starts cleanly and"
echo "   serves none of this. Verify the library, not the banner alone."
/opt/httpd/bin/httpd -k stop >/dev/null 2>&1
[ "$FAIL" -eq 0 ]
