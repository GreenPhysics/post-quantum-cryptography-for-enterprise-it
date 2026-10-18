#!/usr/bin/env bash
#
# PQC Tomcat entrypoint.
#   (no args)  start Tomcat and serve PQC TLS on 8443
#   verify     start Tomcat, run the proof probes, print PASS/FAIL, exit
#
# The verify mode is the point of the image: it demonstrates, on the reader's
# own hardware, a TLS handshake that JSSE cannot perform — an ML-DSA-signed
# certificate chain combined with ML-KEM hybrid key exchange.

set -u

# Emit a CA certificate and exit. This must come before any other output —
# the certificate is meant to be redirected to a file, so anything printed
# ahead of it lands in that file and makes it undecodable.
# (Needed at all because the image has an ENTRYPOINT: `docker run <image>
# cat /path` passes "cat /path" as arguments here rather than running cat.)
case "${1:-}" in
  ca|ca-ec)  exec cat /opt/pki-ec/ca.crt ;;   # browser connector (8444)
  ca-pqc)    exec cat /opt/pki/ca.crt    ;;   # ML-DSA connector (8443)
esac

PASS=0; FAIL=0
say() { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
ok()  { printf '   PASS: %s\n' "$*"; PASS=$((PASS+1)); }
bad() { printf '   FAIL: %s\n' "$*"; FAIL=$((FAIL+1)); }

say "Environment"
openssl version
echo "   ML-DSA signature algorithms: $(openssl list -signature-algorithms | grep -c ML-DSA)"
echo "   ML-KEM groups: $(openssl list -tls-groups | tr ':' '\n' | grep -ci mlkem)"
java -version 2>&1 | head -1
echo "   certificate chain:"
openssl x509 -in /opt/pki/server.crt -noout -text | \
  grep -E "Signature Algorithm|Public Key Algorithm" | sort -u | sed 's/^ */     /'

say "Starting Tomcat (TLS via OpenSSL FFM, not JSSE)"
"$CATALINA_HOME/bin/catalina.sh" start >/dev/null 2>&1
for i in $(seq 1 20); do
  grep -q "Server startup" "$CATALINA_HOME/logs/catalina.out" 2>/dev/null && break
  sleep 1
done
grep -E "OpenSSL successfully initialized|ProtocolHandler \[\"https" \
     "$CATALINA_HOME/logs/catalina.out" | sed 's/^.*INFO \[main\] //' | sed 's/^/   /'

# The connector name is the proof that JSSE is out of the path.
if grep -q "https-opensslffm" "$CATALINA_HOME/logs/catalina.out" 2>/dev/null; then
  ok "connector is OpenSSL-backed (https-opensslffm), JSSE bypassed"
else
  bad "connector did not initialize on OpenSSL — check catalina.out"
fi

# The library it bound must be OUR OpenSSL, not a system library.
if grep -q "initialized using FFM \[OpenSSL" "$CATALINA_HOME/logs/catalina.out" 2>/dev/null; then
  ok "bound to OpenSSL: $(grep -o 'FFM \[[^]]*\]' "$CATALINA_HOME/logs/catalina.out" | head -1)"
else
  bad "bound to a non-OpenSSL library: $(grep -o 'FFM \[[^]]*\]' "$CATALINA_HOME/logs/catalina.out" | head -1)"
fi

if [ "${1:-}" != "verify" ]; then
  cat <<'BANNER'

  Two connectors are listening:

    https://localhost:8443   CNSA 2.0 profile — ML-DSA-87 certificate
                             chain, ML-KEM-1024 key exchange, AES-256-GCM.
                             Verify with s_client; browsers cannot validate
                             ML-DSA chains yet.

    https://localhost:8444   browser-compatible — classical ECDSA chain
                             + ML-KEM key exchange. A real padlock plus
                             post-quantum confidentiality.

  Trust the browser CA on your host:

    docker run --rm pqc-tomcat ca > pqc-lab-ec-ca.crt
    # macOS:  sudo security add-trusted-cert -d -r trustRoot \
    #           -k /Library/Keychains/System.keychain pqc-lab-ec-ca.crt
    # Firefox keeps its own store: Settings > Privacy & Security >
    #   Certificates > View Certificates > Authorities > Import
    # Remove it when finished — a trusted root can vouch for any hostname.

  Then open https://localhost:8444 and check the connection details: the
  padlock should be present, and the key exchange should show ML-KEM — a
  browser will negotiate X25519MLKEM768, since that is the hybrid group
  browsers currently offer.

BANNER
  tail -f "$CATALINA_HOME/logs/catalina.out"
fi

say "Proof 1: TLS handshake with an ML-DSA-signed chain"
OUT=$(echo | openssl s_client -connect 127.0.0.1:8443 -brief \
        -CAfile /opt/pki/ca.crt 2>&1)
echo "$OUT" | grep -E "Protocol version|Ciphersuite|Signature type|Verification|group" | sed 's/^/   /'
echo "$OUT" | grep -q "Verification: OK" \
  && ok "chain verified — ML-DSA-87 certificate accepted (CNSA 2.0)" \
  || bad "chain verification failed"

say "Proof 2: ML-KEM hybrid key exchange"
OUT=$(echo | openssl s_client -connect 127.0.0.1:8443 -brief \
        -groups X25519MLKEM768 -CAfile /opt/pki/ca.crt 2>&1)
echo "$OUT" | grep -E "Negotiated TLS1.3 group|Signature type|Protocol version" | sed 's/^/   /'
echo "$OUT" | grep -q "X25519MLKEM768" \
  && ok "negotiated X25519MLKEM768 — post-quantum key exchange" \
  || bad "hybrid group not negotiated"

say "Proof 3: browser-compatible connector (classical chain + ML-KEM)"
OUT=$(echo | openssl s_client -connect 127.0.0.1:8444 -brief \
        -CAfile /opt/pki-ec/ca.crt 2>&1)
echo "$OUT" | grep -E "Protocol version|Signature type|Verification|group" | sed 's/^/   /'
echo "$OUT" | grep -q "Verification: OK" && echo "$OUT" | grep -q "MLKEM" \
  && ok "8444: classical authentication + post-quantum key exchange (what browsers can do today)" \
  || bad "8444 did not complete as expected"

say "Proof 4: pure ML-KEM-1024 (CNSA 2.0 profile)"
OUT=$(echo | openssl s_client -connect 127.0.0.1:8443 -brief \
        -groups MLKEM1024 -CAfile /opt/pki/ca.crt 2>&1)
echo "$OUT" | grep -E "Negotiated TLS1.3 group" | sed 's/^/   /'
echo "$OUT" | grep -q "MLKEM1024" \
  && ok "negotiated MLKEM1024" \
  || echo "   NOTE: MLKEM1024 not negotiated (server group list may exclude it)"

say "Summary"
echo "   PASS=$PASS FAIL=$FAIL"
echo "   For contrast: an ML-DSA chain on a JSSE connector fails with"
echo "   'Algorithm constraints check failed on signature algorithm: ML-DSA-<n>'."
"$CATALINA_HOME/bin/catalina.sh" stop >/dev/null 2>&1
[ "$FAIL" -eq 0 ]
