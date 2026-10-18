#!/usr/bin/env bash
#
# PQC nginx entrypoint.
#   (no args)  start nginx and serve PQC TLS on 8443/8444/8445/8446
#   verify     start nginx, run the proof probes, print PASS/FAIL, exit
#   ca         emit the browser (EC) CA certificate      — for 8444/8446
#   ca-pqc     emit the ML-DSA-87 CA certificate         — for 8443/8445
#
# The verify mode demonstrates that an nginx statically linked against
# OpenSSL 3.5.x serves fully post-quantum TLS, refuses classical clients
# where configured to, carries ML-DSA and ECDSA certificates side by side
# on one listener — and, unlike Apache, LOGS the negotiated group.

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
/opt/nginx/sbin/nginx -V 2>&1 | head -3 | sed 's/^/   /'
echo "   certificate chain (8443/8445):"
openssl x509 -in /opt/pki/server.crt -noout -text | \
  grep -E "Signature Algorithm|Public Key Algorithm" | sort -u | sed 's/^ */     /'

say "Proof 1: OpenSSL is statically linked — substitution is impossible"
# The Apache chapter showed the identical mod_ssl.so silently binding a
# system libssl.so.3 with no PQC support. nginx built with --with-openssl
# has no libssl dependency at all: there is nothing for the loader to
# substitute, on any host.
if ldd /opt/nginx/sbin/nginx | grep -qE 'libssl|libcrypto'; then
  ldd /opt/nginx/sbin/nginx | grep -E 'libssl|libcrypto' | sed 's/^/   /'
  bad "nginx dynamically links an SSL library — static link expected"
else
  echo "   (no libssl/libcrypto in ldd output)"
  ok "no dynamic SSL dependency; 'nginx -V' says: $(/opt/nginx/sbin/nginx -V 2>&1 | grep -o 'built with OpenSSL [0-9.]*')"
fi

say "Starting nginx"
/opt/nginx/sbin/nginx
sleep 1
if /opt/nginx/sbin/nginx -t >/dev/null 2>&1 && pgrep -x nginx >/dev/null; then
  ok "nginx master and worker running, configuration valid"
else
  bad "nginx did not start — check /opt/nginx/logs/error.log"
fi

if [ "${1:-}" != "verify" ]; then
  cat <<'BANNER'

  Four listeners are serving:

    https://localhost:8443   CNSA 2.0 algorithms, interoperable — ML-DSA-87
                             chain, ML-KEM-1024 preferred, AES-256 only.
    https://localhost:8444   browser-compatible — classical ECDSA chain
                             + ML-KEM hybrid key exchange (padlock works).
    https://localhost:8445   CNSA 2.0 STRICT — ML-KEM-1024 or nothing;
                             classical clients refused (alert 40).
    https://localhost:8446   DUAL CERTIFICATES — ML-DSA and ECDSA side by
                             side; each client gets the strongest
                             authentication it can verify.
    https://localhost:8447   PQC LOAD BALANCER — ML-KEM terminates here;
                             a round-robin pool of classical HTTP backends
                             serves behind it (the edge architecture for
                             backends that cannot do PQC themselves).

  Every TLS connection is recorded with its negotiated group in
  /opt/nginx/logs/pqc_access.log (proto= cipher= group=) — evidence
  Apache's mod_ssl cannot produce.

  Trust the browser CA on your host:
    docker run --rm pqc-nginx ca > pqc-nginx-ec-ca.crt
    # macOS:  sudo security add-trusted-cert -d -r trustRoot \
    #           -k /Library/Keychains/System.keychain pqc-nginx-ec-ca.crt
    # Remove it when finished.

BANNER
  exec tail -f /opt/nginx/logs/error.log /opt/nginx/logs/pqc_access.log
fi

say "Proof 2: full post-quantum handshake (ML-DSA-87 chain + ML-KEM)"
OUT=$(echo | openssl s_client -connect 127.0.0.1:8443 -brief \
        -CAfile /opt/pki/ca.crt 2>&1)
echo "$OUT" | grep -E "Protocol version|Ciphersuite|Signature type|Verification|group|Hash" | sed 's/^/   /'
echo "$OUT" | grep -q "Verification: OK" && echo "$OUT" | grep -qi "mldsa87" \
  && ok "ML-DSA-87 chain verified ('Hash used: UNDEF' is correct — ML-DSA hashes internally)" \
  || bad "PQC handshake on 8443 did not complete as expected"

say "Proof 3: pure ML-KEM-1024, set per server block"
OUT=$(echo | openssl s_client -connect 127.0.0.1:8443 -brief \
        -groups MLKEM1024 -CAfile /opt/pki/ca.crt 2>&1)
echo "$OUT" | grep -E "Negotiated TLS1.3 group|Ciphersuite" | sed 's/^/   /'
echo "$OUT" | grep -q "MLKEM1024" \
  && ok "negotiated MLKEM1024 via ssl_conf_command Groups — per-listener, no global config" \
  || bad "MLKEM1024 not negotiated"

say "Proof 4: browser-compatible listener (classical chain + ML-KEM)"
OUT=$(echo | openssl s_client -connect 127.0.0.1:8444 -brief \
        -CAfile /opt/pki-ec/ca.crt 2>&1)
echo "$OUT" | grep -E "Protocol version|Signature type|Verification|group" | sed 's/^/   /'
echo "$OUT" | grep -q "Verification: OK" && echo "$OUT" | grep -q "MLKEM" \
  && ok "8444: classical authentication + post-quantum confidentiality" \
  || bad "8444 did not complete as expected"

say "Proof 5: strict listener REFUSES a classical-only client"
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

say "Proof 6: strict listener completes a fully CNSA-compliant handshake"
OUT=$(echo | openssl s_client -connect 127.0.0.1:8445 -brief \
        -groups MLKEM1024 -CAfile /opt/pki/ca.crt 2>&1)
echo "$OUT" | grep -E "Ciphersuite|Signature type|Verification|group" | sed 's/^/   /'
echo "$OUT" | grep -q "MLKEM1024" && echo "$OUT" | grep -q "TLS_AES_256_GCM_SHA384" \
    && echo "$OUT" | grep -q "Verification: OK" \
  && ok "MLKEM1024 + AES-256-GCM + ML-DSA-87 — every CNSA 2.0 algorithm" \
  || bad "compliant handshake on 8445 failed"

say "Proof 7: dual certificates — each client gets what it can verify"
A=$(echo | openssl s_client -connect 127.0.0.1:8446 -brief \
      -CAfile /opt/pki/ca.crt 2>&1)
B=$(echo | openssl s_client -connect 127.0.0.1:8446 -brief \
      -sigalgs "ecdsa_secp256r1_sha256" -CAfile /opt/pki-ec/ca.crt 2>&1)
echo "   PQC-capable client:      $(echo "$A" | grep 'Signature type')  $(echo "$A" | grep 'Verification')"
echo "   classical-only client:   $(echo "$B" | grep 'Signature type')  $(echo "$B" | grep 'Verification')"
echo "$A" | grep -qi "mldsa" && echo "$A" | grep -q "Verification: OK" && \
echo "$B" | grep -q "ecdsa" && echo "$B" | grep -q "Verification: OK" \
  && ok "one listener, two verified chains — the authentication migration with no flag day" \
  || bad "dual-certificate selection did not behave as expected"

say "Proof 8: the negotiated group is in nginx's own access log"
printf 'GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n' | \
  openssl s_client -connect 127.0.0.1:8443 -quiet -CAfile /opt/pki/ca.crt >/dev/null 2>&1
sleep 1
LOGLINE=$(grep "group=" /opt/nginx/logs/pqc_access.log | tail -1)
echo "   $LOGLINE"
echo "$LOGLINE" | grep -qE "group=(X25519MLKEM768|MLKEM1024|SecP384r1MLKEM1024)" \
  && ok "\$ssl_curve records the ML-KEM group per connection — audit evidence Apache cannot log" \
  || bad "negotiated group not found in access log"

say "Proof 9: post-quantum load balancing — PQC outside, classical pool inside"
# Route 3 from the Tomcat chapter, demonstrated: TLS with ML-KEM terminates
# at nginx; the upstream pool speaks plain HTTP, standing in for backends
# (JVMs, legacy stacks) that cannot do PQC themselves.
R1=$(printf 'GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n' | \
     openssl s_client -connect 127.0.0.1:8447 -quiet -CAfile /opt/pki/ca.crt 2>/dev/null | tail -1)
R2=$(printf 'GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n' | \
     openssl s_client -connect 127.0.0.1:8447 -quiet -CAfile /opt/pki/ca.crt 2>/dev/null | tail -1)
echo "   request 1 -> $R1"
echo "   request 2 -> $R2"
sleep 1
LB_LOG=$(grep "upstream=127" /opt/nginx/logs/pqc_access.log | tail -2)
echo "$LB_LOG" | sed 's/^/   /'
if [ "$R1" != "$R2" ] && echo "$LB_LOG" | grep -q "group=.*MLKEM.*upstream=127"; then
  ok "round-robin across the pool over ML-KEM sessions; log shows group AND backend per request"
else
  bad "load-balanced PQC termination did not behave as expected"
fi

say "Summary"
echo "   PASS=$PASS FAIL=$FAIL"
echo "   Statically linked, per-listener group control, refusal where"
echo "   required, dual chains for migration, and the group in the log."
/opt/nginx/sbin/nginx -s stop >/dev/null 2>&1
[ "$FAIL" -eq 0 ]
