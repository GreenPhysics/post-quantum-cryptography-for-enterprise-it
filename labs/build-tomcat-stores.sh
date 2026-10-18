#!/usr/bin/env bash
#
# build-tomcat-stores.sh — Tomcat/JSSE keystores for three PQC use cases
#
# Companion to book chapter "PQC Certificates for Tomcat (JSSE)".
# For each use case, builds ALL FOUR store artifacts Tomcat deployments need:
#
#     <uc>-server.p12        server key + cert + chain   (PKCS#12)
#     <uc>-server.jks        same, converted             (JKS)
#     <uc>-truststore.p12    CA certificate(s) only      (PKCS#12)
#     <uc>-truststore.jks    same                        (JKS)
#
# Use cases:
#   uc1-mlkem-hybrid : ML-KEM's real Tomcat role is TLS key exchange, not the
#                      certificate (KEMs cannot sign). Server cert stays
#                      classical-compatible; quantum resistance comes from the
#                      X25519MLKEM768 group in JSSE (JDK 24+). Deployable today.
#   uc2-mldsa        : ML-DSA-65 server certificate chain (FIPS 204).
#   uc3-slhdsa       : SLH-DSA-SHA2-128s server certificate chain (FIPS 205).
#
# Algorithm auto-detect: on OpenSSL < 3.5 the PQC use cases fall back to
# classical keys so the store PIPELINE can still be exercised end-to-end;
# every fallback is labeled loudly. JKS conversion of ML-DSA/SLH-DSA stores
# requires a JDK that understands those algorithms (JDK 24+ for ML-DSA;
# Bouncy Castle for SLH-DSA) — failures are reported per store, not fatal.
#
# Usage: ./build-tomcat-stores.sh [output-dir]   (default ./tomcat-pqc-stores)
# Store password for everything: changeit  (Tomcat convention — CHANGE IT)

set -u
OUT="${1:-./tomcat-pqc-stores}"
PW="changeit"
WORK="$(mktemp -d /tmp/pqc-tomcat.XXXXXX)"
PASS=0; FAIL=0; NOTES=""
say() { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
ok()  { printf '   PASS: %s\n' "$*"; PASS=$((PASS+1)); }
bad() { printf '   FAIL: %s\n' "$*"; FAIL=$((FAIL+1)); }
note(){ printf '   NOTE: %s\n' "$*"; NOTES="$NOTES\n- $*"; }
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$OUT"

say "Probe capability"
openssl version; keytool -help >/dev/null 2>&1 && java -version 2>&1 | head -1
HAVE_PQC=0
openssl list -signature-algorithms 2>/dev/null | grep -qi ML-DSA && HAVE_PQC=1
[ $HAVE_PQC -eq 1 ] && echo "   PQC algorithms available" \
                    || note "OpenSSL < 3.5: uc2/uc3 use labeled classical fallback keys"

# ---------------------------------------------------------------- mini CA
say "Building issuing CA"
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
default_days = 730
# All three use cases share CN=localhost; without this the second issuance
# dies with "TXT_DB error number 2" (duplicate subject) — see the CA chapter.
unique_subject = no
policy = policy_any
x509_extensions = srv_cert
copy_extensions = copy
[ policy_any ]
commonName = supplied
[ srv_cert ]
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
[ req ]
distinguished_name = dn
prompt = no
[ dn ]
CN = Tomcat PQC Lab CA
EOF
if [ $HAVE_PQC -eq 1 ]; then
  openssl genpkey -algorithm ML-DSA-65 -out "$WORK/ca.key" 2>/dev/null
else
  openssl genpkey -algorithm ec -pkeyopt ec_paramgen_curve:P-256 -out "$WORK/ca.key" 2>/dev/null
fi
openssl req -config "$WORK/ca.cnf" -key "$WORK/ca.key" -new -x509 -days 730 \
    -subj "/CN=Tomcat PQC Lab CA" \
    -addext "basicConstraints=critical,CA:true" \
    -addext "keyUsage=critical,keyCertSign,cRLSign,digitalSignature" \
    -out "$WORK/ca.crt" 2>/dev/null
[ -s "$WORK/ca.crt" ] && ok "CA ready" || bad "CA creation failed"

# ---------------------------------------------------- per-use-case pipeline
build_uc() { # $1=name  $2=leaf-algorithm ("EC" | "ML-DSA-65" | "SLH-DSA-SHA2-128S")
  local uc="$1" alg="$2" key="$WORK/$1.key"
  say "Use case $uc  (leaf algorithm: $alg)"

  case "$alg" in
    EC) openssl genpkey -algorithm ec -pkeyopt ec_paramgen_curve:P-256 -out "$key" 2>/dev/null ;;
    *)  if [ $HAVE_PQC -eq 1 ]; then
          openssl genpkey -algorithm "$alg" -out "$key" 2>/dev/null
        else
          note "$uc: '$alg' unavailable — labeled EC fallback (pipeline identical)"
          openssl genpkey -algorithm ec -pkeyopt ec_paramgen_curve:P-256 -out "$key" 2>/dev/null
        fi ;;
  esac

  openssl req -new -key "$key" -subj "/CN=localhost" \
      -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
      -out "$WORK/$uc.csr" 2>/dev/null
  openssl ca -config "$WORK/ca.cnf" -batch -notext \
      -in "$WORK/$uc.csr" -out "$WORK/$uc.crt" 2>/dev/null
  [ -s "$WORK/$uc.crt" ] || { bad "$uc: issuance failed"; return; }
  echo "   leaf: $(openssl x509 -in "$WORK/$uc.crt" -noout -text 2>/dev/null | grep 'Public Key Algorithm' | head -1 | sed 's/^ *//')"

  # --- server keystore: P12 (openssl) then JKS (keytool conversion)
  openssl pkcs12 -export -inkey "$key" -in "$WORK/$uc.crt" \
      -certfile "$WORK/ca.crt" -name "$uc" \
      -out "$OUT/$uc-server.p12" -passout "pass:$PW" 2>/dev/null \
    && ok "$uc-server.p12 created" || bad "$uc-server.p12 failed"

  if keytool -importkeystore -noprompt \
      -srckeystore  "$OUT/$uc-server.p12" -srcstoretype PKCS12 -srcstorepass "$PW" \
      -destkeystore "$OUT/$uc-server.jks" -deststoretype JKS   -deststorepass "$PW" \
      >/dev/null 2>&1; then
    ok "$uc-server.jks created (converted from P12)"
  else
    bad "$uc-server.jks conversion failed — this JDK cannot parse OpenSSL's '$alg' private-key encoding (verified failing on Temurin 26.0.1; certificates parse, private keys do not — use Bouncy Castle, see chapter)"
  fi

  # --- truststore: CA cert only, both formats (keytool native)
  keytool -importcert -noprompt -alias pqc-lab-ca -file "$WORK/ca.crt" \
      -keystore "$OUT/$uc-truststore.p12" -storetype PKCS12 -storepass "$PW" \
      >/dev/null 2>&1 \
    && ok "$uc-truststore.p12 created" || bad "$uc-truststore.p12 failed"
  keytool -importcert -noprompt -alias pqc-lab-ca -file "$WORK/ca.crt" \
      -keystore "$OUT/$uc-truststore.jks" -storetype JKS -storepass "$PW" \
      >/dev/null 2>&1 \
    && ok "$uc-truststore.jks created" || bad "$uc-truststore.jks failed"

  # --- verify by listing
  local n
  n=$(keytool -list -keystore "$OUT/$uc-server.p12" -storetype PKCS12 \
        -storepass "$PW" 2>/dev/null | grep -c "PrivateKeyEntry")
  [ "$n" = "1" ] && ok "$uc-server.p12 verifies: 1 PrivateKeyEntry" \
                 || note "$uc-server.p12: keytool cannot list entry on this JDK (expected for PQC algs pre-JDK24)"
}

build_uc uc1-mlkem-hybrid EC
build_uc uc2-mldsa        ML-DSA-65
build_uc uc3-slhdsa       SLH-DSA-SHA2-128S

# ------------------------------------------------- Tomcat connector snippets
say "Writing Tomcat JSSE connector snippets"
cat > "$OUT/server-xml-snippets.xml" <<'EOF'
<!-- ============================================================== -->
<!-- Tomcat JSSE (Http11NioProtocol) connectors — one per use case. -->
<!-- Password 'changeit' is the lab default: CHANGE IT.             -->
<!-- truststoreFile lines matter only if you enable clientAuth.     -->
<!-- certificateKeyAlias is REQUIRED. Without it Tomcat looks  -->
<!-- for alias "tomcat", finds nothing, STARTS SUCCESSFULLY ANYWAY, -->
<!-- and then drops every handshake. The only warning is one log    -->
<!-- line: certificate type [UNDEFINED]. Verified live on Tomcat    -->
<!-- 11.0.24 — see the chapter's troubleshooting table.             -->
<!-- ============================================================== -->

<!-- UC1: ML-KEM hybrid key exchange, classical-compatible certificate.
     Quantum resistance comes from the TLS group, not the cert.
     Requires JDK 24+ (X25519MLKEM768 in JSSE). Pin it explicitly via:
       -Djdk.tls.namedGroups="X25519MLKEM768,x25519,secp256r1"          -->
<Connector port="8443" protocol="org.apache.coyote.http11.Http11NioProtocol"
           maxThreads="150" SSLEnabled="true">
  <SSLHostConfig protocols="TLSv1.3"
                 truststoreFile="conf/uc1-mlkem-hybrid-truststore.p12"
                 truststorePassword="changeit">
    <Certificate certificateKeystoreFile="conf/uc1-mlkem-hybrid-server.p12"
                 certificateKeystorePassword="changeit"
                 certificateKeyAlias="uc1-mlkem-hybrid" />
  </SSLHostConfig>
</Connector>

<!-- UC2: ML-DSA-65 certificate chain (FIPS 204).
     Stores load on JDK 24+; TLS handshake authentication with ML-DSA
     requires JSSE support for the ML-DSA sigalgs on YOUR JDK — verify
     with the s_client probe before rollout.                            -->
<Connector port="8444" protocol="org.apache.coyote.http11.Http11NioProtocol"
           maxThreads="150" SSLEnabled="true">
  <SSLHostConfig protocols="TLSv1.3"
                 truststoreFile="conf/uc2-mldsa-truststore.p12"
                 truststorePassword="changeit">
    <Certificate certificateKeystoreFile="conf/uc2-mldsa-server.p12"
                 certificateKeystorePassword="changeit"
                 certificateKeyAlias="uc2-mldsa" />
  </SSLHostConfig>
</Connector>

<!-- UC3: SLH-DSA-SHA2-128s certificate chain (FIPS 205).
     Stock JDKs do not parse SLH-DSA; register Bouncy Castle (bcprov/bctls)
     as a security provider first. Conservative choice: signatures are big
     and slow — suits low-volume, high-assurance internal services.      -->
<Connector port="8445" protocol="org.apache.coyote.http11.Http11NioProtocol"
           maxThreads="150" SSLEnabled="true">
  <SSLHostConfig protocols="TLSv1.3"
                 truststoreFile="conf/uc3-slhdsa-truststore.p12"
                 truststorePassword="changeit">
    <Certificate certificateKeystoreFile="conf/uc3-slhdsa-server.p12"
                 certificateKeystorePassword="changeit"
                 certificateKeyAlias="uc3-slhdsa" />
  </SSLHostConfig>
</Connector>
EOF
ok "server-xml-snippets.xml written"
cp "$WORK/ca.crt" "$OUT/pqc-lab-ca.crt" && ok "CA certificate exported (pqc-lab-ca.crt)"

say "Summary"
ls -la "$OUT" | sed 's/^/   /'
echo "   PASS=$PASS FAIL=$FAIL"
[ -n "$NOTES" ] && printf "   Environment notes:%b\n" "$NOTES"
[ "$FAIL" -eq 0 ]
