#!/usr/bin/env bash
#
# audit-cnsa2.sh — CNSA 2.0 compliance checker
#
# Companion to book chapter "CNSA 2.0: The Compliance Profile".
# CNSA 2.0 permits exactly one option per job: ML-DSA-87 signatures,
# ML-KEM-1024 key establishment, SHA-384/512 digests. This script audits
# either a certificate chain file or a live endpoint against that profile.
#
# Usage:
#   ./audit-cnsa2.sh cert <chain.pem>        # every cert in the file
#   ./audit-cnsa2.sh endpoint <host:port>    # live TLS probe
#
# Exit: 0 = compliant, 1 = findings.
# Requires OpenSSL 3.5+ for a meaningful endpoint probe (the script says so).

set -u
MODE="${1:-}"; TARGET="${2:-}"
PASS=0; FAIL=0
ok()  { printf '   PASS: %s\n' "$*"; PASS=$((PASS+1)); }
bad() { printf '   FAIL: %s\n' "$*"; FAIL=$((FAIL+1)); }
[ -z "$MODE" ] || [ -z "$TARGET" ] && { grep '^#' "$0" | head -14; exit 2; }

echo "CNSA 2.0 audit — $(openssl version)"

case "$MODE" in
  cert)
    [ -r "$TARGET" ] || { echo "cannot read $TARGET"; exit 2; }
    SPLIT="$(mktemp -d /tmp/cnsa2.XXXXXX)"
    # one file per certificate, no subshells (counters must survive)
    awk -v d="$SPLIT" '/BEGIN CERT/{n++; f=1} f{print > (d "/c" n ".pem")} /END CERT/{f=0}' "$TARGET"
    N=$(ls "$SPLIT" 2>/dev/null | wc -l)
    [ "$N" -eq 0 ] && bad "no certificates parsed from $TARGET"
    for c in "$SPLIT"/c*.pem; do
      TXT=$(openssl x509 -in "$c" -noout -subject -text 2>/dev/null)
      subj=$(echo "$TXT" | grep "subject=" | head -1 | sed 's/subject=//')
      sig=$(echo "$TXT"  | grep -m1 "Signature Algorithm" | awk '{print $NF}')
      pka=$(echo "$TXT"  | grep -m1 "Public Key Algorithm" | awk '{print $NF}')
      echo "-- cert: $subj"
      case "$sig" in
        ML-DSA-87|mldsa87) ok "signature: $sig" ;;
        *) bad "signature: $sig (CNSA 2.0 requires ML-DSA-87 — ML-DSA-44/65, SLH-DSA, RSA, ECDSA all non-compliant)" ;;
      esac
      case "$pka" in
        ML-DSA-87|mldsa87) ok "subject key: $pka" ;;
        *) bad "subject key: $pka (must be ML-DSA-87 for every cert in the chain: no tiering)" ;;
      esac
    done
    rm -rf "$SPLIT"
    ;;
  endpoint)
    if ! openssl list -tls-groups 2>/dev/null | grep -qi MLKEM1024; then
      echo "   NOTE: this OpenSSL lacks ML-KEM-1024 groups (pre-3.5)."
      echo "   Endpoint verdicts below reflect the PROBE's limits, not the server."
    fi
    HOST="${TARGET%%:*}"
    OUT=$(echo | timeout 10 openssl s_client -connect "$TARGET" \
            -servername "$HOST" -brief 2>&1)
    echo "$OUT" | sed 's/^/   | /' | head -8
    SIG=$(echo "$OUT"  | awk -F': ' '/Signature type/{print $2}')
    GRP=$(echo "$OUT"  | awk -F': ' '/Negotiated TLS1.3 group/{print $2}')
    PROTO=$(echo "$OUT"| awk -F': ' '/Protocol version/{print $2}')
    [ "$PROTO" = "TLSv1.3" ] && ok "protocol: TLSv1.3" \
      || bad "protocol: ${PROTO:-unknown} (CNSA 2.0 TLS requires 1.3)"
    case "$GRP" in
      *MLKEM1024*) ok "key establishment: $GRP (ML-KEM-1024)" ;;
      *MLKEM*) bad "key establishment: $GRP (ML-KEM present but not the required -1024 set)" ;;
      *) bad "key establishment: ${GRP:-none} (CNSA 2.0 requires ML-KEM-1024)" ;;
    esac
    case "$SIG" in
      *ML-DSA-87*|*mldsa87*) ok "certificate signature: $SIG" ;;
      *) bad "certificate signature: ${SIG:-unknown} (CNSA 2.0 requires ML-DSA-87)" ;;
    esac
    ;;
  *) echo "unknown mode '$MODE' (cert|endpoint)"; exit 2 ;;
esac

echo "--"
echo "PASS=$PASS FAIL=$FAIL"
[ "$FAIL" -eq 0 ]
