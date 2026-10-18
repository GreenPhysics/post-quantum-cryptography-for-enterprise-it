#!/usr/bin/env bash
#
# pqc-scan.sh — post-quantum readiness scan for a TLS endpoint
#
#   ./pqc-scan.sh example.com                 human-readable report
#   ./pqc-scan.sh example.com:8443 --html     HTML report on stdout
#   ./pqc-scan.sh --file hosts.txt            scan a list, one host[:port] per line
#
# What this is, and is not. Public scanners already grade internet-facing TLS
# well, and several are free. This tool exists for the case they cannot serve:
# endpoints inside your perimeter, judged against the CNSA 2.0 TLS profile,
# with findings tied to the failure modes documented in this book. It runs
# entirely from your machine and sends nothing anywhere.
#
# Requires OpenSSL 3.5.0+. Older builds cannot offer ML-KEM groups and will
# report post-quantum servers as classical — the instrument would be reporting
# on itself. The script checks and refuses rather than producing a wrong answer.

set -u
OSSL="${OPENSSL:-openssl}"
MODE=text; TARGETS=(); TIMEOUT=10

while [ $# -gt 0 ]; do
  case "$1" in
    --html)  MODE=html; shift ;;
    --file)  while read -r l; do [ -n "$l" ] && TARGETS+=("$l"); done < "$2"; shift 2 ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) TARGETS+=("$1"); shift ;;
  esac
done
[ ${#TARGETS[@]} -eq 0 ] && { sed -n '2,20p' "$0"; exit 2; }

# ---------------------------------------------------------------- probe check
ver=$($OSSL version 2>/dev/null)
if ! $OSSL list -tls-groups 2>/dev/null | grep -qi mlkem; then
  echo "This OpenSSL ($ver) has no ML-KEM groups, so it cannot detect them on"
  echo "a server either. Install OpenSSL 3.5.0+ or set OPENSSL=/path/to/openssl."
  exit 2
fi

probe() {  # $1=host:port  $2..=extra args; prints the -brief block
  echo | timeout "$TIMEOUT" $OSSL s_client -connect "$1" -servername "${1%%:*}" \
        -brief "${@:2}" 2>&1
}

scan_one() {
  local hp="$1"; [[ "$hp" == *:* ]] || hp="$hp:443"
  local host="${hp%%:*}"

  local base group sig proto suite verify staple
  base=$(probe "$hp")
  if ! grep -q "CONNECTION ESTABLISHED" <<<"$base"; then
    RESULT_STATUS="unreachable"; RESULT_ROWS="could not establish a TLS connection"
    return 1
  fi
  proto=$(sed -n 's/^Protocol version: //p'          <<<"$base" | head -1)
  suite=$(sed -n 's/^Ciphersuite: //p'               <<<"$base" | head -1)
  sig=$(sed -n   's/^Signature type: //p'            <<<"$base" | head -1)
  group=$(sed -n 's/^Negotiated TLS1.3 group: //p'   <<<"$base" | head -1)
  verify=$(grep -q "Verification: OK" <<<"$base" && echo OK || echo "not verified")

  # Does the server support post-quantum key exchange when asked directly?
  local hyb pure
  hyb=$(probe "$hp" -groups X25519MLKEM768 | grep -c "X25519MLKEM768")
  pure=$(probe "$hp" -groups MLKEM1024     | grep -c "MLKEM1024")

  # Downgrade probe: will it still accept classical-only? (informational —
  # most estates need this during migration; CNSA profiles must not.)
  local classical
  classical=$(probe "$hp" -groups x25519 | grep -c "Negotiated TLS1.3 group")

  # OCSP stapling — see the stapling chapter for why "no response sent" matters.
  staple=$(echo | timeout "$TIMEOUT" $OSSL s_client -connect "$hp" \
            -servername "$host" -status 2>&1 | grep -m1 -i "OCSP response")

  # ---- verdicts
  local kex_v auth_v cnsa_v
  case "$group" in
    *MLKEM*) kex_v="post-quantum ($group)" ;;
    "")      kex_v="unknown" ;;
    *)       kex_v="classical ($group)" ;;
  esac
  case "$sig" in
    *[Mm][Ll][-]*[Dd][Ss][Aa]*|*mldsa*) auth_v="post-quantum ($sig)" ;;
    "")  auth_v="unknown" ;;
    *)   auth_v="classical ($sig)" ;;
  esac

  # CNSA 2.0 TLS profile (draft-becker-cnsa2-tls-profile): TLS 1.3,
  # TLS_AES_256_GCM_SHA384, ML-KEM-1024, ML-DSA-87 — and non-compliant
  # parameters must be refused, which a client-side probe cannot fully prove.
  local cnsa_fail=()
  [ "$proto" = "TLSv1.3" ]                  || cnsa_fail+=("TLS 1.3 required")
  [ "$suite" = "TLS_AES_256_GCM_SHA384" ]   || cnsa_fail+=("AES-256-GCM/SHA-384 required")
  [ "$pure" -gt 0 ]                          || cnsa_fail+=("ML-KEM-1024 not offered")
  grep -qiE "mldsa87|ML-DSA-87" <<<"$sig"   || cnsa_fail+=("ML-DSA-87 authentication required")
  [ "$classical" -eq 0 ]                     || cnsa_fail+=("accepts classical key exchange (profile requires refusal)")
  if [ ${#cnsa_fail[@]} -eq 0 ]; then cnsa_v="meets the tested requirements"
  else cnsa_v="not met: $(IFS='; '; echo "${cnsa_fail[*]}")"; fi

  RESULT_STATUS=ok
  RESULT_ROWS="Protocol|$proto
Cipher suite|$suite
Key exchange|$kex_v
Authentication|$auth_v
Certificate chain|$verify
Hybrid ML-KEM offered|$([ "$hyb" -gt 0 ] && echo yes || echo no)
Pure ML-KEM-1024 offered|$([ "$pure" -gt 0 ] && echo yes || echo no)
Classical key exchange still accepted|$([ "$classical" -gt 0 ] && echo yes || echo no)
OCSP stapling|${staple:-not reported}
CNSA 2.0 TLS profile|$cnsa_v"
}

# ---------------------------------------------------------------- reporting
if [ "$MODE" = html ]; then
  printf '<!doctype html><meta charset="utf-8"><title>PQC scan</title>\n'
  printf '<style>body{font:15px/1.5 system-ui;margin:2rem auto;max-width:52rem}\n'
  printf 'h2{margin-top:2rem}table{border-collapse:collapse;width:100%%}\n'
  printf 'td{border-bottom:1px solid #ddd;padding:.4rem .6rem}\n'
  printf 'td:first-child{color:#555;width:18rem}code{background:#f4f4f4}</style>\n'
  printf '<h1>Post-quantum readiness scan</h1><p><code>%s</code></p>\n' "$ver"
fi

for t in "${TARGETS[@]}"; do
  scan_one "$t"
  if [ "$MODE" = html ]; then
    printf '<h2>%s</h2><table>\n' "$t"
    while IFS='|' read -r k v; do printf '<tr><td>%s</td><td>%s</td></tr>\n' "$k" "$v"; done <<<"$RESULT_ROWS"
    printf '</table>\n'
  else
    printf '\n\033[1m== %s ==\033[0m\n' "$t"
    while IFS='|' read -r k v; do printf '   %-38s %s\n' "$k" "$v"; done <<<"$RESULT_ROWS"
  fi
done

[ "$MODE" = html ] && printf '<p style="color:#666;font-size:.9em">Generated by pqc-scan.sh. A client-side probe can show what a server accepts, not what it refuses; the CNSA 2.0 TLS profile requires refusal of non-compliant parameters, which needs server-side configuration review.</p>\n'
exit 0
