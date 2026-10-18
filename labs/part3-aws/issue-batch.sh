#!/bin/bash
# issue-batch.sh N — issuance at scale (Chapter 21). Run on the CA host from ~/ceremony (or any directory).
# Issues N ML-DSA-65 leaves from PQC-Issuing-CA through the EJBCA CLI and reports certificates per second for the
# CA path alone (addendentity + createcert), separately from key generation, which happens on this host and is
# not the CA's work. Keys are generated here for timing only — the fleet's real keys are generated on the nodes.
# Output: batch-<timestamp>/ with every leaf, and one line of numbers for the chapter.
set -euo pipefail
N=${1:-100}
E="docker compose -f $HOME/stack/docker-compose.yml exec -T ejbca /opt/keyfactor/ejbca/bin/ejbca.sh"
D="batch-$(date -u +%Y%m%dT%H%MZ)"; mkdir -p "$D"; cd "$D"
PW=$(openssl rand -base64 12)

t0=$(date +%s.%N)
for i in $(seq 1 "$N"); do
  openssl genpkey -algorithm ML-DSA-65 -out "k$i.key" 2>/dev/null
  openssl req -new -key "k$i.key" -subj "/CN=batch-$i.example.internal/O=PQC Book Part3/C=US" -out "r$i.csr" 2>/dev/null
done
t1=$(date +%s.%N)

for i in $(seq 1 "$N"); do
  docker compose -f "$HOME/stack/docker-compose.yml" cp "r$i.csr" ejbca:/tmp/r.csr >/dev/null 2>&1
  $E ra addendentity --username "batch-$i" --password "$PW" --dn "CN=batch-$i.example.internal,O=PQC Book Part3,C=US" \
     --caname PQC-Issuing-CA --type 1 --token USERGENERATED --certprofile SERVER --eeprofile EMPTY >/dev/null 2>&1
  $E createcert --username "batch-$i" --password "$PW" -c /tmp/r.csr -f "/tmp/c$i.pem" >/dev/null 2>&1
done
t2=$(date +%s.%N)

docker compose -f "$HOME/stack/docker-compose.yml" cp ejbca:/tmp/c1.pem c1.pem >/dev/null 2>&1
openssl verify -check_ss_sig -CAfile "$HOME/ceremony/root.pem" -untrusted "$HOME/ceremony/issuing.pem" c1.pem
shred -u k*.key
keygen=$(echo "$t1 - $t0" | bc); ca=$(echo "$t2 - $t1" | bc)
printf 'N=%d  keygen+csr %.1f s (%.1f ms each)  CA issuance %.1f s (%.1f ms each, %.2f certs/s)\n' \
  "$N" "$keygen" "$(echo "$keygen*1000/$N" | bc -l)" "$ca" "$(echo "$ca*1000/$N" | bc -l)" "$(echo "$N/$ca" | bc -l)"
echo "note: each CLI call is a JVM start + EJB call; the CA's own signing time is the delta between consecutive"
echo "      'PEM certificate written' timestamps in 'docker compose logs ejbca', which the chapter reports separately."
