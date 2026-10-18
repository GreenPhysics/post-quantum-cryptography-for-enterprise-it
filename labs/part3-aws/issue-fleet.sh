#!/bin/bash
# issue-fleet.sh — issue a certificate from PQC-Issuing-CA for every ~/fleet/node*.csr (Chapter 21).
# Run on the CA host. Each node generated its own ML-DSA-65 key (USERGENERATED); the CA sees only the request.
# Output: ~/fleet/node<i>.pem (leaf) and ~/fleet/node<i>-chain.pem (leaf + issuing CA), verified against the root.
set -euo pipefail
E="docker compose -f $HOME/stack/docker-compose.yml exec -T ejbca /opt/keyfactor/ejbca/bin/ejbca.sh"
DC="docker compose -f $HOME/stack/docker-compose.yml"
cd ~/fleet
PW=$(openssl rand -base64 12)
for csr in node*.csr; do
  n=${csr%.csr}
  cn=$(openssl req -in "$csr" -noout -subject | sed -n 's/.*CN *= *\([^,]*\).*/\1/p')
  openssl req -in "$csr" -noout -verify >/dev/null
  $DC cp "$csr" ejbca:/tmp/$csr >/dev/null
  $E ra addendentity --username "fleet-$n" --password "$PW" --dn "CN=$cn,O=PQC Book Part3,C=US" \
     --altname "dNSName=$cn" --caname PQC-Issuing-CA --type 1 --token USERGENERATED \
     --certprofile SERVER --eeprofile EMPTY >/dev/null 2>&1 || echo "  (end entity fleet-$n already exists; reissuing)"
  t0=$(date +%s.%N)
  $E createcert --username "fleet-$n" --password "$PW" -c /tmp/$csr -f /tmp/$n.pem >/dev/null 2>&1
  t1=$(date +%s.%N)
  $DC cp ejbca:/tmp/$n.pem ./$n.pem >/dev/null
  cat "$n.pem" ~/ceremony/issuing.pem > "$n-chain.pem"
  printf '%s  %-30s  createcert %.1f s  ' "$n" "$cn" "$(echo "$t1 - $t0" | bc)"
  openssl verify -check_ss_sig -CAfile ~/ceremony/root.pem -untrusted ~/ceremony/issuing.pem "$n.pem"
done
ls -la node*-chain.pem
