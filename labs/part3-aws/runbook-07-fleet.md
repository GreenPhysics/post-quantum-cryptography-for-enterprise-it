# Part III — Runbook 07: The Fleet (Chapter 21), as executed 2026-10-09

*Purpose: deploy the ceremony's chain to a fleet. Three Amazon Linux 2023 nginx nodes, each generating its own ML-DSA-65 key at boot (the CA never sees a private key), certified by `PQC-Issuing-CA` under the Fortanix root, serving TLS 1.3 with hybrid key exchange and ML-DSA-65 authentication. Then issuance at scale through the CLI for the honest floor on certificates per second. Written from the live transcript; the two near-misses are retained because they are the chapter.*

## 0. Before every `terraform apply`, from now on

```bash
# on the CA host — the dump plus ~/stack/.env IS the CA (Chapter 18, §18.3)
docker compose -f ~/stack/docker-compose.yml exec -T db pg_dump -U ejbca -Fc ejbca > ~/ejbca-$(date -u +%Y%m%dT%H%MZ).dump && ls -la ~/ejbca-*.dump | tail -1
```

## 1. Plan — and read it (workstation, PowerShell, in the Terraform working copy)

```powershell
# the Chapter 21 files: fleet.tf, node-user-data.sh.tftpl, and the complete variables.tf / outputs.tf
$ip = (Invoke-RestMethod https://checkip.amazonaws.com).Trim()
Set-Content terraform.tfvars "admin_cidr = `"$ip/32`"`nkey_name   = `"pqc-lab`"`nfleet_size = 3"
terraform validate
terraform plan -out=tfplan | Select-String -Pattern 'must be replaced|will be created|will be updated|will be destroyed|^Plan:'
```

**Measured 2026-10-09 — the first plan said `aws_instance.ejbca must be replaced` (`ami … forces replacement`).** The AL2023 SSM parameter had moved to a newer AMI since the September build, and Terraform proposed destroying the CA host and its volumes. Caught by the Chapter 17 rule: read the plan, expect zero destroys. Fix, now in `main.tf` and `fleet.tf`: `lifecycle { ignore_changes = [ami] }`. The acceptable plan is 4 to add (node SG + 3 nodes), 1 to change (the CA host's SG, re-pinned to the operator's current address), 0 to destroy. Then `terraform apply tfplan` and `terraform output` (three `node_public_ips`). *Measured: nodes created in 13 s.*

## 2. Collect the requests (workstation — the only place the SSH key lives)

```powershell
Start-Sleep 120   # cloud-init: nginx + key + CSR
$nodes = @("<node1-ip>","<node2-ip>","<node3-ip>")
New-Item -ItemType Directory -Force C:\src\fleet | Out-Null
$i = 0
foreach ($n in $nodes) { $i++
  ssh -o StrictHostKeyChecking=accept-new -i ~/.ssh/pqc-lab ec2-user@$n "cat /etc/pqc/node-name; systemctl is-active nginx; openssl req -in /etc/pqc/server.csr -noout -subject"
  scp -i ~/.ssh/pqc-lab ec2-user@${n}:/etc/pqc/server.csr C:\src\fleet\node$i.csr
}
ssh -i ~/.ssh/pqc-lab ec2-user@<ca-host> "mkdir -p fleet"
scp -i ~/.ssh/pqc-lab C:\src\fleet\node*.csr "$repo\issue-fleet.sh" ec2-user@<ca-host>:fleet/
```

*Measured: each node `active`, CSR 7,448 B, subject `CN=pqc-node<i>.example.internal`.*

## 3. Issue (CA host)

```bash
cd ~/fleet && chmod +x issue-fleet.sh && ./issue-fleet.sh      # one line per node: createcert N s  nodeN.pem: OK; chains nodeN-chain.pem
```

*Measured: 7.0 / 6.7 / 7.0 s per `createcert` (CLI = JVM start + EJB call); chains 17,317 B.*

## 4. Install (workstation → nodes)

```powershell
scp -i ~/.ssh/pqc-lab ec2-user@<ca-host>:fleet/node*-chain.pem C:\src\fleet\
$i = 0
foreach ($n in $nodes) { $i++
  scp -i ~/.ssh/pqc-lab C:\src\fleet\node$i-chain.pem ec2-user@${n}:/tmp/chain.pem
  ssh -i ~/.ssh/pqc-lab ec2-user@$n "sudo /usr/local/bin/pqc-install-cert /tmp/chain.pem"
}
```

## 5. Measure (CA host, inside the VPC — the node SG admits 443 from 10.44.0.0/24)

```bash
# private addresses: aws ec2 describe-instances --filters "Name=tag:Name,Values=pqc-book-part3-node*" --query "Reservations[].Instances[].[Tags[?Key=='Name'].Value|[0],PrivateIpAddress]" --output text
cd ~/fleet
for ip in <node1-private> <node2-private> <node3-private>; do
  echo "== $ip"
  openssl s_client -connect $ip:443 -CAfile ~/ceremony/root.pem -groups X25519MLKEM768 -sigalgs mldsa65 </dev/null 2>&1 | grep -E 'subject=|Peer signature type|Cipher is|Verify return|alert'
done
curl -s --resolve x:443:<node1-private> --cacert ~/ceremony/root.pem https://x/ ; echo "(default curl: exit $?)"
OPENSSL_CONF=~/stack/openssl-pqc.cnf curl -s --resolve pqc-node1.example.internal:443:<node1-private> --cacert ~/ceremony/root.pem https://pqc-node1.example.internal/
```

**Measured 2026-10-09 — alert 40 from all three nodes on the first run.** AL2023's crypto policy (`/etc/crypto-policies/back-ends/opensslcnf.config`, included by `openssl.cnf`) fixes `SignatureAlgorithms` (no ML-DSA) and `Groups` (no ML-KEM) for every OpenSSL process on the node, nginx included: a server holding an ML-DSA-65 key cannot select it. Fix, now in `node-user-data.sh.tftpl` and applied live with a two-line sed: `ssl_conf_command Groups X25519MLKEM768:X25519:prime256v1;` and `ssl_conf_command SignatureAlgorithms mldsa65:mldsa87:mldsa44:ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256;` (applied after the policy, so they win). After: all three nodes `Peer signature type: mldsa65`, `TLS_AES_256_GCM_SHA384`, `Verify return code: 0 (ok)` against the Fortanix root. Default `curl`: exit 35 (same policy, client side); with `OPENSSL_CONF` naming ML-DSA: `pqc node ip-10-44-0-9.ec2.internal`.

## 6. Issuance at scale (CA host)

```bash
cd ~ && chmod +x issue-batch.sh && sudo dnf -y -q install bc && ./issue-batch.sh 100
```

The CLI path is the floor (two JVM starts per certificate); the CA's own signing time is the delta between consecutive `createcert` entries in `docker compose logs ejbca`. A fleet of a thousand uses EJBCA's REST/EST interfaces, where the JVM is already running — not measured in this book, stated as the ceiling's location.

## 7. Teardown of the fleet alone

`fleet_size = 0` in `terraform.tfvars`, `terraform plan` (expect 4 to destroy, nothing else), `terraform apply`. The CA host is untouched; the ceremony and the database survive.
