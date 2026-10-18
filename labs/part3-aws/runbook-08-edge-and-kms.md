# Part III — Runbook 08: The Edge and the KMS Twin (Chapter 21), as executed 2026-10-10

*Purpose: put the fleet of Runbook 07 behind AWS load balancers and measure what each mode preserves; then sign the ceremony's issuing CSR with an AWS KMS ML-DSA-87 key so the custody ladder has a second measured rung and the fleet's leaves validate under both roots. Written from the live transcript. Prerequisites: Runbook 07 (fleet up), the ceremony directory on the CA host (`~/ceremony`: `root.pem`, `issuing.csr.der`, `sub.ext`, `root.ext`, `leaf.pem`), and `labs/part3-hsm/ceremony-splice.py`.*

## 0. IAM (console, as the admin identity — the API-only lab user cannot grant itself permissions)

On the `pqc-lab` group: attach `ElasticLoadBalancingFullAccess` and `AWSCertificateManagerFullAccess`; add an inline policy `pqc-lab-kms` allowing `kms:CreateKey, kms:DescribeKey, kms:GetPublicKey, kms:Sign, kms:TagResource, kms:ScheduleKeyDeletion, kms:ListKeys` on `*`. Screenshot the Permissions tab (figure).

## 1. The NLB (workstation, Terraform working copy)

```powershell
# fleet.tf: the node SG also admits the CA host's Elastic IP on 443 — an NLB preserves the client address, so probes from the CA host arrive from it.
# (SG rule descriptions may not contain an apostrophe — the provider's regex rejects it.)
Set-Content terraform.tfvars "admin_cidr = `"$ip/32`"`nkey_name   = `"pqc-lab`"`nfleet_size = 3`nenable_nlb = true"
terraform plan -out=tfplan | Select-String -Pattern 'must be replaced|will be created|will be updated|will be destroyed|^Plan:'
terraform apply tfplan            # measured: +6 (NLB, TG, 3 attachments, listener), SG updated, NLB active after 2 m 32 s
terraform output nlb_dns_name
aws elbv2 describe-target-health --target-group-arn <tg-arn> --query "TargetHealthDescriptions[].[Target.Id,TargetHealth.State]" --output text   # 3 healthy
```

## 2. Probe through the balancer (CA host)

```bash
NLB=<nlb_dns_name>
for i in 1 2 3 4; do
  openssl s_client -connect $NLB:443 -CAfile ~/ceremony/root.pem -groups X25519MLKEM768 -sigalgs mldsa65 </dev/null 2>&1 | grep -E 'subject=|Peer signature type|Cipher is|Verify return|alert' | tr '\n' ' '; echo
done
```

*Measured: 4/4 `Peer signature type: mldsa65`, TLS_AES_256_GCM_SHA384, `Verify return code: 0 (ok)`; flow-hash distribution (node1 ×3, node3). `dig` is not on AL2023 — use `getent hosts`.*

## 3. The ALB question, without building an ALB

```powershell
aws elbv2 describe-ssl-policies --query "SslPolicies[].Name" --output text | tr '\t' '\n' | Select-String -Pattern 'PQ'
aws elbv2 describe-ssl-policies --names ELBSecurityPolicy-TLS13-1-2-PQ-2025-09 --query "SslPolicies[0].{protocols:SslProtocols,lbtypes:SupportedLoadBalancerTypes,ciphers:Ciphers[].Name}" --output json
```

*Measured: 13 `*-PQ-2025-09` policies (FIPS variants included), `application` and `network`, TLS 1.2/1.3, classical cipher list (groups not exposed by the API).* Then the certificate side — a throwaway leaf whose key may leave its host (CA host: `openssl genpkey -algorithm ML-DSA-65 -out acm-test.key`, CSR, `ra addendentity` + `createcert` as in Runbook 06 step 4, `openssl verify` OK), copied to the workstation with `issuing.pem`:

```powershell
aws acm import-certificate --certificate fileb://acm-test.pem --private-key fileb://acm-test.key --certificate-chain fileb://issuing.pem
```

*Measured: `ValidationException: Encryption Algorithm ML-DSA_65 is not supported in us-east-1 region` (2026-10-10). Delete `acm-test.key` from the workstation afterward.*

## 4. The KMS twin — key and public key (workstation)

```powershell
$k = aws kms create-key --key-spec ML_DSA_87 --key-usage SIGN_VERIFY --description "PQC Book Part III - KMS twin root" --query "KeyMetadata.[KeyId,KeySpec,KeyUsage,Origin]" --output text; $k
$KID = ($k -split "\s+")[0]
aws kms get-public-key --key-id $KID --query "[KeySpec, SigningAlgorithms]" --output text          # ML_DSA_87 / ML_DSA_SHAKE_256
aws kms get-public-key --key-id $KID --query PublicKey --output text > kms-root.pub.b64             # NOTE: PowerShell '>' writes UTF-16
scp -i ~/.ssh/pqc-lab kms-root.pub.b64 "$repo\..\part3-hsm\ceremony-splice.py" ec2-user@<ca-host>:ceremony/
```

## 5. Root certificate for the KMS key (CA host builds the TBS; workstation signs; CA host splices)

```bash
cd ~/ceremony
iconv -f UTF-16 -t UTF-8 kms-root.pub.b64 | tr -d '\r\n ' | base64 -d > kms-root.pub.der; wc -c < kms-root.pub.der   # 2614
openssl pkey -pubin -inform DER -in kms-root.pub.der -out kms-root.pub.pem
openssl genpkey -algorithm ML-DSA-87 -out dummy2.key
openssl x509 -new -subj "/CN=PQC Root CA (AWS KMS)/O=PQC Book Part3/C=US" -force_pubkey kms-root.pub.pem -key dummy2.key -days 3650 -extfile root.ext -out kms-root-dummy.pem
python3 ceremony-splice.py tbs kms-root-dummy.pem kms-root.tbs.der                                   # tbs 2902 B
```

```powershell
scp -i ~/.ssh/pqc-lab ec2-user@<ca-host>:ceremony/kms-root.tbs.der C:\src\fleet\
$t = Measure-Command { $sig = aws kms sign --key-id $KID --message fileb://C:\src\fleet\kms-root.tbs.der --message-type RAW --signing-algorithm ML_DSA_SHAKE_256 --query Signature --output text }
"sign round-trip: $([int]$t.TotalMilliseconds) ms"                                                  # measured 638 ms
Set-Content -Path C:\src\fleet\kms-root.sig.b64 -Value $sig -Encoding ascii -NoNewline               # ASCII, not UTF-16
scp -i ~/.ssh/pqc-lab C:\src\fleet\kms-root.sig.b64 ec2-user@<ca-host>:ceremony/
```

```bash
base64 -d kms-root.sig.b64 > kms-root.sig.bin && wc -c < kms-root.sig.bin                           # 4627
python3 ceremony-splice.py splice kms-root-dummy.pem kms-root.sig.bin kms-root.pem
openssl verify -check_ss_sig -CAfile kms-root.pem kms-root.pem                                       # OK
```

## 6. The same issuing CSR, signed by the second root

```bash
SKI2=$(openssl x509 -in kms-root.pem -noout -ext subjectKeyIdentifier | tail -1 | tr -d ' :')
printf "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=$SKI2\nauthorityKeyIdentifier=none\n" > dummy-root2.ext
openssl x509 -new -subj "/CN=PQC Root CA (AWS KMS)/O=PQC Book Part3/C=US" -key dummy2.key -days 3650 -extfile dummy-root2.ext -out dummy-root2.pem
openssl x509 -req -inform DER -in issuing.csr.der -CA dummy-root2.pem -CAkey dummy2.key -days 1825 -extfile sub.ext -out issuing-kms-dummy.pem
python3 ceremony-splice.py tbs issuing-kms-dummy.pem issuing-kms.tbs.der                             # tbs 2291 B
# workstation: sign as in step 5 (measured 679 ms) → issuing-kms.sig.b64 → back to the host
base64 -d issuing-kms.sig.b64 > issuing-kms.sig.bin
python3 ceremony-splice.py splice issuing-kms-dummy.pem issuing-kms.sig.bin issuing-kms.pem
openssl verify -check_ss_sig -CAfile kms-root.pem issuing-kms.pem                                     # OK
openssl verify -check_ss_sig -CAfile kms-root.pem -untrusted issuing-kms.pem leaf.pem ~/fleet/node1.pem   # OK, OK
openssl verify -check_ss_sig -CAfile root.pem     -untrusted issuing.pem     leaf.pem ~/fleet/node1.pem   # OK, OK — same leaves, both roots
shred -u dummy2.key; history -c
```

## 7. Pricing, read the same day

`aws.amazon.com/kms/pricing` (2026-10-10, US East): $1.00/key-month; asymmetric requests $0.15/10,000, excluded from the free tier; ML-DSA not listed separately (asymmetric rate applies — confirm on the statement); CloudHSM example $2,380.80/month for two modules. Thales DPoD marketplace (2026-10-04): Luna Cloud HSM €2,825/month. Fortanix DSM SaaS: quote required.

## 8. Teardown (fleet and balancer; the CA host and the KMS key stay)

`fleet_size = 0`, `enable_nlb = false` → `terraform plan` (10 to destroy, nothing else, no `aws_instance.ejbca`) → `terraform apply tfplan`; stop the CA host. The KMS key costs $1/month as the rung-2 root; `aws kms schedule-key-deletion --key-id $KID --pending-window-in-days 30` when the book no longer needs it.
