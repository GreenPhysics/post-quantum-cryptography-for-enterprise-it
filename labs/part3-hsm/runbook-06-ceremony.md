# Part III — Runbook 06: The Ceremony (Chapter 20), as executed 2026-09-27

*Purpose: bind EJBCA Community's issuing CA to a root whose private key lives in Fortanix DSM and never leaves it. Written from the live transcript, corrections included, so the commands below are the ones that worked. Prerequisites: the Chapter 18/19 stack up (`~/stack`), the Gate A key (`kid b626f99f-…`) and its public key on the host (`~/ftx-mldsa87.pub.pem`), `labs/part3-hsm/ceremony-sign.py` copied to `~`, Python 3 and OpenSSL 3.5 on the host. Credentials: the Fortanix app API key via `read -s` only; the issuing CA's token PIN generated to a mode-600 file and recorded in the operator's password manager.*

Mechanism in one paragraph: OpenSSL builds each `tbsCertificate`/`tbsCertList`, signed by a **throwaway** local ML-DSA-87 key so the structure carries `id-ml-dsa-87`; `ceremony-sign.py` keeps the TBS bytes, has DSM sign them (`/crypto/v1/sign`, pure ML-DSA, empty context), and splices the real signature in; OpenSSL verifies. `openssl x509 -req` requires the CA key to match the CA certificate, so a **placeholder root** built with the throwaway key — same subject and same explicit SKI as the real root — stands in as the issuer template.

## 0. Shell state (redo after every reconnect)

```bash
cd ~/ceremony 2>/dev/null || mkdir -p ~/ceremony && cd ~/ceremony
E="docker compose -f $HOME/stack/docker-compose.yml exec ejbca /opt/keyfactor/ejbca/bin/ejbca.sh"   # $HOME, not ~ — tilde does not expand inside quotes
read -s -p "Fortanix app API key (gate-a): " FTX_API_KEY; echo; export FTX_API_KEY
export FTX=https://amer.smartkey.io FTX_KID=b626f99f-183a-401f-92a3-e1276a2f5997
curl -sS -o /dev/null -w 'auth check: HTTP %{http_code}\n' -X POST "$FTX/sys/v1/session/auth" -H "Authorization: Basic $FTX_API_KEY"   # must be 200 before signing
$E ca listcas 2>&1 | grep 'CA Name'
```

## 1. The root certificate (Fortanix key → self-signed X.509)

```bash
openssl genpkey -algorithm ML-DSA-87 -out dummy.key                                  # throwaway; shredded in step 6
printf 'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=none\n' > root.ext
openssl x509 -new -subj "/CN=PQC Root CA (Fortanix)/O=PQC Book Part3/C=US" -force_pubkey ~/ftx-mldsa87.pub.pem \
  -key dummy.key -days 3650 -extfile root.ext -out root-dummy.pem                    # x509, not req: req has no -force_pubkey
openssl verify -check_ss_sig -CAfile root-dummy.pem root-dummy.pem                   # NEGATIVE CONTROL: must FAIL (without -check_ss_sig it prints OK!)
python3 ~/ceremony-sign.py root-dummy.pem root.pem                                   # measured: tbs 2904 B, sig 4627 B, 0.23 s
openssl verify -check_ss_sig -CAfile root.pem root.pem                               # root.pem: OK
openssl x509 -in root.pem -noout -ext subjectKeyIdentifier -serial -dates            # note the SKI hex for step 3
```

*Measured: SKI `E5:2B:BE:18:C1:94:0C:6A:C9:32:ED:05:C5:3A:6D:3F:0E:2B:8A:0F`, serial `6D966F2DCA65476FB228EDEE3614FEBDDBADC7C5`, valid 2026-09-27 → 2036-09-24, DER 7,553 B. First attempt without `authorityKeyIdentifier=none` failed error 20: `x509 -new` adds an AKI from the SIGNING (throwaway) key. If a verify fails, test the signature alone: extract TBS+sig and `openssl pkeyutl -verify -rawin -pubin -inkey ~/ftx-mldsa87.pub.pem -in tbs.der -sigfile sig.bin`.*

## 2. The issuing CA in EJBCA (externally signed) and its request

```bash
docker compose -f $HOME/stack/docker-compose.yml cp root.pem ejbca:/tmp/root.pem
(umask 077; openssl rand -base64 18 > issuing-ca.pin); echo "record ~/ceremony/issuing-ca.pin with the .env values now"
PIN=$(cat issuing-ca.pin)
$E ca init --caname PQC-Issuing-CA --dn "CN=PQC Issuing CA,O=PQC Book Part3,C=US" \
  --tokenType soft --tokenPass "$PIN" --keytype ML-DSA-65 --keyspec ML-DSA-65 \
  -v 1825 --policy null -s ML-DSA-65 --signedby External -externalcachain /tmp/root.pem
unset PIN
$E ca listcas 2>&1 | grep -E 'CA Name|Signed by'                                     # PQC-Issuing-CA, Signed by: 2 (external)
docker compose -f $HOME/stack/docker-compose.yml cp ejbca:/opt/keyfactor/PQC-Issuing-CA_csr.der ./issuing.csr.der   # CLI cwd = /opt/keyfactor
openssl req -inform DER -in issuing.csr.der -noout -verify -subject                  # Certificate request self-signature verify OK
```

*Measured: CAId -725416869, profile SUBCA, CSR 5,379 B. A rerun of `ca init` is refused with "exists already" — that is correct, not an error.*

## 3. Sign the request with the root (placeholder issuer + script)

```bash
SKI=E52BBE18C1940C6AC932ED05C53A6D3F0E2B8A0F                                         # from step 1, no colons
printf "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=$SKI\nauthorityKeyIdentifier=none\n" > dummy-root.ext
openssl x509 -new -subj "/CN=PQC Root CA (Fortanix)/O=PQC Book Part3/C=US" -key dummy.key -days 3650 -extfile dummy-root.ext -out dummy-root.pem
printf 'basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n' > sub.ext
openssl x509 -req -inform DER -in issuing.csr.der -CA dummy-root.pem -CAkey dummy.key -days 1825 -extfile sub.ext -out issuing-dummy.pem
openssl verify -check_ss_sig -CAfile root.pem issuing-dummy.pem                      # NEGATIVE CONTROL: error 7 certificate signature failure
python3 ~/ceremony-sign.py issuing-dummy.pem issuing.pem                             # measured: tbs 2292 B, 0.31 s
openssl verify -check_ss_sig -CAfile root.pem issuing.pem                            # issuing.pem: OK
openssl x509 -in issuing.pem -noout -ext subjectKeyIdentifier,authorityKeyIdentifier # AKI must equal the root's SKI
```

*Measured: Issuer = root, PK ML-DSA-65, Sig ML-DSA-87, SKI `5F:B3:02:84:…`, valid to 2031-09-26, DER 6,941 B.*

## 4. Import, and the first leaf

```bash
cat issuing.pem root.pem > issuing-chain.pem
docker compose -f $HOME/stack/docker-compose.yml cp issuing-chain.pem ejbca:/tmp/issuing-chain.pem
$E ca importcacert --caname PQC-Issuing-CA -f /tmp/issuing-chain.pem                 # "Received certificate response and activated CA"
$E ca getcacert --caname PQC-Issuing-CA -f /tmp/issuing-from-ejbca.pem
docker compose -f $HOME/stack/docker-compose.yml cp ejbca:/tmp/issuing-from-ejbca.pem .
openssl x509 -in issuing-from-ejbca.pem -noout -fingerprint -sha256; openssl x509 -in issuing.pem -noout -fingerprint -sha256   # identical
openssl genpkey -algorithm ML-DSA-65 -out leaf.key
openssl req -new -key leaf.key -subj "/CN=pqc-leaf1.example.internal/O=PQC Book Part3/C=US" -addext "subjectAltName=DNS:pqc-leaf1.example.internal" -out leaf.csr
docker compose -f $HOME/stack/docker-compose.yml cp leaf.csr ejbca:/tmp/leaf.csr
read -s -p "end-entity password (one-time): " EEPW; echo
$E ra addendentity --username pqc-leaf1 --password "$EEPW" --dn "CN=pqc-leaf1.example.internal,O=PQC Book Part3,C=US" --altname "dNSName=pqc-leaf1.example.internal" --caname PQC-Issuing-CA --type 1 --token USERGENERATED --certprofile SERVER --eeprofile EMPTY
$E createcert --username pqc-leaf1 --password "$EEPW" -c /tmp/leaf.csr -f /tmp/leaf.pem; unset EEPW
docker compose -f $HOME/stack/docker-compose.yml cp ejbca:/tmp/leaf.pem .
openssl verify -check_ss_sig -CAfile root.pem -untrusted issuing.pem leaf.pem        # leaf.pem: OK
for f in root issuing leaf; do printf '%-8s DER %5s B\n' $f $(openssl x509 -in $f.pem -outform DER | wc -c); done
docker compose -f $HOME/stack/docker-compose.yml exec db psql -U ejbca -d ejbca -c "select tokenname from cryptotokendata;"   # the root is NOT a row
```

*Measured: fingerprints `5A:D1:EE:5E:…:C1:73` identical; leaf 7 s; DER 7,553 / 6,941 / 5,683 B; cryptotokendata = ManagementCA, PQC-MLDSA87-CA, PQC-Issuing-CA.*

## 5. Revocation from the top (root CRL through the script; issuing CRL from EJBCA)

```bash
printf '[ca]\ndefault_ca = root\n[root]\ndatabase = index.txt\ncrlnumber = crlnumber\ndefault_crl_days = 30\ndefault_md = default\n' > crl.cnf
touch index.txt; echo 01 > crlnumber
openssl ca -config crl.cnf -gencrl -keyfile dummy.key -cert dummy-root.pem -out root-crl-dummy.pem
python3 ~/ceremony-sign.py root-crl-dummy.pem root-crl.pem                           # X509 CRL: tbs 138 B
openssl crl -in root-crl.pem -noout -CAfile root.pem                                 # verify OK
$E ca createcrl --caname PQC-Issuing-CA
$E ca getcrl --caname PQC-Issuing-CA -f /tmp/issuing.crl                             # DER only
docker compose -f $HOME/stack/docker-compose.yml cp ejbca:/tmp/issuing.crl ./issuing.crl.der
openssl crl -inform DER -in issuing.crl.der -out issuing-crl.pem
cat root-crl.pem issuing-crl.pem > crls.pem
openssl verify -check_ss_sig -crl_check_all -CAfile root.pem -CRLfile crls.pem -untrusted issuing.pem leaf.pem   # leaf.pem: OK
```

*Measured 21:01Z: OK. Monthly root duty = repeat this step with a fresh throwaway key (any ML-DSA-87 key; only the TBS shape matters).*

## 6. Hygiene and deliverables

```bash
shred -u dummy.key leaf.key
unset FTX_API_KEY; history -c
```

To the repo (`labs/part3-hsm/transcripts/ceremony/`): `root.pem`, `issuing.pem`, `issuing-chain.pem`, `leaf.pem`, `root-crl.pem`, `issuing-crl.pem`, `issuing.csr.der`, `root.ext`, `dummy-root.ext`, `sub.ext`, `crl.cnf`. Never: `issuing-ca.pin`, any `*.key`.
