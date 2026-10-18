# Post-Quantum Cryptography for Enterprise IT — the laboratory apparatus

This repository is the companion to the book *Post-Quantum Cryptography for
Enterprise IT: A Practitioner's Guide to ML-KEM, ML-DSA, and SLH-DSA in
Production* (John R. Schultz, 2026). It contains every lab script, container
definition, Terraform configuration, runbook, ceremony tool and public
transcript the book refers to, so that each claim in the text can be
reproduced on the reader's own hardware and in the reader's own cloud account.
The book keeps one rule — no claim without its experiment — and this is where
the experiments live.

The manuscript itself is not here. The chapters explain what each experiment
shows and why it was designed as it was; this repository lets you run it.

## What you can run in the first ten minutes

Parts I and II of the book need nothing but Docker. The lab suite runs five
self-contained experiments and serves the results as a web page:

```bash
cd docker-labs && docker compose up --build        # → http://localhost:8080
```

To prove that an unmodified application server can serve TLS meeting the full
CNSA 2.0 profile — an ML-DSA-87 certificate chain, ML-KEM-1024 key
establishment, AES-256-GCM:

```bash
docker build -f docker-labs/Dockerfile.tomcat -t pqc-tomcat .
docker run --rm pqc-tomcat verify
```

Expected, on your own machine:

```
Protocol version: TLSv1.3
Ciphersuite: TLS_AES_256_GCM_SHA384
Signature type: mldsa87
Verification: OK
Negotiated TLS1.3 group: MLKEM1024
PASS=6 FAIL=0
```

The Apache and nginx images (`Dockerfile.apache`, `Dockerfile.nginx`) prove
the claims of Chapters 14 and 15 the same way, PASS=8 and PASS=10. All three
images need build inputs that are not tracked here — OpenSSL source, a JDK,
the server tarballs — and `docker-labs/vendor/README.md` says exactly what to
place where. To run the scripts directly on a host instead of in a container,
you need OpenSSL 3.5.0 or later; `labs/REQUIREMENTS.md` has the list.

## Part III: the cloud certificate authority

Chapters 17–21 build, operate and price a post-quantum certificate authority
on AWS with its root in a hardware security module the CA software cannot
reach. Reproducing it needs three things this repository cannot supply: an
AWS account, a signer that can produce a raw ML-DSA-87 signature (AWS KMS is
the measured low-cost option; Fortanix DSM is the measured HSM), and your own
credentials, which never appear in any file here.

```bash
cd labs/part3-aws && terraform init && terraform plan   # read the plan in full; expect no "must be replaced"
```

Then follow the runbooks in order: 04 (the declared stack), 05 (post-quantum
PostgreSQL), 06 in `labs/part3-hsm/` (the ceremony), 07 (fleet and batch
issuance), 08 (load balancers and the KMS twin). Each carries an "as measured"
box recording where the plan and the measurement disagreed; those boxes are
the most useful text in the directory.

The public artifacts the book's own runs produced are committed under
`labs/part3-aws/transcripts/` and `labs/part3-hsm/transcripts/`: the root and
issuing certificates, the leaf, both CRLs, the issuing CSR, the fleet's
certificates, the batch's first certificate, and the KMS twin root. With
OpenSSL 3.5 you can verify the book's chain before you build your own:

```bash
cd labs/part3-hsm/transcripts/ceremony
openssl verify -check_ss_sig -CAfile root.pem -untrusted issuing.pem leaf.pem   # leaf.pem: OK
```

## Pins

Every container image the book measured is identified by digest, every
binary installed outside a package manager by version and SHA-256, every
source tree consulted by commit. The table is
`docker-labs/vendor/EJBCA-VERSIONS.md`. Use those identifiers and you get the
bytes the book measured; use newer ones and you are running a new experiment,
which is encouraged, but is not the book's.

## Layout

| Path | Contents |
|---|---|
| `labs/` | Lab scripts for Parts I–II, one per chapter claim; `cbom.py`; `audit-cnsa2.sh`; `pqc-scan.sh` |
| `labs/part3-aws/` | Terraform for host, fleet and load balancer; the Compose stack; runbooks 04–08; issuance scripts; transcripts |
| `labs/part3-hsm/` | Gate runbooks, the ceremony runbook, `ceremony-sign.py` and `ceremony-splice.py`, HSM mechanism transcripts, the ceremony artifacts |
| `docker-labs/` | Container definitions for the lab report, Tomcat, Apache and nginx images; `vendor/` holds the pin file and expects the untracked build inputs |
| `product/` | A design note for the automation this apparatus makes possible; not part of the book |

## Two rules

**No secret is committed.** Private keys, PIN files, `.env` files, Terraform
state, database dumps and `*.tfvars` are excluded by `.gitignore`; if you find
one here, it is a bug — please report it.

**EJBCA Community Edition is consumed unmodified.** Part III operates the
published container image identified by its digest, under the GNU LGPL v2.1,
and cites the source tree by commit for verification only. Nothing from that
source tree is in this repository, and nothing here is an EJBCA product.
EJBCA is a registered trademark of Keyfactor; this work is independent of and
not endorsed by Keyfactor.

## License

Apache License 2.0 — see `LICENSE`, with attributions in `NOTICE`. Use it,
modify it, ship it inside a product, keep the notice. Laboratory methodology
and the private-CA structure derive from the MIT-licensed
[f5devcentral/openssl-pqc-stepbystep-lab](https://github.com/f5devcentral/openssl-pqc-stepbystep-lab).

## A note on the failures

The runbooks and several transcripts retain experiments that failed,
including cases where the author's own instructions were wrong. This is
deliberate. In a technology transition, errors concentrate exactly where
practitioners are still trusting intuitions carried over from the previous
generation of tools, and a documented failure is often worth more than a
polished success.
