# EJBCA Community — Version Pins (Part III)

*EJBCA Community Edition is deliberately **not vendored** in this repository (decision recorded 2026-09-06). It is ~1.2 GB of LGPL v2.1+ source that Keyfactor already distributes; the book's reproducibility promise is honored by pinning, not copying. This file is the pin. Reconstruct the book's exact EJBCA environment from the identifiers below.*

## Source (verified for PQC algorithm surface — research notes finding #56)

- Repository: https://github.com/Keyfactor/ejbca-ce
- Tag/commit verified: `r9.3.7-14-gec54bcb320` (commit `ec54bcb320`, 2026-08-27) — supersedes the earlier pin `3eca262162`; algorithm surface re-verified at this commit (research notes finding #67).
- Tutorial commands (the book's reproducible pair — clone OUTSIDE any cloud-synced folder where possible):

```bat
git clone https://github.com/Keyfactor/ejbca-ce.git
git -C ejbca-ce checkout ec54bcb320
```

- Surface verified at this commit (`CAConstants.java`, cesecore-common): ML-DSA-44/65/87; all twelve SLH-DSA parameter sets (SHA2/SHAKE × S/F × 128/192/256); **LMS** (SP 800-208 — landed via ECA-12579 with Bouncy Castle 1.80, so the CNSA 2.0 firmware-signing algorithm is issuable, not just the TLS-chain algorithms); Falcon-512/1024 (pre-standard FN-DSA — present but not book scope); Ed25519/Ed448 and the classical set.
- What was verified there: `AlgorithmConstants`/`CAConstants` carry ML-DSA-44/65/87 as first-class key algorithms (including CA presign-validation keys); the CSR CLI enumerates all twelve FIPS 205 SLH-DSA parameter sets (SHA2/SHAKE, S/F, categories 1/3/5).
- License: GNU LGPL v2.1 or later (see upstream LICENSE). Source quotations in the book carry attribution to this tag.

## Container (the runtime the book actually uses)

```bash
docker pull keyfactor/ejbca-ce
docker inspect --format '{{index .RepoDigests 0}}' keyfactor/ejbca-ce
```

- Image digest used for the book's Part III runs (recorded at first pull, EC2 first boot, 2026-09-06): `keyfactor/ejbca-ce@sha256:183b86af44b9b13e7cc8912c868f635aeb8dba6bf056ccbd4683b17626964d0a`
- Pull-by-digest for exact reproduction: `docker pull keyfactor/ejbca-ce@sha256:183b86af44b9b13e7cc8912c868f635aeb8dba6bf056ccbd4683b17626964d0a`

## Rule

Nothing from the EJBCA source tree is committed to this repository. Configuration files, compose files, Terraform, and runbooks under `labs/part3-*` are this project's own work. If any EJBCA source file is ever modified for an experiment, the modification is published separately under LGPL terms with a pointer here — not merged into this repo.

## Part III stack pins (every identifier the measured runs depended on)

Images are pinned by digest, never by tag; binaries installed outside a package manager are pinned by version and SHA-256. A reader who reproduces Part III with these identifiers gets the same bytes the book measured. Where the book measured two variants of one component, both are listed and the chapter that compared them is named.

| Component | Pin | Where it is used | Measured |
|---|---|---|---|
| EJBCA Community 9.3.7 (container) | `keyfactor/ejbca-ce@sha256:183b86af44b9b13e7cc8912c868f635aeb8dba6bf056ccbd4683b17626964d0a` | Ch. 17–21; `labs/part3-aws/stack/docker-compose.yml` | 2026-09-06 |
| EJBCA Community (source, read-only reference) | `r9.3.7-14-gec54bcb320` (commit `ec54bcb320`) | Algorithm-surface verification only; never built, never modified | 2026-08-27 |
| PostgreSQL 17.11, Debian 13 trixie, OpenSSL 3.5.7 | `postgres@sha256:f4c66b820c6f974249089d3d16d86a3698eae11e8746eb6644b2271031e91232` | Ch. 18 stack; Ch. 19 Phase B | 2026-09-20 |
| PostgreSQL 17.11, Debian 12 bookworm, OpenSSL 3.0.20 | `postgres@sha256:639ab7ceb90e13123085b741fb31ef493fba25463002f6da665352e7b534b652` | Ch. 19 library control (Phase A) | 2026-09-20 |
| PostgreSQL 18.6, Debian 13 trixie, OpenSSL 3.5.7 | `postgres@sha256:5a5a84b19854a9ffaa54082c166ff4ec27473a361e496e5ea167f298f2da9722` | Ch. 19 onward (`ssl_groups`); `stack/docker-compose.yml` | 2026-09-26 |
| Docker Compose plugin | v5.5.1, `docker-compose-linux-x86_64` SHA-256 `db1889184726840f75c4f9c001048430d4f25b3be3cb084d3ddd762bc0aed576` | CA host (AL2023 ships no compose plugin); Runbook 04 step 1 | 2026-09-20 |
| Docker Buildx plugin | v0.37.2, `buildx-v0.37.2.linux-amd64`, SHA-256 verified against the release checksum file (`<fill from host: sha256sum ~/.docker/cli-plugins/docker-buildx>`) | CA host; Appendix D image build | 2026-10-04 |
| Eclipse Temurin JDK | 25.0.4.1+1, `OpenJDK25U-jdk_x64_linux_hotspot_25.0.4.1_1.tar.gz`, SHA-256 `dbb698396d478e7fa2b1e50f4103324b2a99b90569ee27c33f2261f9215cf41e` | Appendix D only (`stack/ejbca-jdk25/Dockerfile`); vendor JDK 17 remains the baseline | 2026-10-04 |
| Vendor JDK inside the EJBCA image | OpenJDK 17 (as shipped in the digest above; WildFly 35.0.1.Final) | Ch. 17–21 baseline | 2026-09-06 |
| Fortanix DSM PKCS#11 client | 5.8.2962 (Cryptoki 3.2, ML-DSA mechanism family present) | Gate B; Ch. 20 ceremony root | 2026-09-15 |
| Fortanix DSM PKCS#11 client (negative control) | 5.6.2919 (Cryptoki 3.0, 62 mechanisms, no ML-DSA) | Runbook 03F version lesson; `labs/part3-hsm/transcripts/mechs-5.6.2919.txt` | 2026-09-15 |
| Terraform | 1.15.8 on windows_amd64 (winget; 1.16.1 was current) | `labs/part3-aws/*.tf`; configuration requires ≥ 1.5 | 2026-09-06 |
| Amazon Linux 2023 AMI | Resolved by SSM parameter at first apply; subsequently frozen with `lifecycle { ignore_changes = [ami] }` (Ch. 17 erratum) | CA host and fleet nodes | 2026-09-06 / 2026-10-04 |
| AWS KMS asymmetric key | `--key-spec ML_DSA_87 --key-usage SIGN_VERIFY`, signing algorithm `ML_DSA_SHAKE_256`, SPKI 2,614 bytes | Ch. 21 KMS twin root; `labs/part3-hsm/ceremony-splice.py` | 2026-10-10 |
| AWS load balancer TLS policies | `ELBSecurityPolicy-TLS13-1-2-PQ-2025-09` family (13 policies, application + network) | Ch. 21 edge measurement | 2026-10-10 |
| OpenSSL on the CA host and fleet nodes | AL2023 system OpenSSL 3.x, with `/etc/crypto-policies/back-ends/opensslcnf.config` overriding `Groups` and `SignatureAlgorithms` (Ch. 19 and 21) | All host-side `s_client`/`psql`/nginx measurements | 2026-09-26 |

Two pins are deliberately absent. Private keys, the issuing-CA PIN file and the stack `.env` are never committed and have no pin; and the EJBCA source tree is referenced by commit only, under the rule in the section above.
