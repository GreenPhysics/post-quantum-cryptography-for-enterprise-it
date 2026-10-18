# Product Design Note: the One-Command Post-Quantum CA

*Not part of the manuscript. This note records, at the close of the book's assembly (11 October 2026), the engineering project that the book's Part III makes possible, so that it is specified while the evidence is fresh. Every claim here about what works is a claim the book measured; every claim about what the product will do is a design intent.*

## 1. Purpose

The objective is a Terraform module that, from one `apply` against an empty AWS account, produces an operating two-tier post-quantum certificate authority with its root in a custody backend the operator chooses, and either issues to a fleet in that account or exposes an issuance endpoint that any client, in any environment, can use. The motivation is the book's own record: Part III took thirty-six days and eighty-six findings to reach a verified chain, and the great majority of that time was spent discovering facts that are now known. Of the twenty-six points at which an engineer was unavoidable in that record, sixteen are discovery costs that reduce to a few lines in a template, five are decisions that become input variables, and five remain human. The product encodes the sixteen, exposes the five, and documents the last five.

Stated in the book's own terms, the product is Chapter 1's goal made operational: crypto-agility. The algorithm is a variable, the custody backend is a variable, and the book measured that moving a root between backends is one ceremony that touches nothing below it; the next transition — a parameter-set change, a new standard, a different module — is an edit to a `tfvars` file and an apply, not a project.

## 2. What the book established, and the product inherits

The following were measured, not assumed, and are the module's fixed content.

- EJBCA Community 9.3.7, by image digest, on PostgreSQL 18.6 by digest, in Docker Compose with two named volumes and `restart: unless-stopped`; the vendor's own TLS to the database with `ssl_groups=X25519MLKEM768:X25519:prime256v1` (Chapters 18–19).
- The host's crypto policy overridden for clients and servers alike (`OPENSSL_CONF`; nginx `ssl_conf_command Groups` and `SignatureAlgorithms`), without which no process on the host offers or selects a post-quantum algorithm (Chapters 19, 21).
- The ceremony as a sequence of file operations: a throwaway key builds the to-be-signed structures, the custody backend signs them raw, `ceremony-splice.py` assembles the certificates, EJBCA imports the chain, and the verification is `openssl verify -check_ss_sig -crl_check_all` (Chapter 20). The root key never exists outside the backend. Measured with Fortanix DSM and with AWS KMS; the same issuing CSR validated under both roots (Chapter 21).
- Compose and Buildx installed at first boot with pinned versions and checksums; `lifecycle { ignore_changes = [ami, user_data] }` on the host; `pg_dump` before every apply (Chapters 17–18, 21).
- Fleet nodes that generate their own ML-DSA-65 keys and serve hybrid-KEM, ML-DSA TLS behind a Network Load Balancer in passthrough; the Application Load Balancer and Certificate Manager terminate classically, so a post-quantum edge is a fleet that terminates for itself (Chapter 21).

## 3. Inputs (the five decisions)

| Variable | Values | Decided by |
|---|---|---|
| `custody_backend` | `kms` (default), `fortanix`, `luna`, `external` | Compliance target, auditor, budget |
| `root_algorithm`, `issuing_algorithm` | `ML-DSA-87` / `ML-DSA-65` (default), or `ML-DSA-87` / `ML-DSA-87` for CNSA 2.0 | Profile |
| `profile` | `interoperable` (hybrid groups, dual chains permitted), `cnsa2` (pure ML-KEM-1024, refusal) | Profile |
| `fleet_size` | 0 for an issuance endpoint only; N for a served fleet | Workload |
| `crl_interval_days`, `sub_ca_validity_years` | defaults 30 and 5 | Policy |

Nothing else is a decision. Region, VPC addressing and instance sizes are parameters with defaults; secrets are never inputs.

## 4. What one apply produces

1. VPC, subnets, security groups with no operator address: administration is through SSM Session Manager, so the ingress rules that drifted three times during the book do not exist.
2. An instance role for the host. No access key is created, copied, or pasted; the rule that credentials never cross machines becomes structural rather than procedural.
3. A KMS ML-DSA-87 key (`custody_backend = kms`), or the connection parameters for Fortanix or Luna read from Secrets Manager, where the operator placed them before the apply.
4. The host, with Compose and Buildx, the EJBCA and PostgreSQL images pulled by digest, and the database password and token PIN generated on the host and written to Secrets Manager, never to a file an operator reads.
5. The ceremony, executed by cloud-init on first boot: root certificate and root CRL signed by the backend; issuing CA created in EJBCA with `--signedby External`; its CSR signed by the backend; chain imported; issuing CRL published. Every artifact the book committed under `transcripts/` is produced and exported to an S3 bucket the operator owns.
6. The verification suite — the book's own verify lines, from Chapter 4's `-check_ss_sig` to Chapter 21's single-group `s_client` offers — run as the instance's health check. The apply does not report success until the chain verifies and a hybrid-KEM, ML-DSA handshake has completed against the host.
7. Issuance through EST or the REST API with instance identity as the enrolment credential (fleet mode), or through the same endpoint with operator-issued enrolment codes (anywhere mode). The CLI path the book measured at 13.6 s per certificate is retained for the record and not used.
8. Outputs: root and issuing certificates, CRL distribution points, the issuance endpoint, and the verification transcript.

## 5. Two shapes, one module

**Fleet mode** (`fleet_size = N`). Nodes boot, generate ML-DSA-65 keys, enrol through EST using their instance identity document, and serve behind an NLB. This is Chapter 21 with the CLI replaced and the policy fix baked in.

**Anywhere mode** (`fleet_size = 0`). The module produces an authority and an endpoint. Because EJBCA Community, PostgreSQL and the ceremony have no provider dependency, the same Compose stack and the same ceremony run in another cloud, a colocation, or an air-gapped room; the AWS module is the first target, and the stack and ceremony scripts are the portable core.

## 6. Position relative to the managed alternative

AWS Private CA has issued ML-DSA certificates in every region since November 2025, at $400 per CA per month in general-purpose mode plus per-certificate fees, with keys the provider holds. For an estate that lives in one provider's account and imposes no custody requirement of its own, it is often the correct answer, and the product's documentation says so. What the product is for is everything the managed service structurally cannot be: a root in hardware the customer chose and the provider does not hold; a CA that runs identically in AWS, another cloud, a colocation, or an air-gapped room; a CNSA 2.0 profile the customer can prove with transcripts rather than trust in a console; open source with no per-certificate meter, so a two-tier hierarchy with a hundred-node fleet runs on the order of $70 a month rather than $800 plus issuance; and evidence — the verification suite is the deliverable. Underneath all of these is one property: no vendor lock-in. The issuing stack is open source by digest, the root moves between custody backends by one ceremony, the relying parties see X.509 and nothing else, and the whole arrangement leaves a provider's account the way it arrived, as a Compose file, a Terraform module and a set of transcripts. The managed service sells every convenience except that exit. The property has a positive form as well: the product is vendor-agnostic at every layer where a vendor could sit. The custody interface is "sign these bytes with ML-DSA" and nothing more — Fortanix and AWS KMS have both been measured through it, `custody_backend = external` accepts any signer that can, and no vendor's SDK, token type, or agent is built into the authority. The provider layer is a Compose file and a Terraform target. The relying-party layer is X.509. A customer who changes HSM vendor, cloud, or both repeats one ceremony and one apply, and the chain below the root does not know it happened.

## 7. What stays in the fine print

- EJBCA Community's issuing key lives in software custody; the Community/Enterprise line runs exactly through the HSM binding, and the product does not pretend otherwise.
- The product does not carry the EJBCA name or mark. EJBCA Community is consumed unmodified, by digest, under the LGPL; the product is the automation, the ceremony, the custody integration and the verification, and is named for those.
- The authority's own JDBC session is classical until the Java provider offers post-quantum groups and signature schemes; a sidecar (stunnel or PgBouncer, terminating the hybrid on the host) is the available mitigation and is an option, not a default.
- The cloud edge terminates classically. A post-quantum edge is a fleet that terminates for itself behind a passthrough balancer.

## 8. What remains human

Vendor onboarding for a hardware backend (an identity check, a quote); the first IAM grant in a new account, which an API user cannot perform for itself; a witnessed ceremony where an auditor requires one, for which the module emits the transcript and pauses on a flag; the support-contract question of any unsupported component; and the decision to tear down.

## 9. Order of work

Each step retires the largest remaining risk before the next begins.

1. Instance role and Secrets Manager; remove every credential from every procedure.
2. The KMS ceremony in cloud-init, from `ceremony-splice.py`, gated by the verification suite.
3. EST enrolment with instance identity; node bootstrap; the NLB.
4. The verification suite as a test harness, runnable against any deployment.
5. Fortanix as the second backend through the same signing interface; Luna when reachable.
6. Packaging, documentation, the `tfvars` examples for the two shapes, and the fine print.

The estimate is weeks, not months, because every step is a rehearsal of something the book already did once by hand.
