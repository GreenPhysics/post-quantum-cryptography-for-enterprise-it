# Fortanix DSM as the Part III Key Store — Assessment from the Documentation

*Written 2026-09-12 from the thirteen Fortanix DSM documents in `vendor/fortanix/docs` (≈35,000 words: Sign Up, Authentication, Authorization, Group Cryptographic Policy, Key Components, Group KEK, HSM Gateway, Extended Virtual Keys, AWS KMS Group Setup, Cloud Data Control matrix, Account/Group Client Configurations, Example Code). Context: Thales DPoD abandoned after the help desk could not restore MFA within the trial; Fortanix DSM SaaS account provisioned in minutes. Everything below is documentation-derived and marked for live verification per the book's rule.*

## Verdict

**The use case works on paper, and the path to proving it live is short.** Fortanix DSM documents ML-DSA-44/65/87 as a first-class key type with SIGN and VERIFY, exposes PKCS#11/JCE/KMIP/REST interfaces, and offers group-level cryptographic policy that can make the CA key non-exportable by construction. Nothing in the documents contradicts the Part III design (HSM-resident ML-DSA-87 CA key, EJBCA binding, issuance at scale). One unknown is load-bearing and must be measured before anything else: **whether Fortanix's PKCS#11 library exposes the ML-DSA key-generation and signing mechanisms** (the interface EJBCA Community will use), as opposed to ML-DSA being reachable only through the REST API. That is this vendor's mechanism-list gate, and it replaces Runbook 01's Step 4 unchanged in spirit.

## What the documents establish

**Algorithms (Group Cryptographic Policy §2).** Allowed key types include `ML-DSA` (44/65/87), `ML-KEM` (512/768/1024), `LMS`, and `XMSS` — the complete CNSA 2.0 set including the SP 800-208 stateful hash-based signatures that Luna firmware 7.9.0 lacked (finding #66). Default operations: ML-DSA → SIGN, VERIFY, APPMANAGEABLE, **EXPORT**; LMS/XMSS → SIGN, VERIFY, APPMANAGEABLE (no EXPORT — correct for stateful keys). *Consequence:* the CA group's policy must **remove EXPORT** from ML-DSA so the root key cannot leave; the policy mechanism exists for exactly this ("Restrict key operations").

**Policy enforcement is algorithm-retirement machinery (§4).** Non-compliant keys can be *forbidden*, *accepted*, or *limited* — and "limited" permits only "process operations" (Verify, Decrypt, Unwrap) while forbidding "protect operations" (Sign, Encrypt, Wrap). A legacy RSA key can therefore be left able to verify old signatures but unable to make new ones — crypto agility as a group setting. This is Chapter 16's certutil weak-chain policy at the HSM layer, and a candidate measured demonstration for the scale/agility chapter.

**Interfaces.** PKCS#11 (configurable at account/group/app level: concurrency limits, exact-key-ops templates, logging), KMIP (note: keys created via KMIP get **implicit EXPORT** by default — avoid KMIP for the CA key or disable the option), JCE, CNG, REST. The PKCS#11 client is "configured locally through configuration files and environment variables" with defaults pushable from the UI. **The client-library document itself is not in the folder** (deeper dive #1).

**Authentication.** Humans: password (policy is weak — no lockout, no complexity, no expiry; the Sign Up doc says so plainly), SSO (SAML/OIDC/LDAP), and **2FA via FIDO2/WebAuthn** at user, account, or system level — enable account-level 2FA immediately; it is the compensating control for the password policy. Apps: API key; TLS client certificate (CN = app UUID); **trusted-CA client certificates with CRL/OCSP revocation checking** (our own PQC CA could issue EJBCA's credential to DSM — chapters 9–10 in service of 17); JWT; **AWS IAM via SigV4** (app name must equal the caller's ARN — an EC2 instance role as the credential, no static secret on the host, if the PKCS#11 client supports it — deeper dive #1 again); IP whitelisting (pin the app to the EJBCA host's Elastic IP; the doc itself warns IP is not authentication).

**Authorization.** Bearer tokens with inactivity expiry; RBAC (Account Admin/Auditor/Member, Group Admin/Auditor, custom roles); quorum-based approval; **Key Custodian policy** (2–3 custodians, quorum-gated, for component import/export) — a documented key ceremony, which the chapter can perform for the root. **Group KEK**: a per-group AES root-of-trust; disabling or destroying it renders every key in the group unusable — a CA kill switch, and a decommissioning primitive worth a paragraph.

**Trust model (Sign Up §1).** DSM SaaS is an Intel SGX enclave service: "Intel SGX enclaves prevent access to customer's keys or data by Fortanix or any other cloud service provider." This is a different assurance argument than a physical HSM's tamper boundary; the chapter must state it honestly and cite the current FIPS 140 validation status of the SaaS (deeper dive #3).

**AWS.** Two distinct capabilities, not to be conflated in the book: (a) **AWS CDC groups** — DSM as a control plane over AWS KMS (native key management, BYOK, XKS) using IAM credentials with a documented permission list; (b) the CA path, which is EJBCA → DSM's own key store, independent of KMS. John's observation that AWS KMS itself now generates ML-DSA-87 keys opens a third option — KMS-resident CA key — but EJBCA's `AWSKMSCryptoToken` was "Class not found" in the CE image (finding #69), so that route is Enterprise-only or plugin-dependent as far as Community goes.

**HSM Gateway / Extended Virtual Keys.** DSM can front external HSMs (Luna, nShield, CloudHSM — the doc literally shows a `lunaclient` library path) and replicate keys across clusters. Not needed for Part III; noted because the irony writes itself (Fortanix would happily front the Thales we could not log into).

**Commercials.** 30-day Enterprise-tier trial from account creation (John's account: ~mid-October expiry — verify exact date in Settings → Subscription). Post-trial pricing not in these documents (deeper dive #4).

## Deeper-dive requests (documents to fetch, in priority order)

1. **Clients: PKCS#11 Library** — installation, `pkcs11.conf`/environment variables, supported mechanisms (does it list `CKM_ML_DSA` / `CKM_ML_DSA_KEY_PAIR_GEN`?), authentication options (API key / cert / IAM). *Decides the EJBCA binding route.*
2. **Fortanix DSM ↔ EJBCA integration guide** (Fortanix publishes integration articles per product; Keyfactor's `FortanixCryptoToken` class name suggests a dedicated token — check whether it is Enterprise-only and whether a CE path via standard PKCS#11 is documented).
3. **FIPS 140 / compliance statement for DSM SaaS** (validation level and certificate number, current).
4. **Pricing / subscription tiers** after trial.
5. **REST API: security object creation with ML-DSA** (`POST /crypto/v1/keys` parameters for `ML-DSA`, `pqc_params`/parameter-set naming) — needed for the load harness regardless of the PKCS#11 answer.
6. **Quorum Policy** (Account Quorum Policy article) — for the root-key ceremony section.

## Proposed Runbook 01-F (replaces the Luna runbook's Steps 1–4)

1. Account hardening first: enable account-level 2FA (FIDO2), create the `pqc-ca` group with a cryptographic policy restricted to ML-DSA-87 (and ML-DSA-65 for subordinates) with **EXPORT removed**; create the `ejbca` app (API key initially; IP-whitelisted to the EIP), member of that group.
2. **Gate A (REST, minutes):** create an ML-DSA-87 security object through the UI/REST, sign a test message, export the public key, verify the signature with OpenSSL 3.5.7 — proves the HSM side does ML-DSA at all, independent of any client library.
3. **Gate B (PKCS#11, the real one):** install the Fortanix PKCS#11 library on the EC2 host; `pkcs11-tool --module <fortanix.so> --list-mechanisms | grep -i ML_DSA`; attempt `C_GenerateKeyPair` for ML-DSA-87 via `pkcs11-tool --keypairgen`.
4. Bind: EJBCA `ca init --tokenType org.cesecore.keys.token.PKCS11CryptoToken --tokenprop fortanix.properties` with ML-DSA-87 — the §17.9 sweep.

All three outcomes of Gate B are publishable (present / absent-in-PKCS#11-but-present-in-REST / absent), exactly as the Luna runbook framed them.
