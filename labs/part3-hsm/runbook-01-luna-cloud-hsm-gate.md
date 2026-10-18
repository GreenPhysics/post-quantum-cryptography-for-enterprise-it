# Part III — Runbook 01: Luna Cloud HSM Provisioning and the Mechanism-List Gate

*Purpose: bring the Thales Luna Cloud HSM service to an operational state and then verify, at the PKCS#11 mechanism list, whether it exposes ML-DSA — the book's rule applied to a vendor claim: the datasheet asserts, `C_GetMechanismList` testifies. John executes every step (credentials never pass through Claude); outputs are pasted back for analysis and transcription into the chapter.*

*Research state feeding this runbook (verify at use, per the train-wreck rule): Luna HSM **Firmware 7.9.0** (July 2025) introduced `CKM_ML_DSA`, `CKM_ML_DSA_KEY_PAIR_GEN`, `CKM_EXTMU_ML_DSA`, the `CKM_HASH_ML_DSA_*` variants, and the ML-KEM pair (`CKM_ML_KEM_KEY_PAIR_GEN`, `CKM_ML_KEM`), consumed via Luna HSM **Client 10.9.0+**. Two facts from the release notes matter to Part III's design: (a) **no SLH-DSA, LMS, or XMSS mechanisms appear** — so the CNSA 2.0 *software/firmware-signing* algorithms (SP 800-208; finding #23c) may be absent even where ML-DSA is present, which is precisely the kind of gap the enumeration exists to expose; (b) **"ML-DSA and ML-KEM keys not wrapable"** — non-exportability comes free, but so does a question this runbook asks the vendor docs later: how is a non-wrappable CA key backed up or cloned? Whether the multi-tenant **Cloud** service backend runs 7.9.0-class firmware is not stated in the public documents we could reach — that is the open empirical question, and the gate answers it.*

---

## Step 0 — Authentication model check (before anything else)

PED keys and the remote PED reader are **Luna Network/PCIe HSM** apparatus (multi-factor PED authentication). The DPoD **Luna Cloud HSM** service, per Thales's documentation, is operated with **password authentication** through the client bundle — no PED in the path. If the PED gear is intended for use here, the target may actually be a PED-authenticated physical Luna (or a dedicated offering) rather than the standard cloud service — and Steps 1–3 below would change. **Decide and record which service is in play before provisioning.** If it is the standard Luna Cloud HSM service: the PED keys stay in the drawer for Part III's cloud work, and that fact itself goes in the chapter (the cloud service trades PED ceremony for operational simplicity — a real trade enterprises weigh).

## Step 1 — Provision the service (DPoD web console)

1. Log in to the DPoD marketplace/console with the existing account.
2. Add a service: **Luna Cloud HSM** (choose the region tier you intend to keep — NA vs EU mechanisms are listed separately by Thales, and the book should name the region it measured).
3. At the "Configure Service" step, note the **FIPS / non-FIPS partition choice** and record which is selected. *Record for the chapter:* if ML-DSA appears only in one mode, that is a finding.
4. Create the service client when prompted, and **download the client bundle ZIP** (this is the credential — treat as key material).
5. Record (for the lab notebook, not the repo): service name, partition serial, region, mode.

## Step 2 — Install the client on the Windows machine

Working directory suggestion: `C:\dpod\<service-name>\`.

```bat
:: unzip the service client bundle, then from that directory:
cd C:\dpod\<service-name>
setup.exe   :: or: unzip cvclient-min.zip && setenv.cmd  — follow the bundle's README
```

The bundle installs/points to the Luna Cloud HSM client and writes the `Chrystoki.conf`/`crystoki.ini` configuration binding this machine to the partition. Sanity check that the client sees the service:

```bat
lunacm
lunacm:> clientconfig listservers
lunacm:> slot list
```

Expected: one slot presenting the cloud partition. Record the **client version** (`lunacm` banner) — if it predates 10.9.0, ML-DSA mechanisms may be invisible from the client side even where the backend has them (instrument version before conclusions: the openssl-3.0-probe lesson, #9, in HSM form).

## Step 3 — Initialize the partition roles

In `lunacm` (password service — no PED prompts expected):

```
lunacm:> slot set -slot <n>
lunacm:> partition init -label pqc-part3        :: sets Partition SO
lunacm:> role login -name po                    :: Partition SO
lunacm:> role init -name co                     :: Crypto Officer
lunacm:> role logout
lunacm:> role login -name co
lunacm:> role changepw -name co                 :: replace initial CO password
```

Record labels and role passwords in the usual credential store (not the repo).

## Step 4 — THE GATE: enumerate mechanisms and search for ML-DSA

Two independent instruments, so the answer doesn't rest on one tool:

**(a) lunacm's own view:**

```
lunacm:> partition showmechanisms
```

Paste the full list. We grep for `ML_DSA`, `ML_KEM`, `EXTMU`, `HASH_ML_DSA`, and — for the SP 800-208 question — `LMS`, `XMSS`, `HSS`, `SLH`.

**(b) The PKCS#11 API directly** (what EJBCA will actually call). Using the bundle's library (`cryptoki.dll` / `libCryptoki2_64.so` path from the client install) with any PKCS#11 enumerator available — if OpenSC's `pkcs11-tool` is present or installable:

```bat
pkcs11-tool --module "C:\Program Files\SafeNet\LunaClient\cryptoki.dll" --list-mechanisms > mechs.txt
findstr /i "ML_DSA ML_KEM LMS XMSS SLH EXTMU" mechs.txt
findstr /i "ECDSA SHA512" mechs.txt   :: control lines — proves the enumeration worked
```

## Step 5 — Reading the result (all three outcomes are publishable)

- **ML-DSA present:** the flagship gate passes; proceed to Runbook 02 (in-HSM ML-DSA-87 keypair, `CKA_EXTRACTABLE`/wrap attributes examined, sign/verify round-trip against our OpenSSL 3.5.7 — cross-instrument verification before EJBCA ever binds).
- **ML-DSA absent from the cloud service** (while Network HSM firmware 7.9.0 has it): a dated, primary-evidence finding — the vendor's PQC capability exists in the product line but has not reached the as-a-service tier; Part III's HSM-backed CA then needs a service-tier change or a documented wait, and the book says so plainly.
- **ML-DSA present but SP 800-208 absent:** CNSA 2.0's signing story splits — TLS-chain algorithms in the HSM, firmware-signing algorithms not — the #23c distinction measured in hardware.

Whichever branch: paste transcripts verbatim; the chapter is written from them.

## Parked questions this runbook feeds forward

1. Backup/cloning of non-wrappable ML-DSA keys — what does the cloud service offer (partition backup? redundancy claims?) and what does that mean for a root CA key that can never leave?
2. FIPS vs non-FIPS partition mode: where do the ML-DSA mechanisms live, and does the CMVP status of the backend module cover them yet?
3. Client on EC2: Step 2 repeats on the EJBCA instance later — same bundle, Linux flavor; keep the ZIP.
