# Part III — Runbook 03-F: Gate B — Does Fortanix's PKCS#11 library expose ML-DSA?

*Purpose: Gate A proved DSM signs with ML-DSA-87 through its REST API. Gate B asks whether the same capability is reachable through PKCS#11 — the interface a CA product would use — by enumerating the library's mechanism list on the EC2 host and, if the tooling allows, exercising the Gate A key through it. The vendor claim under test: DSM 5.7 release notes, "PKCS#11 library upgraded to version 3.2 with support for ML-DSA algorithm." All three outcomes are publishable. The API key is read silently on the host, never through Claude. The CE/JDK-17 wall (finding #73) is a separate question this gate does not touch: even a PASS here does not make EJBCA Community able to use it.*

## Step 0 — Get the CURRENT client (version matters)

The EJBCA integration guide's package is `fortanix-pkcs11-4.2.1500` — older than the 5.7 release that added ML-DSA. Testing that build would measure the wrong thing. Find the newest PKCS#11 client on Fortanix's download page (support.fortanix.com → Clients: PKCS#11 Library, or the DSM UI's Downloads/Integrations area) and note its version. If a direct URL of the same shape as the guides exists, it looks like `https://download.fortanix.com/clients/<VERSION>/fortanix-pkcs11-<VERSION>-0.x86_64.rpm` (the HSM Gateway doc used the `5.2.2852` series). Record the version you install — it goes in the chapter.

**Current at time of writing (verified 2026-09-15): PKCS#11 client 5.6.2919, released June 16, 2026** — three weeks after the DSM 5.7 release that added ML-DSA to the library. Release note: https://fortanix.zendesk.com/hc/en-us/articles/46700349548948-PKCS-11-5-6-2919. Check the release-notes list for anything newer before installing; substitute the version if so.

```bash
# on the EC2 host (ssh -i ~/.ssh/pqc-lab ec2-user@<ca-host-eip>)
sudo dnf -y install opensc                 # pkcs11-tool
pkcs11-tool --version 2>&1 | head -1       # OpenSC version — decides how much of Step 4 is possible
V=5.6.2919
curl -LO https://download.fortanix.com/clients/$V/fortanix-pkcs11-$V-0.x86_64.rpm
ls -la fortanix-pkcs11-$V-0.x86_64.rpm     # a few MB; a tiny file means the URL returned an error page
sudo dnf -y localinstall ./fortanix-pkcs11-$V-0.x86_64.rpm
ls -la /opt/fortanix/pkcs11/                # expect fortanix_pkcs11.so
rpm -q fortanix-pkcs11                      # record the installed version for the chapter
```

## Step 1 — Point the library at your DSM (endpoint + credential)

The library reads its endpoint from the environment (the EJBCA guide's own hint) and takes the app's API key as the token PIN at login. Same app as Gate A (`gate-a`, member of `pqc-ca`).

```bash
export FORTANIX_API_ENDPOINT=https://amer.smartkey.io
read -s -p "Fortanix app API key: " FTX_API_KEY; echo; export FTX_API_KEY
P11=/opt/fortanix/pkcs11/fortanix_pkcs11.so
```

If the library also supports a config file, the package's README under `/opt/fortanix/pkcs11/` will say; the environment route is enough for the gate.

## Step 2 — Does the library load and see a token?

```bash
pkcs11-tool --module $P11 --show-info
pkcs11-tool --module $P11 --list-slots
```

Expected: a Fortanix-labeled slot/token. If the library refuses to initialize, the log level can be raised via the account's Client Configuration (Section 2.1 of the Account Client Configurations doc) — but first check `FORTANIX_API_ENDPOINT` and network egress from the instance (the security group allows all egress).

## Step 3 — THE GATE: the mechanism list

```bash
pkcs11-tool --module $P11 --list-mechanisms > mechs.txt 2>&1
wc -l mechs.txt
grep -i -E "ML.?DSA|ML.?KEM|LMS|XMSS|SLH|HSS" mechs.txt
grep -i -E "mechtype-0x1[cdef]|mechtype-0x2[0-9a-f]|mechtype-0x00001[cdef]" mechs.txt   # PKCS#11 3.2 assigns the ML-DSA/ML-KEM mechanisms low numbers; an older OpenSC prints unknown ones as mechtype-0x..
grep -i -E "ECDSA|RSA-PKCS-PSS|SHA512" mechs.txt | head -3                                # control lines: enumeration worked
```

**Reading it:**
- Named `ML-DSA` mechanisms (e.g. `ML-DSA`, `ML-DSA-KEY-PAIR-GEN`, hash-ML-DSA variants) → the library exposes FIPS 204 through PKCS#11: **Gate B PASS.**
- No named PQC lines but `mechtype-0x1c`/`0x1d`-style entries → the library exposes them and *OpenSC is too old to name them*: still a PASS, with the numeric evidence — cross-check against the PKCS#11 3.2 mechanism table in the chapter.
- Neither, while ECDSA/RSA lines are present → the library does not expose ML-DSA over PKCS#11 in this version: a dated finding that contradicts (or predates) the 5.7 claim — publishable exactly as measured.

## Step 4 — Exercise the Gate A key through PKCS#11 (as far as the tooling allows)

```bash
# does the key created via REST appear as a PKCS#11 object, and with what key type?
pkcs11-tool --module $P11 --login --pin "$FTX_API_KEY" --list-objects 2>&1 | grep -B2 -A6 -i "gateA"
```

Look for the label `pqc-root-mldsa87-gateA` and its reported key type — a PQC-aware library reports an ML-DSA type; an older one may show it as a foreign/opaque object or omit it. Then, only if your OpenSC understands the mechanism name (Step 3 printed it by name):

```bash
pkcs11-tool --module $P11 --login --pin "$FTX_API_KEY" --sign --mechanism ML-DSA \
  --label pqc-root-mldsa87-gateA --input-file msg.txt --output-file sig-p11.bin
wc -c < sig-p11.bin                                       # expect 4627
openssl pkeyutl -verify -rawin -pubin -inkey ftx-mldsa87.pub.pem -in msg.txt -sigfile sig-p11.bin
```

If that verifies, the same key has now signed through two interfaces (REST and PKCS#11) and one independent verifier accepted both — the strongest form of the result. If OpenSC lacks the mechanism name, note it: the *library* result (Step 3) is the gate; the sign is a bonus.

## Step 5 — Hygiene

```bash
unset FTX_API_KEY; history -c
```

## What Gate B does and does not decide

It decides whether Fortanix's PKCS#11 surface carries ML-DSA — the vendor question. It does **not** decide whether EJBCA Community can use it: CE's classic `PKCS11CryptoToken` runs through Java's SunPKCS11 on JDK 17, which has no ML-DSA mapping regardless of what the library offers (finding #73). A PASS here strengthens the case that the wall is Keyfactor's packaging line, not the HSM's — which is the sentence the chapter needs.
