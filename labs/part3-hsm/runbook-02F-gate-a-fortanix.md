# Part III — Runbook 02-F: Gate A — Fortanix DSM signs with ML-DSA-87, OpenSSL verifies

*Purpose: prove, independent of any client library or CA software, that Fortanix DSM generates an ML-DSA-87 key, signs with it, and that an implementation sharing no code with Fortanix (OpenSSL 3.5.7) verifies the signature and finds the sizes exact to FIPS 204. The same triangle the book used on the EJBCA root, aimed at the key store. Executed from the Part III EC2 host (AL2023 stock OpenSSL 3.5.7). API facts from Fortanix's API reference and the DSM 5.7 release notes (May 2026); verify field names against the live error messages if anything drifts.*

## Step 0 — Console preparation (John, in the DSM UI at https://amer.smartkey.io)

1. **Groups → ADD GROUP** — name `pqc-ca`. In the group's INFO tab, add a **Key Undo Policy** (the EJBCA guide's own tip: without it, deletion is permanent).
2. **Apps → ADD APP** — name `gate-a`, authentication method **API Key**, assign to group `pqc-ca`. Save. Open the app → **VIEW API KEY DETAILS** → copy the API key. (Later: restrict this app's allowed IPs to the Elastic IP `<ca-host-eip>/32`.)
3. Optional but recommended now: **Settings → 2FA** (FIDO2) for your user; the SaaS password policy has no lockout.

## Step 1 — Session (host)

```bash
sudo dnf -y install jq >/dev/null 2>&1 || true
export FTX=https://amer.smartkey.io
read -s -p "Fortanix app API key: " FTX_API_KEY; echo; export FTX_API_KEY
TOKEN=$(curl -sS -X POST "$FTX/sys/v1/session/auth" -H "Authorization: Basic $FTX_API_KEY" | jq -r .access_token)
echo "token: ${TOKEN:0:12}... (${#TOKEN} chars)"
```

Expected: a token of a few hundred characters. An `Authorization` failure here means the API key was pasted wrong or the app is disabled — nothing else is worth debugging until this line works.

## Step 2 — Generate the ML-DSA-87 key inside DSM (never exportable)

```bash
KEYJSON=$(curl -sS -X POST "$FTX/crypto/v1/keys" -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"name":"pqc-root-mldsa87-gateA","obj_type":"MLDSA","key_size":87,
       "key_ops":["SIGN","VERIFY","APPMANAGEABLE"],"description":"PQC Book Part III - Gate A"}')
echo "$KEYJSON" | jq '{kid, name, obj_type, key_size, key_ops, created_at}'
KID=$(echo "$KEYJSON" | jq -r .kid)
echo "$KEYJSON" | jq -r .pub_key | base64 -d > ftx-mldsa87.pub.der
```

Note the deliberate omission of `EXPORT` from `key_ops`: the private key cannot leave DSM by construction. If DSM rejects `key_size`, the error names the field it wants for the parameter set — read it, adjust, re-run (instrument first).

## Step 3 — Sign a message with the key that never leaves

```bash
echo -n "PQC Book Part III Gate A $(date -u +%FT%TZ)" > msg.txt
DATA=$(base64 -w0 msg.txt)
SIGJSON=$(curl -sS -w '\n%{time_total}\n' -X POST "$FTX/crypto/v1/sign" -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d "{\"key\":{\"kid\":\"$KID\"},\"data\":\"$DATA\"}")
echo "$SIGJSON" | tail -1 | sed 's/^/sign round-trip seconds: /'
echo "$SIGJSON" | head -1 | jq -r .signature | base64 -d > sig.bin
echo -n "signature bytes: "; wc -c < sig.bin      # FIPS 204 Table 2, ML-DSA-87: 4627
```

(`hash_alg` is intentionally absent — ML-DSA is not hash-then-sign. If the API insists on a mode, the 5.7 notes name it: `MlDsaMode`, default pure.)

## Step 4 — The second instrument: OpenSSL verifies what DSM signed

```bash
openssl version
openssl pkey -pubin -inform DER -in ftx-mldsa87.pub.der -out ftx-mldsa87.pub.pem
openssl pkey -pubin -in ftx-mldsa87.pub.pem -text -noout | head -2        # expect: ML-DSA-87 public key
openssl asn1parse -inform DER -in ftx-mldsa87.pub.der | grep "BIT STRING"   # expect l=2593 (2592 + unused-bits octet)
openssl pkeyutl -verify -rawin -pubin -inkey ftx-mldsa87.pub.pem -in msg.txt -sigfile sig.bin
```

Expected final line: `Signature Verified Successfully`.

## Step 5 — Negative control (a verifier that cannot fail is not a verifier)

```bash
sed 's/Gate A/Gate B/' msg.txt > msg-tampered.txt
openssl pkeyutl -verify -rawin -pubin -inkey ftx-mldsa87.pub.pem -in msg-tampered.txt -sigfile sig.bin; echo "exit=$?"
```

Expected: `Signature Verification Failure`, non-zero exit.

## Step 6 — Bonus probes (same session, one minute)

```bash
# Is the connection TO the key store itself post-quantum? (DSM 5.7 notes claim X25519MLKEM768 on the API endpoint)
openssl s_client -connect amer.smartkey.io:443 -brief -groups X25519MLKEM768 </dev/null 2>&1 | grep -E "Protocol version|Negotiated|Signature type"

# First latency datum for the custody ladder: 20 sequential signs, wall-clock each
for i in $(seq 1 20); do curl -sS -o /dev/null -w '%{time_total}\n' -X POST "$FTX/crypto/v1/sign" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d "{\"key\":{\"kid\":\"$KID\"},\"data\":\"$DATA\"}"; done | sort -n | awk '{a[NR]=$1} END{print "n="NR" p50="a[int(NR*0.5)]" p95="a[int(NR*0.95)]" max="a[NR]}'
```

## Reading the result

- Steps 2–5 pass → **Gate A PASSED**: Fortanix holds and signs with ML-DSA-87; an independent implementation agrees; sizes exact. The key store half of the custody ladder's Fortanix rung is proven. Record `KID`, sizes, and the sign latency in the notes.
- Step 2 fails on the parameter field → adapt from the error; not a capability failure.
- Step 4 fails to parse the public key → capture the DER (`xxd | head`) — an encoding difference between DSM and OpenSSL would itself be a finding of the #23b class.
- Step 6 negotiates `X25519MLKEM768` → the path to the HSM is post-quantum too: harvest-now-decrypt-later closed on the control channel, not just the data.

Cleanup is deliberate, not automatic: leave the key for Gate B and the ladder measurements; delete via the UI (Key Undo Policy protects against fat fingers) when Part III concludes. Clear the shell's memory of the key: `unset FTX_API_KEY TOKEN; history -c`.
