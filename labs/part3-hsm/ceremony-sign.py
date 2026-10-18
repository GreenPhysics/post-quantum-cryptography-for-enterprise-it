#!/usr/bin/env python3
"""
ceremony-sign.py — replace the signature on an X.509 certificate (or CRL) with one made by the Fortanix-resident
ML-DSA-87 root key. PQC Book Part III, Chapter 20 (Runbook 06).

Why this exists: OpenSSL builds a correct tbsCertificate but can only sign with a key it holds. The root key never
leaves Fortanix DSM (Gate A, non-exportable; Gate B, PKCS#11 attests never-extractable). So: OpenSSL signs the TBS
with a throwaway local ML-DSA-87 key — which gives the TBS the right AlgorithmIdentifier (id-ml-dsa-87, absent
parameters) — and this script sends the TBS bytes to DSM's /crypto/v1/sign (pure ML-DSA, empty context, which is
what X.509 requires) and splices the returned signature in. OpenSSL then verifies the result against the root.

Standard library only (no pip on the host). DER handled as definite-length TLV; nothing is re-encoded except the
outer SEQUENCE and the BIT STRING.

Usage:
  FTX_API_KEY=<app api key>  FTX_KID=<key id>  ./ceremony-sign.py in-dummy-signed.pem out-signed.pem
Environment: FTX (endpoint, default https://amer.smartkey.io), FTX_KID (default: the Gate A key).
"""
import base64, json, os, sys, urllib.request

ID_ML_DSA_87 = bytes.fromhex("0609608648016503040313")   # OID 2.16.840.1.101.3.4.3.19, DER-encoded
FTX = os.environ.get("FTX", "https://amer.smartkey.io")
KID = os.environ.get("FTX_KID", "b626f99f-183a-401f-92a3-e1276a2f5997")
EXPECT_SIG_LEN = 4627                                     # FIPS 204 Table 2, ML-DSA-87

def tlv(b, i):
    """Parse one DER TLV at offset i → (tag, value_bytes, end_offset, full_bytes)."""
    tag, l = b[i], b[i + 1]
    if l & 0x80:
        n = l & 0x7F
        L = int.from_bytes(b[i + 2:i + 2 + n], "big"); hdr = 2 + n
    else:
        L = l; hdr = 2
    return tag, b[i + hdr:i + hdr + L], i + hdr + L, b[i:i + hdr + L]

def der_len(n):
    if n < 0x80: return bytes([n])
    s = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(s)]) + s

def pem_to_der(text):
    body = "".join(l for l in text.splitlines() if not l.startswith("-----"))
    return base64.b64decode(body)

def der_to_pem(der, label):
    b = base64.b64encode(der).decode()
    return f"-----BEGIN {label}-----\n" + "\n".join(b[i:i + 64] for i in range(0, len(b), 64)) + f"\n-----END {label}-----\n"

def ftx_sign(tbs):
    key = os.environ["FTX_API_KEY"]                       # read from the environment, never from the command line
    req = urllib.request.Request(f"{FTX}/sys/v1/session/auth", method="POST",
                                 headers={"Authorization": "Basic " + key})
    token = json.load(urllib.request.urlopen(req))["access_token"]
    body = json.dumps({"key": {"kid": KID}, "data": base64.b64encode(tbs).decode()}).encode()
    req = urllib.request.Request(f"{FTX}/crypto/v1/sign", data=body, method="POST",
                                 headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"})
    return base64.b64decode(json.load(urllib.request.urlopen(req))["signature"])

def main(inp, out):
    text = open(inp).read()
    label = "X509 CRL" if "BEGIN X509 CRL" in text else "CERTIFICATE"
    der = pem_to_der(text)
    tag, outer, end, _ = tlv(der, 0)
    assert tag == 0x30 and end == len(der), "not a single DER SEQUENCE"
    _, _, i, tbs = tlv(outer, 0)                          # tbsCertificate / tbsCertList, kept byte-for-byte
    _, _, j, alg = tlv(outer, i)                          # signatureAlgorithm
    _, _, k, _ = tlv(outer, j)                            # the throwaway signature (BIT STRING), discarded
    assert k == len(outer), "trailing bytes after signature"
    assert alg == b"\x30" + der_len(len(ID_ML_DSA_87)) + ID_ML_DSA_87, \
        "outer AlgorithmIdentifier is not id-ml-dsa-87 with absent parameters; sign the input with an ML-DSA-87 dummy key"
    assert ID_ML_DSA_87 in tbs, "TBS does not carry id-ml-dsa-87 in its signature field"
    sig = ftx_sign(tbs)
    assert len(sig) == EXPECT_SIG_LEN, f"signature is {len(sig)} bytes, expected {EXPECT_SIG_LEN}"
    bitstr = b"\x03" + der_len(len(sig) + 1) + b"\x00" + sig
    body = tbs + alg + bitstr
    open(out, "w").write(der_to_pem(b"\x30" + der_len(len(body)) + body, label))
    print(f"{label}: tbs {len(tbs)} B, signature {len(sig)} B from Fortanix kid {KID} -> {out}")

if __name__ == "__main__":
    if len(sys.argv) != 3: sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2])
