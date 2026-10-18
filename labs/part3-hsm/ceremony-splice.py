#!/usr/bin/env python3
"""
ceremony-splice.py — the ceremony's two halves as separate steps, for a signer that lives somewhere else
(Chapter 21, the KMS twin: AWS credentials on the workstation, OpenSSL on the CA host).

  ceremony-splice.py tbs    in-dummy-signed.pem  tbs.der        # write the tbsCertificate/tbsCertList bytes
  ceremony-splice.py splice in-dummy-signed.pem  sig.bin  out.pem   # replace the throwaway signature with sig.bin

Same DER handling as ceremony-sign.py (which calls Fortanix inline); the TBS is kept byte-for-byte, and the outer
AlgorithmIdentifier must already be id-ml-dsa-87 with absent parameters (sign the input with an ML-DSA-87 throwaway key).
"""
import base64, sys

ID_ML_DSA_87 = bytes.fromhex("0609608648016503040313")
EXPECT_SIG_LEN = 4627

def tlv(b, i):
    tag, l = b[i], b[i + 1]
    if l & 0x80:
        n = l & 0x7F; L = int.from_bytes(b[i + 2:i + 2 + n], "big"); hdr = 2 + n
    else:
        L = l; hdr = 2
    return tag, b[i + hdr:i + hdr + L], i + hdr + L, b[i:i + hdr + L]

def der_len(n):
    if n < 0x80: return bytes([n])
    s = n.to_bytes((n.bit_length() + 7) // 8, "big"); return bytes([0x80 | len(s)]) + s

def pem_to_der(text):
    return base64.b64decode("".join(l for l in text.splitlines() if not l.startswith("-----")))

def der_to_pem(der, label):
    b = base64.b64encode(der).decode()
    return f"-----BEGIN {label}-----\n" + "\n".join(b[i:i + 64] for i in range(0, len(b), 64)) + f"\n-----END {label}-----\n"

def parts(path):
    text = open(path).read()
    label = "X509 CRL" if "BEGIN X509 CRL" in text else "CERTIFICATE"
    der = pem_to_der(text)
    tag, outer, end, _ = tlv(der, 0); assert tag == 0x30 and end == len(der)
    _, _, i, tbs = tlv(outer, 0); _, _, j, alg = tlv(outer, i); _, _, k, _ = tlv(outer, j); assert k == len(outer)
    assert alg == b"\x30" + der_len(len(ID_ML_DSA_87)) + ID_ML_DSA_87, "outer AlgorithmIdentifier is not id-ml-dsa-87"
    return label, tbs, alg

if __name__ == "__main__":
    if len(sys.argv) >= 4 and sys.argv[1] == "tbs":
        label, tbs, _ = parts(sys.argv[2]); open(sys.argv[3], "wb").write(tbs); print(f"{label}: tbs {len(tbs)} B -> {sys.argv[3]}")
    elif len(sys.argv) == 5 and sys.argv[1] == "splice":
        label, tbs, alg = parts(sys.argv[2]); sig = open(sys.argv[3], "rb").read()
        assert len(sig) == EXPECT_SIG_LEN, f"signature is {len(sig)} B, expected {EXPECT_SIG_LEN}"
        body = tbs + alg + b"\x03" + der_len(len(sig) + 1) + b"\x00" + sig
        open(sys.argv[4], "w").write(der_to_pem(b"\x30" + der_len(len(body)) + body, label))
        print(f"{label}: tbs {len(tbs)} B + signature {len(sig)} B -> {sys.argv[4]}")
    else:
        sys.exit(__doc__)
