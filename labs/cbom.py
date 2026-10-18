#!/usr/bin/env python3
"""cbom.py — generate a CycloneDX Cryptography Bill of Materials from a live scan.

    ./cbom.py example.com:443 [host:port ...]        > cbom.json
    OPENSSL=/usr/local/bin/openssl ./cbom.py host    (pin the OpenSSL binary)

Every enterprise post-quantum program begins with the same task: inventory the
cryptography actually in use. The federal mandate (OMB M-23-02, and now Executive
Order 14412) requires that inventory in a machine-readable form, and the standard
for it is CycloneDX's Cryptography Bill of Materials (CBOM), published as
ECMA-424.

Most guidance stops at "produce an inventory." This produces one — a valid
CycloneDX CBOM describing the cryptographic assets a TLS endpoint actually
negotiates, each tagged with its NIST post-quantum security category, so the
output is an auditor-ready artifact rather than a spreadsheet. It runs from your
own machine and sends nothing anywhere.

Requires OpenSSL 3.5.0+ to observe ML-KEM groups; on older builds the scan still
runs but cannot see post-quantum key exchange, and the CBOM will say so.
"""
import json, os, re, subprocess, sys, datetime, uuid

OSSL = os.environ.get("OPENSSL", "openssl")

# What we know about the algorithms a TLS 1.3 handshake can surface. The NIST
# quantum security category (1/3/5) is from FIPS 203/204/205; 0 marks an
# algorithm with no post-quantum security. "primitive" uses CycloneDX vocabulary.
ALGOS = {
    # observed-string (lowercased substring)      primitive   param-set        cat  pq
    "mlkem1024":        ("kem",       "ML-KEM-1024", 5, True),
    "mlkem768":         ("kem",       "ML-KEM-768",  3, True),
    "mlkem512":         ("kem",       "ML-KEM-512",  1, True),
    "x25519mlkem768":   ("kem",       "X25519MLKEM768 (hybrid)", 3, True),
    "secp256r1mlkem768":("kem",       "SecP256r1MLKEM768 (hybrid)", 3, True),
    "secp384r1mlkem1024":("kem",      "SecP384r1MLKEM1024 (hybrid)", 5, True),
    "x25519":           ("key-agree", "X25519",      0, False),
    "secp256r1":        ("key-agree", "secp256r1",   0, False),
    "secp384r1":        ("key-agree", "secp384r1",   0, False),
    "mldsa87":          ("signature", "ML-DSA-87",   5, True),
    "mldsa65":          ("signature", "ML-DSA-65",   3, True),
    "mldsa44":          ("signature", "ML-DSA-44",   2, True),
    "ml-dsa-87":        ("signature", "ML-DSA-87",   5, True),
    "ml-dsa-65":        ("signature", "ML-DSA-65",   3, True),
    "ml-dsa-44":        ("signature", "ML-DSA-44",   2, True),
    "ecdsa":            ("signature", "ECDSA",       0, False),
    "rsa":              ("signature", "RSA",         0, False),
    "aes_256_gcm":      ("ae",        "AES-256-GCM", 5, True),   # symmetric survives Grover at 256
    "aes_128_gcm":      ("ae",        "AES-128-GCM", 1, True),
    "sha384":           ("hash",      "SHA-384",     0, True),
    "sha256":           ("hash",      "SHA-256",     0, True),
}

def run(host, extra):
    try:
        p = subprocess.run([OSSL, "s_client", "-connect", host, "-servername",
                            host.split(":")[0], "-brief", *extra],
                           input=b"", capture_output=True, timeout=12)
        return (p.stdout + p.stderr).decode(errors="replace")
    except Exception:
        return ""

def field(txt, key):
    m = re.search(rf"^{re.escape(key)}:\s*(.+)$", txt, re.M)
    return m.group(1).strip() if m else ""

def crypto_component(observed, ref_host):
    """Map an observed algorithm string to a CycloneDX cryptographic-asset."""
    low = observed.lower()
    for k,(prim,pset,cat,pq) in sorted(ALGOS.items(), key=lambda kv: -len(kv[0])):
        if k in low:
            comp = {
                "type": "cryptographic-asset",
                "name": pset,
                "bom-ref": f"crypto/{ref_host}/{pset}".replace(" ","_"),
                "cryptoProperties": {
                    "assetType": "algorithm",
                    "algorithmProperties": {
                        "primitive": prim,
                        "parameterSetIdentifier": pset,
                        "executionEnvironment": "software-plain-ram",
                        "nistQuantumSecurityLevel": cat,
                    },
                },
                "properties": [
                    {"name": "pqc:quantumSafe", "value": str(pq).lower()},
                    {"name": "pqc:observedAs",  "value": observed},
                ],
            }
            return comp, pq
    # unknown algorithm — record it honestly rather than dropping it
    return ({
        "type": "cryptographic-asset", "name": observed,
        "bom-ref": f"crypto/{ref_host}/{observed}".replace(" ","_"),
        "cryptoProperties": {"assetType": "algorithm",
            "algorithmProperties": {"primitive": "unknown"}},
        "properties": [{"name":"pqc:quantumSafe","value":"unknown"}],
    }, None)

def scan(host):
    if ":" not in host: host += ":443"
    base = run(host, [])
    if "CONNECTION ESTABLISHED" not in base:
        return None
    proto  = field(base, "Protocol version")
    suite  = field(base, "Ciphersuite")
    sig    = field(base, "Signature type")
    group  = field(base, "Negotiated TLS1.3 group")
    peer   = field(base, "Peer certificate")
    verify = "valid" if "Verification: OK" in base else "unverified"

    observed = [x for x in (group, sig, suite) if x]
    comps, flags = [], []
    for o in observed:
        c, pq = crypto_component(o, host)
        comps.append(c); flags.append(pq)

    # a protocol asset for the TLS version itself
    comps.insert(0, {
        "type":"cryptographic-asset","name":f"TLS {proto[4:] if proto.startswith('TLSv') else proto}",
        "bom-ref": f"crypto/{host}/tls",
        "cryptoProperties":{"assetType":"protocol",
            "protocolProperties":{"type":"tls","version":proto.replace('TLSv','')}},
    })
    # the leaf certificate as an asset
    if peer:
        comps.append({
            "type":"cryptographic-asset","name":f"certificate: {peer}",
            "bom-ref": f"crypto/{host}/cert",
            "cryptoProperties":{"assetType":"certificate",
                "certificateProperties":{"subjectName":peer,
                    "signatureAlgorithmRef": sig or "unknown"}},
            "properties":[{"name":"pqc:chainVerification","value":verify}],
        })

    kex_pq  = any("group" in c["bom-ref"] or c["cryptoProperties"].get("algorithmProperties",{}).get("primitive")=="kem" for c in comps if c["cryptoProperties"]["assetType"]=="algorithm" and c["cryptoProperties"]["algorithmProperties"].get("primitive")=="kem")
    # simpler readiness summary from flags of KEM and signature
    kem_safe = any(c["cryptoProperties"]["algorithmProperties"].get("primitive")=="kem"
                   and c["properties"][0]["value"]=="true" for c in comps
                   if c["cryptoProperties"]["assetType"]=="algorithm")
    sig_safe = any(c["cryptoProperties"]["algorithmProperties"].get("primitive")=="signature"
                   and c["properties"][0]["value"]=="true" for c in comps
                   if c["cryptoProperties"]["assetType"]=="algorithm")
    readiness = ("quantum-safe" if kem_safe and sig_safe else
                 "confidentiality-only" if kem_safe else
                 "classical")
    return host, comps, {"keyExchangeQuantumSafe":str(kem_safe).lower(),
                         "authenticationQuantumSafe":str(sig_safe).lower(),
                         "readiness":readiness}

def main():
    targets = sys.argv[1:]
    if not targets:
        print(__doc__); sys.exit(2)
    ver = subprocess.run([OSSL,"version"],capture_output=True,text=True).stdout.strip()
    pq_capable = "MLKEM" in subprocess.run([OSSL,"list","-tls-groups"],
                    capture_output=True,text=True).stdout.upper()
    components, deps, summaries = [], [], []
    for t in targets:
        r = scan(t)
        if not r:
            summaries.append({"name":f"scan:{t}","value":"unreachable"}); continue
        host, comps, summ = r
        components += comps
        summaries.append({"name":f"readiness:{host}","value":summ["readiness"]})

    cbom = {
        "bomFormat":"CycloneDX","specVersion":"1.6",
        "serialNumber":f"urn:uuid:{uuid.uuid4()}","version":1,
        "metadata":{
            "timestamp":datetime.datetime.now(datetime.timezone.utc)
                        .strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tools":[{"name":"cbom.py","vendor":"PQC for Enterprise IT (book lab)"}],
            "properties":[
                {"name":"pqc:openssl","value":ver},
                {"name":"pqc:scannerQuantumCapable","value":str(pq_capable).lower()},
                *summaries,
            ],
        },
        "components":components,
    }
    print(json.dumps(cbom, indent=2))

if __name__ == "__main__":
    main()
