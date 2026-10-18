#!/usr/bin/env python3
# p11sign.py — Gate B, Step 4: sign with the Fortanix-resident ML-DSA-87 key through PKCS#11 (CKM_ML_DSA = 0x1D).
# Why Python and not pkcs11-tool: OpenSC 0.24's pkcs11-tool hands C_Sign a fixed classical-sized buffer and fails with
# CKR_BUFFER_TOO_SMALL on a 4,627-byte ML-DSA-87 signature. PyKCS11 follows the PKCS#11 two-call convention (query size,
# then sign), which is what the standard requires and what the library correctly demanded.
# Credential: the app API key, read from the environment (never on the command line). Verified 2026-09-17:
#   signature bytes: 4627 → openssl pkeyutl -verify -rawin ... → "Signature Verified Successfully".
import os, PyKCS11
lib = PyKCS11.PyKCS11Lib(); lib.load('/opt/fortanix/pkcs11/fortanix_pkcs11.so')
s = lib.openSession(0, PyKCS11.CKF_SERIAL_SESSION | PyKCS11.CKF_RW_SESSION)
s.login(os.environ['FTX_API_KEY'])
keys = s.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY), (PyKCS11.CKA_LABEL, 'pqc-root-mldsa87-gateA')])
assert keys, 'key not found'
data = open('msg.txt', 'rb').read()
sig = bytes(s.sign(keys[0], data, PyKCS11.Mechanism(0x1D, None)))   # CKM_ML_DSA, sized by the two-call convention
open('sig-p11.bin', 'wb').write(sig); print('signature bytes:', len(sig))
s.logout(); s.closeSession()
