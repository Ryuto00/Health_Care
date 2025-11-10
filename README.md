# Industry 5.0 Healthcare Framework (SMA + CP-ABE Demo)

Secure Mutual Authentication (SMA) and CP-ABE Encryption framework implemented in **C with OpenSSL (P-256 curve)**.  
This project simulates the **key phases** from an Industry 5.0 healthcare architecture paper:  
key generation, encryption/tag generation, and verification/audit.

---

##  Description
This repository demonstrates:
- Cryptographic primitives using **Elliptic Curve (P-256)** and **SHA-256**
- Secure Mutual Authentication (SMA) as in *Algorithm 2* of the research paper  
- Integration of **AES + CP-ABE** concept for future data upload phase  
- Real-time execution timing and benchmarking on macOS ARM64  

---

## Project Setup

###  Dependencies
Make sure you have OpenSSL installed:
```bash
brew install openssl

Phase 1 — Setup / Key Generation
Compile:
gcc -O3 keygen.c -o keygen \
-I/opt/homebrew/opt/openssl/include \
-L/opt/homebrew/opt/openssl/lib -lcrypto
Run:
./keygen

Expected Output:
=== Setup / KeyGen Benchmark ===
Key Generation time: 3.875 ms
Hash+Verification time: 0.154 ms
Total Setup Phase: 4.029 ms

Phase 2 — Data Upload (CP-ABE-shaped Demo)
Compile:
gcc -O3 encrypt_upload.c -o encrypt_upload \
-I/opt/homebrew/opt/openssl/include \
-L/opt/homebrew/opt/openssl/lib -lcrypto

Run:
./encrypt_upload "Doctor AND (Cardiology OR Neurology)" \
"Doctor,Cardiology,Hospital-A" \
"patient: Alice\npressure: 128/82\n"

Expected Output:
=== Data Upload Phase (demo) ===
Policy: Doctor AND (Cardiology OR Neurology)
Leaves: doctor, cardiology, neurology
policy_hash: 449c091f89c3f881884a568ed620475fcceadc0106bb1306a8649ef97ba02041
AES.K (demo)    : cbc628bd74f95c2a86d3f48a5ef02c9d422794c9a7444fd54bab3bd5b9c48015
AES.iv          : a09e3ef5db3d81618d55b76c
AES.tag         : a0b8c396342bcd6d5e98bbaba666fe1c
AES.ct (hex)    : 4a0335dc0fa4d0c266dfc43ffd27fdc5b388cc14bb896a25097ccd30e05b28aaceee
s_hex           : 2de3b3919ccbcda5bd3169b38e4955afef5a1e064bb9f55c3f7a609c0de76970
C0 (K XOR H(policy||s)): a8fcb60f86985516396a1d7ce8b87f600b9053b3c3491eaac11e67a0bb7d77df
C1 = g^s (33B)  : 02c4888bcd8155b1f12b58b4fd8020d5082c5488d916209333f39136f0374b96a6
Total execution time: 2.116 ms

Phase 3 — Access / Decrypt Phase
Compile:
gcc -O3 decrypt_access.c -o decrypt_access \
-I/opt/homebrew/opt/openssl/include \
-L/opt/homebrew/opt/openssl/lib -lcrypto

Run:
./decrypt_access \
"Doctor AND (Cardiology OR Neurology)" \
"Doctor,Cardiology,Hospital-A" \
"2de3b3919ccbcda5bd3169b38e4955afef5a1e064bb9f55c3f7a609c0de76970" \
"a09e3ef5db3d81618d55b76c" \
"a0b8c396342bcd6d5e98bbaba666fe1c" \
"4a0335dc0fa4d0c266dfc43ffd27fdc5b388cc14bb896a25097ccd30e05b28aaceee" \
"a8fcb60f86985516396a1d7ce8b87f600b9053b3c3491eaac11e67a0bb7d77df"

Expected Output:
=== Access / Decrypt Phase ===
Policy: Doctor AND (Cardiology OR Neurology)
Recovered K: cbc628bd74f95c2a86d3f48a5ef02c9d422794c9a7444fd54bab3bd5b9c48015
Plaintext: patient: Alice
pressure: 128/82
Key-derive time: 1.254 ms
AES-GCM decrypt time: 0.967 ms
Total time: 2.221 ms

Phase 4 — Verify / Audit (Secure Mutual Authentication, Algorithm 2: SMA)
Compile:
gcc -O3 verify_audit.c -o verify_audit \
-I/opt/homebrew/opt/openssl/include \
-L/opt/homebrew/opt/openssl/lib -lcrypto

Run:
./verify_audit

Expected output:

=== [Requester Phase] ===
n_R: 6E7A3C8FD0E5ED6DFA914B2EF93867F17C82531BC74A44DD2A1016F7FBD42F60
SID_R: d3d335b7021530c094f6e9d537eaa5a2b6ce190d4e28ccdb054737dd9117a514
C_hash: 394edc010fd606a215d02ff50944cb51df53f515c6dfb3297b1eac90ebd4ba5b
sigma: A9C0D693FFD2F775B61942A704401B72C8BD4FAA4407B0819BBBFC6E40408A53
P_R (compressed): 03a9195e25a72853e69cfd8a165d0be7e802af8f486ddb6572589a11df2088c642
 Requester time: 0 ms

=== [Owner Verification Phase] ===
SID_R2:   d3d335b7021530c094f6e9d537eaa5a2b6ce190d4e28ccdb054737dd9117a514
C*_hash:  394edc010fd606a215d02ff50944cb51df53f515c6dfb3297b1eac90ebd4ba5b
C*:       9193897BF9CBA8488D275050D9869E74FDB2BA5819F36279984F1394D724DED6
 Verify time: 0 ms

VERIFY/AUDIT PASSED — Session is VALID.
C:   394edc010fd606a215d02ff50944cb51df53f515c6dfb3297b1eac90ebd4ba5b
C*:  394edc010fd606a215d02ff50944cb51df53f515c6dfb3297b1eac90ebd4ba5b
