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
🕒 Total execution time: 2.116 ms

Phase 4 — Access / Decrypt Phase
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
⏱ Key-derive time: 1.254 ms
⏱ AES-GCM decrypt time: 0.967 ms
⏱ Total time: 2.221 ms


