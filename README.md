# 🧠 Industry 5.0 Healthcare Framework (SMA + CP-ABE Demo)

Secure Mutual Authentication (SMA) and CP-ABE Encryption framework implemented in **C with OpenSSL (P-256 curve)**.  
This project simulates the **key phases** from an Industry 5.0 healthcare architecture paper:  
key generation, encryption/tag generation, and verification/audit.

---

## 📘 Description
This repository demonstrates:
- Cryptographic primitives using **Elliptic Curve (P-256)** and **SHA-256**
- Secure Mutual Authentication (SMA) as in *Algorithm 2* of the research paper  
- Integration of **AES + CP-ABE** concept for future data upload phase  
- Real-time execution timing and benchmarking on macOS ARM64  

---

## ⚙️ Project Setup

### 🧩 Dependencies
Make sure you have OpenSSL installed:
```bash
brew install openssl

🧠 Phase 1 — Setup / Key Generation
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


./decrypt_access \
"Doctor AND (Cardiology OR Neurology)" \
"Doctor,Cardiology,Hospital-A" \
"2de3b3919ccbcda5bd3169b38e4955afef5a1e064bb9f55c3f7a609c0de76970" \
"a09e3ef5db3d81618d55b76c" \
"a0b8c396342bcd6d5e98bbaba666fe1c" \
"4a0335dc0fa4d0c266dfc43ffd27fdc5b388cc14bb896a25097ccd30e05b28aaceee" \
"a8fcb60f86985516396a1d7ce8b87f600b9053b3c3491eaac11e67a0bb7d77df"
