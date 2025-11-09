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
