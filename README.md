Compile the modules
In project folder:
gcc -O3 keygen.c -o keygen \
-I/opt/homebrew/opt/openssl/include \
-L/opt/homebrew/opt/openssl/lib -lcrypto

gcc -O3 encrypt_taggen.c -o encrypt_taggen \
-I/opt/homebrew/opt/openssl/include \
-L/opt/homebrew/opt/openssl/lib -lcrypto

Run the key generation phase
./keygen
Expected Output:
=== Setup / KeyGen Benchmark ===
Key Generation time: 3.875 ms
Hash+Verification time: 0.154 ms
Total Setup Phase: 4.029 ms


Run the encryption + tag generation phase
./encrypt_taggen "Doctor AND (Cardiology OR Neurology)" \
"Doctor,Cardiology,Hospital-A" \
"patient: Alice\npressure: 128/82\n"
Expected Output:
=== Encrypt / TagGen (simulation) ===
Policy: Doctor AND (Cardiology OR Neurology)
Encrypt+TagGen time: 2.301 ms
Plaintext decrypted: patient: Alice
pressure: 128/82