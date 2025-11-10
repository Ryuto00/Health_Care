// policy_update.c
// Phase G: Revocation / Policy Update (function-based)
// Ryu's Industry 5.0 Healthcare Framework (macOS ARM64, OpenSSL 3)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

#define GCM_IV_LEN 12
#define GCM_TAG_LEN 16
#define CHECK(x) do{ if(!(x)){ fprintf(stderr,"[ERR] %s failed @%s:%d\n",#x,__FILE__,__LINE__); goto fail; } }while(0)

/* ========================= Utilities ========================= */

static double now_ms(void){
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (double)tv.tv_sec * 1000.0 + (double)tv.tv_usec / 1000.0;
}

static void print_hex(const char *label, const unsigned char *buf, size_t len){
    printf("%s", label);
    for(size_t i=0;i<len;i++) printf("%02x", buf[i]);
    printf("\n");
}

/* ========================= Cryptographic Helpers ========================= */

// SHA-256 wrapper
static void sha256_buf(const unsigned char *in, size_t len, unsigned char out[32]){
    SHA256(in, len, out);
}

// AES-GCM encryption (returns malloc'd ciphertext)
static int aes_gcm_encrypt(const unsigned char *pt, int ptlen, const unsigned char *key,
                           unsigned char iv[GCM_IV_LEN],
                           unsigned char **ct, int *ctlen,
                           unsigned char tag[GCM_TAG_LEN]){
    if(RAND_bytes(iv, GCM_IV_LEN) != 1) return 0;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(); if(!ctx) return 0;
    int len = 0, clen = 0, ok = 1;
    unsigned char *buf = malloc(ptlen);
    if(!EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) ok=0;
    if(ok && !EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) ok=0;
    if(ok && !EVP_EncryptUpdate(ctx, buf, &len, pt, ptlen)) ok=0;
    clen = len;
    if(ok && !EVP_EncryptFinal_ex(ctx, buf+len, &len)) ok=0;
    clen += len;
    if(ok && !EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN, tag)) ok=0;
    EVP_CIPHER_CTX_free(ctx);
    if(!ok){ free(buf); return 0; }
    *ct = buf; *ctlen = clen; return 1;
}

/* ========================= Policy Update Logic ========================= */

// remove attribute from policy string (simulate revocation)
static void update_policy(char *policy, const char *attr){
    char *p = strcasestr(policy, attr);
    if(p){
        memset(p, ' ', strlen(attr)); // replace revoked attribute with space
    }
}

// re-encrypt payload with new key to simulate re-encryption
static double simulate_reencryption(const char *data){
    unsigned char key[32], iv[GCM_IV_LEN], tag[GCM_TAG_LEN];
    unsigned char *ct = NULL; int ctlen = 0;
    RAND_bytes(key, 32);

    double t0 = now_ms();
    aes_gcm_encrypt((unsigned char*)data, strlen(data), key, iv, &ct, &ctlen, tag);
    double t1 = now_ms();

    print_hex("New AES Key: ", key, 32);
    print_hex("IV: ", iv, GCM_IV_LEN);
    print_hex("Tag: ", tag, GCM_TAG_LEN);
    printf("Re-encrypted data length: %d bytes\n", ctlen);

    free(ct);
    return t1 - t0;
}

/* ========================= Main Benchmark ========================= */

int main(int argc, char **argv){
    if(argc < 3){
        printf("Usage:\n  %s \"<POLICY>\" \"<ATTR_TO_REVOKE>\"\n", argv[0]);
        return 1;
    }

    char policy[512];
    strncpy(policy, argv[1], sizeof(policy)-1);
    const char *revoke = argv[2];

    printf("Old Policy: %s\n", policy);
    printf("Revoked Attribute: %s\n", revoke);

    //  update policy
    double t0 = now_ms();
    update_policy(policy, revoke);
    double t1 = now_ms();

    printf("Updated Policy: %s\n", policy);
    printf("Policy string update time: %.3f ms\n", (t1 - t0));

    //  simulate re-encryption
    const char *sample_data = "confidential healthcare record";
    double t_enc = simulate_reencryption(sample_data);

    // total time
    double total = (t1 - t0) + t_enc;
    printf("\nTotal Policy Update : %.3f ms\n", total);

    return 0;

fail:
    fprintf(stderr, "[FAIL] Policy Update process failed.\n");
    return 1;
}
