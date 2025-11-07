// encrypt_taggen.c  — CP-ABE (sim) Encrypt/TagGen for macOS (ARM) using OpenSSL 3
// Build:  gcc -O3 encrypt_taggen.c -o encrypt_taggen -lcrypto
// Usage:  ./encrypt_taggen "<policy>" "<attrs_csv>" "<plaintext>"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>

#define MAX_ATTRS   64
#define MAX_POLICY  512
#define GCM_IV_LEN  12
#define GCM_TAG_LEN 16

// ---------- helpers ----------
static void hex(const unsigned char *b, size_t n){ for(size_t i=0;i<n;i++) printf("%02x", b[i]); }
static void sha256(const unsigned char *m, size_t n, unsigned char out[32]){ SHA256(m, n, out); }
static void xorb(unsigned char *o, const unsigned char *a, const unsigned char *b, size_t n){ for(size_t i=0;i<n;i++) o[i]=a[i]^b[i]; }

static int aes_gcm_encrypt(const unsigned char *pt, int ptlen,
                           const unsigned char *key,
                           unsigned char iv[GCM_IV_LEN],
                           unsigned char **out_ct, int *out_ct_len,
                           unsigned char tag[GCM_TAG_LEN]){
    RAND_bytes(iv, GCM_IV_LEN);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if(!ctx) return 0;
    int ok = 1, len=0, ctlen=0;
    unsigned char *ct = malloc(ptlen);
    if(!EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) ok=0;
    if(ok && !EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_LEN, NULL)) ok=0;
    if(ok && !EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) ok=0;
    if(ok && !EVP_EncryptUpdate(ctx, ct, &len, pt, ptlen)) ok=0;
    ctlen = len;
    if(ok && !EVP_EncryptFinal_ex(ctx, ct+len, &len)) ok=0;
    ctlen += len;
    if(ok && !EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN, tag)) ok=0;
    EVP_CIPHER_CTX_free(ctx);
    if(!ok){ free(ct); return 0; }
    *out_ct = ct; *out_ct_len = ctlen; return 1;
}

static int aes_gcm_decrypt(const unsigned char *ct, int ctlen,
                           const unsigned char *key,
                           const unsigned char iv[GCM_IV_LEN],
                           const unsigned char tag[GCM_TAG_LEN],
                           unsigned char **out_pt, int *out_pt_len){
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if(!ctx) return 0;
    int ok=1, len=0, ptlen=0;
    unsigned char *pt = malloc(ctlen);
    if(!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) ok=0;
    if(ok && !EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_LEN, NULL)) ok=0;
    if(ok && !EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) ok=0;
    if(ok && !EVP_DecryptUpdate(ctx, pt, &len, ct, ctlen)) ok=0;
    ptlen = len;
    if(ok && !EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_LEN, (void*)tag)) ok=0;
    if(ok && !EVP_DecryptFinal_ex(ctx, pt+len, &len)) ok=0;
    ptlen += len; EVP_CIPHER_CTX_free(ctx);
    if(!ok){ free(pt); return 0; }
    *out_pt = pt; *out_pt_len = ptlen; return 1;
}

// ---------- attribute / policy parsing (supports tokens, AND, OR, parentheses) ----------
typedef struct { const char *s; int pos; } lexer_t;

static void skip_ws(lexer_t *L){ while(isspace((unsigned char)L->s[L->pos])) L->pos++; }
static int match_kw(lexer_t *L, const char *kw){
    skip_ws(L);
    int n = (int)strlen(kw);
    if(strncasecmp(L->s + L->pos, kw, n)==0){
        int end = L->pos + n;
        if(end==(int)strlen(L->s) || isspace((unsigned char)L->s[end]) || L->s[end]==')') { L->pos=end; return 1; }
    }
    return 0;
}
static int parse_expr(lexer_t *L, char attrs[MAX_ATTRS][64], int nattrs); // forward

static int token_attr(lexer_t *L, char out[64]){
    skip_ws(L);
    if(L->s[L->pos]=='(' || L->s[L->pos]==')' || !L->s[L->pos]) return 0;
    int i=0;
    while(L->s[L->pos] && !isspace((unsigned char)L->s[L->pos]) && L->s[L->pos]!=')' && i<63){
        out[i++] = L->s[L->pos++];
    }
    out[i]=0; return i>0;
}
static int has_attr(const char attr[64], char attrs[MAX_ATTRS][64], int nattrs){
    for(int i=0;i<nattrs;i++) if(strcasecmp(attr, attrs[i])==0) return 1;
    return 0;
}
// term := ATTR | '(' expr ')'
static int parse_term(lexer_t *L, char attrs[MAX_ATTRS][64], int nattrs){
    skip_ws(L);
    if(L->s[L->pos]=='('){ L->pos++; int v = parse_expr(L, attrs, nattrs); skip_ws(L); if(L->s[L->pos]==')') L->pos++; return v; }
    char a[64]; if(!token_attr(L, a)) return 0;
    return has_attr(a, attrs, nattrs);
}
// and := term { AND term }
static int parse_and(lexer_t *L, char attrs[MAX_ATTRS][64], int nattrs){
    int v = parse_term(L, attrs, nattrs);
    while(match_kw(L,"AND")){ int rhs = parse_term(L, attrs, nattrs); v = v && rhs; }
    return v;
}
// expr := and { OR and }
static int parse_expr(lexer_t *L, char attrs[MAX_ATTRS][64], int nattrs){
    int v = parse_and(L, attrs, nattrs);
    while(match_kw(L,"OR")){ int rhs = parse_and(L, attrs, nattrs); v = v || rhs; }
    return v;
}
static int policy_satisfied(const char *policy, char attrs[MAX_ATTRS][64], int nattrs){
    lexer_t L = { policy, 0 }; return parse_expr(&L, attrs, nattrs);
}

// ---------- CP-ABE (simulation) structures ----------
typedef struct {
    unsigned char C0[32];     // wraps K  : K XOR H(policy || "wrap")
    unsigned char C1[33];     // g^s (simulated) : compressed EC point (P-256)
    unsigned char policy_hash[32];
    int nleaves;
    unsigned char *Ci;        // nleaves * 32
    unsigned char *Di;        // nleaves * 32
    // symmetric payload
    unsigned char iv[GCM_IV_LEN];
    unsigned char tag[GCM_TAG_LEN];
    unsigned char *C_sym;     // AES-GCM ciphertext of D
    int C_sym_len;
    char policy[MAX_POLICY];
} CT_ABE_SIM;

// extract leaves (attributes) from policy (tokens excluding AND/OR/() )
static int extract_leaves(const char *policy, char leaves[MAX_ATTRS][64]){
    int n=0; lexer_t L={policy,0};
    while(1){
        skip_ws(&L);
        if(!policy[L.pos]) break;
        if(L.s[L.pos]=='(' || L.s[L.pos]==')'){ L.pos++; continue; }
        if(match_kw(&L,"AND")||match_kw(&L,"OR")) continue;
        char a[64]; if(token_attr(&L,a)){ strncpy(leaves[n++],a,64); if(n>=MAX_ATTRS) break; }
        else L.pos++; // safeguard
    }
    return n;
}

// build C1 as compressed EC point from random s (only for timing/visual)
static int make_C1(unsigned char out33[33]){
    int ok=0; EC_KEY *ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if(!ec) return 0;
    BIGNUM *s = BN_new(); BN_rand(s, 256, 0, 0);
    EC_POINT *P = EC_POINT_new(EC_KEY_get0_group(ec));
    if(EC_POINT_mul(EC_KEY_get0_group(ec), P, s, NULL, NULL, NULL)!=1) goto end;
    size_t L = EC_POINT_point2oct(EC_KEY_get0_group(ec), P, POINT_CONVERSION_COMPRESSED, out33, 33, NULL);
    ok = (L==33);
end:
    EC_POINT_free(P); BN_free(s); EC_KEY_free(ec); return ok;
}

// Encrypt/TagGen (simulation faithful to paper’s flow)
static int cpabe_encrypt_sim(const char *policy,
                             const unsigned char *data, int datalen,
                             CT_ABE_SIM *out){
    memset(out,0,sizeof(*out));
    strncpy(out->policy, policy, MAX_POLICY-1);

    // 1) select random symmetric K (32 bytes)
    unsigned char K[32]; RAND_bytes(K, 32);

    // 2) policy hash & wrapper for K  -> C0
    unsigned char ph[32], wrap[32]; sha256((unsigned char*)policy, strlen(policy), ph);
    unsigned char tmp[64]; memcpy(tmp, ph, 32); memcpy(tmp+32, "wrap", 4);
    sha256(tmp, 36, wrap);
    xorb(out->C0, K, wrap, 32);
    memcpy(out->policy_hash, ph, 32);

    // 3) produce C1 = g^s (simulated EC point)
    if(!make_C1(out->C1)) return 0;

    // 4) produce per-leaf {Ci, Di}
    char leaves[MAX_ATTRS][64]; int n = extract_leaves(policy, leaves);
    out->nleaves = n;
    out->Ci = malloc(32*n); out->Di = malloc(32*n);
    for(int i=0;i<n;i++){
        unsigned char h[32];
        unsigned char buf[128];

        // Ci = H("Ci" || leaf || policy_hash)
        int m = snprintf((char*)buf, sizeof(buf), "Ci|%s|", leaves[i]);
        memcpy(buf+m, ph, 32); sha256(buf, m+32, h); memcpy(out->Ci+32*i, h, 32);

        // Di = H("Di" || leaf)
        m = snprintf((char*)buf, sizeof(buf), "Di|%s", leaves[i]);
        sha256(buf, m, h); memcpy(out->Di+32*i, h, 32);
    }

    // 5) AES-256-GCM encrypt data with K  -> C_sym, iv, tag
    if(!aes_gcm_encrypt(data, datalen, K, out->iv, &out->C_sym, &out->C_sym_len, out->tag)) return 0;

    return 1;
}

// Decrypt (simulation): check policy satisfied by requester attributes, then unwrap K and decrypt
static int cpabe_decrypt_sim(const CT_ABE_SIM *ct,
                             char attrs[MAX_ATTRS][64], int nattrs,
                             unsigned char **out_pt, int *out_pt_len){
    if(!policy_satisfied(ct->policy, attrs, nattrs)) return 0;

    unsigned char wrap[32], K[32], tmp[64];
    memcpy(tmp, ct->policy_hash, 32); memcpy(tmp+32, "wrap", 4);
    sha256(tmp, 36, wrap);
    xorb(K, ct->C0, wrap, 32); // recover K

    return aes_gcm_decrypt(ct->C_sym, ct->C_sym_len, K, ct->iv, ct->tag, out_pt, out_pt_len);
}

// ---------- demo main ----------
static int split_csv(char *csv, char out[MAX_ATTRS][64]){
    int n=0; char *tok=strtok(csv, ",");
    while(tok && n<MAX_ATTRS){ // trim spaces
        while(*tok==' ') tok++;
        strncpy(out[n++], tok, 63); out[n-1][63]=0;
        tok=strtok(NULL, ",");
    } return n;
}

int main(int argc, char **argv){
    if(argc<4){
        fprintf(stderr,"Usage: %s \"<policy>\" \"<attrs_csv>\" \"<plaintext>\"\n", argv[0]);
        return 1;
    }
    const char *policy = argv[1];
    char attrs_csv[1024]; strncpy(attrs_csv, argv[2], sizeof(attrs_csv)-1); attrs_csv[sizeof(attrs_csv)-1]=0;
    const unsigned char *plaintext = (unsigned char*)argv[3];
    int ptlen = (int)strlen(argv[3]);

    char attrs[MAX_ATTRS][64]; int nattrs = split_csv(attrs_csv, attrs);

    CT_ABE_SIM ct; clock_t t0,t1;

    t0=clock();
    if(!cpabe_encrypt_sim(policy, plaintext, ptlen, &ct)){
        fprintf(stderr,"encrypt failed\n"); return 1;
    }
    t1=clock();
    double t_encrypt = (double)(t1-t0)/CLOCKS_PER_SEC*1000.0;

    printf("=== Encrypt / TagGen (simulation) ===\n");
    printf("Policy: %s\n", ct.policy);
    printf("Leaves: %d\n", ct.nleaves);
    printf("C0: "); hex(ct.C0,32); printf("\n");
    printf("C1: "); hex(ct.C1,33); printf("\n");
    printf("policy_hash: "); hex(ct.policy_hash,32); printf("\n");
    printf("AES-GCM iv: "); hex(ct.iv,GCM_IV_LEN); printf("  tag: "); hex(ct.tag,GCM_TAG_LEN); printf("\n");
    printf("Ciphertext len: %d bytes\n", ct.C_sym_len);
    printf("Encrypt+TagGen time: %.3f ms\n\n", t_encrypt);

    // Decrypt test
    unsigned char *dec=NULL; int declen=0;
    t0=clock();
    int ok = cpabe_decrypt_sim(&ct, attrs, nattrs, &dec, &declen);
    t1=clock();
    double t_dec = (double)(t1-t0)/CLOCKS_PER_SEC*1000.0;

    if(ok){
        printf("=== Decrypt (with attrs) OK (%.3f ms) ===\n", t_dec);
        printf("Plaintext: %.*s\n", declen, dec);
        free(dec);
    }else{
        printf("=== Decrypt FAILED: attributes do not satisfy policy ===\n");
    }

    // cleanup
    free(ct.Ci); free(ct.Di); free(ct.C_sym);
    return 0;
}
