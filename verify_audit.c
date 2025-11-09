// verify_audit.c
// Phase: Verify / Audit (Algorithm 2: SMA) demo using OpenSSL on P-256
// Ryu's project — Industry 5.0 healthcare framework

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>

#define CHECK(x) do { if(!(x)) { fprintf(stderr,"[ERR] %s failed @%s:%d\n", #x, __FILE__, __LINE__); goto cleanup_fail; } } while(0)

static void print_hex(const char *label, const unsigned char *buf, size_t len){
    printf("%s", label);
    for(size_t i=0;i<len;i++) printf("%02x", buf[i]);
    printf("\n");
}
static void sha256(const unsigned char *in, size_t inlen, unsigned char out32[32]){
    SHA256(in, inlen, out32);
}
static void print_bn(const char *label, const BIGNUM *bn){
    char *hex = BN_bn2hex(bn);
    if(hex){ printf("%s%s\n", label, hex); OPENSSL_free(hex); }
    else   { printf("%s<null>\n", label); }
}

static unsigned char* cat2(const unsigned char *a, size_t la,
                           const unsigned char *b, size_t lb,
                           size_t *outlen){
    *outlen = la + lb;
    unsigned char *m = (unsigned char*)malloc(*outlen);
    if(!m) return NULL;
    memcpy(m, a, la);
    memcpy(m+la, b, lb);
    return m;
}
static unsigned char* cat3(const unsigned char *a, size_t la,
                           const unsigned char *b, size_t lb,
                           const unsigned char *c, size_t lc,
                           size_t *outlen){
    size_t t; unsigned char *ab = cat2(a,la,b,lb,&t);
    if(!ab) return NULL;
    unsigned char *abc = cat2(ab,t,c,lc,outlen);
    free(ab);
    return abc;
}
static unsigned char* cat5(const unsigned char *a, size_t la,
                           const unsigned char *b, size_t lb,
                           const unsigned char *c, size_t lc,
                           const unsigned char *d, size_t ld,
                           const unsigned char *e, size_t le,
                           size_t *outlen){
    size_t t1; unsigned char *ab   = cat2(a,la,b,lb,&t1);             if(!ab) return NULL;
    size_t t2; unsigned char *abc  = cat2(ab,t1,c,lc,&t2);            if(!abc){ free(ab); return NULL; }
    size_t t3; unsigned char *abcd = cat2(abc,t2,d,ld,&t3);           if(!abcd){ free(ab); free(abc); return NULL; }
    unsigned char *abcde = cat2(abcd,t3,e,le,outlen);
    free(ab); free(abc); free(abcd);
    return abcde;
}

// serialize EC_POINT (compressed 33 bytes on P-256)
static int point_to_bytes(const EC_GROUP *grp, const EC_POINT *P, unsigned char out[33]){
    size_t L = EC_POINT_point2oct(grp, P, POINT_CONVERSION_COMPRESSED, out, 33, NULL);
    return (L==33) ? 1 : 0;
}

// map SHA256 -> BIGNUM mod curve order
static int hash_to_bn_mod_n(const unsigned char *msg, size_t len,
                            const BIGNUM *order, BIGNUM **out_bn){
    unsigned char h[32];
    sha256(msg, len, h);

    BIGNUM *x = BN_bin2bn(h, 32, NULL);
    if(!x) return 0;

    BN_CTX *ctx = BN_CTX_new();
    if(!ctx){ BN_free(x); return 0; }

    if(!BN_mod(x, x, order, ctx)){
        BN_free(x);
        BN_CTX_free(ctx);
        return 0;
    }
    BN_CTX_free(ctx);
    *out_bn = x;
    return 1;
}

// wall-clock ms
static long long now_ms(void){
    struct timeval tv; gettimeofday(&tv, NULL);
    return (long long)tv.tv_sec*1000LL + tv.tv_usec/1000LL;
}

int main(void){
    const char *IDu = "owner:doctor.alice";
    const char *Pu  = "S3curePa$$w0rd!";
    const char *IDR = "requester:bob";
    const long  deltaT_ms = 60*1000; // 1 minute

    int ret = 1;
    BN_CTX *bnctx = NULL;
    EC_GROUP *grp = NULL;
    EC_KEY *owner = NULL, *req = NULL;
    BIGNUM *order = NULL, *nR = NULL, *sigma = NULL, *C = NULL, *Cstar = NULL;
    EC_POINT *P_R = NULL, *sigG = NULL, *CpkU = NULL, *lhs = NULL, *left = NULL, *right = NULL;

    long long T_total0 = now_ms();

    // === Setup curve/order ===
    grp = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);                       CHECK(grp);
    order = BN_new();                                                              CHECK(order);
    CHECK(EC_GROUP_get_order(grp, order, NULL));
    bnctx = BN_CTX_new();                                                          CHECK(bnctx);

    // === Owner keys ===
    owner = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);                        CHECK(owner);
    CHECK(EC_KEY_generate_key(owner));
    const BIGNUM  *sk_u = EC_KEY_get0_private_key(owner);                          CHECK(sk_u);
    const EC_POINT*pk_u = EC_KEY_get0_public_key(owner);                           CHECK(pk_u);

    // === Derive SPu (demo) ===
    unsigned char n1[32], n2[32];
    CHECK(RAND_bytes(n1,32)==1 && RAND_bytes(n2,32)==1);
    size_t l1=0, l2=0;
    unsigned char *id_pw    = cat2((const unsigned char*)IDu, strlen(IDu),
                                   (const unsigned char*)Pu,  strlen(Pu), &l1);    CHECK(id_pw);
    unsigned char *id_pw_n1 = cat2(id_pw,l1,n1,32,&l2);                            CHECK(id_pw_n1);
    unsigned char SPu[32]; sha256(id_pw_n1, l2, SPu);
    free(id_pw); free(id_pw_n1);

    // -------------------------------------------
    // Requester Phase
    // -------------------------------------------
    long long T_req0 = now_ms();

    nR = BN_new();                                                                  CHECK(nR);
    do { CHECK(BN_rand_range(nR, order)); } while(BN_is_zero(nR));                 // nR in [1,n-1]
    P_R = EC_POINT_new(grp);                                                       CHECK(P_R);
    CHECK(EC_POINT_mul(grp, P_R, nR, NULL, NULL, bnctx));

    unsigned char PR_ser[33];                                                      CHECK(point_to_bytes(grp, P_R, PR_ser));

    size_t l_spidr_msg=0;
    unsigned char *spidr_msg =
        cat3((const unsigned char*)IDR, strlen(IDR), PR_ser, 33, n1, 32, &l_spidr_msg); CHECK(spidr_msg);
    unsigned char SP_IDR[32]; sha256(spidr_msg, l_spidr_msg, SP_IDR);
    free(spidr_msg);

    size_t l_sid_msg=0;
    unsigned char *sid_msg = cat5((const unsigned char*)IDu, strlen(IDu),
                                  SPu, 32, PR_ser, 33, n1, 32, n2, 32, &l_sid_msg);     CHECK(sid_msg);
    unsigned char SIDR[32]; sha256(sid_msg, l_sid_msg, SIDR);
    free(sid_msg);

    unsigned char PKU_ser[33];                                                     CHECK(point_to_bytes(grp, pk_u, PKU_ser));

    long long T1_ms = now_ms();
    unsigned char T1_buf[16];
    for(int i=0;i<16;i++) T1_buf[15-i] = (unsigned char)((T1_ms >> (i*8)) & 0xff);

    size_t l_cmsg1=0, l_cmsg2=0, l_cmsg=0;
    unsigned char *cmsg1 = cat2(PR_ser,33,SIDR,32,&l_cmsg1);                       CHECK(cmsg1);
    unsigned char *cmsg2 = cat2(PKU_ser,33,T1_buf,16,&l_cmsg2);                    CHECK(cmsg2);
    unsigned char *cmsg  = cat2(cmsg1,l_cmsg1,cmsg2,l_cmsg2,&l_cmsg);              CHECK(cmsg);
    unsigned char C_hash[32]; sha256(cmsg, l_cmsg, C_hash);
    free(cmsg1); free(cmsg2); free(cmsg);

    CHECK(hash_to_bn_mod_n(C_hash, 32, order, &C));

    req = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);                           CHECK(req);
    CHECK(EC_KEY_generate_key(req));
    const BIGNUM *sk_R = EC_KEY_get0_private_key(req);                              CHECK(sk_R);

    sigma = BN_new();                                                               CHECK(sigma);
    CHECK(BN_mod_mul(sigma, C, sk_R, order, bnctx));
    CHECK(BN_mod_add(sigma, sigma, nR, order, bnctx));

    long long T_req1 = now_ms();

    // Debug dump — Requester
    printf("\n=== [Requester Phase] ===\n");
    print_bn("n_R: ", nR);
    print_hex("SID_R: ", SIDR, 32);
    print_hex("C_hash: ", C_hash, 32);
    print_bn("sigma: ", sigma);
    print_hex("P_R (compressed): ", PR_ser, 33);
    printf(" Requester time: %lld ms\n", (T_req1 - T_req0));

    const EC_POINT *pk_R = EC_KEY_get0_public_key(req);


    // -------------------------------------------
    // Owner Verify Phase
    // -------------------------------------------
    long long T_vfy0 = now_ms();

    long long Tcurrent_ms = now_ms();
    if((Tcurrent_ms - T1_ms) >= deltaT_ms){
        printf("[Owner] FAIL: timestamp not fresh (ΔT exceeded)\n");
        goto cleanup_fail;
    }

    size_t l_sid2=0; unsigned char *sid2 = cat5((const unsigned char*)IDu, strlen(IDu),
                                                SPu, 32, PR_ser, 33, n1, 32, n2, 32, &l_sid2); CHECK(sid2);
    unsigned char SIDR2[32]; sha256(sid2, l_sid2, SIDR2); free(sid2);

    size_t l_c2a=0, l_c2b=0, l_c2=0;
    unsigned char *c2a = cat2(PR_ser,33,SIDR2,32,&l_c2a);                           CHECK(c2a);
    unsigned char *c2b = cat2(PKU_ser,33,T1_buf,16,&l_c2b);                         CHECK(c2b);
    unsigned char *c2  = cat2(c2a,l_c2a,c2b,l_c2b,&l_c2);                           CHECK(c2);
    unsigned char Cstar_hash[32]; sha256(c2, l_c2, Cstar_hash);
    free(c2a); free(c2b); free(c2);

    CHECK(hash_to_bn_mod_n(Cstar_hash, 32, order, &Cstar));

    sigG  = EC_POINT_new(grp);                                                      CHECK(sigG);
    CpkU  = EC_POINT_new(grp);                                                      CHECK(CpkU);
    lhs   = EC_POINT_new(grp);                                                      CHECK(lhs);

    CHECK(EC_POINT_mul(grp, sigG, sigma, NULL, NULL, bnctx));        // σ·G
    CHECK(EC_POINT_mul(grp, CpkU, NULL, pk_R, Cstar, bnctx));  // ✅ ใช้ pk_R // C*·pk_u
    CHECK(EC_POINT_invert(grp, CpkU, bnctx));                         // -C*·pk_u
    CHECK(EC_POINT_add(grp, lhs, sigG, CpkU, bnctx));                 // lhs = σ·G - C*·pk_u

    if(EC_POINT_cmp(grp, lhs, P_R, bnctx) != 0){
        printf("[Owner] FAIL: ZK proof check did not match PR\n");
        goto cleanup_fail;
    }

    left  = EC_POINT_new(grp);                                                        CHECK(left);
    right = EC_POINT_new(grp);                                                        CHECK(right);
    CHECK(EC_POINT_mul(grp, left,  NULL, pk_u, nR, bnctx));         // n_R * pk_u
    CHECK(EC_POINT_mul(grp, right, NULL, P_R,  sk_u, bnctx));       // sk_u * P_R
    if(EC_POINT_cmp(grp, left, right, bnctx) != 0){
        printf("[Owner] FAIL: session key consistency (nR·pk_u != P_R·sk_u)\n");
        goto cleanup_fail;
    }

    long long T_vfy1 = now_ms();

    printf("\n=== [Owner Verification Phase] ===\n");
    print_hex("SID_R2:   ", SIDR2, 32);
    print_hex("C*_hash:  ", Cstar_hash, 32);
    print_bn ("C*:       ", Cstar);
    printf(" Verify time: %lld ms\n", (T_vfy1 - T_vfy0));

    printf("\nVERIFY/AUDIT PASSED — Session is VALID.\n");
    print_hex("C:   ", C_hash, 32);
    print_hex("C*:  ", Cstar_hash, 32);
    ret = 0;
    goto cleanup;

cleanup_fail:
    printf("\n VERIFY/AUDIT FAILED.\n");
    if(C)     print_bn("C (bn): ", C);
    if(Cstar) print_bn("C* (bn): ", Cstar);
    if(nR)    print_bn("n_R: ", nR);

cleanup:
    if(P_R)   EC_POINT_free(P_R);
    if(sigG)  EC_POINT_free(sigG);
    if(CpkU)  EC_POINT_free(CpkU);
    if(lhs)   EC_POINT_free(lhs);
    if(left)  EC_POINT_free(left);
    if(right) EC_POINT_free(right);

    if(C)     BN_free(C);
    if(Cstar) BN_free(Cstar);
    if(sigma) BN_free(sigma);
    if(nR)    BN_free(nR);
    if(order) BN_free(order);

    if(owner) EC_KEY_free(owner);
    if(req)   EC_KEY_free(req);
    if(grp)   EC_GROUP_free(grp);
    if(bnctx) BN_CTX_free(bnctx);

    long long T_total1 = now_ms();
    printf("\n Total execution time: %lld ms\n", (T_total1 - T_total0));
    return ret;
}
