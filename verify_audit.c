// sma_verify.c
// Phase: Verify / Audit (Algorithm 2: SMA) demo using OpenSSL on P-256
// Ryu's project — Industry 5.0 healthcare framework

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>

static void print_hex(const char *label, const unsigned char *buf, size_t len){
    printf("%s", label);
    for(size_t i=0;i<len;i++) printf("%02x", buf[i]);
    printf("\n");
}

static void sha256(const unsigned char *in, size_t inlen, unsigned char out32[32]){
    SHA256(in, inlen, out32);
}

// concat helper
static unsigned char* cat2(const unsigned char *a, size_t la,
                           const unsigned char *b, size_t lb,
                           size_t *outlen){
    *outlen = la + lb;
    unsigned char *m = (unsigned char*)malloc(*outlen);
    memcpy(m, a, la);
    memcpy(m+la, b, lb);
    return m;
}
static unsigned char* cat3(const unsigned char *a, size_t la,
                           const unsigned char *b, size_t lb,
                           const unsigned char *c, size_t lc,
                           size_t *outlen){
    size_t t; unsigned char *ab = cat2(a,la,b,lb,&t);
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
    size_t t1; unsigned char *ab = cat2(a,la,b,lb,&t1);
    size_t t2; unsigned char *abc = cat2(ab,t1,c,lc,&t2);
    size_t t3; unsigned char *abcd = cat2(abc,t2,d,ld,&t3);
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
    unsigned char h[32]; sha256(msg, len, h);
    BIGNUM *x = BN_bin2bn(h, 32, NULL);
    if(!x) return 0;
    if(!BN_mod(x, x, order, NULL)){ BN_free(x); return 0; }
    *out_bn = x; return 1;
}

int main(void){
    /* ----- Common parameters ----- */
    const char *IDu = "owner:doctor.alice";       // Owner identity
    const char *Pu  = "S3curePa$$w0rd!";          // Owner password (for SP_u derivation demo)
    const char *IDR = "requester:bob";            // Requester identity (input of Algorithm 2)
    const long  deltaT_ms = 60*1000;              // freshness window ΔT (1 min)

    /* Setup P-256 */
    EC_GROUP *grp = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    const EC_POINT *G = EC_GROUP_get0_generator(grp);
    BIGNUM *order = BN_new(); EC_GROUP_get_order(grp, order, NULL);

    /* Generate Owner long-term key (sk_u, pk_u) */
    EC_KEY *owner = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    EC_KEY_generate_key(owner);
    const BIGNUM *sk_u = EC_KEY_get0_private_key(owner);              // owner secret
    const EC_POINT *pk_u = EC_KEY_get0_public_key(owner);             // owner public

    /* Derive SP_u (from paper Eq. (3): P_u = H(ID_u || P_u || n1))
       Here we just recompute a sample SP_u for hashing in SID_R */
    unsigned char n1[32], n2[32];
    RAND_bytes(n1,32); RAND_bytes(n2,32);
    size_t l1; unsigned char *id_pw = cat2((const unsigned char*)IDu, strlen(IDu),
                                           (const unsigned char*)Pu,  strlen(Pu), &l1);
    size_t l2; unsigned char *id_pw_n1 = cat2(id_pw,l1,n1,32,&l2);
    unsigned char SPu[32]; sha256(id_pw_n1, l2, SPu);
    free(id_pw); free(id_pw_n1);

    /* ----- Requester side (lines 3–10 in the algorithm) ----- */
    // Step 3: Generate nonce n_R ∈ Z_p*
    BIGNUM *nR = BN_new(); BN_rand_range(nR, order);

    // Step 4–5:
    // SP_IDR = H(ID_R || P_R || n1) -- but requires P_R so we do P_R first
    // P_R = n_R * g
    EC_POINT *P_R = EC_POINT_new(grp);
    EC_POINT_mul(grp, P_R, nR, NULL, NULL, NULL); // P_R = nR*G

    unsigned char PR_ser[33]; point_to_bytes(grp, P_R, PR_ser);

    size_t l_spidr_msg; unsigned char *spidr_msg =
        cat3((const unsigned char*)IDR, strlen(IDR), PR_ser, 33, n1, 32, &l_spidr_msg);
    unsigned char SP_IDR[32]; sha256(spidr_msg, l_spidr_msg, SP_IDR);
    free(spidr_msg);

    // SID_R = H(ID_u || SP_u || P_R || n1 || n2)
    size_t l_sid_msg;
    unsigned char *sid_msg = cat5((const unsigned char*)IDu, strlen(IDu),
                                  SPu, 32,
                                  PR_ser, 33,
                                  n1, 32,
                                  n2, 32, &l_sid_msg);
    unsigned char SIDR[32]; sha256(sid_msg, l_sid_msg, SIDR);
    free(sid_msg);

    // C = H(P_R || SID_R || pk_u || T1)
    // serialize pk_u
    unsigned char PKU_ser[33]; point_to_bytes(grp, pk_u, PKU_ser);
    // T1 (timestamp, ms since epoch)
    long long T1_ms = (long long)(clock()) * 1000 / CLOCKS_PER_SEC; // demo timer (process-time)
    // For real system use wall-clock epoch (e.g., gettimeofday)
    unsigned char T1_buf[16]; // put T1_ms as bytes
    for(int i=0;i<16;i++){ T1_buf[15-i] = (unsigned char)((T1_ms >> (i*8)) & 0xff); }

    size_t l_cmsg1; unsigned char *cmsg1 = cat2(PR_ser,33,SIDR,32,&l_cmsg1);
    size_t l_cmsg2; unsigned char *cmsg2 = cat2(PKU_ser,33,T1_buf,16,&l_cmsg2);
    size_t l_cmsg;  unsigned char *cmsg  = cat2(cmsg1,l_cmsg1,cmsg2,l_cmsg2,&l_cmsg);
    unsigned char C_hash[32]; sha256(cmsg, l_cmsg, C_hash);
    free(cmsg1); free(cmsg2); free(cmsg);

    // Map C_hash to scalar mod n
    BIGNUM *C = NULL; hash_to_bn_mod_n(C_hash, 32, order, &C);

    // Prepare requester static secret sk_R (can be long-term); demo generate one
    EC_KEY *req = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    EC_KEY_generate_key(req);
    const BIGNUM *sk_R = EC_KEY_get0_private_key(req);

    // σ = n_R + C * sk_R (mod n)
    BIGNUM *sigma = BN_new();
    BN_CTX *bnctx = BN_CTX_new();
    BN_mod_mul(sigma, C, sk_R, order, bnctx);   // σ = C*sk_R
    BN_mod_add(sigma, sigma, nR, order, bnctx); // σ = nR + C*sk_R

    // “Send” (ID_R, P_R, C, σ, T1) to Owner
    // (We already have them in memory)

    /* ----- Owner side verification (lines 11–16) ----- */

    // 1) Freshness: verify T_current − T1 < ΔT
    long long Tcurrent_ms = (long long)(clock()) * 1000 / CLOCKS_PER_SEC; // demo timer
    if((Tcurrent_ms - T1_ms) >= deltaT_ms){
        printf("[Owner] FAIL: timestamp not fresh (ΔT exceeded)\n");
        goto cleanup_fail;
    }

    // 2) Recompute C* = H(P_R || SID_R || pk_u || T1)  (Owner has ID_u, SP_u, P_R, n1, n2)
    // (we recompute SID_R as well)
    size_t l_sid2;
    unsigned char *sid2 = cat5((const unsigned char*)IDu, strlen(IDu),
                               SPu, 32,
                               PR_ser, 33,
                               n1, 32,
                               n2, 32, &l_sid2);
    unsigned char SIDR2[32]; sha256(sid2, l_sid2, SIDR2);
    free(sid2);

    size_t l_c2a; unsigned char *c2a = cat2(PR_ser,33,SIDR2,32,&l_c2a);
    size_t l_c2b; unsigned char *c2b = cat2(PKU_ser,33,T1_buf,16,&l_c2b);
    size_t l_c2;  unsigned char *c2  = cat2(c2a,l_c2a,c2b,l_c2b,&l_c2);
    unsigned char Cstar_hash[32]; sha256(c2, l_c2, Cstar_hash);
    free(c2a); free(c2b); free(c2);

    BIGNUM *Cstar = NULL; hash_to_bn_mod_n(Cstar_hash, 32, order, &Cstar);

    // 3) Verify:  σ·g − C*·pk_u  ==?  P_R
    EC_POINT *sigG  = EC_POINT_new(grp);
    EC_POINT *CpkU  = EC_POINT_new(grp);
    EC_POINT *lhs   = EC_POINT_new(grp);

    EC_POINT_mul(grp, sigG, sigma, NULL, NULL, bnctx);       // sigG  = σ·G
    EC_POINT_mul(grp, CpkU, NULL, pk_u, Cstar, bnctx);       // CpkU  = C*·pk_u
    EC_POINT_invert(grp, CpkU, bnctx);                       // -C*·pk_u
    EC_POINT_add(grp, lhs, sigG, CpkU, bnctx);               // lhs = σ·G - C*·pk_u

    if(EC_POINT_cmp(grp, lhs, P_R, bnctx) != 0){
        printf("[Owner] FAIL: ZK proof check did not match PR\n");
        goto cleanup_fail;
    }

    // 4) Session Generation: verify n_R·pk_u == P_R · sk_u  (equivalent check)
    //    left  = n_R * pk_u
    //    right = sk_u * P_R
    EC_POINT *left  = EC_POINT_new(grp);
    EC_POINT *right = EC_POINT_new(grp);
    EC_POINT_mul(grp, left, NULL, pk_u, nR, bnctx);     // n_R * pk_u
    EC_POINT_mul(grp, right, NULL, P_R, sk_u, bnctx);   // sk_u * P_R

    if(EC_POINT_cmp(grp, left, right, bnctx) != 0){
        printf("[Owner] FAIL: session key consistency (nR·pk_u != P_R·sk_u)\n");
        goto cleanup_fail;
    }

    printf("✅ VERIFY/AUDIT PASSED — Session is VALID.\n");
    print_hex("C:     ", C_hash, 32);
    print_hex("C*:    ", Cstar_hash, 32);
    goto cleanup_ok;

cleanup_fail:
    printf("❌ VERIFY/AUDIT FAILED.\n");

cleanup_ok:
    // fallthrough

    /* ---- Free resources ---- */
    EC_POINT_free(P_R);
    EC_POINT_free(sigG); EC_POINT_free(CpkU); EC_POINT_free(lhs);
    EC_POINT_free(left); EC_POINT_free(right);
    BN_free(order); BN_free(nR); BN_free(C); BN_free(Cstar); BN_free(sigma);
    EC_KEY_free(owner); EC_KEY_free(req);
    EC_GROUP_free(grp); BN_CTX_free(bnctx);
    return 0;
}
