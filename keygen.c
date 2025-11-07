#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>

static void print_hex(const char *label, const unsigned char *buf, size_t len) {
    printf("%s", label);
    for (size_t i = 0; i < len; i++) printf("%02x", buf[i]);
    printf("\n");
}

static void xor_buf(unsigned char *out, const unsigned char *a, const unsigned char *b, size_t len) {
    for (size_t i = 0; i < len; i++) out[i] = a[i] ^ b[i];
}

static void sha256_hash(const unsigned char *data, size_t len, unsigned char out[32]) {
    SHA256(data, len, out);
}

static unsigned char* concat(const unsigned char *a, size_t la,
                             const unsigned char *b, size_t lb,
                             size_t *out_len) {
    *out_len = la + lb;
    unsigned char *buf = malloc(*out_len);
    memcpy(buf, a, la);
    memcpy(buf + la, b, lb);
    return buf;
}

int main(void) {
    clock_t t_start, t_end;
    double t_keygen, t_hash;

    const char *IDu = "doctor.alice@hospital.example";
    const char *Pu  = "S3curePa$$w0rd!";

    // ---------- Key Generation ----------
    t_start = clock();
    EC_KEY *eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    EC_KEY_generate_key(eckey);
    t_end = clock();
    t_keygen = ((double)(t_end - t_start) / CLOCKS_PER_SEC) * 1000.0;

    const BIGNUM *sk = EC_KEY_get0_private_key(eckey);
    const EC_POINT *pk = EC_KEY_get0_public_key(eckey);
    const EC_GROUP *grp = EC_KEY_get0_group(eckey);

    int priv_len = BN_num_bytes(sk);
    unsigned char *priv = malloc(priv_len);
    BN_bn2bin(sk, priv);

    int pub_len = EC_POINT_point2oct(grp, pk, POINT_CONVERSION_COMPRESSED, NULL, 0, NULL);
    unsigned char *pub = malloc(pub_len);
    EC_POINT_point2oct(grp, pk, POINT_CONVERSION_COMPRESSED, pub, pub_len, NULL);

    // ---------- Hash / Verification ----------
    unsigned char n1[32], n2[32];
    RAND_bytes(n1, 32);
    RAND_bytes(n2, 32);

    t_start = clock();
    unsigned char P_u[32], Ver_u1[32], Ver_u2[32], Ver_u3[32];
    size_t len1, len2;

    // P_u = H(ID_u || P_u || n1)
    size_t l_id = strlen(IDu), l_pw = strlen(Pu), l_tmp;
    unsigned char *id_pw = concat((unsigned char*)IDu, l_id, (unsigned char*)Pu, l_pw, &l_tmp);
    unsigned char *id_pw_n1 = concat(id_pw, l_tmp, n1, 32, &len1);
    sha256_hash(id_pw_n1, len1, P_u);

    // Ver_u1 = H(ID_u || P_u) XOR n1
    unsigned char H_id_pw[32];
    sha256_hash(id_pw, l_tmp, H_id_pw);
    xor_buf(Ver_u1, H_id_pw, n1, 32);

    // Ver_u2 = H(P_u || n1) XOR n2
    unsigned char *pw_n1 = concat((unsigned char*)Pu, l_pw, n1, 32, &len2);
    unsigned char H_pw_n1[32];
    sha256_hash(pw_n1, len2, H_pw_n1);
    xor_buf(Ver_u2, H_pw_n1, n2, 32);

    // Ver_u3 = H(ID_u || P_u || n1 || n2)
    size_t len_all = l_id + l_pw + 64;
    unsigned char *concat_all = malloc(len_all);
    memcpy(concat_all, IDu, l_id);
    memcpy(concat_all + l_id, Pu, l_pw);
    memcpy(concat_all + l_id + l_pw, n1, 32);
    memcpy(concat_all + l_id + l_pw + 32, n2, 32);
    sha256_hash(concat_all, len_all, Ver_u3);
    t_end = clock();
    t_hash = ((double)(t_end - t_start) / CLOCKS_PER_SEC) * 1000.0;

    // ---------- Results ----------
    printf("\n=== Setup / KeyGen Benchmark ===\n");
    printf("Key Generation time:    %.3f ms\n", t_keygen);
    printf("Hash+Verification time: %.3f ms\n", t_hash);
    printf("Total Setup Phase:      %.3f ms\n", t_keygen + t_hash);

    // optional: print key and verification values
    print_hex("pk_u: ", pub, pub_len);
    print_hex("Ver_u3: ", Ver_u3, 32);

    // cleanup
    free(priv); free(pub); free(id_pw); free(id_pw_n1); free(pw_n1); free(concat_all);
    EC_KEY_free(eckey);
    return 0;
}
