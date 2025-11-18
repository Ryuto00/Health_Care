// encrypt_upload.c
// Data Upload Phase (CP-ABE-shaped demo) + timestamp logging (ms with decimals)
// เวอร์ชันนี้จะอ่านไฟล์ทั้งหมดในโฟลเดอร์ "logs/" อัตโนมัติ

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>
#include <time.h>
#include <sys/time.h>
#include <dirent.h>
#include <sys/stat.h>

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>

#define GCM_IV_LEN 12
#define GCM_TAG_LEN 16
#define CHECK(x) do{ if(!(x)){ fprintf(stderr,"[ERR] %s @%s:%d\n",#x,__FILE__,__LINE__); goto fail; } }while(0)

/* ---------- timestamp helper ---------- */
static double now_ms(void){
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (double)tv.tv_sec * 1000.0 + (double)tv.tv_usec / 1000.0;
}

/* อ่านไฟล์ทั้งไฟล์เข้า memory */
static unsigned char* load_file(const char* path, size_t* out_len){
    FILE* f = fopen(path, "rb");
    if(!f){
        perror(path);
        return NULL;
    }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    rewind(f);

    unsigned char* buf = malloc(sz);
    fread(buf, 1, sz, f);
    fclose(f);

    *out_len = sz;
    return buf;
}

static void print_hex(const char*label,const unsigned char*b,size_t l){
    printf("%s",label);
    for(size_t i=0;i<l;i++) printf("%02x",b[i]);
    printf("\n");
}

static void sha256_buf(const unsigned char*in,size_t inl,unsigned char out[32]){
    SHA256(in,inl,out);
}

/* ------------------- parser ------------------- */

typedef enum { T_WORD, T_AND, T_OR, T_LP, T_RP, T_END } Tok;
typedef struct { Tok t; char word[128]; } Token;
typedef struct { const char* s; size_t i,n; } Lexer;

static void skip_ws(Lexer*L){ while(L->i<L->n && isspace((unsigned char)L->s[L->i])) L->i++; }
static Token next_tok(Lexer*L){
    skip_ws(L);
    Token tk={T_END,""};
    if(L->i>=L->n) return tk;
    char c=L->s[L->i];

    if(c=='('){ L->i++; tk.t=T_LP; return tk; }
    if(c==')'){ L->i++; tk.t=T_RP; return tk; }

    if(isalpha((unsigned char)c)){
        size_t j=0;
        while(L->i<L->n &&
             (isalnum((unsigned char)L->s[L->i])||L->s[L->i]=='-'||L->s[L->i]=='_')){
            if(j+1<sizeof(tk.word)) tk.word[j++]=L->s[L->i];
            L->i++;
        }
        tk.word[j]=0;

        if(!strcasecmp(tk.word,"AND")){ tk.t=T_AND; tk.word[0]=0; }
        else if(!strcasecmp(tk.word,"OR")){ tk.t=T_OR; tk.word[0]=0; }
        else tk.t=T_WORD;

        return tk;
    }

    L->i++;
    return tk;
}

typedef struct { char **items; size_t len,cap; } StrList;
static void sl_push(StrList*L,const char*s){
    if(L->len==L->cap){
        L->cap=L->cap?L->cap*2:8;
        L->items=(char**)realloc(L->items,L->cap*sizeof(char*));
    }
    L->items[L->len++] = strdup(s);
}

static unsigned char* cat2(const unsigned char*a,size_t la,const unsigned char*b,size_t lb,size_t*out){
    *out = la + lb;
    unsigned char*m = malloc(*out);
    memcpy(m,a,la);
    memcpy(m+la,b,lb);
    return m;
}

/* AES-GCM */
static int aes_gcm_encrypt(const unsigned char*pt,int ptlen,const unsigned char*key,
                           unsigned char iv[GCM_IV_LEN],unsigned char**out_ct,int*out_ct_len,
                           unsigned char tag[GCM_TAG_LEN]){

    RAND_bytes(iv,GCM_IV_LEN);

    EVP_CIPHER_CTX*ctx = EVP_CIPHER_CTX_new();
    int ok=1,len=0,ctlen=0;
    unsigned char*ct = malloc(ptlen);

    ok &= EVP_EncryptInit_ex(ctx,EVP_aes_256_gcm(),NULL,NULL,NULL);
    ok &= EVP_CIPHER_CTX_ctrl(ctx,EVP_CTRL_GCM_SET_IVLEN,GCM_IV_LEN,NULL);
    ok &= EVP_EncryptInit_ex(ctx,NULL,NULL,key,iv);
    ok &= EVP_EncryptUpdate(ctx,ct,&len,pt,ptlen);
    ctlen=len;
    ok &= EVP_EncryptFinal_ex(ctx,ct+len,&len);
    ctlen+=len;
    ok &= EVP_CIPHER_CTX_ctrl(ctx,EVP_CTRL_GCM_GET_TAG,GCM_TAG_LEN,tag);

    EVP_CIPHER_CTX_free(ctx);
    if(!ok){ free(ct); return 0; }

    *out_ct = ct;
    *out_ct_len = ctlen;
    return 1;
}

static int point_from_scalar_p256(const BIGNUM*s,unsigned char out33[33]){
    int ok=0;

    EC_GROUP*grp = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    EC_POINT*P   = EC_POINT_new(grp);

    if(P && EC_POINT_mul(grp,P,s,NULL,NULL,NULL)){
        size_t L = EC_POINT_point2oct(grp,P,POINT_CONVERSION_COMPRESSED,out33,33,NULL);
        ok = (L == 33);
    }

    EC_POINT_free(P);
    EC_GROUP_free(grp);
    return ok;
}

static void xor32(unsigned char a[32],const unsigned char b[32]){
    for(int i=0;i<32;i++) a[i]^=b[i];
}

static void lowerize(char*s){
    for(;*s;s++) *s = tolower(*s);
}

/* ------------------- MAIN ------------------- */
int main(void){
    double t_global_start = now_ms();

    const char* POLICY  = "(role AND sec-team)";
    const char* LOG_DIR = "logs";

    /* Parse policy */
    Lexer Lx={POLICY,0,strlen(POLICY)};
    Token tk; StrList leafs={0};
    unsigned char*canon=NULL; size_t canon_len=0;

    while((tk=next_tok(&Lx)).t != T_END){
        unsigned char part[140]; size_t pl=0;

        switch(tk.t){
            case T_WORD:{
                char w[128]; strncpy(w,tk.word,sizeof(w));
                lowerize(w);
                sl_push(&leafs,w);
                pl = snprintf((char*)part,sizeof(part),"leaf(%s)",w);
            } break;
            case T_AND: pl = snprintf((char*)part,sizeof(part),"AND"); break;
            case T_OR:  pl = snprintf((char*)part,sizeof(part),"OR"); break;
            case T_LP:  pl = snprintf((char*)part,sizeof(part),"("); break;
            case T_RP:  pl = snprintf((char*)part,sizeof(part),")"); break;
            default: break;
        }

        if(pl){
            size_t nl;
            unsigned char*tmp = cat2(canon,canon_len,part,pl,&nl);
            free(canon);
            canon=tmp; canon_len=nl;
        }
    }

    unsigned char policy_hash[32];
    sha256_buf(canon,canon_len,policy_hash);

    printf("Policy: %s\n", POLICY);
    print_hex("policy_hash: ", policy_hash, 32);

    /* เปิดโฟลเดอร์ logs/ */
    DIR* d = opendir(LOG_DIR);
    if(!d){
        perror(LOG_DIR);
        goto fail;
    }

    mkdir("encrypted", 0755);

    struct dirent* ent;
    while((ent = readdir(d))){
        if(ent->d_type != DT_REG) continue;

        char path[512];
        snprintf(path,sizeof(path),"%s/%s",LOG_DIR,ent->d_name);

        size_t pt_len=0;
        unsigned char* PLAINTEXT = load_file(path,&pt_len);
        if(!PLAINTEXT){
            printf("Skip unreadable file: %s\n", path);
            continue;
        }

        printf("\n=== Encrypting: %s ===\n", ent->d_name);

        double t_start = now_ms();

        unsigned char K[32]; RAND_bytes(K,32);
        unsigned char iv[GCM_IV_LEN], tag[GCM_TAG_LEN];
        unsigned char*ct=NULL; int ctlen=0;

        CHECK(aes_gcm_encrypt(PLAINTEXT, pt_len, K, iv, &ct, &ctlen, tag));

        unsigned char s_bytes[32]; RAND_bytes(s_bytes,32);
        BIGNUM*s = BN_bin2bn(s_bytes,32,NULL);

        unsigned char C1[33];
        CHECK(point_from_scalar_p256(s, C1));

        unsigned char comb[64];
        memcpy(comb, policy_hash, 32);
        memcpy(comb+32, s_bytes, 32);

        unsigned char pair_key[32];
        sha256_buf(comb, 64, pair_key);

        unsigned char C0[32];
        memcpy(C0, K, 32);
        xor32(C0, pair_key);

        /* ===== SAVE .enc FILE ===== */
        char enc_out[512];
        snprintf(enc_out,sizeof(enc_out),"encrypted/%s.enc",ent->d_name);
        FILE *fec = fopen(enc_out,"wb");
        if(fec){
            fwrite(iv, 1, GCM_IV_LEN, fec);
            fwrite(tag,1, GCM_TAG_LEN, fec);
            fwrite(ct, 1, ctlen, fec);
            fclose(fec);
        }

        /* ===== SAVE .meta FILE (ครบทุกฟิลด์) ===== */
        char meta_out[512];
        snprintf(meta_out,sizeof(meta_out),"encrypted/%s.meta",ent->d_name);

        FILE *fm = fopen(meta_out,"w");
        if(fm){
            fprintf(fm, "policy=%s\n", POLICY);

            fprintf(fm, "policy_hash=");
            for(int i=0;i<32;i++) fprintf(fm,"%02x",policy_hash[i]);
            fprintf(fm,"\n");

            fprintf(fm, "s=");
            for(int i=0;i<32;i++) fprintf(fm,"%02x",s_bytes[i]);
            fprintf(fm,"\n");

            fprintf(fm, "C0=");
            for(int i=0;i<32;i++) fprintf(fm,"%02x",C0[i]);
            fprintf(fm,"\n");

            fprintf(fm, "C1=");
            for(int i=0;i<33;i++) fprintf(fm,"%02x",C1[i]);
            fprintf(fm,"\n");

            fclose(fm);
        }

        BN_free(s);
        free(ct);
        free(PLAINTEXT);

        printf("🕒 Time: %.3f ms\n", now_ms() - t_start);
    }

    closedir(d);

    printf("\nALL DONE.\n");
    printf("Total time: %.3f ms\n", now_ms() - t_global_start);
    return 0;

fail:
    printf("[FAIL]\n");
    return 1;
}
