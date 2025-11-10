// encrypt_upload.c
// Data Upload Phase (CP-ABE-shaped demo) + timestamp logging (ms with decimals)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>
#include <time.h>
#include <sys/time.h>   // ✅ สำหรับ timestamp แบบละเอียด
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

static void print_hex(const char*label,const unsigned char*b,size_t l){
    printf("%s",label);
    for(size_t i=0;i<l;i++) printf("%02x",b[i]);
    printf("\n");
}

static void sha256_buf(const unsigned char*in,size_t inl,unsigned char out[32]){
    SHA256(in,inl,out);
}

/* ---------- (ส่วนอื่นๆ เหมือนเดิมทั้งหมด) ---------- */

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
        while(L->i<L->n && (isalnum((unsigned char)L->s[L->i])||L->s[L->i]=='-'||L->s[L->i]=='_')){
            if(j+1<sizeof(tk.word)) tk.word[j++]=L->s[L->i];
            L->i++;
        }
        tk.word[j]=0;
        if(strcasecmp(tk.word,"AND")==0){ tk.t=T_AND; tk.word[0]=0; }
        else if(strcasecmp(tk.word,"OR")==0){ tk.t=T_OR; tk.word[0]=0; }
        else tk.t=T_WORD;
        return tk;
    }
    L->i++;
    return tk;
}

typedef struct { char **items; size_t len,cap; } StrList;
static void sl_push(StrList*L,const char*s){
    if(L->len==L->cap){ L->cap=L->cap?L->cap*2:8; L->items=(char**)realloc(L->items,L->cap*sizeof(char*)); }
    L->items[L->len++]=strdup(s);
}
static unsigned char* cat2(const unsigned char*a,size_t la,const unsigned char*b,size_t lb,size_t*out){
    *out=la+lb; unsigned char*m=(unsigned char*)malloc(*out);
    if(!m) return NULL; memcpy(m,a,la); memcpy(m+la,b,lb); return m;
}
static int aes_gcm_encrypt(const unsigned char*pt,int ptlen,const unsigned char*key,
                           unsigned char iv[GCM_IV_LEN],unsigned char**out_ct,int*out_ct_len,
                           unsigned char tag[GCM_TAG_LEN]){
    if(RAND_bytes(iv,GCM_IV_LEN)!=1) return 0;
    EVP_CIPHER_CTX*ctx=EVP_CIPHER_CTX_new(); if(!ctx) return 0;
    int ok=1,len=0,ctlen=0;
    unsigned char*ct=(unsigned char*)malloc(ptlen); if(!ct){EVP_CIPHER_CTX_free(ctx);return 0;}
    if(!EVP_EncryptInit_ex(ctx,EVP_aes_256_gcm(),NULL,NULL,NULL)) ok=0;
    if(ok && !EVP_CIPHER_CTX_ctrl(ctx,EVP_CTRL_GCM_SET_IVLEN,GCM_IV_LEN,NULL)) ok=0;
    if(ok && !EVP_EncryptInit_ex(ctx,NULL,NULL,key,iv)) ok=0;
    if(ok && !EVP_EncryptUpdate(ctx,ct,&len,pt,ptlen)) ok=0;
    ctlen=len;
    if(ok && !EVP_EncryptFinal_ex(ctx,ct+len,&len)) ok=0;
    ctlen+=len;
    if(ok && !EVP_CIPHER_CTX_ctrl(ctx,EVP_CTRL_GCM_GET_TAG,GCM_TAG_LEN,tag)) ok=0;
    EVP_CIPHER_CTX_free(ctx);
    if(!ok){ free(ct); return 0; }
    *out_ct=ct; *out_ct_len=ctlen; return 1;
}
static int point_from_scalar_p256(const BIGNUM*s,unsigned char out33[33]){
    int ok=0; EC_GROUP*grp=EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    if(!grp) return 0; EC_POINT*P=EC_POINT_new(grp);
    if(P && EC_POINT_mul(grp,P,s,NULL,NULL,NULL)){
        size_t L=EC_POINT_point2oct(grp,P,POINT_CONVERSION_COMPRESSED,out33,33,NULL);
        ok=(L==33);
    }
    if(P) EC_POINT_free(P); EC_GROUP_free(grp); return ok;
}
static void xor32(unsigned char a[32],const unsigned char b[32]){ for(int i=0;i<32;i++) a[i]^=b[i]; }
static void lowerize(char*s){ for(;*s;s++) *s=(char)tolower((unsigned char)*s); }

/* ---------- main ---------- */
int main(int argc,char**argv){
    double t_start = now_ms();   // ✅ เริ่มจับเวลา

    if(argc<4){
        fprintf(stderr,"Usage:\n  %s \"<POLICY>\" \"<attr1,attr2,...>\" \"<PLAINTEXT>\"\n",argv[0]);
        return 1;
    }
    const char*POLICY=argv[1];
    const char*USER_ATTR_CSV=argv[2];
    const char*PLAINTEXT=argv[3];
    (void)USER_ATTR_CSV;

    Lexer L={POLICY,0,strlen(POLICY)};
    Token tk; StrList leafs={0};
    unsigned char*canon=NULL; size_t canon_len=0;
    while((tk=next_tok(&L)).t!=T_END){
        unsigned char piece[140]; size_t pl=0;
        switch(tk.t){
            case T_WORD:{ char w[128]; strncpy(w,tk.word,sizeof(w)); w[sizeof(w)-1]=0; lowerize(w);
                sl_push(&leafs,w);
                pl=(size_t)snprintf((char*)piece,sizeof(piece),"leaf(%s)",w);
            }break;
            case T_AND:pl=(size_t)snprintf((char*)piece,sizeof(piece),"AND");break;
            case T_OR:pl=(size_t)snprintf((char*)piece,sizeof(piece),"OR");break;
            case T_LP:pl=(size_t)snprintf((char*)piece,sizeof(piece),"(");break;
            case T_RP:pl=(size_t)snprintf((char*)piece,sizeof(piece),")");break;
            default:break;
        }
        if(pl){ size_t nl; unsigned char*tmp=cat2(canon,canon_len,piece,pl,&nl);
            if(canon) free(canon); canon=tmp; canon_len=nl;
        }
    }
    if(!canon){ canon=(unsigned char*)strdup(""); canon_len=0; }

    unsigned char policy_hash[32]; sha256_buf(canon,canon_len,policy_hash);

    unsigned char K[32]; CHECK(RAND_bytes(K,32)==1);
    unsigned char iv[GCM_IV_LEN],tag[GCM_TAG_LEN];
    unsigned char*ct=NULL; int ctlen=0;
    CHECK(aes_gcm_encrypt((const unsigned char*)PLAINTEXT,(int)strlen(PLAINTEXT),
                          K,iv,&ct,&ctlen,tag));

    unsigned char s_bytes[32]; CHECK(RAND_bytes(s_bytes,32)==1);
    BIGNUM*s=BN_bin2bn(s_bytes,32,NULL); CHECK(s);
    unsigned char C1[33]; CHECK(point_from_scalar_p256(s,C1));

    unsigned char comb[64]; memcpy(comb,policy_hash,32); memcpy(comb+32,s_bytes,32);
    unsigned char pair_key[32]; sha256_buf(comb,64,pair_key);

    unsigned char C0[32]; memcpy(C0,K,32); xor32(C0,pair_key);

    unsigned char(*Ci)[32]=NULL; unsigned char(*Di)[32]=NULL;
    if(leafs.len){
        Ci=(unsigned char(*)[32])calloc(leafs.len,32);
        Di=(unsigned char(*)[32])calloc(leafs.len,32);
        CHECK(Ci&&Di);
        for(size_t i=0;i<leafs.len;i++){
            const char*ai=leafs.items[i];
            unsigned char buf[4+128+32]; size_t bl=0;
            bl+=(size_t)sprintf((char*)buf+bl,"Ci|%s",ai); memcpy(buf+bl,s_bytes,32); bl+=32;
            sha256_buf(buf,bl,Ci[i]);
            bl=(size_t)sprintf((char*)buf,"Di|%s",ai); memcpy(buf+strlen((char*)buf),s_bytes,32);
            sha256_buf(buf,strlen((char*)buf)+32,Di[i]);
        }
    }

    printf("=== Data Upload Phase (demo) ===\n");
    printf("Policy: %s\nLeaves: ",POLICY);
    for(size_t i=0;i<leafs.len;i++) printf("%s%s",leafs.items[i],(i+1<leafs.len)?", ":"");
    printf("\n");
    print_hex("policy_hash: ",policy_hash,32);
    print_hex("AES.K (demo)    : ",K,32);
    print_hex("AES.iv          : ",iv,GCM_IV_LEN);
    print_hex("AES.tag         : ",tag,GCM_TAG_LEN);
    printf("pt.len=%zu, ct.len=%d\n",strlen(PLAINTEXT),ctlen);
    printf("AES.ct (hex) : ");
    for(int i=0; i<ctlen; i++) printf("%02x", ct[i]);
    printf("\n");
    // หลังจาก RAND_bytes(s_bytes,32)
    printf("s_hex: ");
    for (int i = 0; i < 32; i++) printf("%02x", s_bytes[i]);
    printf("\n");
    print_hex("C0 (K XOR H(policy||s)): ",C0,32);
    print_hex("C1 = g^s (33B)  : ",C1,33);

    for(size_t i=0;i<leafs.len;i++){
        char lbl[64];
        snprintf(lbl,sizeof(lbl),"Ci[%s]: ",leafs.items[i]);
        print_hex(lbl,Ci[i],32);
        snprintf(lbl,sizeof(lbl),"Di[%s]: ",leafs.items[i]);
        print_hex(lbl,Di[i],32);
    }

    double t_end = now_ms();                        // ✅ จับเวลาจบ
    double total = t_end - t_start;
    printf("🕒 Total execution time: %.3f ms\n", total);  // ✅ แสดงผลทศนิยม 3 หลัก

    BN_free(s);
    for(size_t i=0;i<leafs.len;i++) free(leafs.items[i]);
    free(leafs.items); free(canon);
    if(Ci) free(Ci); if(Di) free(Di); free(ct);
    return 0;

fail:
    fprintf(stderr,"[FAIL] Data Upload demo failed.\n");
    return 1;
}
