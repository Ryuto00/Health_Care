// decrypt_access.c
// Phase: Decrypt / Access (paper Section F) — standalone demo
// - Evaluate boolean policy against requester attributes
// - Assume s is reconstructed via Shamir (given as s_hex)
// - Rebuild K = C0 XOR H(policy_hash || s), AES-256-GCM decrypt
// - Print timestamps with decimals (ms)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/time.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#define GCM_IV_LEN 12
#define GCM_TAG_LEN 16

#define CHECK(x) do{ if(!(x)){ fprintf(stderr,"[ERR] %s @%s:%d\n",#x,__FILE__,__LINE__); goto fail; } }while(0)

static double now_ms(void){
    struct timeval tv; gettimeofday(&tv, NULL);
    return (double)tv.tv_sec*1000.0 + (double)tv.tv_usec/1000.0;
}

static void print_hex(const char*label,const unsigned char*buf,size_t len){
    printf("%s",label);
    for(size_t i=0;i<len;i++) printf("%02x", buf[i]);
    printf("\n");
}

static int hex2bin(const char*hex, unsigned char**out, size_t*outlen){
    size_t n = strlen(hex);
    if(n%2) return 0;
    unsigned char* b = (unsigned char*)malloc(n/2);
    if(!b) return 0;
    for(size_t i=0;i<n;i+=2){
        unsigned int v;
        if(sscanf(hex+i, "%2x", &v)!=1){ free(b); return 0; }
        b[i/2] = (unsigned char)v;
    }
    *out=b; *outlen=n/2; return 1;
}
static int hex2fixed32(const char*hex, unsigned char out[32]){
    unsigned char* tmp; size_t L;
    if(!hex2bin(hex,&tmp,&L)) return 0;
    if(L!=32){ free(tmp); return 0; }
    memcpy(out,tmp,32); free(tmp); return 1;
}
static int hex2fixed(const char*hex, unsigned char*out, size_t need){
    unsigned char* tmp; size_t L;
    if(!hex2bin(hex,&tmp,&L)) return 0;
    if(L!=need){ free(tmp); return 0; }
    memcpy(out,tmp,need); free(tmp); return 1;
}

static void sha256_buf(const unsigned char*in,size_t inl,unsigned char out32[32]){
    SHA256(in,inl,out32);
}

static void lowerize(char*s){ for(;*s;s++) *s=(char)tolower((unsigned char)*s); }

/* ===== Tiny boolean policy parser/evaluator (AND / OR / parentheses) ===== */
typedef enum { T_WORD, T_AND, T_OR, T_LP, T_RP, T_END } Tok;
typedef struct { Tok t; char word[128]; } Token;
typedef struct { const char* s; size_t i, n; } Lexer;

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
    L->i++; // skip unknown
    return tk;
}

/* AST */
typedef enum { N_ATTR, N_AND, N_OR } NodeType;
typedef struct Node {
    NodeType type;
    char attr[128];            // when N_ATTR
    struct Node* left;         // when AND/OR
    struct Node* right;
} Node;

static Node* new_leaf(const char*name){
    Node* n=(Node*)calloc(1,sizeof(Node));
    n->type=N_ATTR; strncpy(n->attr,name,sizeof(n->attr)-1); lowerize(n->attr); return n;
}
static Node* new_node(NodeType t, Node*L, Node*R){
    Node* n=(Node*)calloc(1,sizeof(Node)); n->type=t; n->left=L; n->right=R; return n;
}

/* recursive descent:
   expr := term { OR term }
   term := factor { AND factor }
   factor := WORD | '(' expr ')'
*/
static Token lookahead;
static Lexer lex;

static void next(){ lookahead = next_tok(&lex); }

static Node* parse_expr(); // fwd
static Node* parse_factor(){
    if(lookahead.t==T_WORD){
        Node* n = new_leaf(lookahead.word); next(); return n;
    }else if(lookahead.t==T_LP){
        next();
        Node* e = parse_expr();
        if(lookahead.t!=T_RP){ /* unmatched - tolerate */ }
        else next();
        return e;
    }
    return NULL;
}
static Node* parse_term(){
    Node* L = parse_factor();
    while(lookahead.t==T_AND){
        next();
        Node* R = parse_factor();
        L = new_node(N_AND, L, R);
    }
    return L;
}
static Node* parse_expr(){
    Node* L = parse_term();
    while(lookahead.t==T_OR){
        next();
        Node* R = parse_term();
        L = new_node(N_OR, L, R);
    }
    return L;
}
static void free_ast(Node*n){
    if(!n) return;
    free_ast(n->left); free_ast(n->right); free(n);
}

/* attribute set */
typedef struct { char** items; size_t len; } StrList;
static int has_attr(const StrList*S, const char* a){
    for(size_t i=0;i<S->len;i++) if(strcmp(S->items[i],a)==0) return 1;
    return 0;
}
static int eval(Node*n, const StrList*S){
    if(!n) return 0;
    if(n->type==N_ATTR) return has_attr(S,n->attr);
    if(n->type==N_AND)  return eval(n->left,S) && eval(n->right,S);
    if(n->type==N_OR)   return eval(n->left,S) || eval(n->right,S);
    return 0;
}

/* Build canonical policy bytes (same style as encrypt side) */
static unsigned char* cat2(const unsigned char*a,size_t la,const unsigned char*b,size_t lb,size_t*out){
    *out=la+lb; unsigned char*m=(unsigned char*)malloc(*out);
    if(!m) return NULL; memcpy(m,a,la); memcpy(m+la,b,lb); return m;
}
static void append_piece(unsigned char**canon,size_t*len,const char*txt){
    size_t pl=strlen(txt); size_t nl; unsigned char* tmp = cat2(*canon,*len,(const unsigned char*)txt,pl,&nl);
    if(*canon) free(*canon); *canon=tmp; *len=nl;
}
static void canonicalize_policy(const char*POLICY, unsigned char**out, size_t*outlen){
    Lexer L={POLICY,0,strlen(POLICY)}; Token tk; *out=NULL; *outlen=0;
    while((tk=next_tok(&L)).t!=T_END){
        if(tk.t==T_WORD){ char w[128]; strncpy(w,tk.word,sizeof(w)-1); w[sizeof(w)-1]=0; lowerize(w);
            char buf[160]; snprintf(buf,sizeof(buf),"leaf(%s)",w); append_piece(out,outlen,buf); }
        else if(tk.t==T_AND) append_piece(out,outlen,"AND");
        else if(tk.t==T_OR)  append_piece(out,outlen,"OR");
        else if(tk.t==T_LP)  append_piece(out,outlen,"(");
        else if(tk.t==T_RP)  append_piece(out,outlen,")");
    }
    if(!*out){ *out=(unsigned char*)strdup(""); *outlen=0; }
}

/* AES-256-GCM Decrypt */
static int aes_gcm_decrypt(const unsigned char*ct,int ctlen,
                           const unsigned char*key,
                           const unsigned char iv[GCM_IV_LEN],
                           const unsigned char tag[GCM_TAG_LEN],
                           unsigned char**out_pt,int*out_pt_len){
    EVP_CIPHER_CTX*ctx=EVP_CIPHER_CTX_new(); if(!ctx) return 0;
    int ok=1,len=0, ptlen=0;
    unsigned char* pt=(unsigned char*)malloc(ctlen+1); if(!pt){ EVP_CIPHER_CTX_free(ctx); return 0; }
    if(!EVP_DecryptInit_ex(ctx,EVP_aes_256_gcm(),NULL,NULL,NULL)) ok=0;
    if(ok && !EVP_CIPHER_CTX_ctrl(ctx,EVP_CTRL_GCM_SET_IVLEN,GCM_IV_LEN,NULL)) ok=0;
    if(ok && !EVP_DecryptInit_ex(ctx,NULL,NULL,key,iv)) ok=0;
    if(ok && !EVP_DecryptUpdate(ctx,pt,&len,ct,ctlen)) ok=0;
    ptlen = len;
    if(ok && !EVP_CIPHER_CTX_ctrl(ctx,EVP_CTRL_GCM_SET_TAG,GCM_TAG_LEN,(void*)tag)) ok=0;
    if(ok && !EVP_DecryptFinal_ex(ctx,pt+len,&len)) ok=0;
    ptlen += len;
    EVP_CIPHER_CTX_free(ctx);
    if(!ok){ free(pt); return 0; }
    pt[ptlen]=0;
    *out_pt=pt; *out_pt_len=ptlen; return 1;
}

int main(int argc, char**argv){
    if(argc<8){
        fprintf(stderr,
        "Usage:\n  %s \"<POLICY>\" \"<attr1,attr2,...>\" <s_hex> <iv_hex> <tag_hex> <ct_hex> <C0_hex>\n", argv[0]);
        return 1;
    }
    const char* POLICY = argv[1];
    const char* ATTRCSV= argv[2];
    const char* S_HEX  = argv[3];
    const char* IV_HEX = argv[4];
    const char* TAG_HEX= argv[5];
    const char* CT_HEX = argv[6];
    const char* C0_HEX = argv[7];

    /* ---- Parse attributes ---- */
    StrList A={0};
    {
        char* tmp=strdup(ATTRCSV);
        for(char* p=strtok(tmp,","); p; p=strtok(NULL,",")){
            while(*p==' ') ++p;
            for(char* q=p; *q; ++q) *q=(char)tolower((unsigned char)*q);
            A.items=(char**)realloc(A.items,(A.len+1)*sizeof(char*));
            A.items[A.len++]=strdup(p);
        }
        free(tmp);
    }

    /* ---- Build AST for policy & evaluate ---- */
    lex.s=POLICY; lex.i=0; lex.n=strlen(POLICY); next();
    Node* root = parse_expr();
    int ok_attr = eval(root,&A);

    /* ---- Canonical policy hash (must match encrypt side) ---- */
    unsigned char* canon=NULL; size_t canon_len=0;
    canonicalize_policy(POLICY,&canon,&canon_len);
    unsigned char policy_hash[32]; sha256_buf(canon,canon_len,policy_hash);

    /* ---- Decode inputs ---- */
    unsigned char s[32], iv[GCM_IV_LEN], tag[GCM_TAG_LEN];
    unsigned char* ct=NULL; size_t ctlen=0;
    unsigned char C0[32];
    CHECK(hex2fixed32(S_HEX,s));
    CHECK(hex2fixed(IV_HEX,iv,GCM_IV_LEN));
    CHECK(hex2fixed(TAG_HEX,tag,GCM_TAG_LEN));
    CHECK(hex2bin(CT_HEX,&ct,&ctlen));
    CHECK(hex2fixed32(C0_HEX,C0));

    /* ---- If policy not satisfied, deny ---- */
    if(!ok_attr){
        printf("❌ ACCESS DENIED: attributes do not satisfy policy.\n");
        goto fail;
    }

    /* ---- Rebuild K = C0 XOR H(policy_hash || s) ---- */
    double t0 = now_ms();
    unsigned char comb[64]; memcpy(comb,policy_hash,32); memcpy(comb+32,s,32);
    unsigned char pair_key[32]; sha256_buf(comb,64,pair_key);
    unsigned char K[32]; for(int i=0;i<32;i++) K[i] = C0[i] ^ pair_key[i];
    double tK = now_ms();

    /* ---- Decrypt AES-256-GCM ---- */
    unsigned char* pt=NULL; int ptlen=0;
    double t1 = now_ms();
    CHECK(aes_gcm_decrypt(ct,(int)ctlen,K,iv,tag,&pt,&ptlen));
    double t2 = now_ms();

    /* ---- Output ---- */
    printf("=== Decrypt / Access Phase (demo) ===\n");
    printf("Policy: %s\n", POLICY);
    printf("Attributes: %s\n", ATTRCSV);
    print_hex("policy_hash: ", policy_hash, 32);

    print_hex("s (reconstructed): ", s, 32);
    print_hex("C0: ", C0, 32);
    print_hex("K (derived): ", K, 32);

    printf("⏱  Key-derive time: %.3f ms\n", (tK - t0));
    printf("⏱  AES-GCM decrypt time: %.3f ms\n", (t2 - t1));
    printf("⏱  Total time: %.3f ms\n", (t2 - t0));

    printf("\nPlaintext (%d bytes):\n", ptlen);
    fwrite(pt,1,ptlen,stdout); printf("\n");

    /* cleanup */
    free(pt); free(ct); free(canon);
    for(size_t i=0;i<A.len;i++) free(A.items[i]); free(A.items);
    free_ast(root);
    return 0;

fail:
    if(ct) free(ct);
    if(canon) free(canon);
    for(size_t i=0;i<A.len;i++) free(A.items[i]); free(A.items);
    free_ast(root);
    return 1;
}
