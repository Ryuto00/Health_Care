// decrypt_access.c
// Phase: Decrypt / Access (folder mode) + per-file timing + global summary + log counting

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <dirent.h>
#include <sys/time.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#define GCM_IV_LEN 12
#define GCM_TAG_LEN 16

/* ===== Helpers ===== */
static double now_ms(void){
    struct timeval tv; gettimeofday(&tv,NULL);
    return (double)tv.tv_sec*1000.0 + (double)tv.tv_usec/1000.0;
}

static void print_hex(const char*label,const unsigned char*buf,size_t len){
    printf("%s",label);
    for(size_t i=0;i<len;i++) printf("%02x", buf[i]);
    printf("\n");
}

/* Count logs inside JSON array */
static int count_logs(const unsigned char *pt, int ptlen){
    int count = 0;
    for(int i=0;i<ptlen;i++)
        if(pt[i]=='{') count++;
    return count;
}

/* ===== hex2bin ===== */
static int hex2bin(const char*hex,unsigned char**out,size_t*outlen){
    size_t n=strlen(hex);
    if(n%2) return 0;
    unsigned char*b=malloc(n/2);
    if(!b) return 0;
    for(size_t i=0;i<n;i+=2){
        unsigned int v;
        if(sscanf(hex+i,"%2x",&v)!=1){
            free(b);
            return 0;
        }
        b[i/2]=(unsigned char)v;
    }
    *out=b; *outlen=n/2;
    return 1;
}
static int hex2fixed32(const char*hex,unsigned char out[32]){
    unsigned char*tmp; size_t L;
    if(!hex2bin(hex,&tmp,&L)) return 0;
    if(L!=32){ free(tmp); return 0; }
    memcpy(out,tmp,32); free(tmp);
    return 1;
}

static void sha256_buf(const unsigned char*in,size_t inl,unsigned char out[32]){
    SHA256(in,inl,out);
}
static void lowerize(char*s){ for(;*s;s++) *s=(char)tolower((unsigned char)*s); }

/* ===== Boolean Policy Parser ===== */
typedef enum { T_WORD,T_AND,T_OR,T_LP,T_RP,T_END } Tok;
typedef struct { Tok t; char word[128]; } Token;
typedef struct { const char*s; size_t i,n; } Lexer;

static Lexer lex;
static Token lookahead;

static void skip_ws(Lexer*L){
    while(L->i<L->n && isspace((unsigned char)L->s[L->i])) L->i++;
}
static Token next_tok(Lexer*L){
    skip_ws(L); Token tk={T_END,""};
    if(L->i>=L->n) return tk;
    char c=L->s[L->i];

    if(c=='('){ L->i++; tk.t=T_LP; return tk; }
    if(c==')'){ L->i++; tk.t=T_RP; return tk; }

    if(isalpha((unsigned char)c)){
        size_t j=0;
        while(L->i<L->n &&
              (isalnum((unsigned char)L->s[L->i])||L->s[L->i]=='-'||L->s[L->i]=='_'))
        {
            if(j+1<sizeof(tk.word)) tk.word[j++]=L->s[L->i];
            L->i++;
        }
        tk.word[j]=0;
        if(strcasecmp(tk.word,"AND")==0){ tk.t=T_AND; tk.word[0]=0; }
        else if(strcasecmp(tk.word,"OR")==0){ tk.t=T_OR; tk.word[0]=0; }
        else tk.t=T_WORD;
        return tk;
    }
    L->i++; return tk;
}
static void next(){ lookahead=next_tok(&lex); }

/* AST */
typedef enum { N_ATTR,N_AND,N_OR } NodeType;
typedef struct Node {
    NodeType type;
    char attr[128];
    struct Node*L;
    struct Node*R;
} Node;

static Node* new_leaf(const char*name){
    Node*n=calloc(1,sizeof(Node));
    n->type=N_ATTR; strncpy(n->attr,name,sizeof(n->attr)-1);
    lowerize(n->attr); return n;
}
static Node* new_node(NodeType t,Node*L,Node*R){
    Node*n=calloc(1,sizeof(Node)); n->type=t; n->L=L; n->R=R; return n;
}

static Node* parse_expr(); 
static Node* parse_factor(){
    if(lookahead.t==T_WORD){
        Node*n=new_leaf(lookahead.word); next(); return n;
    }
    if(lookahead.t==T_LP){
        next(); Node*e=parse_expr(); if(lookahead.t==T_RP) next(); return e;
    }
    return NULL;
}
static Node* parse_term(){
    Node*L=parse_factor();
    while(lookahead.t==T_AND){ next(); L=new_node(N_AND,L,parse_factor()); }
    return L;
}
static Node* parse_expr(){
    Node*L=parse_term();
    while(lookahead.t==T_OR){ next(); L=new_node(N_OR,L,parse_term()); }
    return L;
}
static void free_ast(Node*n){
    if(!n) return; free_ast(n->L); free_ast(n->R); free(n);
}

typedef struct { char**items; size_t len; } StrList;
static int has_attr(const StrList*S,const char*a){
    for(size_t i=0;i<S->len;i++)
        if(strcmp(S->items[i],a)==0) return 1;
    return 0;
}
static int eval(Node*n,const StrList*S){
    if(!n) return 0;
    if(n->type==N_ATTR) return has_attr(S,n->attr);
    if(n->type==N_AND)  return eval(n->L,S)&&eval(n->R,S);
    if(n->type==N_OR)   return eval(n->L,S)||eval(n->R,S);
    return 0;
}

/* canonical policy */
static unsigned char* cat2(const unsigned char*a,size_t la,
                           const unsigned char*b,size_t lb,size_t*out)
{
    *out=la+lb;
    unsigned char*m=malloc(*out);
    memcpy(m,a,la); memcpy(m+la,b,lb);
    return m;
}
static void append_piece(unsigned char**canon,size_t*len,const char*txt){
    size_t pl=strlen(txt),nl;
    unsigned char*tmp=cat2(*canon,*len,(unsigned char*)txt,pl,&nl);
    if(*canon) free(*canon);
    *canon=tmp; *len=nl;
}
static void canonicalize_policy(const char*POLICY,unsigned char**out,size_t*outlen){
    Lexer L={POLICY,0,strlen(POLICY)}; Token tk; *out=NULL; *outlen=0;
    while((tk=next_tok(&L)).t!=T_END){
        if(tk.t==T_WORD){
            char w[128]; strncpy(w,tk.word,sizeof(w)-1); w[sizeof(w)-1]=0; lowerize(w);
            char buf[160]; snprintf(buf,sizeof(buf),"leaf(%s)",w);
            append_piece(out,outlen,buf);
        }
        else if(tk.t==T_AND) append_piece(out,outlen,"AND");
        else if(tk.t==T_OR)  append_piece(out,outlen,"OR");
        else if(tk.t==T_LP)  append_piece(out,outlen,"(");
        else if(tk.t==T_RP)  append_piece(out,outlen,")");
    }
    if(!*out){ *out=(unsigned char*)strdup(""); *outlen=0; }
}

/* AES-GCM decrypt */
static int aes_gcm_decrypt(const unsigned char*ct,int ctlen,
                           const unsigned char*key,
                           const unsigned char iv[GCM_IV_LEN],
                           const unsigned char tag[GCM_TAG_LEN],
                           unsigned char**pt,int*outlen)
{
    EVP_CIPHER_CTX*ctx=EVP_CIPHER_CTX_new();
    int ok=1,len=0,plen=0;
    unsigned char*p=malloc(ctlen+1);

    ok &= EVP_DecryptInit_ex(ctx,EVP_aes_256_gcm(),NULL,NULL,NULL);
    ok &= EVP_CIPHER_CTX_ctrl(ctx,EVP_CTRL_GCM_SET_IVLEN,GCM_IV_LEN,NULL);
    ok &= EVP_DecryptInit_ex(ctx,NULL,NULL,key,iv);
    ok &= EVP_DecryptUpdate(ctx,p,&len,ct,ctlen);
    plen=len;
    ok &= EVP_CIPHER_CTX_ctrl(ctx,EVP_CTRL_GCM_SET_TAG,GCM_TAG_LEN,(void*)tag);
    ok &= EVP_DecryptFinal_ex(ctx,p+plen,&len);
    plen+=len;

    EVP_CIPHER_CTX_free(ctx);
    if(!ok){ free(p); return 0; }

    p[plen]=0;
    *pt=p; *outlen=plen;
    return 1;
}

/* load meta */
static char* load_meta_value(const char*path,const char*key){
    FILE*f=fopen(path,"r"); if(!f) return NULL;
    char line[512]; size_t klen=strlen(key);
    while(fgets(line,sizeof(line),f)){
        if(strncmp(line,key,klen)==0 && line[klen]=='='){
            char*v=strdup(line+klen+1);
            v[strcspn(v,"\r\n")]=0;
            fclose(f); return v;
        }
    }
    fclose(f); return NULL;
}

/* ================= MAIN ================= */
int main(int argc,char**argv){
    if(argc<2){
        printf("Usage: %s \"role,sec-team,...\"\n",argv[0]);
        return 1;
    }
    const char*ATTRCSV=argv[1];
    const char*DIRNAME="encrypted";

    /* parse attributes */
    StrList A={0};
    {
        char*tmp=strdup(ATTRCSV);
        for(char*p=strtok(tmp,",");p;p=strtok(NULL,",")){
            while(*p==' ') ++p;
            for(char*q=p;*q;q++) *q=(char)tolower((unsigned char)*q);
            A.items=realloc(A.items,(A.len+1)*sizeof(char*));
            A.items[A.len++]=strdup(p);
        }
        free(tmp);
    }

    printf("Requester attributes: %s\n",ATTRCSV);

    DIR*d=opendir(DIRNAME);
    if(!d){ perror(DIRNAME); return 1; }

    /* global summary */
    double global_start=now_ms();
    double total_time=0.0;
    int total_files=0;
    int total_logs=0;

    /* loop files */
    struct dirent*ent;
    while((ent=readdir(d))){
        if(ent->d_type!=DT_REG) continue;
        const char*name=ent->d_name;
        size_t L=strlen(name);
        if(L<5) continue;
        if(strcmp(name+(L-4),".enc")!=0) continue;

        /* build paths */
        char prefix[256];
        strncpy(prefix,name,L-4); prefix[L-4]=0;

        char enc_path[512],meta_path[512];
        snprintf(enc_path,sizeof(enc_path),"%s/%s",DIRNAME,name);
        snprintf(meta_path,sizeof(meta_path),"%s/%s.meta",DIRNAME,prefix);

        printf("\n=== Decrypt file: %s ===\n",prefix);

        /* load meta */
        char*policy = load_meta_value(meta_path,"policy");
        char*s_hex  = load_meta_value(meta_path,"s");
        char*C0_hex = load_meta_value(meta_path,"C0");
        char*ph_hex = load_meta_value(meta_path,"policy_hash");

        if(!policy||!s_hex||!C0_hex||!ph_hex){
            printf("[WARN] meta incomplete\n");
            goto next_file;
        }

        /* check policy */
        lex.s=policy; lex.i=0; lex.n=strlen(policy); next();
        Node*root=parse_expr();
        if(!eval(root,&A)){
            printf("❌ ACCESS DENIED\n");
            free_ast(root); goto next_file;
        }
        printf("✅ Attributes satisfy policy.\n");

        /* canonical hash */
        unsigned char*canon=NULL; size_t clen=0;
        canonicalize_policy(policy,&canon,&clen);
        unsigned char policy_hash[32]; sha256_buf(canon,clen,policy_hash);

        /* decode s, C0 */
        unsigned char s[32],C0[32];
        if(!hex2fixed32(s_hex,s)||!hex2fixed32(C0_hex,C0)){
            printf("[ERR] meta decode failed\n");
            free(canon); free_ast(root); goto next_file;
        }

        /* read encrypted */
        FILE*fe=fopen(enc_path,"rb");
        if(!fe){ perror(enc_path); free(canon); free_ast(root); goto next_file; }
        unsigned char iv[GCM_IV_LEN],tag[GCM_TAG_LEN];
        fread(iv,1,GCM_IV_LEN,fe);
        fread(tag,1,GCM_TAG_LEN,fe);
        fseek(fe,0,SEEK_END);
        long fsize=ftell(fe);
        long ctlen=fsize-(GCM_IV_LEN+GCM_TAG_LEN);
        fseek(fe,GCM_IV_LEN+GCM_TAG_LEN,SEEK_SET);

        unsigned char*ct=malloc(ctlen);
        fread(ct,1,ctlen,fe);
        fclose(fe);

        /* rebuild K */
        unsigned char comb[64];
        memcpy(comb,policy_hash,32);
        memcpy(comb+32,s,32);

        unsigned char pair_key[32]; sha256_buf(comb,64,pair_key);
        unsigned char K[32];
        for(int i=0;i<32;i++) K[i]=C0[i]^pair_key[i];

        /* decrypt */
        double t0=now_ms();
        unsigned char*pt=NULL; int ptlen=0;
        if(!aes_gcm_decrypt(ct,ctlen,K,iv,tag,&pt,&ptlen)){
            printf("❌ decrypt failed\n");
            free(ct); free(canon); free_ast(root); free(pt);
            goto next_file;
        }
        double t1=now_ms();

        printf("⏱  Total time: %.3f ms\n",t1-t0);

        total_files++;
        total_time+=(t1-t0);

        /* print plaintext */
        printf("Plaintext (%d bytes):\n",ptlen);
        fwrite(pt,1,ptlen,stdout);
        printf("\n");

        /* ===== Count logs ===== */
        int logs_in_file = count_logs(pt, ptlen);
        printf("Logs in this file: %d\n", logs_in_file);
        total_logs += logs_in_file;

        free(pt);
        free(ct);
        free(canon);
        free_ast(root);

    next_file:
        if(policy) free(policy);
        if(s_hex) free(s_hex);
        if(C0_hex) free(C0_hex);
        if(ph_hex) free(ph_hex);
    }

    closedir(d);

    /* ===== SUMMARY ===== */
    double global_end=now_ms();
    printf("\n===== SUMMARY =====\n");
    printf("Files processed: %d\n", total_files);
    printf("Total logs decrypted: %d\n", total_logs);
    if(total_files>0)
        printf("Avg logs per file: %.2f\n", (double)total_logs / total_files);
    printf("Total decrypt time: %.3f ms\n", total_time);
    if(total_files>0)
        printf("Avg time per file: %.3f ms\n", total_time/total_files);
    printf("===================\n");

    for(size_t i=0;i<A.len;i++) free(A.items[i]);
    free(A.items);
    return 0;
}
