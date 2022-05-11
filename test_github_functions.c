#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "nuclei_sdk_soc.h"
#include <xoodyak/base.h>
#include <sparkle/test_sparkle_github.h>
#include <sparkle/base.h>
#include <Ascon-128/base.h>
#include <Ascon-128/Permutation/ascon.h>
#include <tiny/base.h>

typedef unsigned char UChar;
typedef unsigned long long ULLInt;

#define SCHWAEMM_KEY_BYTES      16
#define SCHWAEMM_NONCE_BYTES    32
#define SCHWAEMM_TAG_BYTES      16

#define MAX_AD_LEN  256
#define MAX_MSG_LEN 256


#define KAT_SUCCESS 0
#define KAT_FILE_OPEN_ERROR -1
#define KAT_DATA_ERROR -3
#define KAT_CRYPTO_FAILURE -4

#define MAX_MESSAGE_LENGTH_AEAD 128
#define MAX_ASSOCIATED_DATA_LENGTH 128



#define CRYPTO_KEYBYTES 16
#define CRYPTO_NSECBYTES 0
#define CRYPTO_NPUBBYTES 16 // nonce bytes 
#define CRYPTO_ABYTES 16 // tag bytes 
#define CRYPTO_NOOVERLAP 1

// definitions for ascon-128
#define RATE (64 / 8)
#define PA_ROUNDS 12
#define PB_ROUNDS 6
#define IV                                                                     \
    ((u64)(8 * (CRYPTO_KEYBYTES)) << 56 | (u64)(8 * (RATE)) << 48 |            \
    (u64)(PA_ROUNDS) << 40 | (u64)(PB_ROUNDS) << 32)
////////////////////////////////////////////////////////////////////////////

//definition for tiny 

#define TINY_CRYPTO_KEYBYTES 16
#define TINY_CRYPTO_NSECBYTES 0
#define TINY_CRYPTO_NPUBBYTES 12
#define TINY_CRYPTO_ABYTES 8
#define TINY_CRYPTO_NOOVERLAP 1



extern void crypto_aead_encrypt_xoodyak();
extern void perm_xoodyak_asm(); 
extern int github_ascon128_encrypt_asm(); 
extern int github_ascon128_encrypt_asm_new_api();

extern void crypto_aead_encrypt_tiny_asm(); 
extern void crypto_aead_encrypt_tiny(); 


static void init_buffer(UChar *buffer, size_t len){
    size_t i;
    for (i = 0; i < len; i++)
    buffer[i] = (UChar) i;
}

static void print_buffer(const UChar *buffer, size_t len){
    size_t i; 
    for (i = 0; i < len; i++)
    printf("%02x", buffer[i]);
    printf("\n");
}

void test_xoodyak_asm(void){   
    UChar c[MAX_MESSAGE_LENGTH_AEAD+CRYPTO_ABYTES], m[MAX_MESSAGE_LENGTH_AEAD], ad[MAX_ASSOCIATED_DATA_LENGTH];
    UChar npub[CRYPTO_NPUBBYTES], k[CRYPTO_KEYBYTES];
    ULLInt adlen, clen, mlen;
    
    init_buffer(m, MAX_MESSAGE_LENGTH_AEAD);
    init_buffer(ad, MAX_ASSOCIATED_DATA_LENGTH);
    init_buffer(npub, CRYPTO_NPUBBYTES);
    init_buffer(k, CRYPTO_KEYBYTES);
    
    adlen = 16; mlen = 16;
    uint32_t num_cycle = __get_rv_cycle();
    crypto_aead_encrypt_xoodyak(c, &clen, m, mlen, ad, adlen, NULL, npub, k);
    uint32_t num_cycle1 = __get_rv_cycle();
    printf("AEAD output for adlen = %i, mlen = %i:\n Cycles = %d\n", (int) adlen, (int) mlen, num_cycle1 - num_cycle);
    print_buffer(c, (size_t) mlen);
    print_buffer(c + mlen, (size_t) CRYPTO_ABYTES);

    adlen = 32; mlen = 0;
    uint32_t num_cycle2 = __get_rv_cycle();
    crypto_aead_encrypt_xoodyak(c, &clen, m, mlen, ad, adlen, NULL, npub, k);
    uint32_t num_cycle3 = __get_rv_cycle();
    printf("AEAD output for adlen = %i, mlen = %i:\n Cycles = %d\n", (int) adlen, (int) mlen, num_cycle3 - num_cycle2);
    print_buffer(c, (size_t) mlen);
    print_buffer(c + mlen, (size_t) CRYPTO_ABYTES);

    adlen = 128; mlen = 128;
    uint32_t num_cycle4 = __get_rv_cycle();
    crypto_aead_encrypt_xoodyak(c, &clen, m, mlen, ad, adlen, NULL, npub, k);
    uint32_t num_cycle5 = __get_rv_cycle();
    printf("AEAD output for adlen = %i, mlen = %i:\n Cycles = %d\n", (int) adlen, (int) mlen, num_cycle5 - num_cycle4);
    print_buffer(c, (size_t) mlen);
    print_buffer(c + mlen, (size_t) CRYPTO_ABYTES);

    adlen = 0; mlen = 256;
    uint32_t num_cycle6 = __get_rv_cycle();
    crypto_aead_encrypt_xoodyak(c, &clen, m, mlen, ad, adlen, NULL, npub, k);
    uint32_t num_cycle7 = __get_rv_cycle();
    printf("AEAD output for adlen = %i, mlen = %i:\n Cycles = %d\n", (int) adlen, (int) mlen, num_cycle7 - num_cycle6);
    print_buffer(c, (size_t) mlen);
    print_buffer(c + mlen, (size_t) CRYPTO_ABYTES);
}   

void test_xoodyak_func_asm(int steps) // focus on this measure cycles. 
{
    uint32_t state[12];
    uint32_t num_cycle = __get_rv_cycle();
    perm_xoodyak_asm(state, steps);
    uint32_t num_cycle1 = __get_rv_cycle();
    printf("\n Xoodyak function (riscv) with %i steps has %d cycles \n", steps, num_cycle1 - num_cycle);

}

void test_schwaemm_github(void)
{
    UChar c[MAX_MSG_LEN+SCHWAEMM_TAG_BYTES], m[MAX_MSG_LEN], ad[MAX_AD_LEN];
    UChar npub[SCHWAEMM_NONCE_BYTES], k[SCHWAEMM_KEY_BYTES];
    ULLInt adlen, clen, mlen;
    
    init_buffer(m, MAX_MSG_LEN);
    init_buffer(ad, MAX_AD_LEN);
    init_buffer(npub, SCHWAEMM_NONCE_BYTES);
    init_buffer(k, SCHWAEMM_KEY_BYTES);
    
    adlen = 16; mlen = 16;
    uint32_t num_cycle = __get_rv_cycle();
    schwaemm_256_128_github(c, &clen, m, mlen, ad, adlen, NULL, npub, k);
    uint32_t num_cycle1 = __get_rv_cycle();
    printf("AEAD output for schwaemm github adlen = %i, mlen = %i:\n Cycles = %d\n", (int) adlen, (int) mlen, num_cycle1 - num_cycle);
    print_buffer(c, (size_t) mlen);
    print_buffer(c + mlen, (size_t) SCHWAEMM_TAG_BYTES);
    
    adlen = 32; mlen = 0;
    uint32_t num_cycle2 = __get_rv_cycle();
    schwaemm_256_128_github(c, &clen, m, mlen, ad, adlen, NULL, npub, k);
    uint32_t num_cycle3 = __get_rv_cycle();
    printf("AEAD output for schwaemm github adlen = %i, mlen = %i:\n Cycles = %d\n", (int) adlen, (int) mlen, num_cycle3 - num_cycle2);
    print_buffer(c, (size_t) mlen);
    print_buffer(c + mlen, (size_t) SCHWAEMM_TAG_BYTES);

    adlen = 128; mlen = 128; 
    uint32_t num_cycle4 = __get_rv_cycle();
    schwaemm_256_128_github(c, &clen, m, mlen, ad, adlen, NULL, npub, k);
    uint32_t num_cycle5 = __get_rv_cycle();
    printf("AEAD output for schwaemm github adlen = %i, mlen = %i:\n Cycles = %d\n", (int) adlen, (int) mlen, num_cycle5 - num_cycle4);
    print_buffer(c, (size_t) mlen);
    print_buffer(c + mlen, (size_t) SCHWAEMM_TAG_BYTES);

    adlen = 0; mlen = 256;
    uint32_t num_cycle6 = __get_rv_cycle();
    schwaemm_256_128_github(c, &clen, m, mlen, ad, adlen, NULL, npub, k);
    uint32_t num_cycle7 = __get_rv_cycle();
    printf("AEAD output for schwaemm github adlen = %i, mlen = %i:\n Cycles = %d\n", (int) adlen, (int) mlen, num_cycle7 - num_cycle6);
    print_buffer(c, (size_t) mlen);
    print_buffer(c + mlen, (size_t) SCHWAEMM_TAG_BYTES);
}   


void test_ascon128_asm(void){   
    UChar c[MAX_MESSAGE_LENGTH_AEAD+CRYPTO_ABYTES], m[MAX_MESSAGE_LENGTH_AEAD], ad[MAX_ASSOCIATED_DATA_LENGTH];
    UChar npub[CRYPTO_NPUBBYTES], k[CRYPTO_KEYBYTES];
    ULLInt adlen, clen, mlen;
    
    init_buffer(m, MAX_MESSAGE_LENGTH_AEAD);
    init_buffer(ad, MAX_ASSOCIATED_DATA_LENGTH);
    init_buffer(npub, CRYPTO_NPUBBYTES);
    init_buffer(k, CRYPTO_KEYBYTES);
    
    adlen = 16; mlen = 16;
    uint32_t num_cycle = __get_rv_cycle();
    github_ascon128_encrypt_asm(c, &clen, m, mlen, ad, adlen, NULL, npub, k);
    uint32_t num_cycle1 = __get_rv_cycle();
    printf("ascon128_asm Cycles = %d\n",num_cycle1 - num_cycle);
    print_buffer(c, (size_t) mlen);
    print_buffer(c + mlen, (size_t) CRYPTO_ABYTES);

    adlen = 32; mlen = 0;
    uint32_t num_cycle2 = __get_rv_cycle();
    github_ascon128_encrypt_asm(c, &clen, m, mlen, ad, adlen, NULL, npub, k);
    uint32_t num_cycle3 = __get_rv_cycle();
    printf("ascon128_asm Cycles = %d\n", num_cycle3 - num_cycle2);
    print_buffer(c, (size_t) mlen);
    print_buffer(c + mlen, (size_t) CRYPTO_ABYTES);

    adlen = 128; mlen = 128;
    uint32_t num_cycle4 = __get_rv_cycle();
    github_ascon128_encrypt_asm(c, &clen, m, mlen, ad, adlen, NULL, npub, k);
    uint32_t num_cycle5 = __get_rv_cycle();
    printf("ascon128_asm Cycles = %d\n", num_cycle5 - num_cycle4);
    print_buffer(c, (size_t) mlen);
    print_buffer(c + mlen, (size_t) CRYPTO_ABYTES);

    adlen = 0; mlen = 256;
    uint32_t num_cycle6 = __get_rv_cycle();
    github_ascon128_encrypt_asm(c, &clen, m, mlen, ad, adlen, NULL, npub, k);
    uint32_t num_cycle7 = __get_rv_cycle();
    printf("ascon128_asm Cycles = %d\n", num_cycle7 - num_cycle6);
    print_buffer(c, (size_t) mlen);
    print_buffer(c + mlen, (size_t) CRYPTO_ABYTES);
}   

void test_ascon128_func_asm(void){  
    UChar npub[CRYPTO_NPUBBYTES], k[CRYPTO_KEYBYTES];
    init_buffer(npub, CRYPTO_NPUBBYTES);
    init_buffer(k, CRYPTO_KEYBYTES);
    const u64 K0 = BYTES_TO_U64(k, 8);
    const u64 K1 = BYTES_TO_U64(k + 8, 8);
    const u64 N0 = BYTES_TO_U64(npub, 8);
    const u64 N1 = BYTES_TO_U64(npub + 8, 8);
    state s;
    s.x0 = IV;
    s.x1 = K0;
    s.x2 = K1;
    s.x3 = N0;
    s.x4 = N1;
    uint32_t num_cycle = __get_rv_cycle();
    github_ascon128_func_asm(&s, 150);
    uint32_t num_cycle1 = __get_rv_cycle();
    printf("\n ASCON-128 function (riscv) with 6 steps has %d cycles \n", num_cycle1 - num_cycle);
}

void test_tiny_asm(void){   
    UChar c[MAX_MESSAGE_LENGTH_AEAD+TINY_CRYPTO_ABYTES], m[MAX_MESSAGE_LENGTH_AEAD], ad[MAX_ASSOCIATED_DATA_LENGTH];
    UChar npub[TINY_CRYPTO_NPUBBYTES], k[TINY_CRYPTO_KEYBYTES];
    ULLInt adlen, clen, mlen;
    
    init_buffer(m, MAX_MESSAGE_LENGTH_AEAD);
    init_buffer(ad, MAX_ASSOCIATED_DATA_LENGTH);
    init_buffer(npub, TINY_CRYPTO_NPUBBYTES);
    init_buffer(k, TINY_CRYPTO_KEYBYTES);
    
    adlen = 16; mlen = 16;
    uint32_t num_cycle = __get_rv_cycle();
    crypto_aead_encrypt_tiny_asm(c, &clen, m, mlen, ad, adlen, NULL, npub, k);
    uint32_t num_cycle1 = __get_rv_cycle();
    printf("tiny_asm Cycles = %d\n",num_cycle1 - num_cycle);
    print_buffer(c, (size_t) mlen);
    print_buffer(c + mlen, (size_t) CRYPTO_ABYTES);
    printf("--------------\n");
    adlen = 32; mlen = 0;
    uint32_t num_cycle2 = __get_rv_cycle();
    crypto_aead_encrypt_tiny_asm(c, &clen, m, mlen, ad, adlen, NULL, npub, k);
    uint32_t num_cycle3 = __get_rv_cycle();
    printf("tiny_asm Cycles = %d\n", num_cycle3 - num_cycle2);
    print_buffer(c, (size_t) mlen);
    print_buffer(c + mlen, (size_t) CRYPTO_ABYTES);
    printf("--------------\n");

    adlen = 128; mlen = 128;
    uint32_t num_cycle4 = __get_rv_cycle();
    crypto_aead_encrypt_tiny_asm(c, &clen, m, mlen, ad, adlen, NULL, npub, k);
    uint32_t num_cycle5 = __get_rv_cycle();
    printf("tiny_asm Cycles = %d\n", num_cycle5 - num_cycle4);
    //print_buffer(c, (size_t) mlen);
    //print_buffer(c + mlen, (size_t) CRYPTO_ABYTES);
    printf("--------------\n");
    adlen = 0; mlen = 256;
    uint32_t num_cycle6 = __get_rv_cycle();
    crypto_aead_encrypt_tiny_asm(c, &clen, m, mlen, ad, adlen, NULL, npub, k);
    uint32_t num_cycle7 = __get_rv_cycle();
    printf("tiny_asm Cycles = %d\n", num_cycle7 - num_cycle6);
    //print_buffer(c, (size_t) mlen);
    //print_buffer(c + mlen, (size_t) CRYPTO_ABYTES);
    printf("--------------\n");
}   

void test_tiny(void){   
    UChar c[MAX_MESSAGE_LENGTH_AEAD+TINY_CRYPTO_ABYTES], m[MAX_MESSAGE_LENGTH_AEAD], ad[MAX_ASSOCIATED_DATA_LENGTH];
    UChar npub[TINY_CRYPTO_NPUBBYTES], k[TINY_CRYPTO_KEYBYTES];
    ULLInt adlen, clen, mlen;
    
    init_buffer(m, MAX_MESSAGE_LENGTH_AEAD);
    init_buffer(ad, MAX_ASSOCIATED_DATA_LENGTH);
    init_buffer(npub, TINY_CRYPTO_NPUBBYTES);
    init_buffer(k, TINY_CRYPTO_KEYBYTES);
    
    adlen = 16; mlen = 16;
    uint32_t num_cycle = __get_rv_cycle();
    crypto_aead_encrypt_tiny(c, &clen, m, mlen, ad, adlen, NULL, npub, k);
    uint32_t num_cycle1 = __get_rv_cycle();
    printf("tiny Cycles = %d\n",num_cycle1 - num_cycle);
    print_buffer(c, (size_t) mlen);
    print_buffer(c + mlen, (size_t) CRYPTO_ABYTES);
    printf("--------------\n");
    
    adlen = 32; mlen = 0;
    uint32_t num_cycle2 = __get_rv_cycle();
    crypto_aead_encrypt_tiny(c, &clen, m, mlen, ad, adlen, NULL, npub, k);
    uint32_t num_cycle3 = __get_rv_cycle();
    printf("tiny Cycles = %d\n", num_cycle3 - num_cycle2);
    print_buffer(c, (size_t) mlen);
    print_buffer(c + mlen, (size_t) CRYPTO_ABYTES);
    printf("--------------\n");

    adlen = 128; mlen = 128;
    uint32_t num_cycle4 = __get_rv_cycle();
    crypto_aead_encrypt_tiny(c, &clen, m, mlen, ad, adlen, NULL, npub, k);
    uint32_t num_cycle5 = __get_rv_cycle();
    printf("tiny Cycles = %d\n", num_cycle5 - num_cycle4);
    //print_buffer(c, (size_t) mlen);
    //print_buffer(c + mlen, (size_t) CRYPTO_ABYTES);
    printf("--------------\n");
    adlen = 0; mlen = 256;
    uint32_t num_cycle6 = __get_rv_cycle();
    crypto_aead_encrypt_tiny(c, &clen, m, mlen, ad, adlen, NULL, npub, k);
    uint32_t num_cycle7 = __get_rv_cycle();
    printf("tiny Cycles = %d\n", num_cycle7 - num_cycle6);
    //print_buffer(c, (size_t) mlen);
    //print_buffer(c + mlen, (size_t) CRYPTO_ABYTES);
    printf("--------------\n");
}   


void test_ascon128_asm_new_api(void){   
    UChar c[MAX_MESSAGE_LENGTH_AEAD+CRYPTO_ABYTES], m[MAX_MESSAGE_LENGTH_AEAD], ad[MAX_ASSOCIATED_DATA_LENGTH];
    UChar npub[CRYPTO_NPUBBYTES], k[CRYPTO_KEYBYTES];
    ULLInt adlen, clen, mlen;
    
    init_buffer(m, MAX_MESSAGE_LENGTH_AEAD);
    init_buffer(ad, MAX_ASSOCIATED_DATA_LENGTH);
    init_buffer(npub, CRYPTO_NPUBBYTES);
    init_buffer(k, CRYPTO_KEYBYTES);
    
    adlen = 16; mlen = 16;
    uint32_t num_cycle = __get_rv_cycle();
    github_ascon128_encrypt_asm_new_api(c, &clen, m, mlen, ad, adlen, NULL, npub, k);
    uint32_t num_cycle1 = __get_rv_cycle();
    printf("ascon128_asm Cycles = %d\n",num_cycle1 - num_cycle);
    print_buffer(c, (size_t) mlen);
    print_buffer(c + mlen, (size_t) CRYPTO_ABYTES);

    adlen = 32; mlen = 0;
    uint32_t num_cycle2 = __get_rv_cycle();
    github_ascon128_encrypt_asm_new_api(c, &clen, m, mlen, ad, adlen, NULL, npub, k);
    uint32_t num_cycle3 = __get_rv_cycle();
    printf("ascon128_asm Cycles = %d\n", num_cycle3 - num_cycle2);
    print_buffer(c, (size_t) mlen);
    print_buffer(c + mlen, (size_t) CRYPTO_ABYTES);

    adlen = 128; mlen = 128;
    uint32_t num_cycle4 = __get_rv_cycle();
    github_ascon128_encrypt_asm_new_api(c, &clen, m, mlen, ad, adlen, NULL, npub, k);
    uint32_t num_cycle5 = __get_rv_cycle();
    printf("ascon128_asm Cycles = %d\n", num_cycle5 - num_cycle4);
    print_buffer(c, (size_t) mlen);
    print_buffer(c + mlen, (size_t) CRYPTO_ABYTES);

    adlen = 0; mlen = 256;
    uint32_t num_cycle6 = __get_rv_cycle();
    github_ascon128_encrypt_asm_new_api(c, &clen, m, mlen, ad, adlen, NULL, npub, k);
    uint32_t num_cycle7 = __get_rv_cycle();
    printf("ascon128_asm Cycles = %d\n", num_cycle7 - num_cycle6);
    print_buffer(c, (size_t) mlen);
    print_buffer(c + mlen, (size_t) CRYPTO_ABYTES);
}   