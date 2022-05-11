#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include "crypto_aead.h"
#include "schwaemm.h"
#include "sparkle.h"
#include "nuclei_sdk_soc.h"


typedef unsigned char UChar;
typedef unsigned long long ULLInt;


#define MAX_AD_LEN  256
#define MAX_MSG_LEN 256


#if (defined(__arm__) || defined(_M_ARM)) && defined(SPARKLE_ASSEMBLER)
extern void sparkle256_arm(uint32_t *state, int steps);
extern void sparkle384_arm(uint32_t *state, int steps);
extern void sparkle512_arm(uint32_t *state, int steps);
extern void sparkle256f_arm(uint32_t *state, int steps);
extern void sparkle384f_arm(uint32_t *state, int steps);
extern void sparkle512f_arm(uint32_t *state, int steps);
#endif  // if defined(__arm__) || ...

#if defined(__riscv_xlen) && (__riscv_xlen == 32) && defined(SPARKLE_ASSEMBLER)
extern void sparkle384_rv32(uint32_t *state, int steps);
#endif

#if (defined(__AVR) || defined(__AVR__)) && defined(SPARKLE_ASSEMBLER)
extern void sparkle_avr(uint32_t *state, int brans, int steps);
#endif  // if defined(__AVR__) || ...


static void init_buffer(UChar *buffer, size_t len)
{
  size_t i;
  
  for (i = 0; i < len; i++)
    buffer[i] = (UChar) i;
}


static void print_buffer(const UChar *buffer, size_t len)
{
  size_t i;
  
  for (i = 0; i < len; i++)
    printf("%02x", buffer[i]);
  printf("\n\n");
}

/*
void test_sparkle256(int steps)
{
  // SPARKLE256 has 4 branches
  uint32_t state[8];
  int brans = 4;
  
  clear_state(state, brans);
  printf("SPARKLE256 (C99) with %i steps:\n", steps);
  func_sparkle_asm(state, steps);
  print_state(state, brans);
  

#if (defined(__arm__) || defined(_M_ARM)) && defined(SPARKLE_ASSEMBLER)
  clear_state(state, brans);
  printf("SPARKLE256 (ARM) with %i steps:\n", steps);
  sparkle256_arm(state, steps);
  print_state(state, brans);
#endif  // if defined(__arm__) || ...
  
#if (defined(__AVR) || defined(__AVR__)) && defined(SPARKLE_ASSEMBLER)
  clear_state(state, brans);
  printf("SPARKLE256 (AVR) with %i steps:\n", steps);
  sparkle_avr(state, brans, steps);
  print_state(state, brans);
#endif  // if defined(__AVR__) || ...


  printf("\n");
  
  // Expected result for 7 steps:
  // (5e32ce55 527699b6) (50f0533a 366f5449) (7b2dc386 dbb844ee) (45b3a55d 1faf7257)
  // Expected result for 10 steps:
  // (7ed456c0 31af461c) (be53b3bf 8a114ceb) (569bab60 6a87fc0f) (81861d8c b2d026d6)
}
*/


void test_sparkle384(int steps) // focus on this measure cycles. 
{
  // SPARKLE384 has 6 branches
  uint32_t state[12];
  int brans = 6;
  
  clear_state(state, brans);
  printf("SPARKLE384 (C99) with %i steps:\n", steps);
  sparkle(state, brans, steps);
  print_state(state, brans);

#if (defined(__arm__) || defined(_M_ARM)) && defined(SPARKLE_ASSEMBLER)
  clear_state(state, brans);
  printf("SPARKLE384 (ARM) with %i steps:\n", steps);
  sparkle384_arm(state, steps);
  print_state(state, brans);
#endif  // if defined(__arm__) || ...
  
#if (defined(__AVR) || defined(__AVR__)) && defined(SPARKLE_ASSEMBLER)
  clear_state(state, brans);
  printf("SPARKLE384 (AVR) with %i steps:\n", steps);
  sparkle_avr(state, brans, steps);
  print_state(state, brans);
#endif  // if defined(__AVR__) || ...

#if defined(__riscv_xlen) && (__riscv_xlen == 32) && defined(SPARKLE_ASSEMBLER)
  clear_state(state, brans);
  uint32_t num_cycle = __get_rv_cycle();
  sparkle384_rv32(state, steps);
  uint32_t num_cycle1 = __get_rv_cycle();
  printf("\n SPARKLE384 (riscv) with %i steps has %d cycles\n", steps, num_cycle1 - num_cycle);
  //print_state(state, brans);
#endif


  printf("\n");
  
  // Expected result for 7 steps:
  // (7968f94d 332c7c8c) (4a6b2382 d74d4f90) (e830a0d6 aa093bf0) (34bbc3c4 f9df63f0)
  // (ffcef961 fa1fc28e) (0f37df93 e2f1ac83)
  // Expected result for 11 steps:
  // (25bfc2f3 55dd53fc) (0654d6ca 17f9af9e) (8c64a53f 48f2a2e1) (eefc4158 3c7e933a)
  // (442cf761 da73662b) (a5198416 226b9eff)
}


/*void test_sparkle512(int steps)
{
  // SPARKLE512 has 8 branches
  uint32_t state[16];
  int brans = 8;
  
  clear_state(state, brans);
  printf("SPARKLE512 (C99) with %i steps:\n", steps);
  sparkle384_asm(state, steps);
  print_state(state, brans);

#if (defined(__arm__) || defined(_M_ARM)) && defined(SPARKLE_ASSEMBLER)
  clear_state(state, brans);
  printf("SPARKLE512 (ARM) with %i steps:\n", steps);
  sparkle512_arm(state, steps);
  print_state(state, brans);
#endif  // if defined(__arm__) || ...

#if (defined(__AVR) || defined(__AVR__)) && defined(SPARKLE_ASSEMBLER)
  clear_state(state, brans);
  printf("SPARKLE512 (AVR) with %i steps:\n", steps);
  sparkle_avr(state, brans, steps);
  print_state(state, brans);
#endif  // if defined(__AVR__) || ...

  printf("\n");

  // Expected result for 8 steps:
  // (47079ee4 74e39e95) (42eedd60 33fd351b) (97a62956 420ba6d6) (6492b6d2 ad3d9fe8)
  // (ea9c6a5f 91eb1529) (255850ff 01c4a5ed) (82798d09 a0b02bc6) (ebd3a15a 01c08500)
  // Expected result for 12 steps:
  // (4005224e a9a4c139) (ec0751b8 de6955d9) (1e71087e b1991924) (d676f53c 7b5906dc)
  // (68742efb 4d38f1b7) (f6bb41a8 d0169379) (f019a57f e7c86a0b) (e5dec146 c8fa2eb6)
}
*/

void test_schwaemm(void)
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
  crypto_aead_encrypt(c, &clen, m, mlen, ad, adlen, NULL, npub, k);
  uint32_t num_cycle1 = __get_rv_cycle();
  printf("AEAD output for adlen = %i, mlen = %i:\n Cycles = %d\n", (int) adlen, (int) mlen, num_cycle1 - num_cycle);
  print_buffer(c, (size_t) mlen);
  print_buffer(c + mlen, (size_t) SCHWAEMM_TAG_BYTES);
  
  adlen = 32; mlen = 0;
  uint32_t num_cycle2 = __get_rv_cycle();
  crypto_aead_encrypt(c, &clen, m, mlen, ad, adlen, NULL, npub, k);
  uint32_t num_cycle3 = __get_rv_cycle();
  printf("AEAD output for adlen = %i, mlen = %i:\n Cycles = %d\n", (int) adlen, (int) mlen, num_cycle3 - num_cycle2);
  print_buffer(c, (size_t) mlen);
  print_buffer(c + mlen, (size_t) SCHWAEMM_TAG_BYTES);


  adlen = 128; mlen = 128; //!!!!!!! also do this for xoodyak 
  uint32_t num_cycle4 = __get_rv_cycle();
  crypto_aead_encrypt(c, &clen, m, mlen, ad, adlen, NULL, npub, k);
  uint32_t num_cycle5 = __get_rv_cycle();
  printf("AEAD output for adlen = %i, mlen = %i:\n Cycles = %d\n", (int) adlen, (int) mlen, num_cycle5 - num_cycle4);
  print_buffer(c, (size_t) mlen);
  print_buffer(c + mlen, (size_t) SCHWAEMM_TAG_BYTES);


  adlen = 0; mlen = 256;
  uint32_t num_cycle6 = __get_rv_cycle();
  crypto_aead_encrypt(c, &clen, m, mlen, ad, adlen, NULL, npub, k);
  uint32_t num_cycle7 = __get_rv_cycle();
  printf("AEAD output for adlen = %i, mlen = %i:\n Cycles = %d\n", (int) adlen, (int) mlen, num_cycle7 - num_cycle6);
  print_buffer(c, (size_t) mlen);
  print_buffer(c + mlen, (size_t) SCHWAEMM_TAG_BYTES);
}
