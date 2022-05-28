#include <stdio.h>
#include <string.h>
#include "nuclei_sdk_soc.h"


extern void test_sparkle256(int steps);
extern void test_sparkle384(int steps);
extern void test_sparkle512(int steps);
extern void test_schwaemm(void);
extern void test_xoodyak_asm(void); 
extern void test_xoodyak_perm_asm(void);
extern void test_sparkle384_github(int steps); 
extern void test_schwaemm_github(void);
extern void test_ascon128_asm(void); 
extern void test_ascon128_perm_asm(void); 
extern void test_ascon128_asm_new_api(void);
extern void test_tiny_asm(void); 
extern void test_tiny(void);
extern void tiny_perm_asm(void);
extern void tiny_perm_C(void); 

int permutation_counter; 


int main(void){ // ATTENTION: Please use one function at a time, otherwise the board might not print everything. 
  //test_sparkle384_github(7);
  //test_sparkle384(7);
  //test_xoodyak_perm_asm();
  //test_xoodyak_asm();
  //test_schwaemm_github();
  //test_tiny_asm();
  //test_schwaemm();
  //test_ascon128_asm();
  //test_ascon128_perm_asm();
  //test_tiny();
  //test_tiny_asm(); 
  //tiny_perm_asm();
  //tiny_perm_C();
  return 0;
}
