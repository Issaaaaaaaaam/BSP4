#include <stdio.h>
#include <string.h>
#include "nuclei_sdk_soc.h"


extern void test_sparkle256(int steps);
extern void test_sparkle384(int steps);
extern void test_sparkle512(int steps);
extern void test_schwaemm(void);
extern void test_xoodyak_asm(void); 
extern void test_xoodyak_func_asm(int steps);
extern void test_sparkle384_github(int steps); 
extern void test_schwaemm_github(void);
extern void test_ascon128_asm(void); 
extern void test_ascon128_func_asm(void); 
extern void test_ascon128_asm_new_api(void);
extern void test_tiny_asm(void); 
extern void test_tiny(void);
int main(void){
  //printf("Hello World!\n");
  //printf("x = %i\n", x);
  //printf("-------------------------------------------\n\n");
  //test_sparkle384_github(7);
  //printf("-------------------------------------------\n\n");
  //test_sparkle384(7);
  //printf("-------------------------------------------\n\n");
  //test_xoodyak_func_asm(12);
  //printf("-------------------------------------------\n\n");
  //test_xoodyak_asm();
  //printf("-------------------------------------------\n\n");
  //test_schwaemm_github();
  //printf("\n-------------------------------------------\n\n");
  //test_tiny_asm(); 
  //printf("\n\n-------------------------------------------\n\n");
  test_ascon128_asm();
  //printf("\n\n-------------------------------------------\n\n");
  //test_ascon128_func_asm();
  //printf("b\n");
  //test_tiny();
  //test_tiny_asm(); 
  //test_ascon128_asm_new_api(); 
  return 0;
}
