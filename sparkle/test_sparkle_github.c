#include <stdio.h>  
#include <string.h>
#include <stddef.h>
#include <stdlib.h>
#include "nuclei_sdk_soc.h"

extern void func_sparkle_asm(uint32_t *state, unsigned int ns);

void cleara_state(uint32_t *state, int brans)
{
    int i;
    
    for (i = 0; i < 2*brans; i ++) {
    state[i] = 0;
    }
}

void printa_state(const uint32_t *state, int brans)
{
  uint8_t *sbytes = (uint8_t *) state;
    int i, j;
    
    for (i = 0; i < brans; i ++) {
    j = 8*i;
    printf("(%02x%02x%02x%02x %02x%02x%02x%02x)",       \
    sbytes[j],   sbytes[j+1], sbytes[j+2], sbytes[j+3], \
    sbytes[j+4], sbytes[j+5], sbytes[j+6], sbytes[j+7]);
    if (i < brans-1) printf(" ");
    }
    printf("\n");
}

void test_sparkle384_github(int steps) // focus on this measure cycles. 
{
    // SPARKLE384 has 6 branches
    uint32_t state[12];
    int brans = 6;
    cleara_state(state, brans);
    uint32_t num_cycle = __get_rv_cycle();
    func_sparkle_asm(state, steps);
    uint32_t num_cycle1 = __get_rv_cycle();
    printf("\n SPARKLE384 (riscv) github with %i steps has %d cycles\n", steps, num_cycle1 - num_cycle);
    printa_state(state, brans);
    printf("\n");
}