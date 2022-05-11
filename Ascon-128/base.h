#pragma once

// do we have additional tests: void test_perm()


#define github_ascon128_encrypt_asm crypto_aead_encrypt_ref_asm
#define github_ascon128_decrypt_asm crypto_aead_decrypt_ref_asm
#define github_ascon128_encrypt_asm_new_api crypto_aead_encrypt_ref_asm_new_api
#define github_ascon128_decrypt_asm_new_api crypto_aead_decrypt_ref_asm_new_api
#define github_ascon128_func_asm ascon_asm


#include "Permutation/ascon.h"
#include "crypto_aead/crypto_aead.h"
#include "kat.h"
