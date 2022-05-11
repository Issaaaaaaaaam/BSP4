#pragma once

// #define ADDITIONAL
#define NO_CHECK


#include "asm/crypto_aead.h"



#define crypto_aead_encrypt_xoodyak crypto_aead_encrypt_asm_xoodyak
#define perm_xoodyak_asm func_xoodoo_asm