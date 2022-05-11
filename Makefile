TARGET = main

NUCLEI_SDK_ROOT = ../../..

SRCDIRS = . src xoodyak xoodyak/asm sparkle Ascon-128 Ascon-128/crypto_aead Ascon-128/Permutation Ascon-128/crypto_aead/ref_asm tiny

INCDIRS = . inc

COMMON_FLAGS := -O2

include $(NUCLEI_SDK_ROOT)/Build/Makefile.base
