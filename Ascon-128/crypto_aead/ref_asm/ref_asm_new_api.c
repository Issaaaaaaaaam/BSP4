#include "../../Permutation/ascon.h"
#include "../../kat.h"
#include "../crypto_aead.h"

#define RATE (64 / 8)
#define PA_ROUNDS 12
#define PB_ROUNDS 6
#define IV                                                                     \
    ((u64)(8 * (CRYPTO_KEYBYTES)) << 56 | (u64)(8 * (RATE)) << 48 |            \
    (u64)(PA_ROUNDS) << 40 | (u64)(PB_ROUNDS) << 32)

#define P12(s) (ascon_asm((s), 0xf0))
#define P8(s) (ascon_asm((s), 0xb4))
#define P6(s) (ascon_asm((s), 0x96))




void static Initialize(state *s, key *key, nonce *nonce)
{
    s -> x0 = IV;
    s -> x1 = key -> k0;
    s -> x2 = key -> k1;
    s -> x3 = nonce -> n0;
    s -> x4 = nonce -> n1;
    P12(s);
    s -> x3 ^= key -> k0;
    s -> x4 ^= key -> k1;
}

void static ProcessAssocData(state *s, const unsigned char *ad, unsigned long long adlen)
{
    if (adlen) {
        while (adlen >= RATE) {
            s -> x0 ^= BYTES_TO_U64(ad, 8);
            P6(s);
            adlen -= RATE;
            ad += RATE;
        }
        s -> x0 ^= BYTES_TO_U64(ad, adlen);
        s -> x0 ^= 0x80ull << (56 - 8 * adlen);
        P6(s);
    }
    s -> x4 ^= 1;
}

void static ProcessPlainText(state *s, unsigned char *c, const unsigned char *m, unsigned long long mlen)
{
    while (mlen >= RATE) {
        s -> x0 ^= BYTES_TO_U64(m, 8);
        U64_TO_BYTES(c, s -> x0, 8);
        P6(s);
        mlen -= RATE;
        m += RATE;
        c += RATE;
    }
    s -> x0 ^= BYTES_TO_U64(m, mlen);
    s -> x0 ^= 0x80ull << (56 - 8 * mlen);
    U64_TO_BYTES(c, s -> x0, mlen);
    c += mlen;
}

void static ProcessCypherText(state *s, const unsigned char *c, unsigned char *m, unsigned long long clen, uint64_t c0)
{
clen -= CRYPTO_ABYTES;
    while (clen >= RATE) {
        c0 = BYTES_TO_U64(c, 8);
        U64_TO_BYTES(m, s -> x0 ^ c0, 8);
        s -> x0 = c0;
        P6(s);
        clen -= RATE;
        m += RATE;
        c += RATE;
    }
    c0 = BYTES_TO_U64(c, clen);
    U64_TO_BYTES(m, s -> x0 ^ c0, clen);
    s -> x0 &= ~BYTE_MASK(clen);
    s -> x0 |= c0;
    s -> x0 ^= 0x80ull << (56 - 8 * clen);
    c += clen;
}



void static Finalize(state *s,  key *key)
{
    // finalization
    s -> x1 ^= key -> k0;
    s -> x2 ^= key -> k1;
    P12(s);
    s -> x3 ^= key -> k0;
    s -> x4 ^= key -> k1;
}

void static GenerateTag(state *s, unsigned char *c)
{
    U64_TO_BYTES(c, s -> x3, 8);
    U64_TO_BYTES(c + 8, s -> x4, 8);
}

int static CheckTag(state *s, const unsigned char *c)
{
    if (((s -> x3 ^ BYTES_TO_U64(c, 8)) | (s -> x4 ^ BYTES_TO_U64(c + 8, 8))) != 0) {
        return -1;
    }
    return 0;
}


int crypto_aead_encrypt_ref_asm_new_api(unsigned char *c, unsigned long long *clen,
                                const unsigned char *m, unsigned long long mlen,
                                const unsigned char *ad,
                                unsigned long long adlen,
                                const unsigned char *nsec,
                                const unsigned char *npub,
                                const unsigned char *k) {
    state s;
    key ky; 
    nonce n; 
    ky.k0 = BYTES_TO_U64(k, 8);
    ky.k1 = BYTES_TO_U64(k + 8, 8);
    n.n0 = BYTES_TO_U64(npub, 8);
    n.n1 = BYTES_TO_U64(npub + 8, 8);
    (void)nsec;
    // set ciphertext size
    *clen = mlen + CRYPTO_ABYTES;
    Initialize(&s, &ky, &n); 
    ProcessAssocData(&s, ad, adlen);
    ProcessPlainText(&s, c, m, mlen);
    Finalize(&s, &ky);
    GenerateTag(&s, c);
    return 0 ;
}

int crypto_aead_decrypt_ref_asm_new_api(unsigned char *m, unsigned long long *mlen,
                                unsigned char *nsec, const unsigned char *c,
                                unsigned long long clen,
                                const unsigned char *ad,
                                unsigned long long adlen,
                                const unsigned char *npub,
                                const unsigned char *k)
{
    if (clen < CRYPTO_ABYTES) 
    {
            mlen = 0;
            return 1;
    }

    state s;
    key ky; 
    nonce n; 
    ky.k0 = BYTES_TO_U64(k, 8);
    ky.k1 = BYTES_TO_U64(k + 8, 8);
    n.n0 = BYTES_TO_U64(npub, 8);
    n.n1 = BYTES_TO_U64(npub + 8, 8);
    u64 c0;
    (void)nsec;

    // set plaintext size
    *mlen = clen - CRYPTO_ABYTES;
    Initialize(&s, &ky, &n); 
    ProcessAssocData(&s, ad, adlen);
    ProcessCypherText(&s, c, m, clen, c0);
    Finalize(&s, &ky);
    if (CheckTag(&s, c)) {
        mlen = 0;
        return -1; 
    }
    return 0 ;
}