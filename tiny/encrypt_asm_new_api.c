
#define FrameBitsIV  0x10  
#define FrameBitsAD  0x30  
#define FrameBitsPC  0x50  //Framebits for plaintext/ciphertext      
#define FrameBitsFinalization 0x70       

#define NROUND1 128*5 
#define NROUND2 128*8

extern void tiny_rv32(unsigned int *state, const unsigned char *key, unsigned int number_of_steps);



// The initialization  
/* The input to initialization is the 128-bit key; 96-bit IV;*/
void static initialization(const unsigned char *key, const unsigned char *iv, unsigned int *state)
{
    int i;

    //initialize the state as 0  
    for (i = 0; i < 4; i++) state[i] = 0;     

    //update the state with the key  
    tiny_rv32(state, key, NROUND2);  

    //introduce IV into the state  
    for (i = 0;  i < 3; i++)  
    {
            state[1] ^= FrameBitsIV;   
            tiny_rv32(state, key, NROUND1); 
            state[3] ^= ((unsigned int*)iv)[i]; 
    }   
}

//process the associated data   
void static process_ad(const unsigned char *k, const unsigned char *ad, unsigned long long adlen, unsigned int *state)
{
    unsigned long long i; 
    unsigned int j; 

    for (i = 0; i < (adlen >> 2); i++)
    {
            state[1] ^= FrameBitsAD;
            tiny_rv32(state, k, NROUND1);
            state[3] ^= ((unsigned int*)ad)[i];
    }

    // if adlen is not a multiple of 4, we process the remaining bytes
    if ((adlen & 3) > 0)
    {
            state[1] ^= FrameBitsAD;
            tiny_rv32(state, k, NROUND1);
            for (j = 0; j < (adlen & 3); j++)  ((unsigned char*)state)[12 + j] ^= ad[(i << 2) + j];
            state[1] ^= adlen & 3;
    }   
}     

void static ProcessPlaintext(unsigned int *state, const unsigned char *k, const unsigned char *m, unsigned char *c, unsigned long long mlen)
{
    //process the plaintext 
    unsigned long long i; 
    unsigned int j;    
    for (i = 0; i < (mlen >> 2); i++)
    {
            state[1] ^= FrameBitsPC;
            tiny_rv32(state, k, NROUND2);
            state[3] ^= ((unsigned int*)m)[i];
            ((unsigned int*)c)[i] = state[2] ^ ((unsigned int*)m)[i];
    }
    // if mlen is not a multiple of 4, we process the remaining bytes
    if ((mlen & 3) > 0)
    {
            state[1] ^= FrameBitsPC;
            tiny_rv32(state, k, NROUND2);
            for (j = 0; j < (mlen & 3); j++)
            {
                    ((unsigned char*)state)[12 + j] ^= m[(i << 2) + j];
                    c[(i << 2) + j] = ((unsigned char*)state)[8 + j] ^ m[(i << 2) + j];
            }
            state[1] ^= mlen & 3;
    }
}

void static Finalize(unsigned int *state, unsigned char *mac, const unsigned char *k)
{  
    state[1] ^= FrameBitsFinalization;
    tiny_rv32(state, k, NROUND2);
    ((unsigned int*)mac)[0] = state[2];

    state[1] ^= FrameBitsFinalization;
    tiny_rv32(state, k, NROUND1);
    ((unsigned int*)mac)[1] = state[2];
}

void static GenerateTag(unsigned long long *clen,unsigned long long mlen,unsigned char *mac, unsigned char *c){
        unsigned int j;  
    *clen = mlen + 8;
    for (j = 0; j < 8; j++) c[mlen+j] = mac[j]; 
}


void static ProcessCyphertext(unsigned int *state, const unsigned char *k, unsigned char *m, const unsigned char *c, unsigned long long *mlen ){
    //process the ciphertext    
    unsigned int i; 
    unsigned int j;
    for (i = 0; i < (*mlen >> 2); i++)
    {
            state[1] ^= FrameBitsPC;
            tiny_rv32(state, k, NROUND2);
            ((unsigned int*)m)[i] = state[2] ^ ((unsigned int*)c)[i];
            state[3] ^= ((unsigned int*)m)[i];
    }
    // if mlen is not a multiple of 4, we process the remaining bytes
    if ((*mlen & 3) > 0)
    {
            state[1] ^= FrameBitsPC;
            tiny_rv32(state, k, NROUND2);
            for (j = 0; j < (*mlen & 3); j++)
            {
                    m[(i << 2) + j] = c[(i << 2) + j] ^ ((unsigned char*)state)[8 + j];
                    ((unsigned char*)state)[12 + j] ^= m[(i << 2) + j];
            }
            state[1] ^= *mlen & 3;
    }
}

int static VerifyTag(unsigned long long clen,unsigned char *mac, const unsigned char *c, unsigned int check){
    unsigned int j;
    for (j = 0; j < 8; j++) { check |= (mac[j] ^ c[clen - 8 + j]); }
    if (check == 0) return 0;
    else return -1;
}


//encrypt plaintext   
int encrypt_tiny_asm_new_api(
    unsigned char *c, unsigned long long *clen,
	const unsigned char *m, unsigned long long mlen,
	const unsigned char *ad, unsigned long long adlen,
	const unsigned char *nsec,
	const unsigned char *npub,
	const unsigned char *k
)
{
    unsigned char mac[8];
    unsigned int state[4];

    //initialization stage
    initialization(k, npub, state);

    //process the associated data   
    process_ad(k, ad, adlen, state);

    //process the plaintext    
    ProcessPlaintext(state, k, m, c, mlen);

    //finalization stage, we assume that the tag length is 8 bytes
    Finalize(state, mac, k);

    //Generating the tag
    GenerateTag(clen, mlen, mac, c);
    return 0;
}

int decrypt_tiny_asm_new_api(
	unsigned char *m, unsigned long long *mlen,
	unsigned char *nsec,
	const unsigned char *c, unsigned long long clen,
	const unsigned char *ad, unsigned long long adlen,
	const unsigned char *npub,
	const unsigned char *k
    )
{
        unsigned long long i;
        unsigned int j, check = 0;
        unsigned char mac[8];
        unsigned int state[4];

        *mlen = clen - 8;

    //initialization stage
    initialization(k, npub, state);

    //process the associated data   
    process_ad(k, ad, adlen, state);

    //process the plaintext    
    ProcessCyphertext(state, k, m, c, mlen);

    //finalization stage, we assume that the tag length is 8 bytes
    Finalize(state, mac, k);

    //Generating the tag
    return VerifyTag(clen, mac, c, check);
}