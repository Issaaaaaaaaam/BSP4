

#define FrameBitsIV  0x10  
#define FrameBitsAD  0x30  
#define FrameBitsPC  0x50  //Framebits for plaintext/ciphertext      
#define FrameBitsFinalization 0x70       

#define NROUND1 128*5 
#define NROUND2 128*8

extern void tiny_rv32(unsigned int *state, const unsigned char *key, unsigned int number_of_steps);
extern int permutation_counter; // we use this variable to count the number of usage of the permutation


// The initialization  
/* The input to initialization is the 128-bit key; 96-bit IV;*/
void static initialization(const unsigned char *key, const unsigned char *iv, unsigned int *state)
{
        int i;

        //initialize the state as 0  
        for (i = 0; i < 4; i++) state[i] = 0;     

        //update the state with the key 
        permutation_counter++; 
        tiny_rv32(state, key, NROUND2);  

        //introduce IV into the state  
        for (i = 0;  i < 3; i++)  
        {
                state[1] ^= FrameBitsIV;
                permutation_counter++;   
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
                permutation_counter++;
                tiny_rv32(state, k, NROUND1);
                state[3] ^= ((unsigned int*)ad)[i];
        }

        // if adlen is not a multiple of 4, we process the remaining bytes
        if ((adlen & 3) > 0)
        {
                state[1] ^= FrameBitsAD;
                permutation_counter++;
                tiny_rv32(state, k, NROUND1);
                for (j = 0; j < (adlen & 3); j++)  ((unsigned char*)state)[12 + j] ^= ad[(i << 2) + j];
                state[1] ^= adlen & 3;
        }   
}     


//encrypt plaintext   
int encrypt_tiny_asm(
	unsigned char *c, unsigned long long *clen,
	const unsigned char *m, unsigned long long mlen,
	const unsigned char *ad, unsigned long long adlen,
	const unsigned char *nsec,
	const unsigned char *npub,
	const unsigned char *k
)
{
        unsigned long long i;
        unsigned int j;
        unsigned char mac[8];
        unsigned int state[4];

        //initialization stage
        initialization(k, npub, state);

        //process the associated data   
        process_ad(k, ad, adlen, state);

        //process the plaintext    
        for (i = 0; i < (mlen >> 2); i++)
        {
                state[1] ^= FrameBitsPC;
                permutation_counter++;
                tiny_rv32(state, k, NROUND2);
                state[3] ^= ((unsigned int*)m)[i];
                ((unsigned int*)c)[i] = state[2] ^ ((unsigned int*)m)[i];
        }
        // if mlen is not a multiple of 4, we process the remaining bytes
        if ((mlen & 3) > 0)
        {
                state[1] ^= FrameBitsPC;
                permutation_counter++;
                tiny_rv32(state, k, NROUND2);
                for (j = 0; j < (mlen & 3); j++)
                {
                        ((unsigned char*)state)[12 + j] ^= m[(i << 2) + j];
                        c[(i << 2) + j] = ((unsigned char*)state)[8 + j] ^ m[(i << 2) + j];
                }
                state[1] ^= mlen & 3;
        }

        //finalization stage, we assume that the tag length is 8 bytes
        state[1] ^= FrameBitsFinalization;
        permutation_counter++;
        tiny_rv32(state, k, NROUND2);
        ((unsigned int*)mac)[0] = state[2];

        state[1] ^= FrameBitsFinalization;
        permutation_counter++;
        tiny_rv32(state, k, NROUND1);
        ((unsigned int*)mac)[1] = state[2];

        *clen = mlen + 8;
        for (j = 0; j < 8; j++) c[mlen+j] = mac[j];  

        return 0;
}

