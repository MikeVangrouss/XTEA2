/**********************************************************
   XTEA2 - (eXtended Tiny Encryption Algorithm 2)
   Formerly known as TEAN2
   
   XTEA Feistel cipher by David Wheeler & Roger M. Needham
   XTEA2 by Alexander PUKALL 2006
   
   128-bit block cipher (like AES) 256-bit key 128 rounds
   
   Code free for all, even for commercial software
   
   Compile with gcc : gcc xtea2.c -o xtea2
   
 **********************************************************/

#include <stdint.h>
#include <stdio.h>

#define ROUNDS 64 /* each iteration of the loop does two Feistel-cipher rounds */

/**********************************************************
   Input values: 	k[4]	  256-bit key
                  v[2]    128-bit plaintext block
   Output values:	v[2]    128-bit ciphertext block 
 **********************************************************/

void encrypt(uint64_t v[2], uint64_t const key[4]) {
    unsigned int i;
    uint64_t v0=v[0], v1=v[1], sum=0, delta=0x9E3779B97F4A7C15;
    for (i=0; i < 64; i++) {
        v0 += (((v1 << 14) ^ (v1 >> 15)) + v1) ^ (sum + key[sum & 3]);
        sum += delta;
        v1 += (((v0 << 14) ^ (v0 >> 15)) + v0) ^ (sum + key[(sum>>23) & 3]);
    }

    v[0]=v0; v[1]=v1;
}

void decrypt(uint64_t v[2], uint64_t const key[4]) {
    unsigned int i;
    uint64_t v0=v[0], v1=v[1], delta=0x9E3779B97F4A7C15, sum=delta*64;
    for (i=0; i < 64; i++) {
        v1 -= (((v0 << 14) ^ (v0 >> 15)) + v0) ^ (sum + key[(sum>>23) & 3]);
        sum -= delta;
        v0 -= (((v1 << 14) ^ (v1 >> 15)) + v1) ^ (sum + key[sum & 3]);
    }
    v[0]=v0; v[1]=v1;
}

void main()
{
  uint64_t v[2];
  uint64_t k[4];
  
  /* 256-bit key */
  k[0]=0x0000000000000000;
  k[1]=0x0000000000000000;
  k[2]=0x0000000000000000;
  k[3]=0x0000000000000001;
  
  /* 128-bit plaintext block */
  v[0]=0x0000000000000000;
  v[1]=0x0000000000000000;
 
  printf("XTEA2 by Alexander PUKALL 2006 \n 128-bit block 256-bit key 128 rounds\n");
  printf("Code can be freely use even for commercial software\n");
  printf("Based on XTEA by David Wheeler & Roger M. Needham\n\n");
  
  printf("Encryption 1\n");
  
  printf("Key: %0.16llX %0.16llX %0.16llX %0.16llX\n",k[0],k[1],k[2],k[3]);
  
  printf("Plaintext: %0.16llX %0.16llX\n",v[0],v[1]);
  
  encrypt(v,k);
  
  printf("Ciphertext:%0.16llX %0.16llX\n",v[0],v[1]);
  
  decrypt(v,k);
  
  printf("Decrypted: %0.16llX %0.16llX\n\n",v[0],v[1]);
  
  /* 256-bit key */
  k[0]=0x0000000000000000;
  k[1]=0x0000000000000000;
  k[2]=0x0000000000000000;
  k[3]=0x0000000000000001;
  
  /* 128-bit plaintext block */
  v[0]=0x0000000000000000;
  v[1]=0x0000000000000001;
  
  printf("Encryption 2\n");
  
  printf("Key: %0.16llX %0.16llX %0.16llX %0.16llX\n",k[0],k[1],k[2],k[3]);
  
  printf("Plaintext: %0.16llX %0.16llX\n",v[0],v[1]);
  
  encrypt(v,k);
  
  printf("Ciphertext:%0.16llX %0.16llX\n",v[0],v[1]);
  
  decrypt(v,k);
  
  printf("Decrypted: %0.16llX %0.16llX\n\n",v[0],v[1]);
  
  /* 256-bit key */
  k[0]=0x0000000000000000;
  k[1]=0x0000000000000000;
  k[2]=0x0000000000000000;
  k[3]=0x0000000000000001;
  
  /* 128-bit plaintext block */
  v[0]=0x0000000000000001;
  v[1]=0x0000000000000001;
  
  printf("Encryption 3\n");
  
  printf("Key: %0.16llX %0.16llX %0.16llX %0.16llX\n",k[0],k[1],k[2],k[3]);
  
  printf("Plaintext: %0.16llX %0.16llX\n",v[0],v[1]);
  
  encrypt(v,k);
  
  printf("Ciphertext:%0.16llX %0.16llX\n",v[0],v[1]);
  
  decrypt(v,k);
  
  printf("Decrypted: %0.16llX %0.16llX\n\n",v[0],v[1]);
  
   
}

/*

Encryption 1
Key: 0000000000000000 0000000000000000 0000000000000000 0000000000000001
Plaintext: 0000000000000000 0000000000000000
Ciphertext:03D122C7D2E59E74 01EBD4C571CBF328
Decrypted: 0000000000000000 0000000000000000

Encryption 2
Key: 0000000000000000 0000000000000000 0000000000000000 0000000000000001
Plaintext: 0000000000000000 0000000000000001
Ciphertext:5A569C159FA954C8 58C5CD4DF3FF55A8
Decrypted: 0000000000000000 0000000000000001

Encryption 3
Key: 0000000000000000 0000000000000000 0000000000000000 0000000000000001
Plaintext: 0000000000000001 0000000000000001
Ciphertext:BE92F7F5F3B72CAF 2F76CDFE46A46186
Decrypted: 0000000000000001 0000000000000001

*/
