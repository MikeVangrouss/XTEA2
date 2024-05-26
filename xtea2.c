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
#define DELTA 0xFD258F8F3210C68 /* sqr(5)-1 * 2^63 */

/*
for XTEA:
DELTA 0x9e3779b9 / sqr(5)-1 * 2^31 /
sqr(5)-1 = 1.2360679774997896964091736687313 
sqr(5)-1 * 2^31 =  2654435769.4972302964775847707926
2654435769 decimal = 9E3779B9 hexa
* 
for XTEA2:
DELTA 0xFD258F8F3210C68 / sqr(5)-1 * 2^63 /
sqr(5)-1 = 1.2360679774997896964091736687313 
sqr(5)-1 * 2^63 = 11400714819323198485.9516105876220261392289212923904
1140071481932319848 decimal = FD258F8F3210C68 hexa 
*/

/**********************************************************
   Input values: 	k[4]	  256-bit key
                  v[2]    128-bit plaintext block
   Output values:	v[2]    128-bit ciphertext block 
 **********************************************************/

void xtea2(uint64_t *k, uint64_t *v, long N) {
  uint64_t y=v[0], z=v[1];
  uint64_t limit,sum=0;
  if(N>0) { /* ENCRYPT */
    limit=DELTA*N;
    while(sum!=limit) {
      y+=((z<<4)^(z>>5)) + (z^sum) + k[sum&3];
      sum+=DELTA;
      z+=((y<<4)^(y>>5)) + (y^sum) + k[(sum>>11)&3];
    }
  } else { /* DECRYPT */
    sum=DELTA*(-N);
    while(sum) {
      z-=((y<<4)^(y>>5)) + (y^sum) + k[(sum>>11)&3];
      sum-=DELTA;
      y-=((z<<4)^(z>>5)) + (z^sum) + k[sum&3];
    }
  }
  v[0]=y; v[1]=z;
}

void cl_enc_block(uint64_t *k, uint64_t *v) {
 xtea2(k,v,ROUNDS);
}

void cl_dec_block(uint64_t *k, uint64_t *v) {
 xtea2(k,v,-ROUNDS);
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
  
  cl_enc_block(k,v);
  
  printf("Ciphertext:%0.16llX %0.16llX\n",v[0],v[1]);
  
  cl_dec_block(k,v);
  
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
  
  cl_enc_block(k,v);
  
  printf("Ciphertext:%0.16llX %0.16llX\n",v[0],v[1]);
  
  cl_dec_block(k,v);
  
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
  
  cl_enc_block(k,v);
  
  printf("Ciphertext:%0.16llX %0.16llX\n",v[0],v[1]);
  
  cl_dec_block(k,v);
  
  printf("Decrypted: %0.16llX %0.16llX\n\n",v[0],v[1]);
  
   
}

/*

Encryption 1
Key: 0000000000000000 0000000000000000 0000000000000000 0000000000000001
Plaintext: 0000000000000000 0000000000000000
Ciphertext:8E2D46878AC343A8 BA2FF090957266F8
Decrypted: 0000000000000000 0000000000000000

Encryption 2
Key: 0000000000000000 0000000000000000 0000000000000000 0000000000000001
Plaintext: 0000000000000000 0000000000000001
Ciphertext:81451EF8405B4713 7D214E62CD51A1AB
Decrypted: 0000000000000000 0000000000000001

Encryption 3
Key: 0000000000000000 0000000000000000 0000000000000000 0000000000000001
Plaintext: 0000000000000001 0000000000000001
Ciphertext:E2B628D85E1DB91B 305517897DA89FC3
Decrypted: 0000000000000001 0000000000000001

*/
