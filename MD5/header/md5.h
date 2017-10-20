/* md5.h header file for md5.c
 */
 #ifndef MD5_H
 #define MD5_H

 // size of an MD5 block buffer
  #define BUFFER_SIZE 64

 /* UINT2 defines a two byte word */
 typedef unsigned short int UINT2;

 /* UINT4 defines a four byte word */
 typedef unsigned int UINT4;

// one 512-bit block of a message, including its context
typedef struct {
  UINT4 count[2];  // actual number of bits of original message, dynamically increasing
  UINT4 state[4];  // state of four registers A, B, C, D of current block
  unsigned char buffer[BUFFER_SIZE];  // buffer for message block storage, totally 512 bits.
} MD5_BLK;

void MD5Init(MD5_BLK *block);
void MD5Update(MD5_BLK *block, unsigned char *input, unsigned int inputlen);
void MD5Final(unsigned char digest[16], MD5_BLK *block);

#endif
