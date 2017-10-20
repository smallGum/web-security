/* md5.c source code of md5 algorithm
 */

#include <memory.h>
#include "md5.h"

// Constants for MD5Transform routine.
 #define S11 7
 #define S12 12
 #define S13 17
 #define S14 22
 #define S21 5
 #define S22 9
 #define S23 14
 #define S24 20
 #define S31 4
 #define S32 11
 #define S33 16
 #define S34 23
 #define S41 6
 #define S42 10
 #define S43 15
 #define S44 21

// inside functions
void MD5Transform(UINT4 state[4], unsigned char block[64]);
void byteToWord(unsigned char *input, UINT4 *output, unsigned int len);
void wordToByte(UINT4 *input, unsigned char *output, unsigned int len);

// padding bits
unsigned char PADDING[64] = {
  0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

// MD5 basic functions F, G, H, I
#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~z)))

// ROTATE_LEFT rotates x left n bits.
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))

/* FF, GG, HH, and II transformations for rounds 1, 2, 3, and 4.
Rotation is separate from addition to prevent recomputation.
 */
#define FF(a, b, c, d, x, s, ac) { \
 (a) += F ((b), (c), (d)) + (x) + (UINT4)(ac); \
 (a) = ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
  }
#define GG(a, b, c, d, x, s, ac) { \
 (a) += G ((b), (c), (d)) + (x) + (UINT4)(ac); \
 (a) = ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
  }
#define HH(a, b, c, d, x, s, ac) { \
 (a) += H ((b), (c), (d)) + (x) + (UINT4)(ac); \
 (a) = ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
  }
#define II(a, b, c, d, x, s, ac) { \
 (a) += I ((b), (c), (d)) + (x) + (UINT4)(ac); \
 (a) = ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
  }

// MD5 initialization. initialize an MD5 block
void MD5Init(MD5_BLK *block) {
  block -> count[0] = block -> count[1] = 0;  // initial the number of total bits of original message to be 0.
  // initialization for A, B, C, D registers
  block -> state[0] = 0x67452301;  // A register
  block -> state[1] = 0xefcdab89;  // B register
  block -> state[2] = 0x98badcfe;  // C register
  block -> state[3] = 0x10325476;  // D register
}

// add the input message into the given MD5 block and transform
void MD5Update(MD5_BLK *block, unsigned char *input, unsigned int inputLen) {
  unsigned int occupiedSpace;  // space of the given block that has been occupied
                               // by part of previous bits that has been stored in the block buffer.
  unsigned int emptySpace;     // space of the block that is still not occupied
  unsigned int i;              // loop variable

  // calculate the oppcupied space of the block
  // equal to (B / 8) % 64, where B is the number of total previous bits
  occupiedSpace = (unsigned int)((block -> count[0] >> 3) & 0x3F);
  emptySpace = BUFFER_SIZE - occupiedSpace;  // get empty space to store the input string

  // update the number of bits
  // equal to B + inputLen * 8
  block -> count[0] += ((UINT4)inputLen << 3);
  if (block -> count[0] < ((UINT4)inputLen << 3)) {
    block -> count[1]++;
  }
  block -> count[1] += ((UINT4)inputLen >> 29);

  // if the inputLen is larger than empty space, transform as many time as possible
  // if not, we only need to add the input bits into the block buffer
  if (emptySpace <= inputLen) {
    // transform the current bits in the block buffer
    memcpy(&block -> buffer[occupiedSpace], input, emptySpace);
    MD5Transform(block -> state, block -> buffer);

    // transform the remain input bits
    for (i = emptySpace; i + 63 < inputLen; i += 64) {
      MD5Transform(block -> state, &input[i]);
    }

    // reset the occupiedSpace to 0
    // meaning that the bits in the block has been totally transformed
    occupiedSpace = 0;
  } else {
    i = 0;
  }

  // store the remain input bits that hasn't been transformed in the block buffer
  memcpy(&block -> buffer[occupiedSpace], &input[i], inputLen - i);
}

/* MD5 finalization. Ends an MD5 message-digest operation, writing the
  the message digest and zeroizing the context.
 */
void MD5Final(unsigned char digest[16], MD5_BLK *block) {
  unsigned int occupiedSpace;
  unsigned int padLen;        // number of bits to pad
  unsigned char bits[8];      // total number of bits of the message

  // calculate the oppcupied space of the block
  // equal to (B / 8) % 64, where B is the number of total bits of message
  occupiedSpace = (unsigned int)((block -> count[0] >> 3) & 0x3F);
  // Pad out to 56 mod 64
  padLen = occupiedSpace < (BUFFER_SIZE - 8) ? (BUFFER_SIZE - 8 - occupiedSpace) : (BUFFER_SIZE + BUFFER_SIZE - 8 - occupiedSpace);

  // represent the total number of bits to 64-bit binary number
  wordToByte(block -> count, bits, 8);
  MD5Update(block, PADDING, padLen);
  MD5Update(block, bits, 8);

  // store result in digest
  wordToByte(block -> state, digest, 16);

  // Zeroize sensitive information.
  memset(block, 0, sizeof(*block));
}

// convert words to bytes
void wordToByte(UINT4 *input, unsigned char *output, unsigned int len) {
  unsigned int i, index;

  for (i = 0, index = 0; i < len; i += 4, index++) {
    output[i] = (unsigned char)(input[index] & 0xff);
    output[i + 1] = (unsigned char)((input[index] >> 8) & 0xff);
    output[i + 2] = (unsigned char)((input[index] >> 16) & 0xff);
    output[i + 3] = (unsigned char)((input[index] >> 24) & 0xff);
  }
}

// convert bytes of a block to words
void byteToWord(unsigned char *input, UINT4 *output, unsigned int len) {
  unsigned int i, index;

  for (i = 0, index = 0; i < len; i += 4, index++) {
    output[index] = ((UINT4)input[i]) |
                    (((UINT4)input[i + 1]) << 8) |
                    (((UINT4)input[i + 2]) << 16) |
                    (((UINT4)input[i + 3]) << 24);
  }
}

// MD5 basic transformation. Transforms state of A, B, C, D registers based on block.
void MD5Transform(UINT4 state[4], unsigned char block[BUFFER_SIZE]) {
  UINT4 a = state[0], b = state[1], c = state[2], d = state[3];
  UINT4 x[16];

  byteToWord(block, x, BUFFER_SIZE);

  /* Round 1 */
  FF (a, b, c, d, x[ 0], S11, 0xd76aa478); /* 1 */
  FF (d, a, b, c, x[ 1], S12, 0xe8c7b756); /* 2 */
  FF (c, d, a, b, x[ 2], S13, 0x242070db); /* 3 */
  FF (b, c, d, a, x[ 3], S14, 0xc1bdceee); /* 4 */
  FF (a, b, c, d, x[ 4], S11, 0xf57c0faf); /* 5 */
  FF (d, a, b, c, x[ 5], S12, 0x4787c62a); /* 6 */
  FF (c, d, a, b, x[ 6], S13, 0xa8304613); /* 7 */
  FF (b, c, d, a, x[ 7], S14, 0xfd469501); /* 8 */
  FF (a, b, c, d, x[ 8], S11, 0x698098d8); /* 9 */
  FF (d, a, b, c, x[ 9], S12, 0x8b44f7af); /* 10 */
  FF (c, d, a, b, x[10], S13, 0xffff5bb1); /* 11 */
  FF (b, c, d, a, x[11], S14, 0x895cd7be); /* 12 */
  FF (a, b, c, d, x[12], S11, 0x6b901122); /* 13 */
  FF (d, a, b, c, x[13], S12, 0xfd987193); /* 14 */
  FF (c, d, a, b, x[14], S13, 0xa679438e); /* 15 */
  FF (b, c, d, a, x[15], S14, 0x49b40821); /* 16 */

  /* Round 2 */
  GG (a, b, c, d, x[ 1], S21, 0xf61e2562); /* 17 */
  GG (d, a, b, c, x[ 6], S22, 0xc040b340); /* 18 */
  GG (c, d, a, b, x[11], S23, 0x265e5a51); /* 19 */
  GG (b, c, d, a, x[ 0], S24, 0xe9b6c7aa); /* 20 */
  GG (a, b, c, d, x[ 5], S21, 0xd62f105d); /* 21 */
  GG (d, a, b, c, x[10], S22,  0x2441453); /* 22 */
  GG (c, d, a, b, x[15], S23, 0xd8a1e681); /* 23 */
  GG (b, c, d, a, x[ 4], S24, 0xe7d3fbc8); /* 24 */
  GG (a, b, c, d, x[ 9], S21, 0x21e1cde6); /* 25 */
  GG (d, a, b, c, x[14], S22, 0xc33707d6); /* 26 */
  GG (c, d, a, b, x[ 3], S23, 0xf4d50d87); /* 27 */
  GG (b, c, d, a, x[ 8], S24, 0x455a14ed); /* 28 */
  GG (a, b, c, d, x[13], S21, 0xa9e3e905); /* 29 */
  GG (d, a, b, c, x[ 2], S22, 0xfcefa3f8); /* 30 */
  GG (c, d, a, b, x[ 7], S23, 0x676f02d9); /* 31 */
  GG (b, c, d, a, x[12], S24, 0x8d2a4c8a); /* 32 */

  /* Round 3 */
  HH (a, b, c, d, x[ 5], S31, 0xfffa3942); /* 33 */
  HH (d, a, b, c, x[ 8], S32, 0x8771f681); /* 34 */
  HH (c, d, a, b, x[11], S33, 0x6d9d6122); /* 35 */
  HH (b, c, d, a, x[14], S34, 0xfde5380c); /* 36 */
  HH (a, b, c, d, x[ 1], S31, 0xa4beea44); /* 37 */
  HH (d, a, b, c, x[ 4], S32, 0x4bdecfa9); /* 38 */
  HH (c, d, a, b, x[ 7], S33, 0xf6bb4b60); /* 39 */
  HH (b, c, d, a, x[10], S34, 0xbebfbc70); /* 40 */
  HH (a, b, c, d, x[13], S31, 0x289b7ec6); /* 41 */
  HH (d, a, b, c, x[ 0], S32, 0xeaa127fa); /* 42 */
  HH (c, d, a, b, x[ 3], S33, 0xd4ef3085); /* 43 */
  HH (b, c, d, a, x[ 6], S34,  0x4881d05); /* 44 */
  HH (a, b, c, d, x[ 9], S31, 0xd9d4d039); /* 45 */
  HH (d, a, b, c, x[12], S32, 0xe6db99e5); /* 46 */
  HH (c, d, a, b, x[15], S33, 0x1fa27cf8); /* 47 */
  HH (b, c, d, a, x[ 2], S34, 0xc4ac5665); /* 48 */

  /* Round 4 */
  II (a, b, c, d, x[ 0], S41, 0xf4292244); /* 49 */
  II (d, a, b, c, x[ 7], S42, 0x432aff97); /* 50 */
  II (c, d, a, b, x[14], S43, 0xab9423a7); /* 51 */
  II (b, c, d, a, x[ 5], S44, 0xfc93a039); /* 52 */
  II (a, b, c, d, x[12], S41, 0x655b59c3); /* 53 */
  II (d, a, b, c, x[ 3], S42, 0x8f0ccc92); /* 54 */
  II (c, d, a, b, x[10], S43, 0xffeff47d); /* 55 */
  II (b, c, d, a, x[ 1], S44, 0x85845dd1); /* 56 */
  II (a, b, c, d, x[ 8], S41, 0x6fa87e4f); /* 57 */
  II (d, a, b, c, x[15], S42, 0xfe2ce6e0); /* 58 */
  II (c, d, a, b, x[ 6], S43, 0xa3014314); /* 59 */
  II (b, c, d, a, x[13], S44, 0x4e0811a1); /* 60 */
  II (a, b, c, d, x[ 4], S41, 0xf7537e82); /* 61 */
  II (d, a, b, c, x[11], S42, 0xbd3af235); /* 62 */
  II (c, d, a, b, x[ 2], S43, 0x2ad7d2bb); /* 63 */
  II (b, c, d, a, x[ 9], S44, 0xeb86d391); /* 64 */

  state[0] += a;
  state[1] += b;
  state[2] += c;
  state[3] += d;

  // zeroize sensitive information
  memset(x, 0, sizeof(x));
}
