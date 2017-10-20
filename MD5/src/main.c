#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "md5.h"

int main(int argc, char *argv[]) {
  // test my md5 program
  unsigned char *testSet[7] = {
    "",
    "a",
    "abc",
    "message digest",
    "abcdefghijklmnopqrstuvwxyz",
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
    "12345678901234567890123456789012345678901234567890123456789012345678901234567890"
  };
  int i;

  for (i = 0; i < 7; ++i) {
    MD5_BLK md5;
    int j;
    unsigned char decrypt[16];

    MD5Init(&md5);
    MD5Update(&md5, testSet[i], strlen((char *)testSet[i]));
    MD5Final(decrypt, &md5);

    printf("message: %s\n", testSet[i]);
    printf("MD5 key: ");
    for(j = 0; j < 16; j++) { printf("%02x",decrypt[j]); }
    printf("\n");
  }

  return 0;
}
