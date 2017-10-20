# MD5 Algorithm Implementation by C

This project implements the MD5 Message-Digest Algorithm by C. To see more details about this algorithm, please see [RFC1321](https://www.rfc-editor.org/rfc/rfc1321.txt) .

## Build

Enter "MD5" directory on your linux terminal, then run the command "make":

```shell
$ make
```

The project will be built in the same directory. 

## Run

Next, just run the executable file "main":

```
./main
```

It should print the result of test set:

```shell
message: 
MD5 key: d41d8cd98f00b204e9800998ecf8427e
message: a
MD5 key: 0cc175b9c0f1b6a831c399e269772661
message: abc
MD5 key: 900150983cd24fb0d6963f7d28e17f72
message: message digest
MD5 key: f96b697d7cb7938d525a2f31aaf161d0
message: abcdefghijklmnopqrstuvwxyz
MD5 key: c3fcd3d76192e4007dfb496cca67e13b
message: ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789
MD5 key: d174ab98d277d9f5a5611c2c9f419d9f
message: 12345678901234567890123456789012345678901234567890123456789012345678901234567890
MD5 key: 57edf4a22be3c955ac49da2e2107b67a
```

## Some crucial details

### count

We define the structure `MD5_BLK` to represent one 512-bit block of the message and context of the block:

```c
/* UINT4 defines a four byte word */
 typedef unsigned int UINT4;

// one 512-bit block of a message, including its context
typedef struct {
  UINT4 count[2];  // actual number of bits of original message, dynamically increasing
  UINT4 state[4];  // state of four registers A, B, C, D of current block
  unsigned char buffer[BUFFER_SIZE];  // buffer for message block storage, totally 512 bits.
} MD5_BLK;
```

Note that the array `count` , which stores the total number of bits of a message, is not figured out at the beginning of the program. Instead, `count` will increase dynamically when the MD5 block is updated and new input string is added into its buffer.

### unsigned long int

In RFC 1321, the type `UINT4` is defined as `unsigned long int` , which is 4 bytes. However, on my 64-bit linux ubuntu system, the type `unsigned long int` is 8 bytes! Thus, I have to use `unsigned int` .  