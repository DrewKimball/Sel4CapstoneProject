#include <camkes.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <tomcrypt.h>

# To run as root process, remove the _test postfix.
int run_test(void) {
  printf("\nTesting Crypto Library:\n\n");
   unsigned char buf[200], hash[512 / 8];
   int i;
   hash_state c;
   const unsigned char c1 = 0xa3;

   const unsigned char sha3_512_0xa3_200_times[512 / 8] = {
      0xe7, 0x6d, 0xfa, 0xd2, 0x20, 0x84, 0xa8, 0xb1,
      0x46, 0x7f, 0xcf, 0x2f, 0xfa, 0x58, 0x36, 0x1b,
      0xec, 0x76, 0x28, 0xed, 0xf5, 0xf3, 0xfd, 0xc0,
      0xe4, 0x80, 0x5d, 0xc4, 0x8c, 0xae, 0xec, 0xa8,
      0x1b, 0x7c, 0x13, 0xc3, 0x0a, 0xdf, 0x52, 0xa3,
      0x65, 0x95, 0x84, 0x73, 0x9a, 0x2d, 0xf4, 0x6b,
      0xe5, 0x89, 0xc5, 0x1c, 0xa1, 0xa4, 0xa8, 0x41,
      0x6d, 0xf6, 0x54, 0x5a, 0x1c, 0xe8, 0xba, 0x00
   };

   XMEMSET(buf, c1, sizeof(buf));

   /* SHA3-512 as a single buffer. [FIPS 202] */
   sha3_512_init(&c);
   sha3_process(&c, buf, sizeof(buf));
   sha3_done(&c, hash);
   if (compare_testvector(hash, sizeof(hash), sha3_512_0xa3_200_times, sizeof(sha3_512_0xa3_200_times), "SHA3-512", 0)) {
      printf("Failed\n");      
      return CRYPT_FAIL_TESTVECTOR;
   }

   /* SHA3-512 in two steps. [FIPS 202] */
   sha3_512_init(&c);
   sha3_process(&c, buf, sizeof(buf) / 2);
   sha3_process(&c, buf + sizeof(buf) / 2, sizeof(buf) / 2);
   sha3_done(&c, hash);
   if (compare_testvector(hash, sizeof(hash), sha3_512_0xa3_200_times, sizeof(sha3_512_0xa3_200_times), "SHA3-512", 1)) {
      printf("Failed\n");
      return CRYPT_FAIL_TESTVECTOR;
   }

   /* SHA3-512 byte-by-byte: 200 steps. [FIPS 202] */
   i = 200;
   sha3_512_init(&c);
   while (i--) {
       sha3_process(&c, &c1, 1);
   }
   sha3_done(&c, hash);
   if (compare_testvector(hash, sizeof(hash), sha3_512_0xa3_200_times, sizeof(sha3_512_0xa3_200_times), "SHA3-512", 2)) {
      printf("Failed\n");
      return CRYPT_FAIL_TESTVECTOR;
   }

  printf("\n\nSuccess!\n");
  return 0;
}
