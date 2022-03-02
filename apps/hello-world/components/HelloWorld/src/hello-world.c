#include <camkes.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <aes.h>
#include <libtomcrypt.c>

int run(void) {
  printf("\nTesting Crypto Library:\n\n");
	WORD key_schedule[60], idx;
	BYTE enc_buf[128];
	BYTE plaintext[2][16] = {
		{0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a},
		{0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51}
	};
	BYTE ciphertext[2][16] = {
		{0xf3,0xee,0xd1,0xbd,0xb5,0xd2,0xa0,0x3c,0x06,0x4b,0x5a,0x7e,0x3d,0xb1,0x81,0xf8},
		{0x59,0x1c,0xcb,0x10,0xd4,0x10,0xed,0x26,0xdc,0x5b,0xa7,0x4a,0x31,0x36,0x28,0x70}
	};
	BYTE key[1][32] = {
		{0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4}
	};
	int pass = 1;

	// Raw ECB mode.
	printf("* ECB mode:\n");
	aes_key_setup(key[0], key_schedule, 256);
	printf(  "Key          : ");
        for(int idx = 0; idx < 32; idx++)
                printf("%02x", key[0][idx]);

	for(idx = 0; idx < 2; idx++) {
		aes_encrypt(plaintext[idx], enc_buf, key_schedule, 256);
		printf("\nPlaintext    : ");
                for(int idx = 0; idx < 16; idx++)
                    printf("%02x", plaintext[idx]);
		printf("\n-encrypted to: ");
                for(int idx = 0; idx < 16; idx++)
                    printf("%02x", enc_buf[idx]);
		pass = pass && !memcmp(enc_buf, ciphertext[idx], 16);

		aes_decrypt(ciphertext[idx], enc_buf, key_schedule, 256);
		printf("\nCiphertext   : ");
                for(int idx = 0; idx < 16; idx++)
                    printf("%02x", ciphertext[idx]);
		printf("\n-decrypted to: ");
                for(int idx = 0; idx < 16; idx++)
                    printf("%02x", enc_buf[idx]);
		pass = pass && !memcmp(enc_buf, plaintext[idx], 16);

		printf("\n");
	}
  if (pass) {
    printf("\nSucceeded!\n");
  } else {
    printf("\nFailed!\n");
  }
  printf("\nTesting tlse Library\n");
  unsigned char* ptext = "blah blah blah";
  printf("Plaintext = %s\n", ptext);
  unsigned char output[65];
  for (int i = 0; i < 65; i++)
    output[i] = 0;
  register_hash(&sha512_desc);
  hash_state state;
  int ok;
  ok = sha512_init(&state);
  if (ok != CRYPT_OK) {
    printf("Failed sha512_init\n");
    return 1;
  }
  ok = sha512_process(&state, ptext, strlen(ptext));
  if (ok != CRYPT_OK) {
    printf("Failed sha512_process\n");
    return 1;
  }
  ok = sha512_done(&state, output);
  if (ok != CRYPT_OK) {
    printf("Failed sha512_done\n");
    return 1;
  }
  printf("Hash: ");
  for(int idx = 0; idx < 64; idx++)
    printf("%02x", output[idx]);
  printf("\n\nDone\n");
  return 0;
}
