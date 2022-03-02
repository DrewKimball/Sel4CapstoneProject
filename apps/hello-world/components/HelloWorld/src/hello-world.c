#include <camkes.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <aes.h>
#include <rsa.h>

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
  printf("\nTesting RSA Library\n");
  struct public_key_class pub[1];
  struct private_key_class priv[1];
  rsa_gen_keys(pub, priv, PRIME_SOURCE_FILE);

  printf("Private Key:\n Modulus: %lld\n Exponent: %lld\n", (long long)priv->modulus, (long long) priv->exponent);
  printf("Public Key:\n Modulus: %lld\n Exponent: %lld\n", (long long)pub->modulus, (long long) pub->exponent);
  
  char message[] = "123abc";
  int i;

  printf("Original:\n");
  for(i=0; i < strlen(message); i++){
    printf("%lld\n", (long long)message[i]);
  }  
  
  long long *encrypted = rsa_encrypt(message, sizeof(message), pub);
  if (!encrypted){
    fprintf(stderr, "Error in encryption!\n");
    return 1;
  }
  printf("Encrypted:\n");
  for(i=0; i < strlen(message); i++){
    printf("%lld\n", (long long)encrypted[i]);
  }  
  
  char *decrypted = rsa_decrypt(encrypted, 8*sizeof(message), priv);
  if (!decrypted){
    fprintf(stderr, "Error in decryption!\n");
    return 1;
  }
  printf("Decrypted:\n");
  for(i=0; i < strlen(message); i++){
    printf("%lld\n", (long long)decrypted[i]);
  }  
  
  printf("\n");
  free(encrypted);
  free(decrypted);
  printf("\nDone\n");
  return 0;
}
