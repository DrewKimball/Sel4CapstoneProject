#include <camkes.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <aes.h>

int run(void) {
  printf("\nHello World\n");
  const size_t BLOCK_LEN = 16; // Length of aes blocks in bytes.
  struct AES_ctx ctx;
  // Message and key are byte of 'Thats my Kung Fu'.
  const uint8_t key[] = {
    0x54, 0x68, 0x61, 0x74,
    0x73, 0x20, 0x6D, 0x79,
    0x20, 0x4B, 0x75, 0x6E,
    0x67, 0x20, 0x46, 0x75,
  };
  AES_init_ctx(&ctx, key);
  uint8_t message[] = {
    0x54, 0x68, 0x61, 0x74,
    0x73, 0x20, 0x6D, 0x79,
    0x20, 0x4B, 0x75, 0x6E,
    0x67, 0x20, 0x46, 0x75,
  };
  AES_ECB_encrypt(&ctx, message);
  for (int i = 0; i < BLOCK_LEN; i++)
    printf("%02X", message[i]);
  printf("\nDone.\n");
  return 0;
}
