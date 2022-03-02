#include <camkes.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <aes.h>
#include <rsa.h.in>
#include <randapi.h>

int run(void) {
  printf("\nTesting Tiny AES Library:\n");
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
  printf("\nTesting Cryptography Library:\n");
      int i;
    unsigned long ran;
    char m[RFS_WWW],ml[RFS_WWW],c[RFS_WWW],e[RFS_WWW],s[RFS_WWW],raw[100];
    rsa_public_key_WWW pub;
    rsa_private_key_WWW priv;
    csprng RNG;
    octet M= {0,sizeof(m),m};
    octet ML= {0,sizeof(ml),ml};
    octet C= {0,sizeof(c),c};
    octet E= {0,sizeof(e),e};
    octet S= {0,sizeof(s),s};
    octet RAW= {0,sizeof(raw),raw};

    time((time_t *)&ran);

    RAW.len=100;				/* fake random seed source */
    RAW.val[0]=ran;
    RAW.val[1]=ran>>8;
    RAW.val[2]=ran>>16;
    RAW.val[3]=ran>>24;
    for (i=0; i<100; i++) RAW.val[i]=i;

    CREATE_CSPRNG(&RNG,&RAW);   /* initialise strong RNG */

    printf("Generating public/private key pair\n");
    RSA_WWW_KEY_PAIR(&RNG,65537,&priv,&pub,NULL,NULL);

    printf("Encrypting test string\n");
    OCT_jstring(&M,(char *)"Hello World\n");

    OAEP_ENCODE(HASH_TYPE_RSA_WWW,&M,&RNG,NULL,&E); /* OAEP encode message m to e  */

    RSA_WWW_ENCRYPT(&pub,&E,&C);     /* encrypt encoded message */
    printf("Ciphertext= ");
    OCT_output(&C);

    printf("Decrypting test string\n");
    RSA_WWW_DECRYPT(&priv,&C,&ML);   /* ... and then decrypt it */

    OAEP_DECODE(HASH_TYPE_RSA_WWW,NULL,&ML);    /* decode it */
    OCT_output_string(&ML);


    if (!OCT_comp(&M,&ML))
    {
        printf("FAILURE RSA Encryption failed");
        return 1;
    }

    printf("Signing message\n");
    PKCS15(HASH_TYPE_RSA_WWW,&M,&C);

    RSA_WWW_DECRYPT(&priv,&C,&S); /* create signature in S */

    printf("Signature= ");
    OCT_output(&S);

    RSA_WWW_ENCRYPT(&pub,&S,&ML);

    if (OCT_comp(&C,&ML))
    {
        printf("Signature is valid\n");
    }
    else
    {
        printf("FAILURE RSA Signature Verification failed");
        return 1;
    }

    KILL_CSPRNG(&RNG);
    RSA_WWW_PRIVATE_KEY_KILL(&priv);

    OCT_clear(&M);
    OCT_clear(&ML);   /* clean up afterwards */
    OCT_clear(&C);
    OCT_clear(&RAW);
    OCT_clear(&E);

    printf("SUCCESS\n");
  printf("Done\n");
  return 0;
}
