#include <stdio.h>
#include "tls.h"

const unsigned char exampleClientHelloPacket[] = {
    0x16, 0x03, 0x03, 0x00, 0xa5, 0x01, 0x00, 0x00, 0xa1, 0x03,
    0x03, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12,
    0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
    0x1d, 0x1e, 0x1f, 0x00, 0x00, 0x20, 0xcc, 0xa8, 0xcc, 0xa9,
    0xc0, 0x2f, 0xc0, 0x30, 0xc0, 0x2b, 0xc0, 0x2c, 0xc0, 0x13,
    0xc0, 0x09, 0xc0, 0x14, 0xc0, 0x0a, 0x00, 0x9c, 0x00, 0x9d,
    0x00, 0x2f, 0x00, 0x35, 0xc0, 0x12, 0x00, 0x0a, 0x01, 0x00,
    0x00, 0x58, 0x00, 0x00, 0x00, 0x18, 0x00, 0x16, 0x00, 0x00,
    0x13, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x75,
    0x6c, 0x66, 0x68, 0x65, 0x69, 0x6d, 0x2e, 0x6e, 0x65, 0x74,
    0x00, 0x05, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x0a, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x1d, 0x00, 0x17, 0x00,
    0x18, 0x00, 0x19, 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00, 0x00,
    0x0d, 0x00, 0x12, 0x00, 0x10, 0x04, 0x01, 0x04, 0x03, 0x05,
    0x01, 0x05, 0x03, 0x06, 0x01, 0x06, 0x03, 0x02, 0x01, 0x02,
    0x03, 0xff, 0x01, 0x00, 0x01, 0x00, 0x00, 0x12, 0x00, 0x00};

const unsigned char exampleClientRandom[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
    0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
    0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
    0x1e, 0x1f
};

const unsigned char exampleServerHelloPacket[] = {
    0x16, 0x03, 0x03, 0x00, 0x31, 0x02, 0x00, 0x00, 0x2d, 0x03,
    0x03, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78,
    0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80, 0x81, 0x82,
    0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c,
    0x8d, 0x8e, 0x8f, 0x00, 0xc0, 0x13, 0x00, 0x00, 0x05, 0xff,
    0x01, 0x00, 0x01, 0x00
};

const unsigned char exampleClientKeyExchangePacket[] = {
    0x16, 0x03, 0x03, 0x00, 0x25, 0x10, 0x00, 0x00, 0x21, 0x20,
    0x35, 0x80, 0x72, 0xd6, 0x36, 0x58, 0x80, 0xd1, 0xae, 0xea,
    0x32, 0x9a, 0xdf, 0x91, 0x21, 0x38, 0x38, 0x51, 0xed, 0x21,
    0xa2, 0x8e, 0x3b, 0x75, 0xe9, 0x65, 0xd0, 0xd2, 0xcd, 0x16,
    0x62, 0x54
};

const unsigned char exampleClientDHPrivate[] = {
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29,
    0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33,
    0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d,
    0x3e, 0x3f
};

int validate(char* name, const unsigned char* given, const unsigned char* expected, int len) {
    for (int i = 0; i < len; i++) {
        if (given[i] != expected[i]) {
            printf("%s differed from expected at byte %d\n", name, i);
            return 0;
        }
    }
    return 1;
}

void printHex(const unsigned char* buf, int len) {
    for (int i = 0; i < len; i++)
        printf("%02x", buf[i]);
}

void printFixedLenField(char* name, const unsigned char* field, int len) {
    printf("%s: 0x", name);
    printHex(field, len);
    printf("\n");
}

void printVarLenField(char* name, const unsigned char* field, int len) {
    printf("%s Bytes: %d\n", name, len);
    if (len) {
        printf("%s: 0x", name);
        printHex(field, len);
        printf("\n");
    }
}

void printClientHello(struct TLSSession session) {
    struct ClientHello ch = session.clientHello;
    printf("Printing Client Hello:\n");
    printf("Protocol Version: 0x%04x\n", ch.protocolVersion);
    printFixedLenField("Client Random", ch.random, 32);
    printVarLenField("Session ID", ch.sessionID, ch.sessionIDBytes);
    printVarLenField("Cipher Suites", ch.cipherSuites, ch.cipherSuiteBytes);
    printVarLenField("Compression Methods", ch.compMethods, ch.compressionBytes);
    printVarLenField("Extensions", ch.extensions, ch.extensionBytes);
    printVarLenField("Message Raw", ch.raw, ch.rawBytes);
    printf("\n");
}

void printServerHello(struct TLSSession session) {
    struct ServerHello sh = session.serverHello;
    printf("Printing Server Hello:\n");
    printf("Protocol Version: 0x%04x\n", sh.protocolVersion);
    printFixedLenField("Server Random", sh.random, 32);
    printVarLenField("Session ID", sh.sessionID, sh.sessionIDBytes);
    printf("Cipher Suite: 0x%04x\n", sh.cipherSuite);
    printf("Compression Method: 0x%02x\n", sh.compressionMethod);
    printVarLenField("Extensions", sh.extensions, sh.extensionBytes);
    printVarLenField("Message Raw", sh.raw, sh.rawBytes);
    printf("\n");
}

void printKeyExchange(struct TLSSession session) {
    struct KeyExchange ke = session.keyExchange;
    printf("Printing Key Exchange:\n");
    printFixedLenField("Server DH Private", ke.serverDHPrivate, 32);
    printFixedLenField("Server DH Public", ke.serverDHPublic, 32);
    printFixedLenField("Client DH Public", ke.clientDHPublic, 32);
    printFixedLenField("Premaster Secret", ke.premasterSecret, 32);
    printFixedLenField("Master Secret", ke.masterSecret, 48);
    printFixedLenField("Client MAC Key", ke.clientMACKey, 20);
    printFixedLenField("Server MAC Key", ke.serverMACKey, 20);
    printFixedLenField("Client Symmetric Key", ke.clientSymKey, 16);
    printFixedLenField("Server Symmetric Key", ke.serverSymKey, 16);
    printFixedLenField("Client IV", ke.clientIV, 16);
    printFixedLenField("Server IV", ke.serverIV, 16);
}

// Should run through a mock TLS transaction with data from https://tls.ulfheim.net
int run(void) {
  // Set up crypto library.
  register_all_ciphers();
  register_all_hashes();
  register_all_prngs();

  // Set up random number generator.
  prng_state st;
  unsigned char entropy[] = {
      0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
      0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
      0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
      0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
      0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32
  };
  if (sober128_start(&st) != CRYPT_OK)
      return 0;
  if (sober128_add_entropy(entropy, sizeof(entropy), &st) != CRYPT_OK)
      return 0;
  if (sober128_ready(&st) != CRYPT_OK)
      return 0;

  struct TLSSession session = newTLSSession(&st);

  printf("Attempting to parse client hello\n");
  if (!parseTLSRecord(&session, exampleClientHelloPacket, sizeof(exampleClientHelloPacket))) {
    printf("Failed to parse client hello\n");
    freeTLSSession(&session);
    return 0;
  }
  printClientHello(session);
  if (!validate("Client Random", session.clientHello.random, exampleClientRandom, sizeof(exampleClientRandom))) {
    printf("Failed to parse client hello\n");
    freeTLSSession(&session);
    return 0;
  }
  printf("Attempting to process client hello\n");
  if (!processClientHello(&session)) {
    printf("Failed to process client hello\n");
    freeTLSSession(&session);
    return 0;
  }
  printf("\nAttempting to send server hello\n");
  if (!sendServerHello(&session)) {
    printf("Failed to send server hello\n");
    freeTLSSession(&session);
    return 0;
  }
  printServerHello(session);
  if (!validate("Server Hello", session.serverHello.raw, exampleServerHelloPacket, sizeof(exampleServerHelloPacket))) {
    printf("Failed to parse client hello\n");
    freeTLSSession(&session);
    return 0;
  }
  printf("\nAttempting to send server key exchange\n");
  if (!sendServerKeyExchange(&session)) {
      printf("Failed to send server key exchange\n");
      freeTLSSession(&session);
      return 0;
  }
  printf("\nAttempting to parse client key exchange\n");
  if (!parseTLSRecord(&session, exampleClientKeyExchangePacket, sizeof(exampleClientKeyExchangePacket))) {
      printf("Failed to parse client key exchange\n");
      freeTLSSession(&session);
      return 0;
  }
  printf("\nAttempting to calculate key exchange information\n");
  if (!processClientKeyExchange(&session)) {
      printf("Failed to process client key exchange\n");
      freeTLSSession(&session);
      return 0;
  }
  printKeyExchange(session);

  freeTLSSession(&session);
  return 0;
}
