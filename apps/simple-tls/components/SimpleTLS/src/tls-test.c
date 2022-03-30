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

// Should run through a mock TLS transaction with data from https://tls.ulfheim.net
int run(void) {
  struct TLSSession session = newTLSSession();

  printf("Attempting to parse client hello\n");
  if (!parseTLSRecord(&session, exampleClientHelloPacket, 170)) {
    printf("Failed to parse client hello\n");
    freeTLSSession(&session);
    return 0;
  }
  printClientHello(session);

  printf("Attempting to process client hello\n");
  if (!processClientHello(&session)) {
    printf("Failed to process client hello\n");
    freeTLSSession(&session);
    return 0;
  }
  printf("Attempting to send server hello\n");
  if (!sendServerHello(&session)) {
    printf("Failed to send server hello\n");
    freeTLSSession(&session);
    return 0;
  }
  printServerHello(session);

  freeTLSSession(&session);
  return 0;
}
