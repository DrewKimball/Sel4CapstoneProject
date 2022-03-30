#include <string.h>
#include "tls.h"

// TODO: Hard-coded for now, but should be changed later.
const unsigned char SERVER_RANDOM[] = {
        0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
        0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
        0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f
};
#define SESSION_ID_BYTES 0
const unsigned char SESSION_ID[] = {0x00};

// Still need to implement:
//int processClientHandshakeFinished(struct TLSSession* session);
//int processClientData(struct TLSSession* session);
//int processClientCloseNotify(struct TLSSession* session);

int processClientHello(struct TLSSession* session) {
  // In the future, some or all of these hard-coded fields
  // should be determined dynamically.
  struct ServerHello* sh = &session->serverHello;
  sh->protocolVersion = TLS_VERSION;
  memcpy(sh->random, SERVER_RANDOM, 32);
  sh->sessionIDBytes = SESSION_ID_BYTES;
  sh->sessionID = (unsigned char*) calloc(sh->sessionIDBytes, 1);
  memcpy(sh->sessionID, SESSION_ID, SESSION_ID_BYTES);
  sh->cipherSuite = CIPHER_SUITE;
  sh->compressionMethod = COMPRESSION_METHOD;
  
  // Not handling extensions for now.
  sh->extensionBytes = 0;

  return 1;
}
