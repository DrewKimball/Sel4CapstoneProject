#include <stdlib.h>
#include <string.h>
#include "tls.h"

// Functions for sending TLS messages to the client.
//int sendServerCertificate(struct TLSSession* session);
//int sendServerKeyExchange(struct TLSSession* session);
//int sendServerHelloDone(struct TLSSession* session);
//int sendServerCipherChangeSpec(struct TLSSession* session);
//int sendServerHandshakeFinished(struct TLSSession* session);
//int sendServerData(struct TLSSession* session);

int sendServerHello(struct TLSSession* session) {
  struct ServerHello* sh = &session->serverHello;
  int helloBytes = sh->sessionIDBytes + sh->extensionBytes + 42;
  int handshakeBytes = helloBytes + 4; // Add handshake header.
  int totalBytes = handshakeBytes + 5; // Add record header.
  sh->rawBytes = totalBytes;
  sh->raw = (unsigned char*) calloc(totalBytes, 1);
  int idx = 0;

  // Record Header
  sh->raw[idx++] = 0x16; // Handshake record.
  sh->raw[idx++] = (sh->protocolVersion >> 8) & 0xff;
  sh->raw[idx++] = sh->protocolVersion & 0xff;
  sh->raw[idx++] = (handshakeBytes >> 8) & 0xff;
  sh->raw[idx++] = handshakeBytes & 0xff;

  // Handshake Header
  sh->raw[idx++] = 0x02; // Server Hello.
  sh->raw[idx++] = (helloBytes >> 16) & 0xff;
  sh->raw[idx++] = (helloBytes >> 8) & 0xff;
  sh->raw[idx++] = helloBytes & 0xff;

  // Server Hello
  sh->raw[idx++] = (sh->protocolVersion >> 8) & 0xff;
  sh->raw[idx++] = (sh->protocolVersion) & 0xff;
  memcpy((sh->raw)+idx, sh->random, 32);
  idx += 32;
  sh->raw[idx++] = (sh->sessionIDBytes) & 0xff;
  memcpy(sh->raw+idx, sh->sessionID, sh->sessionIDBytes);
  idx += sh->sessionIDBytes;
  sh->raw[idx++] = (sh->cipherSuite >> 8) & 0xff;
  sh->raw[idx++] = (sh->cipherSuite) & 0xff;
  sh->raw[idx++] = (sh->compressionMethod) & 0xff;
  sh->raw[idx++] = (sh->extensionBytes >> 8) & 0xff;
  sh->raw[idx++] = (sh->extensionBytes) & 0xff;
  memcpy(sh->raw+idx, sh->extensions, sh->extensionBytes);

  // TODO: should send the raw over the network!
  return 1;
}
