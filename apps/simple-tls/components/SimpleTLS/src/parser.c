#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "tls.h"

// Still need to implement:
//int parseClientKeyExchange(struct TLSSession* session, const unsigned char* buf, int len);
//int parseClientChangeCipherSpec(struct TLSSession* session, const unsigned char* buf, int len);
//int parseClientHandshakeFinished(struct TLSSession* session, const unsigned char* buf, int len);
//int parseClientData(struct TLSSession* session, const unsigned char* buf, int len);
//int parseClientCloseNotify(struct TLSSession* session, const unsigned char* buf, int len);

int parseClientHello(struct TLSSession* session, const unsigned char* buf, int len) {
  if (len < 40) // Minimum length of a client hello.
    return 0;
  struct ClientHello* ch = &session->clientHello;
  ch->rawBytes = len;
  ch->raw = (unsigned char*) calloc(len, 1);
  memcpy(ch->raw, buf, len);

  int idx = 0;

  // First two bytes: ProtocolVersion
  // TLS 1.2 uses 3, 3
  ch->protocolVersion = (buf[idx]<<8) | buf[idx+1];
  idx += 2;

  // Next 32 bytes: Client Random
  memcpy(ch->random, buf+idx, 32);
  idx += 32;

  // Variable Length: SessionID
  // If nonzero, indicates resuming previous session
  int sessionIDLen = buf[idx++];
  ch->sessionIDBytes = sessionIDLen;
  if (idx+sessionIDLen > len)
    return 0;
  ch->sessionID = (unsigned char*) calloc(sessionIDLen+1, 1);
  if (sessionIDLen) {
    ch->sessionID = (unsigned char*) calloc(sessionIDLen, 1);
    memcpy(ch->sessionID, buf+idx, sessionIDLen);
  }
  idx += sessionIDLen;

  // Variable Length: supported cipher suites (each two bytes)
  // Watch out for GREASE compatibility checks.
  int cipherSuitesLen = (buf[idx]<<8) | buf[idx+1];
  ch->cipherSuiteBytes = cipherSuitesLen;
  idx += 2;
  if (idx+cipherSuitesLen > len)
    return 0;
  if (cipherSuitesLen) {
    ch->cipherSuites = (unsigned char*) calloc(cipherSuitesLen, 1);
    memcpy(ch->cipherSuites, buf + idx, cipherSuitesLen);
  }
  int foundSuite = 0;
  for (int i = 0; i < cipherSuitesLen; i += 2) {
    int cipherSuite = (buf[idx]<<8) | buf[idx+1];
    if (cipherSuite == CIPHER_SUITE)
      foundSuite = 1;
    idx += 2;
  }
  if (!foundSuite)
    return 0; // Only TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA implemented.

  // Variable Length: compression methods
  int compressionLen = buf[idx++];
  ch->compressionBytes = compressionLen;
  if (idx+compressionLen > len)
    return 0;
  if (compressionLen) {
    ch->compMethods = (unsigned char*) calloc(compressionLen, 1);
    memcpy(ch->compMethods, buf + idx, compressionLen);
  }
  // Never use compression.
  idx += compressionLen;

  // Variable Length: extensions
  // A server MUST accept ClientHello messages both with and without
  // the extensions field, and (as for all other messages) it MUST check
  // that the amount of data in the message precisely matches one of
  // these formats; if not, then it MUST send a fatal "decode_error" alert.
  int extensionsLen = (buf[idx]) | buf[idx+1];
  ch->extensionBytes = extensionsLen;
  idx += 2;
  if (idx+extensionsLen > len)
    return 0;
  if (extensionsLen) {
    ch->extensions = (unsigned char*) calloc(extensionsLen, 1);
    memcpy(ch->extensions, buf + idx, extensionsLen);
  }
  // TODO: parse extensions

  return 1;
}

int parseTLSHandshake(struct TLSSession* session, const unsigned char* buf, int len) {
    if (len < 4) // Length of a handshake header.
    return 0;

  // Parse header.
  int handshakeType = buf[0];
  int handshakeLength = (buf[1]<<16) | (buf[2]<<8) | buf[3];
  if (handshakeLength+4 > len)
    return 0;
  buf += 4;

  // Parse body.
  switch (handshakeType) {
    case 0:
      // Hello Request
      break;
    case 1:
      // Client Hello
      return parseClientHello(session, buf, handshakeLength);
    case 2:
      // Server Hello
      break;
    case 11:
      // Certificate
      break;
    case 12:
      // Server Key Exchange
      break;
    case 13:
      // Certificate Request
      break;
    case 14:
      // Server Hello Done
      break;
    case 15:
      // Certificate Verify
      break;
    case 16:
      // Client Key Exchange
      break;
    case 20:
      // Finished
      break;
    default:
      return 0;
  }

  return 1;
}

int parseTLSRecord(struct TLSSession* session, const unsigned char* buf, int len) {
  if (len < 5) // Length of a record header.
    return 0;

  // Parse header.
  int contentType = buf[0];
  int protocolVersion = (buf[1]<<8) | buf[2];
  int recordLength = (buf[3]<<8) | buf[4];
  if (recordLength+5 > len)
    return 0;
  if (protocolVersion != 0x0303) // Only TLS 1.2 supported for now.
    return 0;
  buf += 5;

  // Parse body.
  switch (contentType) {
    case 20:
      // Change Cipher Spec
      break;
    case 21:
      // Alert
      break;
    case 22:
      // Handshake
      return parseTLSHandshake(session, buf, recordLength);
    case 23:
      // Application Data
      break;
    default:
      return 0;
  }

  return 1;
}
