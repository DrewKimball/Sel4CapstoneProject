#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const unsigned char exampleClientHelloPacket[] = {
    0x16, 0x03, 0x01, 0x00, 0xa5, 0x01, 0x00, 0x00, 0xa1, 0x03, 
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

int parseClientHello(TLSSession* session, const unsigned char* buf, int len) {
  if (len < 40) // Minimum length of a client hello.
    return 0;
  session->clientHello.rawBytes = len;
  memcpy(session->clientHello.raw, buf, len);

  int idx = 0;

  // First two bytes: ProtocolVersion
  // TLS 1.2 uses 3, 3
  session->clientHello.protocolVersion = (buf[idx]<<1) | buf[idx+1];
  idx += 2;

  // Next 32 bytes: Client Random
  memcpy(session->clientHello.random, buf+idx, 32);
  idx += 32;

  // Variable Length: SessionID
  // If nonzero, indicates resuming previous session
  int sessionIDLen = buf[idx++];
  session->clientHello.sessionIDBytes = sessionIDLen;
  if (idx+sessionIDLen > len)
    return 0;
  session->clientHello.sessionID = (unsigned char*) calloc(sessionIDLen+1, 1);
  if (sessionIDLen) {
    memcpy(session->clientHello.sessionID, buf+idx, sessionIDLen);
  }
  idx += sessionIDLen;

  // Variable Length: supported cipher suites (each two bytes)
  // Watch out for GREASE compatibility checks.
  int cipherSuitesLen = (buf[idx]<<1) | buf[idx+1];
  session->clientHello.cipherSuiteBytes = cipherSuitesLen;
  idx += 2;
  if (idx+cipherSuitesLen > len)
    return 0;
  if (cipherSuitesLen)
    memcpy(session->clientHello.cipherSuites, buf+idx, cipherSuitesLen);
  int foundSuite = 0;
  for (int i = 0; i < cipherSuitesLen; i += 2) {
    int cipherSuite = (buf[idx]<<1) | buf[idx+1];
    if (cipherSuite == CIPHER_SUITE)
      foundSuite = 1;
    idx += 2;
  }
  if (!foundSuite)
    return 0; // Only TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA implemented.

  // Variable Length: compression methods
  int compressionLen = buf[idx++];
  session->clientHello.compressionBytes = compressionLen;
  if (idx+compressionLen > len)
    return 0;
  if (compressionLen)
    memcpy(session->clientHello.compMethods, buf+idx, compressionLen);
  // Never use compression.
  idx += compressionLen;

  // Variable Length: extensions
  // A server MUST accept ClientHello messages both with and without
  // the extensions field, and (as for all other messages) it MUST check
  // that the amount of data in the message precisely matches one of
  // these formats; if not, then it MUST send a fatal "decode_error" alert.
  int extensionsLen = (buf[idx]) | buf[idx+1];
  session->clientHello.extensionBytes = extensionsLen;
  idx += 2;
  if (idx+extensionsLen > len)
    return 0;
  if (extensionsLen)
    memcpy(session->clientHello.extensions, buf+idx, extensionsLen);
  // TODO: parse extensions

  return 1;
}

int parseTLSHandshake(TLSSession* session, const unsigned char* buf, int len) {
  if (len < 4) // Length of a handshake header.
    return 0;

  // Parse header.
  int handshakeType = buf[0];
  int handshakeLength = (buf[1]<<2) | (buf[2]<<1) | buf[3];
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

int parseTLSRecord(TLSSession* session, const unsigned char* buf, int len) {
  if (len < 5) // Length of a record header.
    return 0;

  // Parse header.
  int contentType = buf[0];
  int protocolVersion = (buf[1]<<1) | buf[2];
  int recordLength = (buf[3]<<1) | buf[4];
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
      return parseTLSHandshake(buf, recordLength);
    case 23:
      // Application Data
      break;
    default:
      return 0;
  }

  return 1;
}

int main() {
    printf("\nHERE\n");
    return 0;
}
