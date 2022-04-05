#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "tomcrypt.h"

#define DEBUG 1
#define TLS_VERSION 0x0303      // This is a TLS 1.2 implementation
#define CIPHER_SUITE 0xC013     // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
#define COMPRESSION_METHOD 0x00 // No compression

struct ClientHello {
  int protocolVersion;         // 2 bytes, (3, 3) for TLS 1.2
  unsigned char* random;       // 32 bytes
  int sessionIDBytes;          // 1 byte
  unsigned char* sessionID;    // Variable length
  int cipherSuiteBytes;        // 2 bytes
  unsigned char* cipherSuites; // Variable length
  int compressionBytes;        // 2 bytes
  unsigned char* compMethods;  // Variable length
  int extensionBytes;          // 2 bytes
  unsigned char* extensions;   // Variable length
  int rawBytes;                // 2 bytes
  unsigned char* raw;          // Variable length
};

struct ServerHello {
  int protocolVersion;       // 2 bytes, (3, 3) for TLS 1.2
  unsigned char* random;     // 32 bytes
  int sessionIDBytes;        // 1 byte
  unsigned char* sessionID;  // Variable length
  int cipherSuite;           // 2 bytes
  int compressionMethod;     // 1 byte
  int extensionBytes;        // 2 bytes
  unsigned char* extensions; // Variable length;
  int rawBytes;              // 2 bytes
  unsigned char* raw;        // Variable length
};

struct KeyExchange {
  curve25519_key serverDHPair;    // 32 bytes
  unsigned char* serverDHPrivate; // 32 bytes
  unsigned char* serverDHPublic;  // 32 bytes
  unsigned char* clientDHPublic;  // 32 bytes
  unsigned char* premasterSecret; // 32 bytes
  unsigned char* masterSecret;    // 48 bytes
  unsigned char* clientMACKey;    // 20 bytes
  unsigned char* serverMACKey;    // 20 bytes
  unsigned char* clientSymKey;    // 16 bytes
  unsigned char* serverSymKey;    // 16 bytes
  unsigned char* clientIV;        // 16 bytes
  unsigned char* serverIV;        // 16 bytes
  int rawBytes;
  unsigned char* raw;
};

struct TLSSession {
  prng_state* prng;
  unsigned char* serverRSAPrivate;  // 32 bytes
  unsigned char* serverRSAPublic;   // 32 bytes
  struct ClientHello clientHello;
  struct ServerHello serverHello;
  int serverCertificateBytes;       // 2 bytes
  unsigned char* serverCertificate; // Variable length
  struct KeyExchange keyExchange;
};

// Returns an uninitialized TLSSession with fixed-size
// allocations performed up-front.
struct TLSSession newTLSSession(prng_state* prng) {
  struct TLSSession session;
  struct ClientHello* ch = &session.clientHello;
  struct ServerHello* sh = &session.serverHello;
  struct KeyExchange* ks = &session.keyExchange;
  session.prng = prng;

  // Allocate fixed-size buffers.
  session.serverRSAPrivate = (unsigned char*) calloc(32, 1);
  session.serverRSAPublic  = (unsigned char*) calloc(32, 1);
  ch->random               = (unsigned char*) calloc(32, 1);
  sh->random               = (unsigned char*) calloc(32, 1);
  ks->serverDHPrivate      = (unsigned char*) calloc(32, 1);
  ks->serverDHPublic       = (unsigned char*) calloc(32, 1);
  ks->clientDHPublic       = (unsigned char*) calloc(32, 1);
  ks->premasterSecret      = (unsigned char*) calloc(32, 1);
  ks->masterSecret         = (unsigned char*) calloc(48, 1);
  ks->clientMACKey         = (unsigned char*) calloc(20, 1);
  ks->serverMACKey         = (unsigned char*) calloc(20, 1);
  ks->clientSymKey         = (unsigned char*) calloc(16, 1);
  ks->serverSymKey         = (unsigned char*) calloc(16, 1);
  ks->clientIV             = (unsigned char*) calloc(16, 1);
  ks->serverIV             = (unsigned char*) calloc(16, 1);

  // Set variable-length buffers to null to avoid freeing unallocated memory later.
  session.serverCertificate = NULL;
  ch->sessionID             = NULL;
  ch->cipherSuites          = NULL;
  ch->compMethods           = NULL;
  ch->extensions            = NULL;
  ch->raw                   = NULL;
  sh->sessionID             = NULL;
  sh->extensions            = NULL;
  sh->raw                   = NULL;

  return session;
}

// Frees all allocated fields of the TLSSession.
void freeTLSSession(struct TLSSession* session) {
  free(session->serverRSAPrivate);
  free(session->serverRSAPublic);
  free(session->clientHello.random);
  free(session->clientHello.sessionID);
  free(session->clientHello.cipherSuites);
  free(session->clientHello.compMethods);
  free(session->clientHello.extensions);
  free(session->clientHello.raw);
  free(session->serverHello.random);
  free(session->serverHello.sessionID);
  free(session->serverHello.extensions);
  free(session->serverHello.raw);
  free(session->serverCertificate);
  free(session->keyExchange.serverDHPrivate);
  free(session->keyExchange.serverDHPublic);
  free(session->keyExchange.clientDHPublic);
  free(session->keyExchange.premasterSecret);
  free(session->keyExchange.masterSecret);
  free(session->keyExchange.clientMACKey);
  free(session->keyExchange.serverMACKey);
  free(session->keyExchange.clientSymKey);
  free(session->keyExchange.serverSymKey);
  free(session->keyExchange.clientIV);
  free(session->keyExchange.serverIV);
}

// =================================================================
// Parser
// =================================================================

// Still need to implement:
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

int parseClientKeyExchange(struct TLSSession* session, const unsigned char* buf, int len) {
  if (len < 33) // Length of public key plus a byte to specify the length.
    return 0;

  // Parse key exchange message.
  if (buf[0] != 0x20)
    return 0; // Expecting 32 byte public key.
  memcpy(session->keyExchange.clientDHPublic, buf+1, 32);

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
      return parseClientKeyExchange(session, buf, handshakeLength);
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

// =================================================================
// Server
// =================================================================

// Functions for sending TLS messages to the client.
//int sendServerCertificate(struct TLSSession* session);
//int sendServerHelloDone(struct TLSSession* session);
//int sendServerCipherChangeSpec(struct TLSSession* session);
//int sendServerHandshakeFinished(struct TLSSession* session);
//int sendServerData(struct TLSSession* session);

int sendServerHello(struct TLSSession* session) {
  struct ServerHello* sh = &session->serverHello;
  int helloBytes = sh->sessionIDBytes + sh->extensionBytes + 40;
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

int sendServerKeyExchange(struct TLSSession* session) {
  struct KeyExchange* ke = &session->keyExchange;
  struct ServerHello* sh = &session->serverHello;
  int exchangeBytes = 36;
  int handshakeBytes = exchangeBytes + 4; // Add handshake header.
  int totalBytes = handshakeBytes + 5; // Add record header.
  ke->rawBytes = totalBytes;
  ke->raw = (unsigned char*) calloc(totalBytes, 1);
  int idx = 0;

  // Record Header
  ke->raw[idx++] = 0x16; // Handshake record.
  ke->raw[idx++] = (sh->protocolVersion >> 8) & 0xff;
  ke->raw[idx++] = sh->protocolVersion & 0xff;
  ke->raw[idx++] = (handshakeBytes >> 8) & 0xff;
  ke->raw[idx++] = handshakeBytes & 0xff;

  // Handshake Header
  ke->raw[idx++] = 0x0c; // Key Exchange.
  ke->raw[idx++] = (exchangeBytes >> 16) & 0xff;
  ke->raw[idx++] = (exchangeBytes >> 8) & 0xff;
  ke->raw[idx++] = exchangeBytes & 0xff;

  // Key Exchange
  ke->raw[idx++] = 0x03; // named_curve
  ke->raw[idx++] = 0x00; // Curve x25519
  ke->raw[idx++] = 0x1d; // Curve x25519
  memcpy(ke->raw, ke->serverDHPublic, 32);
  idx += 32;

  // TODO: should send the raw over the network!
  return 1;
}

// =================================================================
// Processor
// =================================================================

// TODO: Hard-coded for now, but should be changed later.
const unsigned char SERVER_RANDOM[] = {
        0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
        0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
        0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f
};
#define SESSION_ID_BYTES 0
const unsigned char SESSION_ID[] = {0x00};
#define EXTENSION_BYTES 5
// Indicates a new message that is not being renegotiated.
const unsigned char EXTENSIONS[] = {0xff, 0x01, 0x00, 0x01, 0x00};

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

  // Not handling extensions for now, except the renegotiation extension.
  sh->extensionBytes = EXTENSION_BYTES;
  sh->extensions = (unsigned char*) calloc(EXTENSION_BYTES, 1);
  memcpy(sh->extensions, EXTENSIONS, EXTENSION_BYTES);

  // Generate the public-private key pair for Diffie-Hellman.
  struct KeyExchange* ke = &session->keyExchange;
  int prngDescIdx = find_prng("sober128");
  if (prngDescIdx == -1)
    return 0;
  if (x25519_make_key(session->prng, prngDescIdx, &ke->serverDHPair) != CRYPT_OK)
    return 0;
  unsigned long int dhKeyLen = 32;
  if (x25519_export(ke->serverDHPrivate, &dhKeyLen, PK_PRIVATE, &ke->serverDHPair) != CRYPT_OK)
    return 0;
  if (x25519_export(ke->serverDHPublic, &dhKeyLen, PK_PUBLIC, &ke->serverDHPair) != CRYPT_OK)
    return 0;
  return 1;
}

int processClientKeyExchange(struct TLSSession* session) {
  // Now that the client DH public key has been received, a shared secret
  // can be calculated.
  struct ClientHello* ch = &session->clientHello;
  struct ServerHello* sh = &session->serverHello;
  struct KeyExchange* ke = &session->keyExchange;

  // Premaster Secret
  unsigned long int premasterLen = 32;
  curve25519_key clientKey;
  if (x25519_import_raw(ke->clientDHPublic, 32, PK_PUBLIC, &clientKey) != CRYPT_OK)
    return 0;
  if (x25519_shared_secret(&ke->serverDHPair, &clientKey, ke->premasterSecret, &premasterLen) != CRYPT_OK)
    return 0;

  // Master Secret
  int hash = find_hash("sha256");
  if (hash == -1)
    return 0;
  unsigned char buf[128], seed[80], a1[32], a2[32], p1[32], p2[32];
  strcpy((char*)seed, "master secret");
  memcpy(seed+13, ch->random, 32);
  memcpy(seed+45, sh->random, 32); // seed is 77 bytes
  unsigned long int keylen = 32;
  unsigned long int outlen = 32;
  if (hmac_memory(hash, ke->premasterSecret, keylen, seed, 77, a1, &outlen) != CRYPT_OK)
    return 0;
  if (hmac_memory(hash, ke->premasterSecret, keylen, a1, 77, a2, &outlen) != CRYPT_OK)
    return 0;
  memcpy(buf, a1, 32);
  memcpy(buf+32, seed, 77); // 109 bytes
  if (hmac_memory(hash, ke->premasterSecret, keylen, buf, 109, p1, &outlen) != CRYPT_OK)
    return 0;
  memcpy(buf, a2, 32);
  if (hmac_memory(hash, ke->premasterSecret, keylen, buf, 109, p2, &outlen) != CRYPT_OK)
    return 0;
  memcpy(ke->masterSecret, p1, 32);
  memcpy(ke->masterSecret+32, p2, 16);

  // Encryption Keys
  keylen = 48;
  unsigned char a3[32], a4[32], p3[32], p4[32], p[128];
  memset(seed, 0, 80);
  strcpy((char*)seed, "key expansion");
  memcpy(seed+13, sh->random, 32);
  memcpy(seed+45, ch->random, 32); // seed is 77 bytes
  if (hmac_memory(hash, ke->masterSecret, keylen, seed, 77, a1, &outlen) != CRYPT_OK)
    return 0;
  if (hmac_memory(hash, ke->masterSecret, keylen, a1, 32, a2, &outlen) != CRYPT_OK)
    return 0;
  if (hmac_memory(hash, ke->masterSecret, keylen, a2, 32, a3, &outlen) != CRYPT_OK)
    return 0;
  if (hmac_memory(hash, ke->masterSecret, keylen, a3, 32, a4, &outlen) != CRYPT_OK)
    return 0;
  memset(buf, 0, 128);
  memcpy(buf, a1, 32);
  memcpy(buf+32, seed, 77); // 109 bytes
  if (hmac_memory(hash, ke->masterSecret, keylen, buf, 109, p1, &outlen) != CRYPT_OK)
    return 0;
  memcpy(buf, a2, 32);
  if (hmac_memory(hash, ke->masterSecret, keylen, buf, 109, p2, &outlen) != CRYPT_OK)
    return 0;
  memcpy(buf, a3, 32);
  if (hmac_memory(hash, ke->masterSecret, keylen, buf, 109, p3, &outlen) != CRYPT_OK)
    return 0;
  memcpy(buf, a4, 32);
  if (hmac_memory(hash, ke->masterSecret, keylen, buf, 109, p4, &outlen) != CRYPT_OK)
    return 0;
  memcpy(p, p1, 32);
  memcpy(p+32, p2, 32);
  memcpy(p+64, p3, 32);
  memcpy(p+96, p4, 32);
  memcpy(ke->clientMACKey, p, 20);
  memcpy(ke->serverMACKey, p+20, 20);
  memcpy(ke->clientSymKey, p+40, 16);
  memcpy(ke->serverSymKey, p+56, 16);
  memcpy(ke->clientIV, p+72, 16);
  memcpy(ke->serverIV, p+88, 16);

  return 1;
}

// =================================================================
// Test
// =================================================================

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
