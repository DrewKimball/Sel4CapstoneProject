#include <string.h>
#include <stdio.h>
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
