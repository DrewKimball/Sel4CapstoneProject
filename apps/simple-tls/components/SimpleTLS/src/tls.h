#include <stdlib.h>

#DEFINE TLS_VERSION 0x0303  // This is a TLS 1.2 implementation
#DEFINE CIPHER_SUITE 0xC013 // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA

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
}

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
}

struct KeyExchange {
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
}

struct TLSSession {
  unsigned char* serverRSAPrivate;  // 32 bytes
  unsgined char* serverRSAPublic;   // 32 bytes
  struct ClientHello clientHello;
  struct ServerHello serverHello;
  int serverCertificateBytes;       // 2 bytes
  unsigned char* serverCertificate; // Variable length
  struct KeyExchange keyExchange;
}

// Returns an uninitialized TLSSession with fixed-size
// allocations performed up-front.
TLSSession newTLSSession();

// Frees all allocated fields of the TLSSession.
void freeTLSSession(TLSSession* session);
