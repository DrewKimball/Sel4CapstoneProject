#include <stdlib.h>
#include <tomcrypt.h>

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
struct TLSSession newTLSSession(prng_state* prng);

// Frees all allocated fields of the TLSSession.
void freeTLSSession(struct TLSSession* session);

// Functions for parsing TLS messages received from the client.
int parseTLSRecord(struct TLSSession* session, const unsigned char* buf, int len);
int parseTLSHandshake(struct TLSSession* session, const unsigned char* buf, int len);
int parseClientHello(struct TLSSession* session, const unsigned char* buf, int len);
int parseClientKeyExchange(struct TLSSession* session, const unsigned char* buf, int len);
int parseClientChangeCipherSpec(struct TLSSession* session, const unsigned char* buf, int len);
int parseClientHandshakeFinished(struct TLSSession* session, const unsigned char* buf, int len);
int parseClientData(struct TLSSession* session, const unsigned char* buf, int len);
int parseClientCloseNotify(struct TLSSession* session, const unsigned char* buf, int len);

// Functions for calculating session variables after messages
// have been received from the client.
int processClientHello(struct TLSSession* session);
int processClientKeyExchange(struct TLSSession* session);
int processClientHandshakeFinished(struct TLSSession* session);
int processClientData(struct TLSSession* session);
int processClientCloseNotify(struct TLSSession* session);

// Functions for sending TLS messages to the client.
int sendServerHello(struct TLSSession* session);
int sendServerCertificate(struct TLSSession* session);
int sendServerKeyExchange(struct TLSSession* session);
int sendServerHelloDone(struct TLSSession* session);
int sendServerCipherChangeSpec(struct TLSSession* session);
int sendServerHandshakeFinished(struct TLSSession* session);
int sendServerData(struct TLSSession* session);
