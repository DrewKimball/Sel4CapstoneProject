#include <stdlib.h>
#include "tls.h"

// Returns an uninitialized TLSSession with fixed-size
// allocations performed up-front.
struct TLSSession newTLSSession() {
  struct TLSSession session;
  struct ClientHello* ch = &session.clientHello;
  struct ServerHello* sh = &session.serverHello;
  struct KeyExchange* ks = &session.keyExchange;

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
