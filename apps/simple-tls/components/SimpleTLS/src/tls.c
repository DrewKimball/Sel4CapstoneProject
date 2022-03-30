#include <stdlib.h>
#include "tls.h"

// Returns an uninitialized TLSSession with fixed-size
// allocations performed up-front.
TLSSession newTLSSession() {
  struct TLSSession session;
  session.serverRSAPrivate            = (unsigned char*) calloc(32, 1);
  session.serverRSAPublic             = (unsigned char*) calloc(32, 1);
  session.clientHello.random          = (unsigned char*) calloc(32, 1);
  session.serverHello.random          = (unsigned char*) calloc(32, 1);
  session.keyExchange.serverDHPrivate = (unsigned char*) calloc(32, 1);
  session.keyExchange.serverDHPublic  = (unsigned char*) calloc(32, 1);
  session.keyExchange.clientDHPublic  = (unsigned char*) calloc(32, 1);
  session.keyExchange.premasterSecret = (unsigned char*) calloc(32, 1);
  session.keyExchange.masterSecret    = (unsigned char*) calloc(32, 1);
  session.keyExchange.clientMACKey    = (unsigned char*) calloc(32, 1);
  session.keyExchange.serverMACKey    = (unsigned char*) calloc(32, 1);
  session.keyExchange.clientSymKey    = (unsigned char*) calloc(32, 1);
  session.keyExchange.serverSymKey    = (unsigned char*) calloc(32, 1);
  session.keyExchange.clientIV        = (unsigned char*) calloc(32, 1);
  session.keyExchange.serverIV        = (unsigned char*) calloc(32, 1);
}

// Frees all allocated fields of the TLSSession.
void freeTLSSession(TLSSession* session) {
  free(session.serverRSAPrivate);
  free(session.serverRSAPublic);
  free(session.clientHello.random);
  free(session.clientHello.sessionID);
  free(session.clientHello.cipherSuites);
  free(session.clientHello.compMethods);
  free(session.clientHello.extensions);
  free(session.clientHello.raw);
  free(session.serverHello.random);
  free(session.serverHello.sessionID);
  free(session.serverHello.extensions);
  free(session.serverHello.raw);
  free(session.serverCertificate);
  free(session.keyExchange.serverDHPrivate);
  free(session.keyExchange.serverDHPublic);
  free(session.keyExchange.clientDHPublic);
  free(session.keyExchange.premasterSecret);
  free(session.keyExchange.masterSecret);
  free(session.keyExchange.clientMACKey);
  free(session.keyExchange.serverMACKey);
  free(session.keyExchange.clientSymKey);
  free(session.keyExchange.serverSymKey);
  free(session.keyExchange.clientIV);
  free(session.keyExchange.serverIV);
}
