#include <stdlib.h>
#include <stdio.h>
#include <string.h>

struct tlsServer {
  char* serverPrivateKey;
  char* sslCertificate;
  char* chosenCipherSuite;
  char* serverRandom, clientRandom;
  char* serverDHParam, clientDHParam;
  char* premasterKey;
  char* sessionKey;
}

void initServer(tlsServer* server) {
  server->sslCertificate = "blah"; // TODO: fill this out.
  server->serverRandom = "blah"; // TODO: fill this out.
  server->serverDHParam = "blah"; // TODO: fill this out.
}

void cleanupServer(tlsServer* server) {
  //TODO
}

const char* supportedCipherSuite = "DHE-RSA-AES256-SHA256";

int receiveClientHello(tlsServer* server, char* tlsVersion, char* clientRandom, char* supportedSuites) {
  if (strncmp(tlsVersion, "1.2", 3)) {
    printf("unsupported TLS version: %s\n", tlsVersion);
    return 0;
  }
  server->clientRandom = strndup(clientRandom, 32); // Client random is always 32 bytes.
  server->chosenCipherSuite = "DHE-RSA-AES256-SHA256"; // Always use this one for now.
  if (strncmp(supportedCipherSuite, supportedSuites, strlen(supportedCipherSuite)) == 0) {
    printf("failed to choose cipher suite\n");
    return 0;
  } 

  printf("\nCLIENT HELLO\n");
  printf("Receive TLS Version: %s\n", tlsVersion);
  printf("Receive Client Random: %s\n", clientRandom);
  printf("Receive Client Supported Suites: %s\n", supportedSuites);

  return 1;
}

void generateDigitalSignature(tlsServer* server) {
  // TODO: actually implement this.
  server->digitalSignature = calloc(1024, 1);
  strcat(digitalSignature, server->clientRandom);
  strcat(digitalSigature, server->serverRandom);
  strcat(digitalSignature, server->serverDHParam);
  // Encrypt with server private key.
}

void sendServerHello(tlsServer* server) {
  generateDigitalSignature(server);

  printf("\nSERVER HELLO\n);
  printf("Send Server SSL Certificate: %s\n", server->sslCertificate);
  printf("Send Server Selected Cipher Suite: %s\n", server->chosenCipherSuite);
  printf("Server Random: %s\n", server->serverRandom);
  printf("Server DH Param: %s\n", server->serverDHParam);
  printf("Send Server Digital Signature: %s\n", server->digitalSignature);
}

void receiveClientDHParam(tlsServer* server, char* clientDHParam) {
  server->clientDHParam = strdup(clientDHParam);
}

void generatePremaster(tlsServer* server) {

}

void generateSessionKey(tlsServer* server) {

}

// Simulation of a TLS handshake.
int run() {
  tlsServer server;

  // Receive client hello.
  int tlsVersion = 1.2;
  char* clientRandom = "336b4cd035ae4765f6323b279f36930dde15341bcd777d003401cb47ff2564e8";
  char* supportedCipherSuites = "DHE-RSA-AES256-SHA256";
  if (!receiveClientHello(&server, tlsVersion, clientRandom, supportedCipherSuites))
    return 0;

  // Send server hello.
  sendServerHello(&server);

  // Receive client DH param.
  char& clientDHParam = "b34005aeafb75f8d2c5be114f480fbfe068d59c6bb3bfecf727f6e82537eec6c";
  receiveClientDHParam(&server, clientDHParam);

  // Calculate premaster using DH params.
  calculatePremaster(&server);

  // Calculate session key using premaster secret, client random, and server random.
  calculateSessionKey(&server);

  // Receive client finish. TODO: replace the finished message.
  char* clientFinished = "8e63f590147087a5e46b7d79235b44964e870644fef2065da1ed5ae9ce31b1fa";

  // Send server finish.
  sendServerFinished(&server);

  // Handshake is now complete.
  printf("Handshake complete!\n"); 
  return 0;
}
