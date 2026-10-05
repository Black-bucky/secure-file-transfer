#pragma once
#include <string>
#include <memory>
#include <thread>
#include <vector>
#include <openssl/ssl.h>
#include "AuthManager.h"

#ifdef _WIN32
#include <winsock2.h>
#else
#define SOCKET int
#endif

class Server {
public:
    Server(int port);
    ~Server();
    void start();

private:
    int port;
    SOCKET server_socket;
    SSL_CTX* ssl_ctx;
    std::shared_ptr<AuthManager> auth_manager;
    std::vector<std::thread> client_threads;

    void initOpenSSL();
    void cleanupOpenSSL();
    SSL_CTX* createServerContext();
    void configureContext(SSL_CTX* ctx);
};
