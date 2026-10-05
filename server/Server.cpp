#include "Server.h"
#include "ClientHandler.h"
#include <iostream>
#include <stdexcept>

#ifdef _WIN32
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#endif

Server::Server(int port) : port(port) {
    initOpenSSL();
    ssl_ctx = createServerContext();
    configureContext(ssl_ctx);
    auth_manager = std::make_shared<AuthManager>("super_secret_jwt_key_12345");
}

Server::~Server() {
    SSL_CTX_free(ssl_ctx);
    cleanupOpenSSL();
#ifdef _WIN32
    closesocket(server_socket);
    WSACleanup();
#else
    close(server_socket);
#endif
}

void Server::initOpenSSL() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void Server::cleanupOpenSSL() {
    EVP_cleanup();
}

SSL_CTX* Server::createServerContext() {
    const SSL_METHOD* method = TLS_server_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) {
        throw std::runtime_error("Unable to create SSL context");
    }
    return ctx;
}

void Server::configureContext(SSL_CTX* ctx) {
    // Note: You must generate server.crt and server.key
    // openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes
    if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0) {
        std::cerr << "Warning: Cannot load server.crt\n";
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0) {
        std::cerr << "Warning: Cannot load server.key\n";
    }
}

void Server::start() {
#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        throw std::runtime_error("Failed to init Winsock");
    }
#endif

    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    
    sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_socket, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        throw std::runtime_error("Unable to bind");
    }

    if (listen(server_socket, 10) < 0) {
        throw std::runtime_error("Unable to listen");
    }

    std::cout << "Server listening on port " << port << "...\n";

    while (true) {
        sockaddr_in client_addr;
#ifdef _WIN32
        int len = sizeof(client_addr);
#else
        socklen_t len = sizeof(client_addr);
#endif
        SOCKET client = accept(server_socket, (struct sockaddr*)&client_addr, &len);
        if (client < 0) {
            std::cerr << "Unable to accept\n";
            continue;
        }

#ifdef _WIN32
        DWORD timeout = 10000;
#else
        struct timeval timeout;
        timeout.tv_sec = 10;
        timeout.tv_usec = 0;
#endif
        setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
        setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));

        client_threads.emplace_back([this, client]() {
            ClientHandler handler(client, ssl_ctx, auth_manager);
            handler.handle();
        });
    }
}
