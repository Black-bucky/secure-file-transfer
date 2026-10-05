#pragma once
#include <openssl/ssl.h>
#include <memory>
#include <string>
#include "AuthManager.h"

#ifdef _WIN32
#include <winsock2.h>
#else
#define SOCKET int
#endif

class ClientHandler {
public:
    ClientHandler(SOCKET socket, SSL_CTX* ctx, std::shared_ptr<AuthManager> authManager);
    ~ClientHandler();
    void handle();

private:
    SOCKET client_socket;
    SSL* ssl;
    std::shared_ptr<AuthManager> auth_manager;
    std::string logged_in_user;
    
    void processAuthRequest(const std::string& payload);
    void processUploadRequest(const std::string& payload);
    void processChunkData(const std::string& payload);
    void processDownloadRequest(const std::string& payload);
    
    void sendResponse(int type, const std::string& payload);
};
