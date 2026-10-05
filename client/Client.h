#pragma once
#include <string>
#include <openssl/ssl.h>

#ifdef _WIN32
#include <winsock2.h>
#else
#define SOCKET int
#endif

class Client {
public:
    Client(const std::string& host, int port);
    ~Client();
    bool connect();
    bool authenticate(const std::string& username, const std::string& password);
    void uploadFile(const std::string& path);
    void downloadFile(const std::string& filename);

private:
    std::string host;
    int port;
    SOCKET client_socket;
    SSL_CTX* ssl_ctx;
    SSL* ssl;
    std::string jwt_token;

    void initOpenSSL();
    void cleanupOpenSSL();
    SSL_CTX* createClientContext();
    
    void sendRequest(int type, const std::string& payload);
};
