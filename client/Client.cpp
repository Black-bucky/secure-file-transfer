#include "Client.h"
#include "../common/Protocol.h"
#include "../common/Utils.h"
#include <iostream>
#include <stdexcept>
#include <nlohmann/json.hpp>

#ifdef _WIN32
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#endif

using json = nlohmann::json;

Client::Client(const std::string& host, int port) : host(host), port(port) {
    initOpenSSL();
    ssl_ctx = createClientContext();
    ssl = nullptr;
}

Client::~Client() {
    if (ssl) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    if (ssl_ctx) {
        SSL_CTX_free(ssl_ctx);
    }
    cleanupOpenSSL();
#ifdef _WIN32
    closesocket(client_socket);
    WSACleanup();
#else
    close(client_socket);
#endif
}

void Client::initOpenSSL() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void Client::cleanupOpenSSL() {
    EVP_cleanup();
}

SSL_CTX* Client::createClientContext() {
    const SSL_METHOD* method = TLS_client_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) {
        throw std::runtime_error("Unable to create SSL context");
    }
    return ctx;
}

bool Client::connect() {
#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif

    client_socket = socket(AF_INET, SOCK_STREAM, 0);
    
    sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    
    // Resolve hostname
    struct hostent* host_entry = gethostbyname(host.c_str());
    if (!host_entry) {
        std::cerr << "Cannot resolve hostname\n";
        return false;
    }
    addr.sin_addr.s_addr = *((unsigned long*)host_entry->h_addr);

    if (::connect(client_socket, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        std::cerr << "Connect failed\n";
        return false;
    }

#ifdef _WIN32
    DWORD timeout = 10000;
#else
    struct timeval timeout;
    timeout.tv_sec = 10;
    timeout.tv_usec = 0;
#endif
    setsockopt(client_socket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
    setsockopt(client_socket, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));

    ssl = SSL_new(ssl_ctx);
    SSL_set_fd(ssl, client_socket);

    if (SSL_connect(ssl) <= 0) {
        std::cerr << "SSL Connect failed\n";
        return false;
    }

    std::cout << "Connected to server using TLS\n";
    return true;
}

void Client::sendRequest(int type, const std::string& payload) {
    Protocol::Header header;
    header.type = static_cast<Protocol::MessageType>(type);
    header.payloadSize = payload.size();

    Utils::writeExact(ssl, &header, sizeof(header));
    if (!payload.empty()) {
        Utils::writeExact(ssl, payload.data(), payload.size());
    }
}

bool Client::authenticate(const std::string& username, const std::string& password) {
    json req;
    req["username"] = username;
    req["password"] = password;
    
    sendRequest(Protocol::AUTH_REQ, req.dump());

    Protocol::Header header;
    if (!Utils::readExact(ssl, &header, sizeof(header))) return false;

    std::string payload;
    payload.resize(header.payloadSize);
    if (!Utils::readExact(ssl, &payload[0], header.payloadSize)) return false;

    if (header.type == Protocol::AUTH_RES) {
        auto res = json::parse(payload);
        if (res["status"] == "success") {
            jwt_token = res["token"];
            std::cout << "Authenticated successfully.\n";
            return true;
        } else {
            std::cerr << "Auth failed: " << res["message"] << "\n";
        }
    }
    return false;
}

void Client::uploadFile(const std::string& path) {
    std::cout << "Uploading " << path << "...\n";
    FILE* f = fopen(path.c_str(), "rb");
    if (!f) {
        std::cerr << "Cannot open file " << path << "\n";
        return;
    }
    
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    std::string filename = path.substr(path.find_last_of("/\\") + 1);

    json req;
    req["filename"] = filename;
    req["size"] = size;
    req["token"] = jwt_token;
    
    sendRequest(Protocol::UPLOAD_REQ, req.dump());

    Protocol::Header header;
    if (!Utils::readExact(ssl, &header, sizeof(header))) return;
    
    std::string payload;
    payload.resize(header.payloadSize);
    if (!Utils::readExact(ssl, &payload[0], header.payloadSize)) return;

    if (header.type == Protocol::UPLOAD_RES) {
        auto res = json::parse(payload);
        if (res["status"] == "success") {
            long offset = res["offset"];
            fseek(f, offset, SEEK_SET);

            const size_t CHUNK_SIZE = 64 * 1024;
            std::vector<uint8_t> buffer(CHUNK_SIZE);
            
            while (offset < size) {
                size_t bytesRead = fread(buffer.data(), 1, CHUNK_SIZE, f);
                if (bytesRead <= 0) break;

                std::vector<uint8_t> chunkData(buffer.begin(), buffer.begin() + bytesRead);
                std::string hash = Utils::calculateSHA256(chunkData);

                json chunkMeta;
                chunkMeta["filename"] = filename;
                chunkMeta["offset"] = offset;
                chunkMeta["hash"] = hash;
                
                std::string metaStr = chunkMeta.dump();
                uint32_t metaLen = metaStr.size();
                
                std::vector<uint8_t> packet;
                packet.insert(packet.end(), (uint8_t*)&metaLen, ((uint8_t*)&metaLen) + sizeof(metaLen));
                packet.insert(packet.end(), metaStr.begin(), metaStr.end());
                packet.insert(packet.end(), chunkData.begin(), chunkData.end());

                sendRequest(Protocol::CHUNK_DATA, std::string(packet.begin(), packet.end()));

                // Read ACK
                Protocol::Header ackHeader;
                if (!Utils::readExact(ssl, &ackHeader, sizeof(ackHeader))) break;
                std::string ackPayload;
                ackPayload.resize(ackHeader.payloadSize);
                Utils::readExact(ssl, &ackPayload[0], ackHeader.payloadSize);

                offset += bytesRead;
                
                int progress = (int)((offset * 100) / size);
                std::cout << "\r[";
                for (int i = 0; i < 50; ++i) {
                    if (i < progress / 2) std::cout << "=";
                    else if (i == progress / 2) std::cout << ">";
                    else std::cout << " ";
                }
                std::cout << "] " << progress << "% (" << offset << "/" << size << " bytes)" << std::flush;
            }
            std::cout << "\nUpload complete!\n";
        }
    }
    fclose(f);
}

void Client::downloadFile(const std::string& filename) {
    std::cout << "Downloading " << filename << "...\n";
    
    // Check if we already have a partial file for resuming
    long offset = 0;
    FILE* f = fopen(filename.c_str(), "rb+");
    if (f) {
        fseek(f, 0, SEEK_END);
        offset = ftell(f);
        fclose(f);
    }

    json req;
    req["filename"] = filename;
    req["offset"] = offset;
    req["token"] = jwt_token;
    
    sendRequest(Protocol::DOWNLOAD_REQ, req.dump());

    Protocol::Header header;
    if (!Utils::readExact(ssl, &header, sizeof(header))) return;
    
    std::string payload;
    payload.resize(header.payloadSize);
    if (!Utils::readExact(ssl, &payload[0], header.payloadSize)) return;

    if (header.type == Protocol::DOWNLOAD_RES) {
        auto res = json::parse(payload);
        if (res["status"] == "success") {
            long size = res["size"];
            
            f = fopen(filename.c_str(), offset == 0 ? "wb" : "ab");
            if (!f) {
                std::cerr << "Cannot open local file for writing\n";
                return;
            }

            while (offset < size) {
                Protocol::Header chunkHeader;
                if (!Utils::readExact(ssl, &chunkHeader, sizeof(chunkHeader))) break;
                
                std::string chunkPayload;
                chunkPayload.resize(chunkHeader.payloadSize);
                if (!Utils::readExact(ssl, &chunkPayload[0], chunkHeader.payloadSize)) break;

                if (chunkHeader.type == Protocol::CHUNK_DATA) {
                    if (chunkPayload.size() < 4) break;
                    uint32_t metaLen = *reinterpret_cast<const uint32_t*>(chunkPayload.data());
                    
                    std::string metaStr = chunkPayload.substr(4, metaLen);
                    auto j = json::parse(metaStr);
                    std::string hash = j["hash"];
                    
                    std::vector<uint8_t> chunkData(chunkPayload.begin() + 4 + metaLen, chunkPayload.end());
                    
                    // Verify integrity
                    std::string calculatedHash = Utils::calculateSHA256(chunkData);
                    if (calculatedHash != hash) {
                        std::cerr << "\nHash mismatch for chunk at offset " << offset << "\n";
                        break;
                    }

                    fwrite(chunkData.data(), 1, chunkData.size(), f);
                    offset += chunkData.size();

                    // Send ACK
                    json ack;
                    ack["offset"] = offset;
                    sendRequest(Protocol::CHUNK_ACK, ack.dump());

                    int progress = (int)((offset * 100) / size);
                    std::cout << "\r[";
                    for (int i = 0; i < 50; ++i) {
                        if (i < progress / 2) std::cout << "=";
                        else if (i == progress / 2) std::cout << ">";
                        else std::cout << " ";
                    }
                    std::cout << "] " << progress << "% (" << offset << "/" << size << " bytes)" << std::flush;
                }
            }
            std::cout << "\nDownload complete!\n";
            fclose(f);
        } else {
            std::cerr << "Download failed: " << res["message"] << "\n";
        }
    }
}
