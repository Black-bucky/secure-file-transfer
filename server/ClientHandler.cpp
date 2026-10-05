#include "ClientHandler.h"
#include "../common/Protocol.h"
#include "../common/Utils.h"
#include <nlohmann/json.hpp>
#include <iostream>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <unistd.h>
#endif

using json = nlohmann::json;

ClientHandler::ClientHandler(SOCKET socket, SSL_CTX* ctx, std::shared_ptr<AuthManager> authManager)
    : client_socket(socket), auth_manager(authManager) {
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, client_socket);
}

ClientHandler::~ClientHandler() {
    if (ssl) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
#ifdef _WIN32
    closesocket(client_socket);
#else
    close(client_socket);
#endif
}

void ClientHandler::handle() {
    if (SSL_accept(ssl) <= 0) {
        std::cerr << "SSL Handshake failed\n";
        return;
    }

    std::cout << "Client connected over TLS\n";

    while (true) {
        Protocol::Header header;
        if (!Utils::readExact(ssl, &header, sizeof(header))) {
            break; // connection closed or error
        }

        std::string payload;
        payload.resize(header.payloadSize);
        if (!Utils::readExact(ssl, &payload[0], header.payloadSize)) {
            break;
        }

        switch (header.type) {
            case Protocol::AUTH_REQ:
                processAuthRequest(payload);
                break;
            case Protocol::UPLOAD_REQ:
                processUploadRequest(payload);
                break;
            case Protocol::CHUNK_DATA:
                processChunkData(payload);
                break;
            case Protocol::DOWNLOAD_REQ:
                processDownloadRequest(payload);
                break;
            default:
                std::cout << "Unknown message type\n";
                break;
        }
    }
}

void ClientHandler::sendResponse(int type, const std::string& payload) {
    Protocol::Header header;
    header.type = static_cast<Protocol::MessageType>(type);
    header.payloadSize = payload.size();

    Utils::writeExact(ssl, &header, sizeof(header));
    if (!payload.empty()) {
        Utils::writeExact(ssl, payload.data(), payload.size());
    }
}

void ClientHandler::processAuthRequest(const std::string& payload) {
    auto j = json::parse(payload);
    std::string username = j["username"];
    std::string password = j["password"];

    std::string token = auth_manager->authenticate(username, password);
    json response;
    if (!token.empty()) {
        response["status"] = "success";
        response["token"] = token;
        logged_in_user = username;
        std::cout << "User " << username << " authenticated successfully.\n";
    } else {
        response["status"] = "error";
        response["message"] = "Invalid credentials";
    }

    sendResponse(Protocol::AUTH_RES, response.dump());
}

#include <sys/stat.h>

long getFileSize(const std::string& filename) {
    struct stat stat_buf;
    int rc = stat(filename.c_str(), &stat_buf);
    return rc == 0 ? stat_buf.st_size : 0;
}

void ClientHandler::processUploadRequest(const std::string& payload) {
    auto j = json::parse(payload);
    std::string token = j["token"];
    std::string user = auth_manager->validateToken(token);
    
    json response;
    if (user.empty()) {
        response["status"] = "error";
        response["message"] = "Invalid or expired token";
    } else {
        std::string filename = j["filename"];
        std::string filepath = "uploads_" + filename; // Simplified to current dir for testing
        
        long offset = getFileSize(filepath);
        response["status"] = "success";
        response["offset"] = offset;
    }
    sendResponse(Protocol::UPLOAD_RES, response.dump());
}

void ClientHandler::processChunkData(const std::string& payload) {
    if (payload.size() < 4) return;
    uint32_t metaLen = *reinterpret_cast<const uint32_t*>(payload.data());
    
    std::string metaStr = payload.substr(4, metaLen);
    auto j = json::parse(metaStr);
    
    std::string filename = j["filename"];
    long offset = j["offset"];
    std::string hash = j["hash"];
    
    std::vector<uint8_t> chunkData(payload.begin() + 4 + metaLen, payload.end());
    
    // Integrity check
    std::string calculatedHash = Utils::calculateSHA256(chunkData);
    if (calculatedHash != hash) {
        std::cerr << "Hash mismatch for " << filename << " at offset " << offset << "\n";
        return;
    }

    std::string filepath = "uploads_" + filename;
    FILE* f = fopen(filepath.c_str(), offset == 0 ? "wb" : "rb+");
    if (!f && offset > 0) f = fopen(filepath.c_str(), "wb");
    if (f) {
        fseek(f, offset, SEEK_SET);
        fwrite(chunkData.data(), 1, chunkData.size(), f);
        fclose(f);
    }
    
    json ack;
    ack["offset"] = offset + chunkData.size();
    sendResponse(Protocol::CHUNK_ACK, ack.dump());
}

void ClientHandler::processDownloadRequest(const std::string& payload) {
    auto j = json::parse(payload);
    std::string token = j["token"];
    std::string user = auth_manager->validateToken(token);
    
    json response;
    if (user.empty()) {
        response["status"] = "error";
        response["message"] = "Invalid or expired token";
        sendResponse(Protocol::DOWNLOAD_RES, response.dump());
        return;
    }

    std::string filename = j["filename"];
    long offset = j["offset"];
    std::string filepath = "uploads_" + filename;
    
    FILE* f = fopen(filepath.c_str(), "rb");
    if (!f) {
        response["status"] = "error";
        response["message"] = "File not found";
        sendResponse(Protocol::DOWNLOAD_RES, response.dump());
        return;
    }

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, offset, SEEK_SET);

    response["status"] = "success";
    response["size"] = size;
    sendResponse(Protocol::DOWNLOAD_RES, response.dump());

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

        sendResponse(Protocol::CHUNK_DATA, std::string(packet.begin(), packet.end()));

        // Wait for ACK
        Protocol::Header ackHeader;
        if (!Utils::readExact(ssl, &ackHeader, sizeof(ackHeader))) break;
        std::string ackPayload;
        ackPayload.resize(ackHeader.payloadSize);
        Utils::readExact(ssl, &ackPayload[0], ackHeader.payloadSize);

        offset += bytesRead;
    }
    fclose(f);
}
