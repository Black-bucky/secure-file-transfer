#pragma once
#include <string>
#include <vector>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <iomanip>
#include <sstream>

namespace Utils {

    inline std::string calculateSHA256(const std::vector<uint8_t>& data) {
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256_CTX sha256;
        SHA256_Init(&sha256);
        SHA256_Update(&sha256, data.data(), data.size());
        SHA256_Final(hash, &sha256);

        std::stringstream ss;
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
        }
        return ss.str();
    }

    inline bool readExact(SSL* ssl, void* buffer, size_t length) {
        size_t total_read = 0;
        char* ptr = static_cast<char*>(buffer);
        while (total_read < length) {
            int bytes = SSL_read(ssl, ptr + total_read, length - total_read);
            if (bytes <= 0) {
                int err = SSL_get_error(ssl, bytes);
                if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                    continue;
                }
                return false;
            }
            total_read += bytes;
        }
        return true;
    }

    inline bool writeExact(SSL* ssl, const void* buffer, size_t length) {
        size_t total_written = 0;
        const char* ptr = static_cast<const char*>(buffer);
        while (total_written < length) {
            int bytes = SSL_write(ssl, ptr + total_written, length - total_written);
            if (bytes <= 0) {
                int err = SSL_get_error(ssl, bytes);
                if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                    continue;
                }
                return false;
            }
            total_written += bytes;
        }
        return true;
    }
}
