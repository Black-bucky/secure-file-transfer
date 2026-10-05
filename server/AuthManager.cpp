#include "AuthManager.h"
#include <jwt-cpp/jwt.h>

AuthManager::AuthManager(const std::string& secret) : secret_key(secret) {
    // Hardcoded mock users for demonstration
    users["admin"] = {"adminpass", "admin"};
    users["user1"] = {"userpass", "user"};
}

std::string AuthManager::authenticate(const std::string& username, const std::string& password) {
    auto it = users.find(username);
    if (it != users.end() && it->second.password == password) {
        auto token = jwt::create()
            .set_issuer("auth0")
            .set_type("JWS")
            .set_payload_claim("user", jwt::claim(std::string(username)))
            .set_payload_claim("role", jwt::claim(std::string(it->second.role)))
            .set_expires_at(std::chrono::system_clock::now() + std::chrono::hours(1))
            .sign(jwt::algorithm::hs256{secret_key});
        return token;
    }
    return "";
}

std::string AuthManager::validateToken(const std::string& token) {
    try {
        auto decoded = jwt::decode(token);
        auto verifier = jwt::verify()
            .allow_algorithm(jwt::algorithm::hs256{secret_key})
            .with_issuer("auth0");
        verifier.verify(decoded);
        return decoded.get_payload_claim("user").as_string();
    } catch (const std::exception& e) {
        return "";
    }
}

bool AuthManager::isAdmin(const std::string& username) {
    auto it = users.find(username);
    return it != users.end() && it->second.role == "admin";
}
