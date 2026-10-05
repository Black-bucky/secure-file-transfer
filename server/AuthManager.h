#pragma once
#include <string>
#include <unordered_map>

class AuthManager {
public:
    AuthManager(const std::string& secret);
    
    // Returns JWT token if successful, empty string otherwise
    std::string authenticate(const std::string& username, const std::string& password);
    
    // Validates token and returns username if valid, empty string otherwise
    std::string validateToken(const std::string& token);
    
    // Returns true if user has admin role
    bool isAdmin(const std::string& username);

private:
    std::string secret_key;
    // Mock user database: username -> {password, role}
    struct UserData {
        std::string password;
        std::string role;
    };
    std::unordered_map<std::string, UserData> users;
};
