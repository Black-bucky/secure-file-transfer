add_executable(server main.cpp Server.cpp ClientHandler.cpp AuthManager.cpp)
target_include_directories(server PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ../common)
target_link_libraries(server PRIVATE OpenSSL::SSL OpenSSL::Crypto jwt-cpp::jwt-cpp nlohmann_json::nlohmann_json)
