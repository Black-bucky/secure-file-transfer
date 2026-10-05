add_executable(client main.cpp Client.cpp)
target_include_directories(client PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ../common)
target_link_libraries(client PRIVATE OpenSSL::SSL OpenSSL::Crypto jwt-cpp::jwt-cpp nlohmann_json::nlohmann_json)
