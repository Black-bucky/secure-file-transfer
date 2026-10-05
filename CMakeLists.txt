cmake_minimum_required(VERSION 3.14)
project(SecureFileTransfer CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Find Windows socket library
if(WIN32)
    link_libraries(ws2_32)
endif()

# Find OpenSSL
find_package(OpenSSL REQUIRED)

# Fetch nlohmann_json
include(FetchContent)
FetchContent_Declare(
    json
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG v3.11.2
)
FetchContent_MakeAvailable(json)

# Fetch jwt-cpp
FetchContent_Declare(
    jwt-cpp
    GIT_REPOSITORY https://github.com/Thalhammer/jwt-cpp.git
    GIT_TAG v0.6.0
)
FetchContent_MakeAvailable(jwt-cpp)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/common)

add_subdirectory(server)
add_subdirectory(client)
