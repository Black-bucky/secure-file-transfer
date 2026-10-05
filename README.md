# Secure Multi-Client File Transfer System

A robust C++ file transfer system utilizing TCP/IP socket programming, multithreading, TLS/SSL, and JWT-based authentication.

## Features implemented
- **Concurrent Connections**: Multi-threaded server that handles multiple clients simultaneously using `std::thread`.
- **JWT Authentication & RBAC**: Uses `jwt-cpp` to issue tokens that expire in 1 hour and includes "user" and "role" claims.
- **TLS/SSL Security**: Network communication is encrypted using OpenSSL (both `SSL_accept` and `SSL_connect` are utilized).
- **Chunking & Integrity**: Files are chunked during upload, and each chunk includes a SHA256 hash. The server validates the hash before writing to disk.
- **Interrupted Transfer Recovery**: Uses offset tracking to automatically resume interrupted file uploads without starting from scratch.

## Project Structure
- `common/` - Contains the custom protocol definitions and OpenSSL SHA256/IO utility functions.
- `server/` - Multi-threaded server handling TLS termination, AuthManager (JWT), and Client handlers.
- `client/` - Client that connects, authenticates, and reliably streams files in chunks.

## Prerequisites
- **CMake** 3.14+
- **OpenSSL** (e.g. via vcpkg `vcpkg install openssl`)
- A C++17 compatible compiler (MSVC, GCC, Clang)

## Build Instructions (Windows/Linux)

1. Generate TLS Certificates for the Server:
   ```bash
   openssl req -x509 -newkey rsa:4096 -keyout build/server.key -out build/server.crt -days 365 -nodes
   ```
   *(Ensure `server.crt` and `server.key` are in the server's working directory when executing)*

2. Configure and Build:
   ```bash
   mkdir build && cd build
   cmake .. -DCMAKE_TOOLCHAIN_FILE=[path_to_vcpkg]/scripts/buildsystems/vcpkg.cmake
   cmake --build . --config Release
   ```

3. Run Server:
   ```bash
   ./server/Release/server.exe
   ```

4. Run Client:
   ```bash
   ./client/Release/client.exe
   ```
