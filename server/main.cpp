#include "Server.h"
#include <iostream>

int main() {
    try {
        Server server(8080);
        server.start();
    } catch (const std::exception& e) {
        std::cerr << "Server error: " << e.what() << "\n";
    }
    return 0;
}
