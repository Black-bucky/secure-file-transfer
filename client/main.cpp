#include "Client.h"
#include <iostream>

int main() {
    try {
        Client client("127.0.0.1", 8080);
        if (client.connect()) {
            if (client.authenticate("admin", "adminpass")) {
                FILE* f = fopen("test.txt", "wb");
                if (f) {
                    for(int i=0; i<100000; ++i) {
                        fprintf(f, "This is a test line %d\n", i);
                    }
                    fclose(f);
                }
                client.uploadFile("test.txt");
                client.downloadFile("test.txt");
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "Client error: " << e.what() << "\n";
    }
    return 0;
}
