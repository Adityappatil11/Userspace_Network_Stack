#include "tapinterface.h"
#include "networkstack.h"
#include <iostream>

int main() {
    try {
        TapInterface tap("tap0");
        NetworkStack stack(tap);
        std::cout << "Stack Running on tap0...\n";

        uint8_t buffer[2048];
        while (true) {
            int len = tap.read_packet(buffer, sizeof(buffer));
            if (len > 0) stack.handle_packet(buffer, len);
        }
    } catch (const std::exception& e) {
        std::cerr << "Fatal Error: " << e.what() << "\n";
        return 1;
    }
    return 0;
}