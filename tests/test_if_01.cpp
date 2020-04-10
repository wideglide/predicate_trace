#include <iostream>

int main(int argc, char** argv) {
    if (argc > 0) {
        std::cout << "OK\n";
        if (argc > 1) {
            std::cout << "REALLY OK\n";
            if (argc > 2) {
                std::cout << "REALLY REALLY OK\n";
                if (argc > 3) {
                    std::cout << "REALLY REALLY REALLY OK\n";
                }
            }
        }
    }

    return 0;
}
