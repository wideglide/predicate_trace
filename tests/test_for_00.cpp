#include <iostream>

int main(int argc, char** argv) {
    for (auto i = 10; i >= argc; --i) {
        std::cerr << "OK\n";
    }

    return 0;
}
