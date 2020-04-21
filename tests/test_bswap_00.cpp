#include <iostream>

int f(int x) {
    return __builtin_bswap32(x);
}

int main(int argc, char** argv) {
    std::cerr << argc << " -> " << f(argc) << "\n";
    return 0;
}
