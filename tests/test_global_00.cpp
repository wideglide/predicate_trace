#include <iostream>

const char some_global[] = "this is a global variable";

int main(int argc, char** argv) {
    if (argc > 0) {
        puts(some_global);
    }

    return 0;
}
