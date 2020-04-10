#include <iostream>

int g(int argc, char** argv) {
    if (argc > -2) {
        puts("OK again again");
        return argc + 1;
    }

    return argc;
}

void f(int argc, char** argv) {
    int x = 0;
    if (argc > -1) {
        puts("OK again");
        x = g(argc, argv);
    }

    if (x >= argc) {
        puts("OK again again again");
    }
}

int main(int argc, char** argv) {
    if (argc > 0) {
        puts("OK");
        f(argc, argv);
    }

    return 0;
}
