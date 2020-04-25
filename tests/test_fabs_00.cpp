#include <cmath>
#include <cstdlib>
#include <iostream>

static __attribute__((unused)) double duk_js_arith_pow(double x, double y) {
    int cx, cy, sx = {0};

    do {
        (void)(cx);
    } while (0);
    do {
        (void)(sx);
    } while (0);
    cy = (int)__builtin_fpclassify(0, 1, 4, 3, 2, y);

    if (cy == 0) {
        goto ret_nan;
    }
    if (fabs(x) == 1.0 && cy == 1) {
        goto ret_nan;
    }
    do {
    } while (0);
    do {
    } while (0);
    do {
    } while (0);
    do {
    } while (0);

    return pow(x, y);

ret_nan:
    return (__builtin_nanf(""));
}

int main(int argc, char** argv) {
    if (argc > 0) {
        double x = strtod(argv[0], nullptr);
        double y = strtod(argv[0], nullptr);
        std::cerr << duk_js_arith_pow(x, y) << "\n";
    }

    return 0;
}
