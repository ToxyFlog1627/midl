#include "math.h"

int add(int a, int b) { return a + b; }

int multiply(int a, int b) {
    int result = 0;
    for (int i = 0; i < b; i++) result = add(result, a);
    return result;
}