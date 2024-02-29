// Example that uses chained libraries and accesses envp
//       example
//          |
//       libprint
//          |
//      libsyscall

#include "libs/print.h"

#define COUNT 5

int main(int argc, char *argv[], char *envp[]) {
    (void) argc;
    (void) argv;

    for (int i = 0; envp[i] && i < COUNT; i++) {
        print(envp[i]);
        print("\n");
    }

    return 0;
}