// Example that uses chained libraries and accesses envp
//       example
//          |
//       libprint
//          |
//      libsyscall

#include "libs/print.h"

int main(int argc, char *argv[], char *envp[]) {
    (void) argc;
    (void) argv;

    for (int i = 0; envp[i]; i++) {
        print(envp[i]);
    }

    return 0;
}