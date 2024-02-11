// Example that uses chained libraries and accesses envp

#include "libs/print.h"

int main(int argc, char *argv[], char *envp[]) {
    for (int i = 0; envp[i]; i++) {
        print(envp[i]);
    }

    return 0;
}