// Example that uses multiple(two) statically-compiled library and arguments
//       example
//       |     |
//   libmath  libprint
//                |
//            libsyscall

#include "libs/math.h"
#include "libs/print.h"

int parse_num(int *result, const char *string) {
    int value = 0, i = 0, mult = 1;
    while (string[i]) i++;
    while (--i >= 0) {
        if (i == 0 && string[i] == '-') {
            value *= -1;
            break;
        }

        if (string[i] < '0' || string[i] > '9') return 1;

        value += (string[i] - '0') * mult;
        mult *= 10;
    }

    *result = value;
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 4) goto usage;

    int op1, op2;
    if (parse_num(&op1, argv[1])) {
        print("First operand is not a number!\n");
        goto usage;
    }
    if (parse_num(&op2, argv[3])) {
        print("Second operand is not a number!\n");
        goto usage;
    }

    if (argv[2][1] != '\0') {
        print("Unkown operation!\n");
        goto usage;
    }

    char op = argv[2][0];
    if (op == '+') {
        int result = add(op1, op2);
        print_num(result);
        return 0;
    } else if (op == '*') {
        int result = multiply(op1, op2);
        print_num(result);
        return 0;
    }

usage:
    print("usage: ");
    print(argv[0]);
    print(" [operand1]");
    print(" [+ OR *]");
    print(" [operand2]\n");
    return 1;
}