// Example that uses one statically-compiled library and arguments

#include "libs/math.h"

void print(const char *msg) {
    long retval, len = 0;
    while (msg[len] != '\0') len++;
    __asm__ volatile("syscall\n\t" : "=a"(retval) : "a"(1), "D"(1), "S"(msg), "d"(len));
}

void print_num(int num) {
    char buffer[100];
    int i = 0, mask = 1;

    if (num < 0) {
        buffer[i++] = '-';
        num *= -1;
    }

    int num_copy = num;
    do {
        mask *= 10;
        num_copy /= 10;
    } while (num_copy > 0);
    mask /= 10;

    do {
        buffer[i++] = '0' + (num / mask) % 10;
        mask /= 10;
    } while (mask > 0);

    buffer[i] = '\n';
    buffer[i + 1] = '\0';

    print(buffer);
}

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