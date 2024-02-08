#define SYS_OPEN 2
#define SYS_READ 0
#define SYS_WRITE 1
#define SYS_EXIT 60

#define STDIN 0
#define STDOUT 1
#define STDERR 2

#define BUF_SIZE 128

typedef long size_t;  // word size

typedef struct {
    int argc;
    char **argv;
    char **envp;
} MainArgs;

size_t syscall(size_t call_num, size_t a1, size_t a2, size_t a3) {
    size_t retval;
    __asm__ volatile("syscall\n\t" : "=a"(retval) : "a"(call_num), "D"(a1), "S"(a2), "d"(a3));
    return retval;
}

#define open(path, flags, mode) syscall(SYS_OPEN, path, flags, mode)
#define read(fd, buf, len) syscall(SYS_READ, fd, buf, len)
#define write(fd, buf, len) syscall(SYS_WRITE, fd, buf, len)
#define exit(exit_code) syscall(SYS_EXIT, exit_code, 0, 0)

size_t strlen(const char *msg) {
    size_t len = 0;
    while (msg[len] != '\0') len++;
    return len;
}

size_t print(const char *msg) { return write(STDOUT, msg, strlen(msg)); }

size_t print_num(size_t num) {
    char buffer[BUF_SIZE];
    size_t i = 0, mask = 1;

    if (num < 0) {
        buffer[i++] = '-';
        num *= -1;
    }

    size_t num_copy = num;
    do {
        mask *= 10;
        num_copy /= 10;
    } while (num_copy > 0);
    mask /= 10;

    do {
        buffer[i++] = '0' + (num / mask) % 10;
        mask /= 10;
    } while (mask > 0 && i < BUF_SIZE);
    if (i + 1 >= BUF_SIZE) return 1;

    buffer[i] = '\n';
    buffer[i + 1] = '\0';

    print(buffer);
    return 0;
}

size_t print_hex(unsigned long num) {
    char buffer[BUF_SIZE];
    size_t i = 17;
    for (size_t j = 0; j <= i; j++) buffer[j] = '0';
    buffer[1] = 'x';
    buffer[i + 1] = '\n';
    buffer[i + 2] = '\0';

    while (num > 0) {
        size_t digit = num % 0x10;
        buffer[i--] = digit > 9 ? ('A' + digit - 10) : ('0' + digit);

        num >>= 4;
        if (i == 0) return 1;
    }

    print(buffer);
    return 0;
}

MainArgs get_args(size_t rbp) {
    MainArgs args;

    __asm__ volatile("mov (%[ptr]), %[ret]\n\t" : [ret] "=r"(args.argc) : [ptr] "r"(rbp));
    args.argv = rbp + sizeof(size_t);
    args.envp = args.argv + args.argc + 1;

    return args;
}

void entry() {
    size_t rbp;
    __asm__ volatile("mov %%rbp, %[ret]\n\t" : [ret] "=r"(rbp));
    rbp += sizeof(size_t);  // skip previous frame pointer because there is none

    MainArgs args = get_args(rbp);

    exit(0);
}
