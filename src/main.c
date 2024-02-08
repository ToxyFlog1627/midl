#define SYS_READ 0
#define SYS_WRITE 1
#define SYS_OPEN 2
#define SYS_EXIT 60

#define STDIN 0
#define STDOUT 1
#define STDERR 2

#define O_RDONLY 0
#define O_WRONLY 1
#define O_RDWR 2

typedef long word;
typedef unsigned long size_t;
typedef unsigned long off_t;

typedef char int8_t;
typedef unsigned char uint8_t;
typedef short int int16_t;
typedef short unsigned int uint16_t;
typedef int int32_t;
typedef unsigned int uint32_t;
typedef long int int64_t;
typedef long unsigned int uint64_t;

typedef struct {
    int argc;
    char **argv;
    char **envp;
} MainArgs;

word syscall(word call_num, word a1, word a2, word a3) {
    word retval;
    __asm__ volatile("syscall\n\t" : "=a"(retval) : "a"(call_num), "D"(a1), "S"(a2), "d"(a3));
    return retval;
}

#define read(fd, buf, len) syscall(SYS_READ, fd, buf, len)
#define write(fd, buf, len) syscall(SYS_WRITE, fd, buf, len)
#define open(path, flags, mode) syscall(SYS_OPEN, path, flags, mode)
#define exit(exit_code) syscall(SYS_EXIT, exit_code, 0, 0)

size_t strlen(const char *msg) {
    size_t len = 0;
    while (msg[len] != '\0') len++;
    return len;
}

int print(const char *msg) { return write(STDOUT, msg, strlen(msg)); }

#undef BUF_SIZE
#define BUF_SIZE 128
int print_num(int64_t num) {
    char buffer[BUF_SIZE];
    size_t i = 0, mask = 1;

    if (num < 0) {
        buffer[i++] = '-';
        num *= -1;
    }

    int64_t num_copy = num;
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

#undef BUF_SIZE
#define BUF_SIZE 32
int print_hex(uint64_t num) {
    char buffer[BUF_SIZE];
    size_t i = 17;
    for (size_t j = 0; j <= i; j++) buffer[j] = '0';
    buffer[1] = 'x';
    buffer[i + 1] = '\n';
    buffer[i + 2] = '\0';

    while (num > 0) {
        uint8_t digit = num % 0x10;
        buffer[i--] = digit > 9 ? ('A' + digit - 10) : ('0' + digit);

        num >>= 4;
        if (i == 0) return 1;
    }

    print(buffer);
    return 0;
}

MainArgs get_args(word rbp) {
    MainArgs args;

    __asm__ volatile("mov (%[ptr]), %[ret]\n\t" : [ret] "=r"(args.argc) : [ptr] "r"(rbp));
    args.argv = rbp + sizeof(word);
    args.envp = args.argv + args.argc + 1;

    return args;
}

void entry() {
    word rbp;
    __asm__ volatile("mov %%rbp, %[ret]\n\t" : [ret] "=r"(rbp));
    rbp += sizeof(word);  // skip previous frame pointer because there is none

    MainArgs args = get_args(rbp);

    exit(0);
}
