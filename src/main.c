#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1

#define SYS_WRITE 1
#define SYS_EXIT 60

#define STDOUT_FD 1

typedef long size_t;  // word size

size_t strlen(const char *msg) {
    size_t len = 0;
    while (msg[len] != '\0') len++;
    return len;
}

int print(const char *msg) {
    int retval;
    size_t msg_len = strlen(msg);
    __asm__ volatile("syscall\n\t" : "=a"(retval) : "a"(SYS_WRITE), "D"(STDOUT_FD), "S"(msg), "d"(msg_len));
    return retval;
}

void exit(size_t exit_code) { __asm__ volatile("syscall\n\t" : : "a"(SYS_EXIT), "D"(exit_code)); }

void entry() {
    size_t retval;

    retval = print("Hello from the dynamic linker!\n");
    if (retval == -1) exit(EXIT_FAILURE);

    exit(EXIT_SUCCESS);
}
