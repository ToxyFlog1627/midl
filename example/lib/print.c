#define SYS_WRITE 1

#define STDOUT_FD 1

typedef unsigned long size_t;

size_t strlen(const char *msg) {
    size_t len = 0;
    while (msg[len] != '\0') len++;
    return len;
}

void print(char *msg) {
    size_t msg_len = strlen(msg);
    __asm__ volatile("syscall\n\t" : : "a"(SYS_WRITE), "D"(STDOUT_FD), "S"(msg), "d"(msg_len));
}