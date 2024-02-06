#define SYS_WRITE 1

#define STDOUT_FD 1

typedef unsigned long size_t;

size_t __syscall(size_t nr, size_t a0, size_t a1, size_t a2, size_t a3, size_t a4, size_t a5) {
    size_t ret;
    __asm__ volatile(
        "mov %[a3], %%r10\n\t"
        "mov %[a4], %%r8\n\t"
        "mov %[a5], %%r9\n\t"
        "syscall\n\t"
        : "=a"(ret)
        : "a"(nr), "D"(a0), "S"(a1), "d"(a2), [a3] "rm"(a3), [a4] "rm"(a4), [a5] "rm"(a5)
        : "rcx", "r8", "r9", "r10");
    return ret;
}

size_t strlen(const char *msg) {
    size_t len = 0;
    while (msg[len] != '\0') len++;
    return len;
}

void print(const char *msg) { __syscall(SYS_WRITE, STDOUT_FD, (size_t) msg, strlen(msg), 0, 0, 0); }

void exit() {
    __asm__ volatile(
        "mov $60,  %eax\n\t"
        "xor %edi, %edi\n\t"
        "syscall\n\t");
}

void entry() {
    print("Hello from the dynamic linker!\n");
    exit();
}