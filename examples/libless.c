// Example that doesn't use any libraries

int main() {
    long retval, len = 0;
    const char *msg = "Hello, World!\n";
    while (msg[len] != '\0') len++;
    __asm__ volatile("syscall\n\t" : "=a"(retval) : "a"(1), "D"(1), "S"(msg), "d"(len));
    return 0;
}