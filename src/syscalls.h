#ifndef SYSCALL_H
#define SYSCALL_H

#include "types.h"

__attribute__((unused)) static word syscall3(word call_num, word a0, word a1, word a2) {
    word retval;
    __asm__ volatile("syscall\n\t" : "=a"(retval) : "a"(call_num), "D"(a0), "S"(a1), "d"(a2));
    return retval;
}

__attribute__((unused)) static word syscall6(word call_num, word a0, word a1, word a2, word a3, word a4, word a5) {
    word retval;
    __asm__ volatile(
        "mov %[a3], %%r10\n\t"
        "mov %[a4], %%r8\n\t"
        "mov %[a5], %%r9\n\t"
        "syscall\n\t"
        : "=a"(retval)
        : "a"(call_num), "D"(a0), "S"(a1), "d"(a2), [a3] "r"(a3), [a4] "r"(a4), [a5] "r"(a5)
        : "r10", "r9", "r8");
    return retval;
}

#define read(fd, buf, len)        syscall3(0x00, fd, ((word) (buf)), len)
#define write(fd, buf, len)       syscall3(0x01, fd, ((word) (buf)), len)
#define open(path, flags, mode)   syscall3(0x02, ((word) (path)), flags, mode)
#define close(fd)                 syscall3(0x03, fd, NULL, NULL)
#define lseek(fd, offset, whence) syscall3(0x08, fd, offset, whence)
#define mmap(addr, length, prot, flags, fd, offset)                                                                    \
    ((void *) syscall6(0x09, ((word) (addr)), length, prot, flags, fd, offset))
#define munmap(addr, len)           syscall3(0x0b, addr, len, NULL)
#define brk(brk)                    ((void *) syscall3(0x0c, ((word) (brk)), NULL, NULL))
#define _exit(exit_code)            syscall3(0x3c, exit_code, NULL, NULL)
#define getdents(fd, dirent, count) syscall3(0xd9, fd, direct, count)

// error codes
#define ENOENT -0x02

// open
#define O_RDONLY 0
#define O_WRONLY 1
#define O_RDWR   2

// lseek
#define SEEK_SET 0
#define SEEK_CUR 1
#define SEEK_END 2

// mmap
#define MAP_PROT_NONE  0x00
#define MAP_PROT_READ  0x01
#define MAP_PROT_WRITE 0x02
#define MAP_PROT_EXEC  0x04
#define MAP_PRIVATE    0x02
#define MAP_FIXED      0x10
#define MAP_ANONYMOUS  0x20

// getdents
enum DIRENT_TYPES {
    DE_UNKNOWN = 0,
    DE_FIFO = 1,
    DE_CHAR_DEV = 2,
    DE_DIR = 4,
    DE_BLOCK_DEV = 6,
    DE_FILE = 8,
    DE_LINK = 10,
    DE_SOCKET = 12
};

typedef struct {
    uint64_t inode;
    uint64_t offset;
    uint16_t size;
    uint8_t type;
    char *filename;
} dirent64;

#endif  // SYSCALL_H