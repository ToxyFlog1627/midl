// Example that uses same library (libsyscall) multiple times
//        example
//        |     |
//  libsyscall  libprint
//                  |
//              libsyscall

#include "libs/print.h"
#include "libs/syscall.h"

#define BUFFER_SIZE 256

int main(int argc, char **argv) {
    if (argc != 2) goto usage;
    const char *file_path = argv[1];

    int fd = open(file_path, O_RDONLY);
    if (fd < 0) {
        print("Invalid file path.\n");
        return 1;
    }

    int read_num = 0;
    char buffer[BUFFER_SIZE + 1];
    while ((read_num = read(fd, buffer, BUFFER_SIZE)) > 0) {
        buffer[read_num] = '\0';
        print(buffer);
    }

    close(fd);
    return 0;

usage:
    print("usage: ");
    print(argv[0]);
    print(" [path]\n");
    return 1;
}