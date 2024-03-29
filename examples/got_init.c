// Example that uses Global Offset Table and library with init function
//        example
//       |       |
//   libtime  libprint
//       |       |
//      libsyscall

#include "libs/print.h"
#include "libs/time.h"

int main() {
    print_num(utime);
    for (int i = 0; i < 1000 * 1000 * 1000; i++) continue;
    update_time();
    print_num(utime);
    return 0;
}