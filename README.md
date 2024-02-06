# MIDL - minimalistic dynamic linker
<!-- TODO: is there really no difference between a linker and a loader? -->
MIDL is a minimal loader capable of dynamically linking shared libraries. \
It was built in order to learn more about linkers, loaders and ELF.



## What is a dynamic linker?
Dynamic linker is a program responsible for loading executable and linking it with shared libraries at runtime, such as glibc's `ld-linux`. \
A dynamically-linked ELF contains `PT_INTERP` field in the header which specifies a path to the interpreter. \
When file is executed, kernel loads an ELF into the memory, loads an appropriate interpreter(e.g. dynamic linker) and calls its entry point. \
Interpreter is then responsible for doing everything needed to run this binary, this includes but not limited to loading libraries and linking them.

## Building a dynamic linker
Compilation and linking flags:
1. `-fPIE` to make position independent, because dynamic linker can get loaded anywhere in the memory.
2. `-nostdlib` to disable standard library, because it must not dependent on shared libraries
3. `-Wl,--no-dynamic-linker` to make it statically-linked
4. (opt) `-e func_name` to change entry point 

Entry point must end with an exit syscall, exit code should be set to main's return value.

## Usage
**Tested only with GCC on x86_64** 

Compilation and linking flags for binaries that use this linker.
1. Disable standard library with `--nostdlib` to disable standard linker (i.e. `ld-loader`).
2. Set path to our dynamic linker with `-Wl,--dynamic-linker,PATH_TO_LINKER`

## Examples

<!-- TODO: write about compiling/using examples -->

# References
[ELF dynamic linking reference specification](https://refspecs.linuxfoundation.org/elf/elf.pdf) \
[Handy system calls table](https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md)