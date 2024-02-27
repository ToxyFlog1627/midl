# MIDL - MInimal Dynamic Linker
MIDL is a small dynamic linker written for 64bit Intel Linux in order to learn more about shared libraries and ELF.

## What is a dynamic linker?
Dynamic linker is a program responsible for loading executable and linking it with shared libraries at runtime, such as glibc's `ld-linux`. \
A dynamically-linked ELF contains `PT_INTERP` field in the header which specifies a path to the interpreter. \
When file is executed, kernel loads an ELF into the memory, loads an appropriate interpreter(e.g. dynamic linker) and calls its entry point. \
Interpreter will then prepare the environment before passing the execution to the ELF itself. Preparations includes but not limited to loading libraries and linking them.

## Interpreter: shared object vs executable

If interpreter is an executable, it will be loaded at a fixed address, therefore it is possible that it will overlap with with another ELF.

If it is a shared object (i.e. shared library) it is position independent, thus can be loaded anywhere. Although it is easier to deal with, it has its own downsides, namely having to start the execution with linking itself.

## Building a dynamic linker
Flags required to build linker:
1. `-pie` to make it position independent, because dynamic linker can get loaded anywhere in the memory.
2. `-Wl,--no-dynamic-linker` to make it statically-linked \
Alternatively, `-pie -Wl,--no-dynamic-linker` can be replaced with `-static-pie`.
3. `-nostdlib` to disable standard library, because it must not dependent on shared libraries
4. (opt) `-e func_name` to change entry point

If you have built executable correctly, running `file` on it would result in `ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), static-pie linked`

Entry point must end with an exit syscall, exit code should be set to main's return value.

Entry point:
1. Read main() arguments, i.e. `argc, argv, envp`. They are located on the stack right after old stack frame pointer(which is NULL as entry is the first frame).
2. Find out where the binary is mapped. It can be obtained from auxillary variables(see `man getauxval` for types/values) which are located on the stack right after `envp`. They are stored as a series of `type, value` pairs, each field is word-sized. Specifically from `AT_PHDR`, which contains the address of the mapped program header.
3. Now we can offset mapped memory by ELF's entry offset to execute binary.

### -pie, -fpic, -fpie, -fPIC, -fPIE, -static-pie
What is the differences between all these flags?
1. `-fpie`(`-fPIE`) imply that you are building an executable, so it disables interposition, whereas `-fpic`(`-fPIC`) enables it. \
2. The case sets the data mode, lowercase for `-msmall-data` and uppercase for `-mlarge-data`. More on this in [gcc's man page](https://man7.org/linux/man-pages/man1/gcc.1.html).

Flags prefixed with `-f` use specified mode *if possible*, whereas `-pie` always produces PIE.

`-static-pie` is basically an alias for `-static -pie --no-dynamic-linker -z text`.

### Linker, Loader, Dynamic Linker and Interpreter

*Interpreter* is a shared object (or an executable) which is ran before the ELF to prepare the environment. 

*Linker* is an executable which **links** object files together, e.g. `gcc a.o b.o c.o -o a.out`(acts as `ld`).

*Dynamic linker* is a shared object or an executable which links the main ELF executable with shared libraries at runtime(i.e. **dynamically**).

*Loader* is a shared object or an executable which **loads** dynamic loader.


## Usage

Compilation and linking flags for executables that use this linker.
1. Disable standard library with `--nostdlib` to disable standard linker (i.e. `ld-loader`).
2. Set path to dynamic linker with `-Wl,--dynamic-linker,PATH_TO_LINKER`
3. Set runtime library search path with `-Wl,-rpath,PATH_TO_DIRECTORY_WITH_LIBRARIES`

# References
[32-bit ELF reference specification](https://refspecs.linuxfoundation.org/elf/elf.pdf) \
[64-bit ELF specification](https://uclibc.org/docs/elf-64-gen.pdf) \
[Handy system calls table](https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md) \
[GCC inline assembly guide](https://www.ibiblio.org/gferg/ldp/GCC-Inline-Assembly-HOWTO.html#s3) \
[Source of Linux kernel function which loads ELF](https://github.com/torvalds/linux/blob/master/fs/binfmt_elf.c#L819C12-L819C27) \
[Other dynamic loader](https://github.com/Ferdi265/dynamic-loader) \
[GNU Hash section layout summary](https://sourceware.org/legacy-ml/binutils/2006-10/msg00377.html) \
[The process of looking up using GNU Hash (at 1.5.3 The GNU-style Hash Table)](https://www.akkadia.org/drepper/dsohowto.pdf)