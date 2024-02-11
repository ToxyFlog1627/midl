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
Options required to build linker:
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

## Usage
**Tested only with GCC on x86_64** 

Compilation and linking flags for binaries that use this linker.
1. Disable standard library with `--nostdlib` to disable standard linker (i.e. `ld-loader`).
2. Set path to our dynamic linker with `-Wl,--dynamic-linker,PATH_TO_LINKER`

## Examples

<!-- TODO: write about compiling/using examples -->

# References
[32-bit ELF reference specification](https://refspecs.linuxfoundation.org/elf/elf.pdf) \
[64-bit ELF specification](https://uclibc.org/docs/elf-64-gen.pdf) \
[Handy system calls table](https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md) \
[GCC inline assembly guide](https://www.ibiblio.org/gferg/ldp/GCC-Inline-Assembly-HOWTO.html#s3) \
[Source of Linux kernel function which loads ELF](https://github.com/torvalds/linux/blob/master/fs/binfmt_elf.c#L819C12-L819C27)