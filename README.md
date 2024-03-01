# MIDL - MInimal Dynamic Linker
MIDL is a small dynamic linker written for 64-bit Intel in order to learn more about shared libraries and ELF. \
It only implements a small portion of all cases, just enough to make provided examples work.

## Compiling the linker

Linked must be of type `ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), static-pie linked`:
1. `static-pie` means that it doesn't need neither shared libraries nor dynamic linker.
2. From ELF specification linker must be shared object in order to be loaded anywhere in the memory.

Therefore, the following flags have to be used: \
`-shared -Wl,-z,now -Wl,-Bstatic -Wl,-no-dynamic-linker -Wl,--dynamic-list=export.txt`\
where `export.txt` is a list of exported symbol names (currently empty), which makes other symbols internal.

## Using the linker

In order for the ELF to use non-default linker the following flags has to be used(when compiling with `gcc`): `-Wl,--dynamic-linker,PATH`. \
Also, because it does NOT support standard library it has to be disabled with `-nostdlib`.

## Linking process

The linking process itself is quite easy, although there is little documentation and examples on it. 

1. Get arguments (argc, argv, etc.), which are located on the stack right after the old stack frame address (which is null because it is the first frame).
2. Locate ELF to parse its DYNAMIC section. The base address can be derived from Program header (PHDR) found in auxillary variables(`man getauxval`) of type `PHDR`.
3. Recursively load all needed libraries from `NEEDED` entry of `DYNAMIC`:
    1.  Load new libraries by first finding continuous address space which fits it using anonymous `mmap`, and then overriding it with file-backed `MAP_FIXED` `mmap`s.
    2. Run appropriate initialization functions. When compiling, they can be provided with `-Wl,-init=FUNC_NAME`.
    3. Perform relocations by finding matching symbol names across loaded libraries.

### Finding symbols

In order to speed up the process of finding symbols by symbol names ELFs contain hash tables.

GNU has introduced its own hash table for ELF, which is much more efficient than the regular one, although more complex. \
Looking up a symbol access multiple data structures as follows:
1. Check 2-bit bloom filter with symbol name's hash.
2. Find hash bucket which gives index into both symbol table and hash chain.
3. Follow hash chain, for each entry check whether the hash matches (ignoring first bit).
4. If hashes match, compare symbol name with one from symbol table at the current index and return.
5. If it doesn't continue searching until the first bit of hash chain is set, it indicates the end of chain.

### Relocating

There are two ways of resolving relocations - during init or lazily.

The easier option is to handle them at initialization which means iterating over all relocations for all the libraries.

For lazy loading, which is usually faster, linker has to set up handler at the beginning of GOT before passing control to the program: \
After the initial setup first calls to function through PLT will save PLT offset to the stack and jump to the handler. \
Handler then performs the necessary relocations, so that the same call will be immediately redirected to the corresponding function.

### R_x_COPY and R_x_GLOB_DAT

These two types of relocations work together in order to have a single instance of a global variable. They do so by copying initial value into application's variable and redirecting shared library's reads and writes to that same variable, effectively sharing it between the executable and the library.

COPY relocations are found in executables. They simply, as the name implies, copy the initial value from library variable to the local one. \
GLOB_DAT relocations are placed in shared library. They write application symbol's address into local variable, thus thus redirecting library's variable to application's copy.

Thus, after relocations only application's variable is used and shared between all ELFs.

# References
[32-bit ELF reference specification](https://refspecs.linuxfoundation.org/elf/elf.pdf) \
[64-bit ELF specification](https://uclibc.org/docs/elf-64-gen.pdf) \
[Handy system calls table](https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md) \
[GCC inline assembly guide](https://www.ibiblio.org/gferg/ldp/GCC-Inline-Assembly-HOWTO.html#s3) \
[Source of Linux kernel function which loads ELF](https://github.com/torvalds/linux/blob/master/fs/binfmt_elf.c#L819C12-L819C27) \
[Other dynamic loader](https://github.com/Ferdi265/dynamic-loader) \
[GNU Hash section layout summary](https://sourceware.org/legacy-ml/binutils/2006-10/msg00377.html) \
[The process of looking up using GNU Hash (at 1.5.3 The GNU-style Hash Table)](https://www.akkadia.org/drepper/dsohowto.pdf) \
[GNU's ld-linux](https://github.com/bminor/glibc/blob/master/elf/rtld.c) \
[R_x_COPY and R_x_GLOB_DAT explanation](https://netwinder.osuosl.org/users/p/patb/public_html/elf_relocs.html)