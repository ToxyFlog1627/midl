#include "dynamic.h"
#include "elf.h"
#include "library.h"
#include "relocate.h"
#include "symbol.h"
#include "syscalls.h"
#include "types.h"
#include "ulibc.h"
#include "vector.h"

#define AT_NULL 0
#define AT_PHDR 3

typedef struct {
    int argc;
    char **argv;
    char **envp;
    word *auxv;
} Args;

typedef int main_t(int argc, char **argv, char **envp);

static vec_libs loaded_libraries;

static Args get_args() {
    word stack_pointer;
    __asm__ volatile("mov (%%rbp), %[ret]\n\t" : [ret] "=r"(stack_pointer));
    stack_pointer += sizeof(word);  // skip old call frame

    Args args;

    args.argc = *((size_t *) stack_pointer);
    args.argv = ((char **) (stack_pointer)) + 1;
    args.envp = args.argv + args.argc + 1;
    args.auxv = (word *) args.envp;
    while (*(args.auxv++)) continue;

    return args;
}

static char *get_program_base(Args *args) {
    word *aux_var = args->auxv;
    while (*aux_var != AT_PHDR) aux_var += 2;

    ELFSegment *phdr = (ELFSegment *) (*(aux_var + 1));
    return (char *) (((word) phdr) - phdr->file_offset);
}

static bool is_library_loaded(const char *library_name) {
    for (size_t j = 0; j < loaded_libraries.length; j++) {
        if (strcmp(loaded_libraries.data[j].name, library_name) == 0) return true;
    }
    return false;
}

static void perform_rela_relocations(char *base, const Dynamic *dynamic, ELFRela *relas, size_t rela_count) {
    ELFRela *rela = relas;
    for (size_t i = 0; i < rela_count; i++, rela++) {
        const ELFSymbol *rela_symbol = dynamic->symbol_table + rela->info.v.symbol_index;
        const char *symbol_name = dynamic->string_table + rela_symbol->name_offset;

        ELFSymbol *symbol = find_symbol(dynamic, symbol_name);
        if (symbol) {
            relocate_rela(base, rela, base, symbol, symbol_name);
            continue;
        }

        for (size_t j = 0; j < loaded_libraries.length; j++) {
            Library library = loaded_libraries.data[j];
            symbol = find_symbol(&library.dynamic, symbol_name);
            if (symbol) {
                relocate_rela(base, rela, library.base, symbol, symbol_name);
                break;
            }
        }

        if (symbol == NULL) {
            print("ERROR: Unable to find symbol \"");
            print(symbol_name);
            print("\".\n");
            exit(1);
        }
    }
}

static void perform_relr_relocations(char *base, const Dynamic *dynamic, ELFRela *relrs, size_t relr_count) {
    UNIMPLEMENTED("relr");
    // uint64_t *where = NULL;
    // uint64_t *relr = relrs;
    // for (size_t i = 0; i < relr_count; i++, relr++) {
    //     uint64_t entry = *relr;
    //     if ((entry & 1) == 0) {
    //         where = (uint64_t *) (base + entry);
    //         *where++ += (uint64_t) base;
    //     } else {
    //         for (long i = 0; (entry >>= 1) != 0; i++) {
    //             if ((entry & 1) != 0) where[i] += (uint64_t) base;
    //         }
    //         where += 8 * sizeof(uint64_t) - 1;
    //     }
    // }
}

static void resolve_symbols(char *base, const Dynamic *dynamic) {
    for (size_t i = 0; i < dynamic->needed_libraries.length; i++) {
        const char *library_name = dynamic->needed_libraries.data[i];
        if (is_library_loaded(library_name)) continue;

        Library library = load_library(&dynamic->library_search_paths, library_name);
        VECTOR_PUSH(loaded_libraries, library);

        resolve_symbols(library.base, &library.dynamic);

        for (size_t i = 0; i < library.dynamic.init_array.length; i++) library.dynamic.init_array.data[i]();
        for (size_t i = 0; i < library.dynamic.fini_array.length; i++) UNIMPLEMENTED("fini");
    }

    if (dynamic->jump_relocs) perform_rela_relocations(base, dynamic, dynamic->jump_relocs, dynamic->jump_relocs_count);
    if (dynamic->relas) perform_rela_relocations(base, dynamic, dynamic->relas, dynamic->rela_count);
    if (dynamic->relrs) perform_relr_relocations(base, dynamic, dynamic->relrs, dynamic->relr_count);
}

void entry() {
    Args args = get_args();
    char *base = get_program_base(&args);
    const ELFHeader *elf = (ELFHeader *) base;
    check_elf_header(elf);

    Dynamic dynamic = get_dynamic(base, elf);
    resolve_symbols(base, &dynamic);

    main_t *main;
    FUN_PTR_CAST(main) = base + elf->entry;
    int exit_code = main(args.argc, args.argv, args.envp);

    exit(exit_code);
}