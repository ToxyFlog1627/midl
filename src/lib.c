#include "lib.h"
#include "elf.h"
#include "print.h"
#include "syscalls.h"
#include "types.h"
#include "ulibc.h"
#include "vector.h"

#define MAX_PATH_LENGTH 4096

static void concat_path(char *buffer, const char *path, const char *filename) {
    size_t path_length = strlen(path), filename_length = strlen(filename);

    memcpy(buffer, path, path_length);
    buffer[path_length++] = '/';

    memcpy(buffer + path_length, filename, filename_length);
    buffer[path_length + filename_length] = '\0';
}

static int open_library(const vec_cstr *library_search_paths, const char *library_name) {
    static char library_path[MAX_PATH_LENGTH];

    for (size_t i = 0; i < library_search_paths->length; i++) {
        concat_path(library_path, library_search_paths->elements[i], library_name);
        int fd = open(library_path, O_RDWR, NULL);
        if (fd >= 0) return fd;
    }

    print("Error loading shared library: unable to find library \"");
    print(library_name);
    print("\".\n");
    exit(1);
}

#define ALIGN(value, alignment) (value & ~(alignment - 1))

void load_library(LibInfo *lib_info, const vec_cstr *lib_search_paths, const char *lib_name) {
    int fd = open_library(lib_search_paths, lib_name);

    ELFHeader lib_elf;
    read(fd, &lib_elf, sizeof(lib_elf));
    check_elf_header(&lib_elf);

    size_t segments_size = lib_elf.segment_entry_num * sizeof(Segment);
    Segment *segments = (Segment *) malloc(segments_size);
    lseek(fd, lib_elf.segments_offset, SEEK_SET);
    read(fd, segments, segments_size);

    size_t memory_size = 0;
    for (size_t i = 0; i < lib_elf.segment_entry_num; i++) {
        Segment *seg = &segments[i];
        if (seg->type != SG_LOAD) continue;

        if (seg->memory_offset % seg->alignment != 0) {
            uint64_t aligned_file_offset = ALIGN(seg->file_offset, seg->alignment);
            uint64_t aligned_memory_offset = ALIGN(seg->memory_offset, seg->alignment);

            uint64_t size_diff = seg->file_offset - aligned_file_offset + seg->file_size;
            seg->file_size += size_diff;
            seg->memory_size += size_diff;

            seg->file_offset = aligned_file_offset;
            seg->memory_offset = aligned_memory_offset;
        }

        size_t new_size = seg->memory_offset + seg->memory_size;
        if (new_size > memory_size) memory_size = new_size;
    }

    // memory of this mmap is not used, because the purpose of this call is to locate
    // contiguous chunk of address space which later gets overriden with library data
    char *lib_base = mmap(NULL, memory_size, MAP_PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, NULL, NULL);
    if (((int64_t) lib_base) < 0) {
        print("Anonymous mmap failed: unable to allocate memory for a shared library.\n");
        exit(1);
    }

    for (size_t i = 0; i < lib_elf.segment_entry_num; i++) {
        Segment *seg = &segments[i];
        if (seg->type != SG_LOAD) continue;

        void *result = mmap(lib_base + seg->memory_offset, seg->file_size, seg->flags, MAP_PRIVATE | MAP_FIXED, fd,
                            seg->file_offset);
        if (((int64_t) result) < 0) {
            print("mmap failed: unable to load shared library.\n");
            exit(1);
        }
    }

    close(fd);
    free(segments);

    lib_info->name = strdup(lib_name);
    lib_info->base = lib_base;
    get_dynamic_info(&lib_info->dyn_info, lib_base, &lib_elf);
}