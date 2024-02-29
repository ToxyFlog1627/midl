#include "library.h"
#include "elf.h"
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
        concat_path(library_path, library_search_paths->data[i], library_name);
        int fd = open(library_path, O_RDWR, NULL);
        if (fd >= 0) return fd;
    }

    print("ERROR: unable to find shared library \"");
    print(library_name);
    print("\".\n");
    exit(1);
}

#define ALIGN(value, alignment) (value & ~(alignment - 1))

Library load_library(const vec_cstr *lib_search_paths, const char *lib_name) {
    Library library;
    memset(&library, 0, sizeof(library));

    int fd = open_library(lib_search_paths, lib_name);

    ELFHeader lib_elf;
    read(fd, &lib_elf, sizeof(lib_elf));
    check_elf_header(&lib_elf);

    size_t segments_size = lib_elf.segment_entry_num * sizeof(ELFSegment);
    ELFSegment *segments = (ELFSegment *) malloc(segments_size);
    lseek(fd, lib_elf.segments_offset, SEEK_SET);
    read(fd, segments, segments_size);

    size_t memory_size = 0;
    for (size_t i = 0; i < lib_elf.segment_entry_num; i++) {
        ELFSegment *segment = &segments[i];
        if (segment->type != SG_LOAD) continue;

        if (segment->memory_offset % segment->alignment != 0) {
            uint64_t aligned_file_offset = ALIGN(segment->file_offset, segment->alignment);
            uint64_t aligned_memory_offset = ALIGN(segment->memory_offset, segment->alignment);

            uint64_t size_diff = segment->file_offset - aligned_file_offset + segment->file_size;
            segment->file_size += size_diff;
            segment->memory_size += size_diff;

            segment->file_offset = aligned_file_offset;
            segment->memory_offset = aligned_memory_offset;
        }

        size_t new_size = segment->memory_offset + segment->memory_size;
        if (new_size > memory_size) memory_size = new_size;
    }

    // memory of this mmap is not used, because the purpose of this call is to locate
    // contiguous chunk of address space which later gets overriden with library data
    char *lib_base = mmap(NULL, memory_size, MAP_PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, NULL, NULL);
    assert(((int64_t) lib_base) >= 0, "mmap failed.");

    for (size_t i = 0; i < lib_elf.segment_entry_num; i++) {
        ELFSegment *segment = &segments[i];
        if (segment->type != SG_LOAD) continue;

        void *result = mmap(lib_base + segment->memory_offset, segment->file_size, segment->flags,
                            MAP_PRIVATE | MAP_FIXED, fd, segment->file_offset);
        assert(((int64_t) result) >= 0, "mmap failed.");
    }

    close(fd);
    free(segments);

    library.name = strdup(lib_name);
    library.base = lib_base;
    library.dynamic = get_dynamic(lib_base, &lib_elf);

    return library;
}