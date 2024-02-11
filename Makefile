CC      := gcc
CFLAGS  := -std=c17 -Wall -Wextra -pedantic

ifeq ($(DEBUG),1)
	CFLAGS += -ggdb -g3 -DDEBUG -O0
else
	CFLAGS += -s -O2
endif

SOURCE_DIR  := src
BUILD_DIR   := build
OBJECTS_DIR := $(BUILD_DIR)/$(SOURCE_DIR)

SOURCES := $(shell find $(SOURCE_DIR) -type f -name '*.c')
LOADER  := $(BUILD_DIR)/loader.so
OBJECTS := $(patsubst $(SOURCE_DIR)/%.c, $(OBJECTS_DIR)/%.o, $(SOURCES))

EXAMPLE_BIN_CFLAGS := $(CFLAGS) -e main -Wl,--dynamic-linker,$(PWD)/$(LOADER) -nostdlib
EXAMPLE_LIB_CFLAGS := $(CFLAGS) -shared -nostdlib

EXAMPLE_BIN_SRC_DIR   := examples
EXAMPLE_BIN_OBJ_DIR   := $(BUILD_DIR)/$(EXAMPLE_BIN_SRC_DIR)
EXAMPLE_BIN_BUILD_DIR := $(BUILD_DIR)/bins
EXAMPLE_LIB_SRC_DIR   := examples/libs
EXAMPLE_LIB_OBJ_DIR   := $(BUILD_DIR)/$(EXAMPLE_LIB_SRC_DIR)
EXAMPLE_LIB_BUILD_DIR := $(BUILD_DIR)/libs

.PHONY: all
all: build examples

.PHONY: build
build: $(LOADER)

.PHONY: clean
clean:
	@rm -rf $(BUILD_DIR)

.PHONY: $(LOADER)
$(LOADER): $(OBJECTS)
	$(CC) $(CFLAGS) -e entry -nostdlib $^ -o $@ -static-pie

$(OBJECTS_DIR)/%.o: $(SOURCE_DIR)/%.c
	@mkdir -p $(OBJECTS_DIR)
	$(CC) $(CFLAGS) -I src -c $^ -o $@ -fno-stack-protector

.PHONY: examples
examples: libless single_lib chained_libs

.PHONY: libmath
libmath: $(EXAMPLE_LIB_OBJ_DIR)/math.o
	@mkdir -p $(EXAMPLE_LIB_BUILD_DIR)
	$(CC) $(EXAMPLE_LIB_CFLAGS) $^ -o $(EXAMPLE_LIB_BUILD_DIR)/$@.so

.PHONY: libsyscall
libsyscall: $(EXAMPLE_LIB_OBJ_DIR)/syscall.o
	@mkdir -p $(EXAMPLE_LIB_BUILD_DIR)
	$(CC) $(EXAMPLE_LIB_CFLAGS) $^ -o $(EXAMPLE_LIB_BUILD_DIR)/$@.so

.PHONY: libprint
libprint: $(EXAMPLE_LIB_OBJ_DIR)/print.o libsyscall
	@mkdir -p $(EXAMPLE_LIB_BUILD_DIR)
	$(CC) $(EXAMPLE_LIB_CFLAGS) -L $(EXAMPLE_LIB_BUILD_DIR) -Wl,-rpath=$(PWD)/$(EXAMPLE_LIB_BUILD_DIR) $< -o $(EXAMPLE_LIB_BUILD_DIR)/$@.so -lsyscall

$(EXAMPLE_LIB_OBJ_DIR)/%.o: $(EXAMPLE_LIB_SRC_DIR)/%.c
	@mkdir -p $(EXAMPLE_LIB_OBJ_DIR)
	$(CC) $(CFLAGS) -c $^ -o $@  -fno-stack-protector

.PHONY: libless
libless: $(EXAMPLE_BIN_OBJ_DIR)/libless.o
	@mkdir -p $(EXAMPLE_BIN_BUILD_DIR)
	$(CC) $(EXAMPLE_BIN_CFLAGS) $^ -o $(EXAMPLE_BIN_BUILD_DIR)/$@

.PHONY: single_lib
single_lib: $(EXAMPLE_BIN_OBJ_DIR)/single_lib.o libmath
	@mkdir -p $(EXAMPLE_BIN_BUILD_DIR)
	$(CC) $(EXAMPLE_BIN_CFLAGS) $< -o $(EXAMPLE_BIN_BUILD_DIR)/$@ -L $(EXAMPLE_LIB_BUILD_DIR) -lmath

.PHONY: chained_libs
chained_libs: $(EXAMPLE_BIN_OBJ_DIR)/chained_libs.o libprint
	@mkdir -p $(EXAMPLE_BIN_BUILD_DIR)
	$(CC) $(EXAMPLE_BIN_CFLAGS) $< -o $(EXAMPLE_BIN_BUILD_DIR)/$@ -L $(EXAMPLE_LIB_BUILD_DIR) -lprint

$(EXAMPLE_BIN_OBJ_DIR)/%.o: $(EXAMPLE_BIN_SRC_DIR)/%.c
	@mkdir -p $(EXAMPLE_BIN_OBJ_DIR)
	$(CC) $(CFLAGS) -c $^ -o $@  -fno-stack-protector
