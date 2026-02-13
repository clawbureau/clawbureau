CC ?= gcc
CFLAGS = -Wall -Wextra -O3 -fPIC -std=gnu99 -fno-omit-frame-pointer

UNAME_S := $(shell uname -s)

ifeq ($(UNAME_S),Linux)
  TARGET = libclawsig_interpose.so
  SHARED_FLAGS = -shared
  LDFLAGS = -ldl
endif

ifeq ($(UNAME_S),Darwin)
  CC = clang
  TARGET = libclawsig_interpose.dylib
  SHARED_FLAGS = -dynamiclib
  LDFLAGS =
endif

all: $(TARGET)

$(TARGET): libclawsig_interpose.c
	$(CC) $(CFLAGS) $(SHARED_FLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f *.so *.dylib

.PHONY: all clean
