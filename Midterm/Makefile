# tools
CC := /usr/bin/gcc
RM := rm -f

# flags
CFLAGS := -ggdb -Wno-format-security
LDFLAGS :=
LDLIBS :=

# sources
sources := sploit.c target.c
support := /share/copy/ece568f/midterm/stackSetup.o /share/copy/ece568f/midterm/murmur3.o
targets := $(sources:.c=)

# gmake magic
.PHONY: default all clean

#targets
default: all
all: $(targets) 

clean:
	$(RM) $(targets) $(sources:.c=.o) 

#dependencies
$(sources:.c=.o): shellcode-64.h
target : target.o $(support)
	$(CC) $(CFLAGS) -pthread -o target $(support) target.o

