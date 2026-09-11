CC     ?= gcc
# -O1: -O2 can vectorise the constant-time loop into something that no
# longer resembles what an embedded compiler emits, and -O0 exaggerates
# the naive loop unfairly. -O1 is the honest middle.
CFLAGS := -std=c11 -O1 -g -Wall -Wextra -Wconversion

.PHONY: all clean
all: timing
	@./timing

timing: timing.c
	$(CC) $(CFLAGS) timing.c -o $@

clean:
	rm -f timing
