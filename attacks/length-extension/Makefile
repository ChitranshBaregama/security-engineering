CC     ?= gcc
ROOT   := ../..
CFLAGS := -std=c11 -O2 -g -Wall -Wextra -Wconversion \
          -I$(ROOT)/primitives/sha256 -I$(ROOT)/primitives/hmac
SRCS   := extend.c $(ROOT)/primitives/sha256/sha256.c $(ROOT)/primitives/hmac/hmac_sha256.c

.PHONY: all clean
all: extend
	@./extend

extend: $(SRCS)
	$(CC) $(CFLAGS) $(SRCS) -o $@

clean:
	rm -f extend
