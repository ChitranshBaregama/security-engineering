# Known-answer tests, under AddressSanitizer and UBSan by default.
#
# Sanitisers on by default is deliberate: a buffer overrun in a hash or MAC
# is the bug class that becomes a CVE, and catching it here costs seconds.

CC     ?= gcc
ROOT   := ..
WARN   := -Wall -Wextra -Wconversion -Wshadow -Wundef -Wpointer-arith
SAN    := -fsanitize=address,undefined -fno-omit-frame-pointer
CFLAGS := -std=c11 -O1 -g $(WARN) -I$(ROOT)/primitives/sha256 -I$(ROOT)/primitives/hmac
SRCS   := test_vectors.c $(ROOT)/primitives/sha256/sha256.c $(ROOT)/primitives/hmac/hmac_sha256.c

.PHONY: all fast clean
all: test_vectors
	@./test_vectors

fast: CFLAGS := -std=c11 -O2 $(WARN) -I$(ROOT)/primitives/sha256 -I$(ROOT)/primitives/hmac
fast: SAN :=
fast: all

test_vectors: $(SRCS) $(ROOT)/primitives/sha256/sha256.h $(ROOT)/primitives/hmac/hmac_sha256.h
	$(CC) $(CFLAGS) $(SAN) $(SRCS) -o $@

clean:
	rm -f test_vectors
