/* SHA-256, implemented from FIPS 180-4.
 *
 * A study implementation. It is correct - it reproduces the NIST vectors -
 * but it is not hardened and it is not fast. Ship a library.
 */
#ifndef SHA256_H
#define SHA256_H

#include <stdint.h>
#include <stddef.h>

#define SHA256_DIGEST_LEN 32u
#define SHA256_BLOCK_LEN  64u

typedef struct {
    uint32_t state[8];          /* H0..H7, the running hash value  */
    uint64_t bitlen;            /* total message length in BITS    */
    uint8_t  buf[SHA256_BLOCK_LEN];
    size_t   buflen;            /* bytes currently buffered        */
} sha256_ctx;

void sha256_init(sha256_ctx *c);
void sha256_update(sha256_ctx *c, const void *data, size_t len);
void sha256_final(sha256_ctx *c, uint8_t out[SHA256_DIGEST_LEN]);
void sha256(const void *data, size_t len, uint8_t out[SHA256_DIGEST_LEN]);

/* Resume from a known state and message length. This exists ONLY to make
 * the length-extension attack in attacks/length-extension/ constructible.
 * No legitimate use needs it - and that is the lesson. */
void sha256_resume(sha256_ctx *c, const uint8_t digest[SHA256_DIGEST_LEN],
                   uint64_t bytes_already_hashed);
#endif
