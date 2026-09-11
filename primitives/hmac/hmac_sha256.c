#include "hmac_sha256.h"
#include <string.h>

void hmac_sha256(const void *key, size_t keylen,
                 const void *msg, size_t msglen,
                 uint8_t out[HMAC_SHA256_LEN])
{
    uint8_t k_prime[SHA256_BLOCK_LEN];
    uint8_t k_ipad[SHA256_BLOCK_LEN];
    uint8_t k_opad[SHA256_BLOCK_LEN];
    uint8_t inner[SHA256_DIGEST_LEN];
    sha256_ctx c;

    memset(k_prime, 0, sizeof k_prime);

    if (keylen > SHA256_BLOCK_LEN) {
        /* RFC 2104: a key longer than the block is hashed first. Note the
         * consequence - a 64-byte key and its SHA-256 digest are the SAME
         * key to HMAC. Key equivalence classes surprise people. */
        sha256(key, keylen, k_prime);
    } else {
        memcpy(k_prime, key, keylen);
    }

    for (size_t i = 0; i < SHA256_BLOCK_LEN; i++) {
        k_ipad[i] = (uint8_t)(k_prime[i] ^ 0x36u);
        k_opad[i] = (uint8_t)(k_prime[i] ^ 0x5cu);
    }

    sha256_init(&c);
    sha256_update(&c, k_ipad, sizeof k_ipad);
    sha256_update(&c, msg, msglen);
    sha256_final(&c, inner);

    sha256_init(&c);
    sha256_update(&c, k_opad, sizeof k_opad);
    sha256_update(&c, inner, sizeof inner);
    sha256_final(&c, out);

    /* Zeroise. A compiler is allowed to delete a memset whose result is
     * never read - which is why real code uses explicit_bzero or a
     * volatile pointer. This memset may well be optimised away, and
     * pointing that out is more useful than pretending otherwise. */
    memset(k_prime, 0, sizeof k_prime);
    memset(k_ipad, 0, sizeof k_ipad);
    memset(k_opad, 0, sizeof k_opad);
}

int ct_equal(const void *a, const void *b, size_t len)
{
    const volatile uint8_t *x = (const volatile uint8_t *)a;
    const volatile uint8_t *y = (const volatile uint8_t *)b;
    uint8_t diff = 0u;

    /* No early exit, no branch on the data. Accumulate every difference
     * and test once at the end. The loop runs the same number of times
     * whatever the inputs are. */
    for (size_t i = 0; i < len; i++) {
        diff |= (uint8_t)(x[i] ^ y[i]);
    }
    return diff == 0u;
}
