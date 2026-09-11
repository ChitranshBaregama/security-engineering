/* HMAC-SHA-256, implemented from RFC 2104 / FIPS 198-1.
 *
 *   HMAC(K, m) = H( (K' XOR opad) || H( (K' XOR ipad) || m ) )
 *
 * where K' is K padded to the block size, or H(K) first if K is longer.
 * The nested structure is not decoration: it is precisely what makes HMAC
 * immune to the length-extension attack that breaks the naive H(K || m).
 * See attacks/length-extension/.
 */
#ifndef HMAC_SHA256_H
#define HMAC_SHA256_H

#include <stdint.h>
#include <stddef.h>
#include "sha256.h"

#define HMAC_SHA256_LEN SHA256_DIGEST_LEN

void hmac_sha256(const void *key, size_t keylen,
                 const void *msg, size_t msglen,
                 uint8_t out[HMAC_SHA256_LEN]);

/* Compare two tags without leaking where they differ. Returns 1 on equal.
 *
 * memcmp returns as soon as it finds a differing byte, so the time it
 * takes reveals how many leading bytes matched. Given an oracle that says
 * only accept/reject, that is enough to forge a tag byte by byte. The
 * measurement is in attacks/timing/.
 */
int ct_equal(const void *a, const void *b, size_t len);

#endif
