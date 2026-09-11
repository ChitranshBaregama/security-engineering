#include "sha256.h"
#include <string.h>

/* FIPS 180-4 section 4.2.2: the first 32 bits of the fractional parts of
 * the cube roots of the first 64 primes. Nothing-up-my-sleeve numbers -
 * they are chosen so that nobody can claim a hidden trapdoor. */
static const uint32_t K[64] = {
    0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,
    0x923f82a4u,0xab1c5ed5u,0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,
    0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,0xe49b69c1u,0xefbe4786u,
    0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
    0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,
    0x06ca6351u,0x14292967u,0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,
    0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,0xa2bfe8a1u,0xa81a664bu,
    0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
    0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,
    0x5b9cca4fu,0x682e6ff3u,0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,
    0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
};

static uint32_t rotr(uint32_t x, unsigned n) { return (x >> n) | (x << (32u - n)); }

/* FIPS 180-4 section 4.1.2 */
#define CH(x,y,z)   (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z)  (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define BSIG0(x)    (rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22))
#define BSIG1(x)    (rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25))
#define SSIG0(x)    (rotr(x, 7) ^ rotr(x, 18) ^ ((x) >> 3))
#define SSIG1(x)    (rotr(x, 17) ^ rotr(x, 19) ^ ((x) >> 10))

static void compress(uint32_t state[8], const uint8_t block[64])
{
    uint32_t w[64];

    /* Message schedule. Big-endian: SHA is defined on big-endian words
     * regardless of your CPU, which is why this is done by hand rather
     * than by casting a pointer. */
    for (unsigned t = 0; t < 16u; t++) {
        w[t] = ((uint32_t)block[4*t] << 24) | ((uint32_t)block[4*t+1] << 16)
             | ((uint32_t)block[4*t+2] << 8) | (uint32_t)block[4*t+3];
    }
    for (unsigned t = 16u; t < 64u; t++) {
        w[t] = SSIG1(w[t-2]) + w[t-7] + SSIG0(w[t-15]) + w[t-16];
    }

    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];

    for (unsigned t = 0; t < 64u; t++) {
        uint32_t t1 = h + BSIG1(e) + CH(e, f, g) + K[t] + w[t];
        uint32_t t2 = BSIG0(a) + MAJ(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

void sha256_init(sha256_ctx *c)
{
    /* First 32 bits of the fractional parts of the square roots of the
     * first eight primes. */
    c->state[0] = 0x6a09e667u; c->state[1] = 0xbb67ae85u;
    c->state[2] = 0x3c6ef372u; c->state[3] = 0xa54ff53au;
    c->state[4] = 0x510e527fu; c->state[5] = 0x9b05688cu;
    c->state[6] = 0x1f83d9abu; c->state[7] = 0x5be0cd19u;
    c->bitlen = 0u;
    c->buflen = 0u;
}

void sha256_update(sha256_ctx *c, const void *data, size_t len)
{
    const uint8_t *p = (const uint8_t *)data;
    c->bitlen += (uint64_t)len * 8u;

    while (len > 0u) {
        size_t take = SHA256_BLOCK_LEN - c->buflen;
        if (take > len) { take = len; }
        memcpy(c->buf + c->buflen, p, take);
        c->buflen += take;
        p += take;
        len -= take;
        if (c->buflen == SHA256_BLOCK_LEN) {
            compress(c->state, c->buf);
            c->buflen = 0u;
        }
    }
}

void sha256_final(sha256_ctx *c, uint8_t out[SHA256_DIGEST_LEN])
{
    /* The padding is the whole story behind length extension:
     * 0x80, then zeros, then the 64-bit big-endian BIT length. It is a
     * deterministic function of the message length alone - so an attacker
     * who knows the length can reconstruct it exactly. */
    uint64_t bitlen = c->bitlen;
    uint8_t  pad    = 0x80u;
    sha256_update(c, &pad, 1u);
    c->bitlen = bitlen;                    /* padding is not message data */

    uint8_t zero = 0x00u;
    while (c->buflen != 56u) {
        sha256_update(c, &zero, 1u);
        c->bitlen = bitlen;
    }

    uint8_t len_be[8];
    for (unsigned i = 0; i < 8u; i++) {
        len_be[i] = (uint8_t)((bitlen >> (56u - 8u * i)) & 0xFFu);
    }
    sha256_update(c, len_be, 8u);

    for (unsigned i = 0; i < 8u; i++) {
        out[4*i]     = (uint8_t)((c->state[i] >> 24) & 0xFFu);
        out[4*i + 1] = (uint8_t)((c->state[i] >> 16) & 0xFFu);
        out[4*i + 2] = (uint8_t)((c->state[i] >> 8) & 0xFFu);
        out[4*i + 3] = (uint8_t)(c->state[i] & 0xFFu);
    }
}

void sha256(const void *data, size_t len, uint8_t out[SHA256_DIGEST_LEN])
{
    sha256_ctx c;
    sha256_init(&c);
    sha256_update(&c, data, len);
    sha256_final(&c, out);
}

void sha256_resume(sha256_ctx *c, const uint8_t digest[SHA256_DIGEST_LEN],
                   uint64_t bytes_already_hashed)
{
    /* A SHA-256 digest IS the internal state. There is no separation
     * between "output" and "state" - publishing the digest publishes
     * everything needed to keep hashing. That single design fact is what
     * makes MAC(k||m) forgeable. */
    for (unsigned i = 0; i < 8u; i++) {
        c->state[i] = ((uint32_t)digest[4*i] << 24)
                    | ((uint32_t)digest[4*i + 1] << 16)
                    | ((uint32_t)digest[4*i + 2] << 8)
                    | (uint32_t)digest[4*i + 3];
    }
    c->bitlen = bytes_already_hashed * 8u;
    c->buflen = 0u;
}
