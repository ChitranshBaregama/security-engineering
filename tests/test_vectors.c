/* Known-answer tests against the published vectors.
 *
 * SHA-256:      FIPS 180-4 examples and NIST CAVP byte-oriented KATs
 * HMAC-SHA-256: RFC 4231 test cases 1-7
 *
 * The point of a KAT suite is that it is not self-referential. An
 * implementation that agrees with itself proves nothing; one that
 * reproduces the published constants is interoperable with everyone else
 * who did the same.
 */
#include "../primitives/sha256/sha256.h"
#include "../primitives/hmac/hmac_sha256.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int failures = 0, checks = 0;

static void hexs(const uint8_t *b, size_t n, char *out)
{
    static const char d[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2*i] = d[b[i] >> 4];
        out[2*i + 1] = d[b[i] & 0xF];
    }
    out[2*n] = '\0';
}

static void expect(const char *name, const uint8_t *got, size_t n, const char *want)
{
    char g[129];
    checks++;
    hexs(got, n, g);
    if (strcmp(g, want) == 0) {
        printf("  %-56s ok\n", name);
    } else {
        printf("  %-56s FAIL\n    got  %s\n    want %s\n", name, g, want);
        failures++;
    }
}

static void sha_kats(void)
{
    uint8_t d[SHA256_DIGEST_LEN];
    printf("\nSHA-256 (FIPS 180-4 / NIST CAVP)\n");

    sha256("", 0, d);
    expect("empty string", d, sizeof d,
           "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

    sha256("abc", 3, d);
    expect("\"abc\"  (FIPS 180-4 B.1)", d, sizeof d,
           "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

    const char *m2 = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    sha256(m2, strlen(m2), d);
    expect("56-byte message  (FIPS 180-4 B.2)", d, sizeof d,
           "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");

    const char *m3 = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
                     "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    sha256(m3, strlen(m3), d);
    expect("112-byte message  (FIPS 180-4 B.3)", d, sizeof d,
           "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1");

    /* One million 'a'. Exercises multi-block handling and the 64-bit
     * length field, which is where hand-written SHA goes wrong. */
    uint8_t *big = malloc(1000000u);
    if (!big) { fprintf(stderr, "allocation failed\n"); exit(EXIT_FAILURE); }
    memset(big, 'a', 1000000u);
    sha256(big, 1000000u, d);
    free(big);
    expect("one million 'a'  (FIPS 180-4 B.3 long)", d, sizeof d,
           "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");

    /* Exactly one block, and one byte either side: the padding boundaries
     * where an off-by-one hides. */
    uint8_t blk[64];
    memset(blk, 0x61, sizeof blk);
    sha256(blk, 55u, d);
    expect("55 bytes (last that fits with padding in one block)", d, sizeof d,
           "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318");
    sha256(blk, 56u, d);
    expect("56 bytes (forces a second block)", d, sizeof d,
           "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a");
    sha256(blk, 64u, d);
    expect("64 bytes (exactly one block)", d, sizeof d,
           "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb");
}

static void hmac_kats(void)
{
    uint8_t t[HMAC_SHA256_LEN];
    printf("\nHMAC-SHA-256 (RFC 4231)\n");

    uint8_t k1[20];  memset(k1, 0x0b, sizeof k1);
    hmac_sha256(k1, sizeof k1, "Hi There", 8, t);
    expect("case 1", t, sizeof t,
           "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");

    hmac_sha256("Jefe", 4, "what do ya want for nothing?", 28, t);
    expect("case 2  (key shorter than block)", t, sizeof t,
           "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");

    uint8_t k3[20];  memset(k3, 0xaa, sizeof k3);
    uint8_t d3[50];  memset(d3, 0xdd, sizeof d3);
    hmac_sha256(k3, sizeof k3, d3, sizeof d3, t);
    expect("case 3", t, sizeof t,
           "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe");

    uint8_t k4[25];
    for (unsigned i = 0; i < sizeof k4; i++) { k4[i] = (uint8_t)(i + 1); }
    uint8_t d4[50];  memset(d4, 0xcd, sizeof d4);
    hmac_sha256(k4, sizeof k4, d4, sizeof d4, t);
    expect("case 4", t, sizeof t,
           "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b");

    /* RFC 4231 section 4.6: compare only the published 128-bit prefix. */
    uint8_t k5[20]; memset(k5, 0x0c, sizeof k5);
    const char *m5 = "Test With Truncation";
    hmac_sha256(k5, sizeof k5, m5, strlen(m5), t);
    expect("case 5  (128-bit truncated tag)", t, 16,
           "a3b6167473100ee06e0c796c2955552b");

    uint8_t k6[131]; memset(k6, 0xaa, sizeof k6);
    const char *m6 = "Test Using Larger Than Block-Size Key - Hash Key First";
    hmac_sha256(k6, sizeof k6, m6, strlen(m6), t);
    expect("case 6  (key longer than block, hashed first)", t, sizeof t,
           "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");

    const char *m7 = "This is a test using a larger than block-size key and a "
                     "larger than block-size data. The key needs to be hashed "
                     "before being used by the HMAC algorithm.";
    hmac_sha256(k6, sizeof k6, m7, strlen(m7), t);
    expect("case 7", t, sizeof t,
           "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2");
}

static void streaming_equivalence(void)
{
    /* Feeding the same message in different chunk sizes must give the same
     * digest. This is where buffering bugs live, and no published vector
     * will catch them. */
    printf("\nStreaming equivalence (buffering)\n");
    uint8_t msg[300];
    for (unsigned i = 0; i < sizeof msg; i++) { msg[i] = (uint8_t)(i * 7u + 1u); }

    uint8_t one_shot[SHA256_DIGEST_LEN];
    sha256(msg, sizeof msg, one_shot);

    int bad = 0;
    for (size_t chunk = 1; chunk <= 130; chunk++) {
        sha256_ctx c;
        uint8_t d[SHA256_DIGEST_LEN];
        sha256_init(&c);
        for (size_t off = 0; off < sizeof msg; off += chunk) {
            size_t n = sizeof msg - off;
            if (n > chunk) { n = chunk; }
            sha256_update(&c, msg + off, n);
        }
        sha256_final(&c, d);
        if (memcmp(d, one_shot, sizeof d) != 0) { bad++; }
    }
    checks++;
    if (bad == 0) {
        printf("  %-56s ok\n", "130 chunk sizes all agree with one-shot");
    } else {
        printf("  %-56s FAIL (%d differ)\n", "chunked vs one-shot", bad);
        failures++;
    }
}

static void constant_time_compare(void)
{
    printf("\nConstant-time comparison\n");
    uint8_t a[32], b[32];
    memset(a, 0xA5, sizeof a);
    memcpy(b, a, sizeof b);
    checks++;
    if (ct_equal(a, b, sizeof a) == 1) { printf("  %-56s ok\n", "equal buffers compare equal"); }
    else { printf("  %-56s FAIL\n", "equal buffers"); failures++; }

    int all = 1;
    for (size_t i = 0; i < sizeof a; i++) {
        for (unsigned bit = 0; bit < 8u; bit++) {
            memcpy(b, a, sizeof b);
            b[i] ^= (uint8_t)(1u << bit);
            if (ct_equal(a, b, sizeof a) != 0) { all = 0; }
        }
    }
    checks++;
    if (all) { printf("  %-56s ok\n", "every single-bit difference detected"); }
    else { printf("  %-56s FAIL\n", "single-bit differences"); failures++; }
}

int main(void)
{
    sha_kats();
    hmac_kats();
    streaming_equivalence();
    constant_time_compare();
    printf("\n%d checks, %d failed\n", checks, failures);
    return failures ? 1 : 0;
}
