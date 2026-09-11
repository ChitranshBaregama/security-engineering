/* Length-extension attack against MAC(k || m) = SHA256(k || m).
 *
 * The scenario is a real one and it looks harmless:
 *
 *   A server authenticates requests with  tag = SHA256(secret || message).
 *   An attacker sees one legitimate (message, tag) pair.
 *   The attacker does NOT know the secret and never learns it.
 *
 * The attacker can still produce a valid tag for
 *
 *     message || glue-padding || anything-they-like
 *
 * The reason is structural. SHA-256 is a Merkle-Damgard construction: it
 * absorbs the message block by block into an internal state, and the
 * digest IS that state. Publishing the tag publishes the state. The
 * attacker loads it and keeps hashing.
 *
 * The glue padding is not a guess either - SHA padding is a deterministic
 * function of the message length, so knowing (or guessing) the secret's
 * length is enough to reconstruct it byte for byte.
 *
 * Build and run:  make -C attacks/length-extension
 */
#include "sha256.h"
#include "hmac_sha256.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static void hexdump(const char *label, const uint8_t *b, size_t n)
{
    printf("%s", label);
    for (size_t i = 0; i < n; i++) { printf("%02x", b[i]); }
    printf("\n");
}

static void printable(const char *label, const uint8_t *b, size_t n)
{
    printf("%s", label);
    for (size_t i = 0; i < n; i++) {
        if (b[i] >= 0x20u && b[i] < 0x7fu) { putchar(b[i]); }
        else { printf("\\x%02x", b[i]); }
    }
    printf("\n");
}

/* Rebuild SHA-256's padding for a message of `len` bytes. Deterministic:
 * 0x80, zeros to 56 mod 64, then the 64-bit big-endian bit length. */
static size_t sha256_padding(uint64_t len, uint8_t *out)
{
    size_t n = 0;
    out[n++] = 0x80u;
    while (((len + n) % 64u) != 56u) { out[n++] = 0x00u; }
    uint64_t bits = len * 8u;
    for (int i = 7; i >= 0; i--) { out[n++] = (uint8_t)((bits >> (8 * i)) & 0xFFu); }
    return n;
}

/* ---- the server -------------------------------------------------------- */

static const uint8_t SECRET[] = "s3cr3t-key-the-attacker-never-sees";
static const size_t  SECRET_LEN = sizeof SECRET - 1u;

static void server_sign_naive(const uint8_t *msg, size_t len, uint8_t tag[32])
{
    sha256_ctx c;
    sha256_init(&c);
    sha256_update(&c, SECRET, SECRET_LEN);     /* <-- the flaw: k || m */
    sha256_update(&c, msg, len);
    sha256_final(&c, tag);
}

static int server_verify_naive(const uint8_t *msg, size_t len, const uint8_t tag[32])
{
    uint8_t expect[32];
    server_sign_naive(msg, len, expect);
    return ct_equal(expect, tag, 32u);
}

static void server_sign_hmac(const uint8_t *msg, size_t len, uint8_t tag[32])
{
    hmac_sha256(SECRET, SECRET_LEN, msg, len, tag);
}

static int server_verify_hmac(const uint8_t *msg, size_t len, const uint8_t tag[32])
{
    uint8_t expect[32];
    server_sign_hmac(msg, len, expect);
    return ct_equal(expect, tag, 32u);
}

/* ---- the attack -------------------------------------------------------- */

int main(void)
{
    const char *original = "user=guest&role=viewer";
    const char *append   = "&role=admin";
    const size_t olen    = strlen(original);

    uint8_t tag[32];
    server_sign_naive((const uint8_t *)original, olen, tag);

    printf("=== what the attacker legitimately observes ===\n");
    printf("  message : %s\n", original);
    hexdump("  tag     : ", tag, 32);
    printf("  secret  : UNKNOWN (%zu bytes - the attacker guesses the length)\n\n",
           SECRET_LEN);

    /* Step 1: rebuild the padding the server applied to (secret || message). */
    uint8_t glue[128];
    size_t  glue_len = sha256_padding(SECRET_LEN + olen, glue);
    printf("=== step 1: reconstruct the glue padding ===\n");
    printf("  the server hashed %zu bytes (secret %zu + message %zu)\n",
           SECRET_LEN + olen, SECRET_LEN, olen);
    printf("  padding is a pure function of that length: %zu bytes\n", glue_len);
    printable("  glue    : ", glue, glue_len);

    /* Step 2: resume SHA-256 from the published tag and keep hashing. */
    printf("\n=== step 2: resume from the tag and append ===\n");
    sha256_ctx c;
    sha256_resume(&c, tag, SECRET_LEN + olen + glue_len);
    sha256_update(&c, append, strlen(append));
    uint8_t forged[32];
    sha256_final(&c, forged);
    printf("  appended: %s\n", append);
    hexdump("  forged  : ", forged, 32);

    /* Step 3: the forged message is original || glue || append. */
    size_t flen = olen + glue_len + strlen(append);
    uint8_t *forged_msg = malloc(flen);
    memcpy(forged_msg, original, olen);
    memcpy(forged_msg + olen, glue, glue_len);
    memcpy(forged_msg + olen + glue_len, append, strlen(append));

    printf("\n=== step 3: submit it ===\n");
    printable("  message : ", forged_msg, flen);
    int accepted = server_verify_naive(forged_msg, flen, forged);
    printf("  server accepts the forgery: %s\n", accepted ? "YES" : "no");

    if (!accepted) {
        printf("\n  the attack did not work - that is a bug in this demo\n");
        free(forged_msg);
        return 1;
    }

    printf("\n  The attacker never learned the secret. They appended\n");
    printf("  \"%s\" to an authenticated message and produced a tag the\n", append);
    printf("  server accepts. A parser that takes the LAST role= wins is\n");
    printf("  now an admin.\n");

    /* ---- the same attack against HMAC ---------------------------------- */
    printf("\n=== the same attack against HMAC-SHA-256 ===\n");
    uint8_t htag[32];
    server_sign_hmac((const uint8_t *)original, olen, htag);
    hexdump("  legitimate tag : ", htag, 32);

    sha256_ctx hc;
    sha256_resume(&hc, htag, SECRET_LEN + olen + glue_len);
    sha256_update(&hc, append, strlen(append));
    uint8_t hforged[32];
    sha256_final(&hc, hforged);
    hexdump("  forged tag     : ", hforged, 32);

    int haccepted = server_verify_hmac(forged_msg, flen, hforged);
    printf("  server accepts : %s\n", haccepted ? "YES" : "no");

    printf("\n  HMAC's outer hash is the defence. The tag the attacker sees is\n");
    printf("  H(opad-key || H(ipad-key || m)) - it is the state of the OUTER\n");
    printf("  hash, whose input the attacker cannot extend without the key.\n");
    printf("  Resuming from it produces nothing useful.\n");

    printf("\n=== the rule ===\n");
    printf("  Never build a MAC as H(key || message).\n");
    printf("  Use HMAC, or a hash without this structure (SHA-3, BLAKE2),\n");
    printf("  or an AEAD that authenticates for you.\n");

    free(forged_msg);
    return (accepted && !haccepted) ? 0 : 1;
}
