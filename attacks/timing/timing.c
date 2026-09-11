/* _POSIX_C_SOURCE: clock_gettime is POSIX.1-2001, and -std=c11 hides it. */
#define _POSIX_C_SOURCE 200809L
/* Measuring the timing leak in a naive tag comparison.
 *
 * A tag check that returns as soon as it finds a differing byte takes
 * longer the more leading bytes match. That is a side channel: an
 * attacker with an accept/reject oracle and a clock can recover a tag
 * one byte at a time - 256 x 32 guesses instead of 2^256.
 *
 * This program does not perform the full recovery. It measures the signal
 * the recovery depends on, which is the honest and reproducible half:
 * compare tags agreeing on 0..31 leading bytes and look at the trend.
 *
 * Build and run:  make -C attacks/timing
 *
 * Caveat worth reading: on a loaded machine, a shared CI runner, or a
 * virtualised host, the noise can swamp the signal. A flat result here is
 * NOT evidence that a naive compare is safe - it is evidence that this
 * measurement was too crude on this host. The structural argument stands
 * regardless of what the clock says.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

#define TAG_LEN 32u
#define REPS    200000u

/* The vulnerable compare: an ordinary, reasonable-looking byte loop. */
static int naive_equal(const uint8_t *a, const uint8_t *b, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        if (a[i] != b[i]) { return 0; }     /* early exit == the leak */
    }
    return 1;
}

/* The safe compare: no early exit, no data-dependent branch. */
static int const_equal(const volatile uint8_t *a, const volatile uint8_t *b, size_t n)
{
    uint8_t diff = 0u;
    for (size_t i = 0; i < n; i++) { diff |= (uint8_t)(a[i] ^ b[i]); }
    return diff == 0u;
}

static uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static volatile int sink;

static double measure(int (*cmp)(const uint8_t *, const uint8_t *, size_t),
                      const uint8_t *a, const uint8_t *b)
{
    /* Warm caches and branch predictors before timing. */
    for (unsigned i = 0; i < 10000u; i++) { sink = cmp(a, b, TAG_LEN); }
    uint64_t t0 = now_ns();
    for (unsigned i = 0; i < REPS; i++) { sink = cmp(a, b, TAG_LEN); }
    return (double)(now_ns() - t0) / (double)REPS;
}

static int ce_shim(const uint8_t *a, const uint8_t *b, size_t n)
{
    return const_equal(a, b, n);
}

int main(void)
{
    uint8_t secret[TAG_LEN], guess[TAG_LEN];
    for (unsigned i = 0; i < TAG_LEN; i++) { secret[i] = (uint8_t)(i * 37u + 11u); }

    printf("Comparing %u-byte tags, %u repetitions each.\n\n", TAG_LEN, REPS);
    printf("  matching     naive compare      constant-time compare\n");
    printf("  prefix       (ns per call)      (ns per call)\n");
    printf("  ---------    ---------------    ---------------------\n");

    double first_naive = 0.0, last_naive = 0.0;
    double first_ct = 0.0, last_ct = 0.0;

    for (unsigned m = 0; m <= TAG_LEN; m += 4u) {
        memset(guess, 0xFF, TAG_LEN);
        memcpy(guess, secret, m);              /* m leading bytes correct */
        if (m == TAG_LEN) { memcpy(guess, secret, TAG_LEN); }

        double tn = measure(naive_equal, secret, guess);
        double tc = measure(ce_shim, secret, guess);

        if (m == 0u)       { first_naive = tn; first_ct = tc; }
        if (m == TAG_LEN)  { last_naive = tn;  last_ct = tc;  }

        printf("  %2u bytes     %10.2f         %14.2f", m, tn, tc);
        int bars = (int)((tn - first_naive) * 4.0);
        if (bars > 0) { printf("   "); for (int i = 0; i < bars && i < 40; i++) putchar('#'); }
        printf("\n");
    }

    printf("\n  naive:          %.2f ns -> %.2f ns   (%.1fx across the range)\n",
           first_naive, last_naive, last_naive / first_naive);
    printf("  constant-time:  %.2f ns -> %.2f ns   (%.2fx)\n",
           first_ct, last_ct, last_ct / first_ct);

    double naive_spread = (last_naive - first_naive) / first_naive;
    double ct_spread    = (last_ct - first_ct) / first_ct;

    printf("\n");
    if (naive_spread > 0.15 && naive_spread > ct_spread * 2.0) {
        printf("  MEASURED: the naive compare leaks. Its runtime tracks how many\n");
        printf("  leading bytes matched; the constant-time version does not.\n");
        printf("\n  That monotonic trend is the whole attack. Guess byte 0 through\n");
        printf("  all 256 values, keep the slowest, move to byte 1. 8192 queries\n");
        printf("  instead of 2^256.\n");
        return 0;
    }
    printf("  INCONCLUSIVE on this host: the timing difference did not clear the\n");
    printf("  noise floor (naive spread %.1f%%, constant-time spread %.1f%%).\n",
           naive_spread * 100.0, ct_spread * 100.0);
    printf("\n  This is a measurement limitation, not a safety result. The early\n");
    printf("  exit is still there in the object code. Re-run on an idle machine,\n");
    printf("  or read the disassembly instead - the branch is plainly visible.\n");
    return 0;
}
