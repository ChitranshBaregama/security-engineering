# Hashes and MACs

> What a hash actually promises, why a hash is not a MAC, and the two
> mistakes that turn a correct-looking authentication check into no
> authentication at all.

**Contents**
[What a hash guarantees](#what-a-hash-guarantees) ·
[Inside SHA-256](#inside-sha-256) ·
[A hash is not a MAC](#a-hash-is-not-a-mac) ·
[Length extension](#length-extension) ·
[HMAC](#hmac) ·
[Constant-time comparison](#constant-time-comparison) ·
[The code](#the-code) ·
[Questions](#questions-i-should-be-able-to-answer) ·
[Sources](#sources)

---

## What a hash guarantees

A cryptographic hash maps any input to a fixed-length digest and promises
three things:

| Property | Means |
| :--- | :--- |
| **Preimage resistance** | Given `H(m)`, you cannot find `m` |
| **Second preimage resistance** | Given `m`, you cannot find `m' ≠ m` with `H(m') = H(m)` |
| **Collision resistance** | You cannot find *any* pair `m ≠ m'` with equal digests |

Collision resistance is the strongest and the first to fall — MD5 and SHA-1
are collision-broken while remaining preimage-resistant. That distinction
matters: SHA-1 is fatally weak for certificate signatures, where an attacker
chooses both documents, and much less urgent for HMAC-SHA-1, where they do
not.

And three things it does **not** promise:

- **It is not encryption.** There is no key and nothing to reverse. A digest
  of a 4-digit PIN is a lookup table away from the PIN.
- **It is not authentication.** Anyone can hash. A digest proves only that
  whoever produced it had the message.
- **It is not a password store.** Hashes are designed to be *fast*, which is
  precisely wrong for passwords. Use Argon2, scrypt or bcrypt, which are
  designed to be slow and memory-hard.

---

## Inside SHA-256

SHA-256 is a **Merkle–Damgård** construction, and that structure — not the
arithmetic — is what you need to hold in your head:

```
  message ──► pad ──► split into 512-bit blocks
                          │
   IV ──► [compress] ──► [compress] ──► [compress] ──► digest
             ▲               ▲              ▲
           block 1        block 2        block 3
```

The state starts at a fixed IV, absorbs one block at a time, and **the final
state is the digest**. There is no finalisation step that separates internal
state from published output.

Two consequences follow, and both are load-bearing:

1. **The digest is the state.** Publish a digest and you publish everything
   needed to carry on hashing from that point. This is
   [length extension](#length-extension).
2. **The padding is a pure function of the length.** `0x80`, then zeros, then
   the 64-bit big-endian bit count. An attacker who knows the message length
   can reconstruct it byte for byte.

SHA-3 (Keccak) uses a sponge and is not length-extendable. BLAKE2 avoids it
too. SHA-256 is not broken — it is *shaped* in a way you have to respect.

---

## A hash is not a MAC

The problem: Alice sends Bob a message and Bob must know it came from Alice
and was not modified. They share a secret key.

The wrong answer, which looks obviously right:

```c
tag = SHA256(key || message);        /* DO NOT DO THIS */
```

It is fast, it is simple, only key-holders can produce it, and it is
**forgeable**.

## Length extension

An attacker who sees one `(message, tag)` pair can produce a valid tag for

```
message || glue-padding || anything-they-choose
```

without ever learning the key. They load the published tag back into the hash
state, and continue.

[`attacks/length-extension/`](../attacks/length-extension/) performs it:

```
=== what the attacker legitimately observes ===
  message : user=guest&role=viewer
  tag     : 0925b7585de8c611af78d50fc5018c40c5b80d1cc684f2ce620be89260e28305
  secret  : UNKNOWN (34 bytes - the attacker guesses the length)

=== step 3: submit it ===
  message : user=guest&role=viewer\x80\x00...\x01\xc0&role=admin
  server accepts the forgery: YES
```

The attacker appended `&role=admin` to an authenticated message and the
server accepted it. Any parser where the last `role=` wins has just been
handed an admin session.

Three details worth noticing:

- The secret was **never recovered**. The attack does not need it.
- The secret's **length** had to be known or guessed. It is a small search —
  try every plausible length and see which forgery is accepted.
- The glue padding is **visible junk** in the message. Parsers that reject
  non-printable bytes make this harder. They do not make it impossible, and
  "the parser might notice" is not a security control.

## HMAC

```
HMAC(K, m) = H( (K ⊕ opad) ‖ H( (K ⊕ ipad) ‖ m ) )
```

The nesting is the defence. The tag you publish is the state of the **outer**
hash, and extending that requires knowing `K ⊕ opad` — which requires the key.
Run the same attack against HMAC in the same program and the server rejects it.

Two implementation details that catch people:

- **A key longer than the block is hashed first.** So a 64-byte key and its
  SHA-256 digest are *the same key* to HMAC. Key equivalence classes exist.
- **`ipad`/`opad` are 0x36 and 0x5c** repeated. They differ in enough bits
  that the two derived keys are effectively independent; that is the whole
  reason two constants are used rather than one.

---

## Constant-time comparison

You have computed the expected tag. You compare it with the one that arrived:

```c
if (memcmp(expected, received, 32) == 0) { accept(); }   /* DO NOT DO THIS */
```

`memcmp` returns as soon as it finds a differing byte. How long the check
takes reveals **how many leading bytes matched**. With an accept/reject oracle
and a clock, an attacker recovers the tag one byte at a time: 256 guesses per
byte, 32 bytes, 8192 queries — instead of 2^256.

[`attacks/timing/`](../attacks/timing/) measures it. On the machine that wrote
this document:

```
  matching     naive compare      constant-time compare
   0 bytes           1.61                  19.90
   8 bytes           5.23                  20.01
  16 bytes           7.89                  18.36
  24 bytes          10.37                  19.65
  32 bytes          12.98                  17.19

  naive:          1.61 ns -> 12.98 ns   (8.0x across the range)
  constant-time:  19.90 ns -> 17.19 ns   (0.86x)
```

Monotonic, and an 8× spread. That trend *is* the attack.

The fix is to remove the early exit:

```c
uint8_t diff = 0;
for (size_t i = 0; i < n; i++) { diff |= a[i] ^ b[i]; }
return diff == 0;
```

Same work every time, no branch on the data. Note the `volatile` pointers in
[the real implementation](../primitives/hmac/hmac_sha256.c) — without them a
compiler is entitled to notice what you are doing and reintroduce the early
exit.

**Where this bites in embedded work specifically:** the leak does not need a
network. A local attacker with a scope on a power rail gets a far cleaner
measurement than a remote one with a stopwatch, and an MCU without a cache or
a branch predictor is *more* predictable, not less. Constant-time discipline
matters more on a microcontroller than on a server, not less.

---

## The code

| Path | What |
| :--- | :--- |
| [`primitives/sha256/`](../primitives/sha256/) | SHA-256 from FIPS 180-4 |
| [`primitives/hmac/`](../primitives/hmac/) | HMAC-SHA-256 from RFC 2104, plus `ct_equal` |
| [`tests/`](../tests/) | FIPS 180-4 and RFC 4231 vectors, padding boundaries, streaming equivalence |
| [`attacks/length-extension/`](../attacks/length-extension/) | The forgery, and HMAC refusing it |
| [`attacks/timing/`](../attacks/timing/) | The measurement above |

```bash
make          # everything
make -C tests # just the vectors
```

> [!WARNING]
> Study implementations. Correct against the published vectors, not hardened,
> not fast, not side-channel resistant beyond the one comparison above. Ship
> mbedTLS, wolfSSL, or a hardware engine.

---

## Questions I should be able to answer

1. Which of the three hash properties does a collision attack break, and why
   does that matter more for certificate signatures than for HMAC?
2. Why is a fast hash the wrong primitive for storing passwords?
3. What exactly is published when you publish a SHA-256 digest?
4. Reconstruct SHA-256's padding for a 100-byte message.
5. Why does the length-extension attacker need the secret's *length* but not
   the secret?
6. Why is HMAC immune, in one sentence about its structure?
7. A 64-byte HMAC key and its SHA-256 digest authenticate identically. Why?
8. Why would SHA-3 not need HMAC to resist this?
9. How many oracle queries does a byte-at-a-time timing attack need against a
   32-byte tag, versus brute force?
10. Why does `ct_equal` use `volatile`, and what breaks without it?
11. Why is a timing side channel often *easier* to exploit on an MCU than on a
    server?
12. `memcmp` is constant-time on some libc implementations. Why is relying on
    that still wrong?

---

## Sources

- **FIPS 180-4**, *Secure Hash Standard* — SHA-256 definition, §4.1.2, §5.3.3,
  and the worked examples in Appendix B.
- **FIPS 198-1**, *The Keyed-Hash Message Authentication Code*.
- **RFC 2104**, *HMAC: Keyed-Hashing for Message Authentication*.
- **RFC 4231** — the HMAC-SHA-256 test vectors used in `tests/`.
- **NIST CAVP** — the byte-oriented SHA known-answer test sets.
- Bellare, Canetti, Krawczyk (1996), *Keying Hash Functions for Message
  Authentication* — the proof that HMAC is secure given a reasonable
  assumption about the compression function.

---

[Back to the index](../README.md)
