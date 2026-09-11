# Security Engineering

[![verify](https://github.com/ChitranshBaregama/security-engineering/actions/workflows/ci.yml/badge.svg)](https://github.com/ChitranshBaregama/security-engineering/actions/workflows/ci.yml)
[![vectors](https://img.shields.io/badge/verified%20against-FIPS%20180--4%20%C2%B7%20RFC%204231-brightgreen)](tests/)
[![licence](https://img.shields.io/badge/docs-CC%20BY%204.0-lightgrey)](LICENSE)
[![licence](https://img.shields.io/badge/code-MIT-lightgrey)](LICENSE-CODE)

Cryptographic primitives implemented from their specifications, verified
against the published test vectors, and then deliberately broken.

Not another explainer. There are excellent books on cryptography and this is
not competing with them. What is rare is a repository where every claim is
executable: the primitive is built from the standard, it reproduces the
official vectors, and the attack that motivates each rule is demonstrated
rather than described.

```bash
make                      # build everything, run the vectors, run the attacks
```

---

## Why implement, rather than summarise

You do not really understand why a MAC nonce must never repeat until your own
code hands you the private key. You do not feel why a tag comparison must be
constant-time until you have plotted your own timing data and watched the
secret leak out byte by byte.

So each topic has four parts:

| | |
| :--- | :--- |
| **Implementation** | Written from the specification, in C, no library calls |
| **Verification** | Known-answer tests against the published vectors — NIST, RFC |
| **Attack** | The failure the rule exists to prevent, performed |
| **Notes** | What the spec does not tell you, and what bit first |

---

## Current state

| Topic | Implementation | Vectors | Attack |
| :--- | :--- | :--- | :--- |
| **SHA-256** | [FIPS 180-4](primitives/sha256/) | FIPS 180-4 §B, NIST CAVP, padding boundaries | [length extension](attacks/length-extension/) |
| **HMAC-SHA-256** | [RFC 2104](primitives/hmac/) | RFC 4231 cases 1–7 | resists the same attack — shown side by side |
| **Tag comparison** | [`ct_equal`](primitives/hmac/hmac_sha256.c) | every single-bit difference | [timing measurement](attacks/timing/) |

**[Chapter 1 — Hashes and MACs](docs/01-hashes-and-macs.md)** is the written
companion.

Everything else is on the [roadmap](ROADMAP.md). The table above is short on
purpose: one topic done to this standard is worth more than ten sketched.

---

## The two results worth seeing

**A MAC built as `SHA256(key ‖ message)` is forgeable without the key.**

```
  message : user=guest&role=viewer
  tag     : 0925b7585de8c611af78d50fc5018c40c5b80d1cc684f2ce620be89260e28305
  secret  : UNKNOWN (34 bytes - the attacker guesses the length)
  ...
  message : user=guest&role=viewer\x80\x00...\x01\xc0&role=admin
  server accepts the forgery: YES
```

The same attack against HMAC-SHA-256, in the same program: **rejected.** That
is what HMAC's outer hash buys you, and seeing both in one run is the point.

**A tag comparison that returns early leaks the tag.**

```
  matching     naive compare      constant-time compare
   0 bytes           1.61 ns               19.90 ns
  16 bytes           7.89 ns               18.36 ns
  32 bytes          12.98 ns               17.19 ns

  naive:          8.0x across the range
  constant-time:  0.86x
```

Monotonic. That trend is the attack: 8192 oracle queries to recover a 32-byte
tag, instead of 2^256.

---

## Running it

```bash
make                              # everything
make -C tests                     # known-answer tests, ASan + UBSan
make -C tests fast                # same, no sanitisers
make -C attacks/length-extension  # the forgery
make -C attacks/timing            # the measurement
```

No dependencies beyond a C compiler and `make`. CI runs all of it on every
push; the length-extension demo **exits non-zero unless the forgery succeeds
against the naive MAC and fails against HMAC**, so it is a test, not a
performance.

The timing measurement reports but never fails the build — a shared CI runner
is too noisy for a timing assertion, and a flaky test that cries wolf is worse
than no test. The program says so itself when the signal does not clear the
noise floor, rather than claiming a result it did not get.

---

## A necessary warning

**These are study implementations. Do not ship them.**

They are correct against the published vectors, and that is all they are. They
are not constant-time beyond the one comparison that is the subject of its own
demonstration, not resistant to fault injection, not hardened against anything
an attacker with physical access can do, and not fast.

Use mbedTLS, wolfSSL, BearSSL, libsodium, or your MCU's crypto engine. Writing
your own is how you learn what those libraries are doing; it is not how you
ship a product.

---

## Roadmap

[`ROADMAP.md`](ROADMAP.md) has the full arc: block ciphers and modes, AEAD and
nonce reuse, randomness and DRBGs, ECC from first principles, key management,
PKI, side channels, and secure boot. Gaps are listed openly rather than left
as silent holes.

## Related

- [**Embedded systems reference**](https://github.com/ChitranshBaregama/embedded-systems-resources) — bare-metal firmware notes and runnable Cortex-M code
- [**DLMS/COSEM security**](https://github.com/ChitranshBaregama/EncryptionAlgorithm-) — the same discipline applied to one protocol, including a general PKI and ECC companion volume

## Licence

Prose [CC BY 4.0](LICENSE); code [MIT](LICENSE-CODE).
