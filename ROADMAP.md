# Roadmap

The full arc, and how much of it exists. Listed openly — a repository that
hides its gaps is harder to trust than one that names them.

Every topic gets the same four parts: implementation from the specification,
known-answer tests against published vectors, a demonstrated attack, and notes
on what the spec leaves out.

---

## Done

| Topic | Implementation | Vectors | Attack |
| :--- | :--- | :--- | :--- |
| SHA-256 | FIPS 180-4 | FIPS 180-4 §B, CAVP, padding boundaries, streaming equivalence | Length extension against `H(k‖m)` |
| HMAC-SHA-256 | RFC 2104 | RFC 4231 cases 1–7 | Shown resisting the same attack |
| Constant-time comparison | — | Every single-bit difference | Timing measurement, 8× spread |

---

## Next, in order

**1. Block ciphers and modes — AES.**
AES-128/192/256 from FIPS 197. Vectors from FIPS 197 Appendix C and NIST CAVP
KAT. Modes from SP 800-38A: ECB, CBC, CTR.
*Attacks:* the ECB penguin (structure survives encryption); CBC bit-flipping
against an unauthenticated ciphertext; IV reuse in CTR recovering plaintext by
XOR.

**2. AEAD — AES-GCM.**
From SP 800-38D, with GHASH written out. Vectors from the NIST GCM test set.
*Attack:* nonce reuse. Two messages under one nonce give the keystream by XOR,
and — the part people miss — enough to **recover the GHASH authentication key**
and forge tags at will. This is the single most valuable demonstration on the
list.

**3. Randomness.**
Entropy versus PRNG versus CSPRNG, CTR_DRBG from SP 800-90A, and RNG on a
microcontroller: ring oscillators, health tests, seeding at first boot.
*Attack:* predicting a Mersenne Twister from observed output; recovering an
ECDSA key from a biased nonce.

**4. ECC from first principles.**
Curve arithmetic, ECDH, ECDSA, and RFC 6979 deterministic nonces. Vectors from
FIPS 186-4 and RFC 6979.
*Attack:* nonce reuse recovering the private key, and an invalid-curve point.
**Partly written already** — see the companion volume in the DLMS repository,
which has a worked toy-curve implementation and the nonce-reuse recovery.
Needs porting to C and real curves here.

**5. Key management.**
Hierarchies and blast radius, AES Key Wrap (RFC 3394), HKDF (RFC 5869),
rotation, and key storage on constrained hardware.
*Attack:* a single compromised key and what it unlocks, traced through a
realistic hierarchy.

**6. PKI and certificates.**
X.509 structure, DER by hand, chain building and validation, revocation.
*Attack:* the classic validation omissions — accepting a valid signature from
an untrusted chain, ignoring Basic Constraints, missing key-usage checks.

**7. Side channels and fault injection.**
Timing (started), simple power analysis on a square-and-multiply, and glitching
a boot-time signature check.
*Note:* demonstrations against this repository's own toy implementations only.

**8. Secure boot and the chain of trust.**
ROM → bootloader → application, signature verification, anti-rollback, and
where the root of trust actually lives.
*Attack:* rollback to a known-vulnerable image when version binding is absent.

---

## Explicitly not goals

- **Not a cryptography textbook.** *Serious Cryptography* and *Cryptography
  Engineering* already exist and are better than anything this could be. This
  repository exists for the part books cannot do: code you run, vectors that
  pass, attacks that fire.
- **Not a library.** Do not vendor this. The warning in the README is meant.
- **Not novel research.** Every attack here is decades old and thoroughly
  published. Reproducing them is the exercise.

---

## Infrastructure

- [x] Known-answer test harness, ASan + UBSan by default
- [x] CI running vectors, attacks and link checking
- [x] Link and anchor checker
- [x] Licences, `.editorconfig`
- [ ] A test-vector loader for NIST CAVP `.rsp` files, so whole suites can be
      run rather than hand-picked cases
- [ ] Cross-compilation for Cortex-M, to show the footprint of each primitive
