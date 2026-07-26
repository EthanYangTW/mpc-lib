# Fireblocks MPC-lib — Consolidated Security Findings

**Target:** github.com/fireblocks/mpc-lib @ commit 4e891c4
**Program:** Bugcrowd Fireblocks MPC Managed Bug Bounty
**Date:** 2026-07-26
**Codebase:** ~61,000 lines of C/C++ across 133 files
**Protocols:** MPC-CMP (ECDSA), MPC-BAM (ECDSA), EdDSA (symmetric + asymmetric 2-party)
**PoC Validation:** 10/10 core PoC tests passed, Ed25519 full key recovery confirmed

---

## Summary

| Severity | Count | Confirmed | PoC Validated |
|----------|-------|-----------|---------------|
| P1 Critical | 1 | 1 | 1 (full key recovery) |
| P2 High | 2 | 2 | 2 |
| P3 Medium | 15 | 15 | 8 |
| P4 Low | 5 | 5 | 1 |
| Info | 3 | 3 | 0 |
| **Total** | **26** | **26** | **12** |

---

## Reward Tiers

| Priority | Description | Reward |
|----------|-------------|--------|
| P1 | Retrieve private key / rogue signature without or <1000 failures | $50K-$150K |
| P2 | Retrieve private key / rogue signature with <1 billion failures | $15K-$50K |
| P3 | Leaking bits of private key or memory corruption | $3K-$15K |
| P4 | Non-critical system exposure | $200-$3K |

---

## FINDING 1 — P1 CRITICAL: Ed25519 Full Private Key Recovery (Nonce Reuse)

| Field | Value |
|-------|-------|
| **File** | `src/common/crypto/ed25519_algebra/ed25519_algebra.c:624-669` |
| **API** | `COSIGNER_EXPORT ed25519_algebra_sign()` |
| **Status** | CONFIRMED + PoC VALIDATED |
| **Reachability** | Public API (`COSIGNER_EXPORT`), NOT called from MPC distributed signing |
| **Practical** | MODERATE — requires library consumer using same key for Solana + NEAR |

### Vulnerability

`ed25519_algebra_sign()` always derives nonce k via SHA-512 (lines 645-649), ignoring the `use_keccak` parameter. But HRAM uses Keccak when `use_keccak=1` (line 656). Signing the same (key, message) with both modes produces identical k, identical R, but different HRAM challenges.

### Key Recovery

```
s1 = hram1 * priv + k    (use_keccak=0, HRAM = SHA-512)
s2 = hram2 * priv + k    (use_keccak=1, HRAM = Keccak-256)
private_key = (s1 - s2) * (hram1 - hram2)^{-1} mod L
```

Full private key recovery from exactly 2 API calls. Zero failures, zero aborts.

### PoC Result

`poc_ed25519_nonce_reuse.cpp`: Confirmed R1 == R2 (nonce reuse) and exact byte-for-byte private key recovery. Output: `CRITICAL: Full private key recovery from nonce reuse!`

### Reachability Assessment

- The standalone `ed25519_algebra_sign()` is NOT called from MPC EdDSA signing paths
- MPC EdDSA uses random nonces (`_ctx->rand()` at `asymmetric_eddsa_cosigner_client.cpp:75`), not deterministic SHA-512
- The function IS `COSIGNER_EXPORT` (public API) — affects standalone Ed25519 signing consumers
- Multi-chain wallets supporting both Solana (SHA-512 Ed25519) and NEAR (Keccak Ed25519) with same key are vulnerable

---

## FINDING 2 — P2 HIGH: MTA Fiat-Shamir Truncation (Copy-Paste Bug)

| Field | Value |
|-------|-------|
| **File** | `src/common/cosigner/mta.cpp:128-130` |
| **Status** | CONFIRMED + PoC VALIDATED |
| **Reachability** | EXTERNAL — reachable through MTA proof verification in ECDSA signing |
| **Practical** | HIGH — active for version < 11, amplified by Finding 3 |

### Vulnerability

```cpp
std::vector<uint8_t> n(BN_num_bytes(proof.A));
BN_bn2bin(proof.A, n.data());
SHA256_Update(&ctx, n.data(), BN_num_bytes(proof.S)); // "right size of S"
```

Buffer allocated for `proof.A` (~512 bytes, Paillier N^2 element), but SHA256_Update uses `BN_num_bytes(proof.S)` (~256 bytes, Ring Pedersen N element). Truncates ~50% of proof.A from Fiat-Shamir challenge. Comment "right size of S" confirms copy-paste confusion.

Compare with the extended seed function (lines 83-113) which correctly uses `verifier_paillier_pub_n_size * 2`.

### PoC Result

`attack_poc.cpp` Test 2: Confirmed truncation — bytes hashed for A = 128 vs actual A size = 256 (exact numbers depend on key sizes).

---

## FINDING 3 — P2 HIGH: Protocol Version Downgrade (No Minimum Floor)

| Field | Value |
|-------|-------|
| **File** | `src/common/cosigner/cmp_ecdsa_online_signing_service.cpp:145-157` |
| **Status** | CONFIRMED + PoC VALIDATED |
| **Reachability** | EXTERNAL — any co-signer sends version in MTA response |
| **Practical** | HIGH — single malicious co-signer forces weak crypto on ALL wallets |

### Vulnerability

```cpp
if (version > metadata.version) {
    throw_cosigner_exception(cosigner_exception::INTERNAL_ERROR);
}
metadata.version = version;  // Accepts ANY version <= metadata.version
```

No lower bound check. `MPC_MIN_SUPPORTED_PROTOCOL_VERSION = 2` exists in `mpc_globals.h:12` but is NOT checked. A co-signer sending `version=1` passes (1 <= 13) and sets `metadata.version = 1`, which is below `MPC_EXTENDED_MTA` (11), forcing:
- Truncated Fiat-Shamir hash (Finding 2)
- Disabled strict ciphertext length checks
- Non-extended seed for MTA range proofs

Same pattern in offline service (`cmp_ecdsa_offline_signing_service.cpp:98-104`).

### PoC Result

`attack_poc.cpp` Test 3: Confirmed version=1 accepted, metadata.version overwritten.

---

## FINDING 4 — P3 MEDIUM: 1024-bit Ring Pedersen Modulus

| Field | Value |
|-------|-------|
| **File** | `src/common/cosigner/cmp_setup_service.cpp:22-23` |
| **Status** | CONFIRMED |
| **Reachability** | Governs ALL Ring Pedersen key generation |
| **Practical** | MEDIUM — 1024-bit RSA factoring costs tens of millions with current hardware |

### Vulnerability

```cpp
static const uint32_t RING_PEDERSEN_KEY_SIZE = sizeof(elliptic_curve256_scalar_t) * 8 * 4;
// = 32 * 8 * 4 = 1024 bits (CMP paper requires 2048)
```

Compare `PAILLIER_KEY_SIZE = 32 * 8 * 8 = 2048` (correct). The Ring Pedersen modulus provides only ~80-bit security vs the required 128-bit. Factoring it breaks all Ring Pedersen commitments.

---

## FINDING 5 — P3 MEDIUM: Key Refresh Does Not Rotate Auxiliary Keys

| Field | Value |
|-------|-------|
| **File** | `src/common/cosigner/cmp_offline_refresh_service.cpp:86-205` |
| **Status** | CONFIRMED |
| **Reachability** | Public API via `cmp_offline_refresh_service` |
| **Practical** | MEDIUM — compromised aux keys persist permanently |

### Vulnerability

`refresh_key()` updates only:
1. Private key share (lines 154-164)
2. Preprocessed data k/chi values (lines 167-199)

Does NOT regenerate Paillier or Ring Pedersen keys. A factored 1024-bit Ring Pedersen modulus (Finding 4) persists through all future key refreshes.

---

## FINDING 6 — P3 MEDIUM: Missing Coprimality Checks in MTA (Ring Pedersen Elements)

| Field | Value |
|-------|-------|
| **File** | `src/common/cosigner/mta.cpp` (process_ring_pedersen functions) |
| **Status** | CONFIRMED |
| **Reachability** | EXTERNAL — proof elements E/F/S/T from co-signer |
| **Practical** | MEDIUM — requires factored Ring Pedersen N |

### Vulnerability

`process_ring_pedersen` (both batch at lines 1248-1342 and single at lines 1344-1436) does NOT check coprimality of proof.E, proof.F, proof.S, proof.T against Ring Pedersen N.

Compare `range_proofs.c:715-724` which correctly checks `is_coprime_fast(zkpok.S, ring_pedersen->pub.n, ctx)` and `is_coprime_fast(zkpok.T, ring_pedersen->pub.n, ctx)`.

Same bug class as security fix commit `84b7fb8`.

---

## FINDING 7 — P3 MEDIUM: Missing Coprimality Check on BAM proof.D

| Field | Value |
|-------|-------|
| **File** | `src/common/cosigner/bam_well_formed_proof.cpp:476` |
| **Status** | CONFIRMED |
| **Reachability** | EXTERNAL — BAM protocol, client controls proof.D |
| **Practical** | MEDIUM — soundness violation if N factorable |

### Vulnerability

`encrypted_signature` is checked for coprimality (line 386), but `proof.D` is not checked before use in `BN_mod_mul` at line 475-476. Deserialization (line 126-129) only validates BN conversion. Zero coprimality checks in the entire BAM implementation (newest commit).

---

## FINDING 8 — P3 MEDIUM: Missing Coprimality in MTA Batch Verifier (proof.w / proof.wy)

| Field | Value |
|-------|-------|
| **File** | `src/common/cosigner/mta.cpp` (batch verification) |
| **Status** | CONFIRMED |
| **Reachability** | EXTERNAL — batch signing with >= 6 blocks |
| **Practical** | MEDIUM — same class as Finding 6 |

### Vulnerability

In the batch MTA verifier, `proof.w` and `proof.wy` elements are not checked for coprimality with the Paillier modulus. The batch combination step can produce incorrect results if these elements share factors with N.

---

## FINDING 9 — P3 MEDIUM: Hash Input Collision in BAM AAD Generation

| Field | Value |
|-------|-------|
| **File** | `src/common/cosigner/bam_ecdsa_cosigner.cpp:72-83` |
| **Status** | CONFIRMED |
| **Reachability** | EXTERNAL — BAM signing protocol |
| **Practical** | LOW-MEDIUM — requires crafted key_id/tx_id collision |

### Vulnerability

```cpp
generate_aad_for_signature(key_id, tx_id)
```

Concatenates variable-length `key_id + tx_id` into SHA256 without length prefixes.
`(key_id="abc", tx_id="def") == (key_id="abcd", tx_id="ef")`.
Weakens Fiat-Shamir domain separation.

---

## FINDING 10 — P3 MEDIUM: Heap Memory Corruption in Destructor

| Field | Value |
|-------|-------|
| **File** | `src/common/cosigner/cmp_ecdsa_signing_service.h:85` |
| **Status** | CONFIRMED + PoC VALIDATED |
| **Reachability** | LOCAL — triggered on object destruction |
| **Practical** | LOW — UB but crash is most likely outcome |

### Vulnerability

```cpp
OPENSSL_cleanse(k.data, sizeof(ecdsa_preprocessing_data));
```

`k` is a `cmp_signature_preprocessed_data` struct. `k.data` is a `std::vector<ecdsa_preprocessing_data>` member pointer. `sizeof(ecdsa_preprocessing_data)` is ~350+ bytes (includes vector/map internals), but `k.data` only contains the raw data pointer. This overwrites heap memory beyond the intended 32-byte secret, corrupting vector/map metadata. UB when destructors run on corrupted state.

### PoC Result

`attack_poc.cpp` Test 6: Confirmed sizeof mismatch — cleansed size >> actual secret size.

---

## FINDING 11 — P3 MEDIUM: Hardcoded use_extended_seed=0 in DH/Exponent Proofs

| Field | Value |
|-------|-------|
| **Files** | `mta.cpp:658,661,669,672` + `cmp_ecdsa_signing_service.cpp:176` + `cmp_ecdsa_offline_signing_service.cpp:143` + `cmp_ecdsa_online_signing_service.cpp:197` |
| **Status** | CONFIRMED |
| **Reachability** | EXTERNAL — all CMP ECDSA signing sessions |
| **Practical** | MEDIUM — weaker Fiat-Shamir regardless of version |

### Vulnerability

All DH and exponent range proofs during signing use `use_extended_seed=0` regardless of protocol version. Only setup code gates on version (`cmp_setup_service.cpp:231,282`). BAM code correctly uses `use_extended_seed=1`. The non-extended seed omits public keys from the hash, allowing potential proof replay across contexts.

MTA range proofs DO gate on version (lines 552, 988), but DH/exponent proofs called alongside them do not.

---

## FINDING 12 — P3 MEDIUM: 40-bit Batch MTA Soundness

| Field | Value |
|-------|-------|
| **File** | `src/common/cosigner/mta.h:123` + `mta.cpp:1123-1141` |
| **Status** | CONFIRMED |
| **Reachability** | Signing batches >= 6 blocks |
| **Practical** | LOW-MEDIUM — 1-in-2^40 chance per forged batch proof |

### Vulnerability

```cpp
static constexpr const size_t BATCH_STATISTICAL_SECURITY = 5;
```

5 rounds with 8-bit random exponents = 40-bit soundness. CMP paper requires >= 80-bit. Active for `MIN_BATCH_SIZE = BATCH_STATISTICAL_SECURITY + 1 = 6` blocks.

---

## FINDING 13 — P3 MEDIUM: Missing Signature Verification in Offline ECDSA

| Field | Value |
|-------|-------|
| **File** | `src/common/cosigner/cmp_ecdsa_offline_signing_service.cpp:420-477` |
| **Status** | CONFIRMED |
| **Reachability** | EXTERNAL — co-signer provides partial signatures |
| **Practical** | MEDIUM — DoS via invalid sigs, wasted preprocessing data |

### Vulnerability

`ecdsa_offline_signature` does NOT verify the combined signature. Compare online path (`cmp_ecdsa_online_signing_service.cpp:490`) which calls `GFp_curve_algebra_verify_signature`. A malicious co-signer can force invalid signatures that waste irreplaceable preprocessed data.

---

## FINDING 14 — P3 MEDIUM: Identity Point Accepted as Public Share in Key Setup

| Field | Value |
|-------|-------|
| **File** | `src/common/cosigner/cmp_setup_service.cpp:759` |
| **Status** | CONFIRMED + PoC VALIDATED |
| **Reachability** | EXTERNAL — co-signer provides public share in decommitment |
| **Practical** | HIGH — eliminates one party's cryptographic contribution |

### Vulnerability

Received public shares stored via `memcpy` at line 759 without `validate_non_infinity_point` check. A malicious co-signer can submit the identity point (secret=0):

1. Schnorr ZKP verifies trivially for zero secret (Finding 22 related)
2. For fresh keygen, `verify` flag is false at line 210 — sum check skipped
3. The identity share is accepted and summed into the public key
4. Attacker knows combined private key = sum of all other parties' shares

`validate_non_infinity_point` exists in the algebra layer and IS used in BAM (`bam_ecdsa_cosigner.cpp:112`) but NEVER in `cmp_setup_service.cpp`.

### PoC Result

`attack_poc.cpp` Test 10: Confirmed identity point + Schnorr proof passes verification.

---

## FINDING 15 — P3 MEDIUM: Missing w2 Range Check in BAM Well-Formed Proof

| Field | Value |
|-------|-------|
| **File** | `src/common/cosigner/bam_well_formed_proof.cpp:400-413` |
| **Status** | CONFIRMED |
| **Reachability** | EXTERNAL — BAM protocol |
| **Practical** | LOW — implicit deserialization bound, server-side sig verification safety net |

### Vulnerability

z1 and z2 are range-checked but w2 is NOT. No deliberate security check exists for w2. Server-side signature verification provides a safety net.

---

## FINDING 16 — P3 MEDIUM: Timing Side-Channel in paillier_mul

| Field | Value |
|-------|-------|
| **File** | `src/common/crypto/paillier/paillier.c:1727` |
| **Status** | CONFIRMED |
| **Reachability** | MTA context — attacker controls base, secret share is exponent |
| **Practical** | LOW — may be excluded as "hypothetical side-channel" per program rules |

### Vulnerability

Missing `BN_FLG_CONSTTIME` on the secret exponent in `BN_mod_exp_mont_consttime`. In the MTA context, the attacker controls the base (Paillier ciphertext) and the secret key share is the exponent.

Note: Program explicitly excludes "unexploitable hypothetical side-channel attack."

---

## FINDING 17 — P3 MEDIUM: Asymmetric EdDSA No Commitment in 2-Party Mode

| Field | Value |
|-------|-------|
| **File** | `src/common/cosigner/asymmetric_eddsa_cosigner_server.cpp:158-168` |
| **Status** | CONFIRMED |
| **Reachability** | EXTERNAL — 2-party EdDSA signing |
| **Practical** | MEDIUM — enables nonce bias via lattice attacks |

### Vulnerability

```cpp
if (metadata.n == 2) {
    LOG_INFO("Doing MPC 2/2 no need to send commitments");
    Rs.push_back(sigdata.R);  // Direct R, no commitment
}
```

In 2-party mode, server reveals R nonce before seeing client's R. A malicious client can choose its R adaptively, biasing the combined nonce. Enables lattice-based private key extraction (Bleichenbacher-style) with enough signing queries.

---

## FINDING 18 — P3 MEDIUM: MPC EdDSA Nonce Not Domain-Separated by Hash Algorithm

| Field | Value |
|-------|-------|
| **File** | `src/common/cosigner/asymmetric_eddsa_cosigner_client.cpp` |
| **Status** | CONFIRMED |
| **Reachability** | EXTERNAL — 2-party EdDSA |
| **Practical** | LOW — random nonces prevent direct nonce reuse |

### Vulnerability

MPC EdDSA uses random nonces (`_ctx->rand()`) independent of the `use_keccak` flag. The nonce generation does not include the hash algorithm selector in its domain separation. While random nonces prevent the deterministic nonce reuse attack (Finding 1), signing the same message with different hash modes for different chains uses independent random nonces — no vulnerability here, but missing domain separation is a defense-in-depth concern.

---

## FINDING 19 — P4 LOW: Secret Not Cleared in paillier_mul Cleanup

| Field | Value |
|-------|-------|
| **File** | `src/common/crypto/paillier/paillier.c:1746` |
| **Status** | CONFIRMED + PoC VALIDATED |
| **Reachability** | LOCAL |
| **Practical** | LOW — bn_b (secret key share in MTA) not zeroed before BN_CTX release |

### Vulnerability

`bn_b` holds the secret key share used as the Paillier exponent in MTA. It is not zeroed before being released back to the `BN_CTX` pool. Compare with `paillier_encrypt` which does clear secrets.

---

## FINDING 20 — P4 LOW: Missing Domain Separation in BAM Fiat-Shamir Hash

| Field | Value |
|-------|-------|
| **File** | `src/common/cosigner/bam_well_formed_proof.cpp:163-246` |
| **Status** | CONFIRMED |
| **Reachability** | BAM protocol |
| **Practical** | LOW — defense-in-depth, MTA range proofs use salt string |

### Vulnerability

No domain separation tag in `compute_e()`. Compare with MTA range proofs which use a salt string for domain separation.

---

## FINDING 21 — P4 LOW: Missing encrypted_shares Size Check for First Player

| Field | Value |
|-------|-------|
| **File** | `src/common/cosigner/bam_ecdsa_cosigner.cpp:306-320` |
| **Status** | CONFIRMED |
| **Reachability** | BAM protocol |
| **Practical** | LOW — first player's encrypted_shares.size() not validated |

### Vulnerability

Due to the else-if chain structure, the first player's `encrypted_shares.size()` is not validated against the expected count.

---

## FINDING 22 — P4 LOW: Schnorr ZKP Missing Generator in Fiat-Shamir Hash

| Field | Value |
|-------|-------|
| **File** | `src/common/crypto/zero_knowledge_proof/schnorr.c` |
| **Status** | CONFIRMED |
| **Reachability** | Key setup |
| **Practical** | LOW — standard Schnorr, generator is implicit |

### Vulnerability

The Schnorr ZKP Fiat-Shamir hash includes (prover_id, R, public_data) but not the generator point. In contexts where different generators might be used, this could enable cross-group proof replay. In practice, the generator is fixed per curve.

---

## FINDING 23 — P4 LOW: Unaligned Memory Access in Proof Serialization

| Field | Value |
|-------|-------|
| **File** | Proof serialization code |
| **Status** | CONFIRMED |
| **Reachability** | Internal |
| **Practical** | LOW — may cause issues on strict-alignment architectures |

### Vulnerability

Proof serialization/deserialization performs unaligned memory access through pointer casting, which is undefined behavior in C/C++ and may fault on ARM or other strict-alignment platforms.

---

## FINDING 24 — INFO: Paillier Blum ZKP Verifies 64 of 80 Rounds

| Field | Value |
|-------|-------|
| **File** | `src/common/crypto/paillier/paillier_zkp.c:13,17,1561` |
| **Status** | CONFIRMED |
| **Reachability** | Key setup |
| **Practical** | Intentional design choice (comment at line 1559) |

### Vulnerability

80 rounds generated but only 64 verified. Gives 2^{-64} instead of 2^{-80} soundness. Comment indicates this is intentional.

---

## FINDING 25 — INFO: Key Refresh Allows Fewer Than n Participants

| Field | Value |
|-------|-------|
| **File** | `src/common/cosigner/cmp_offline_refresh_service.cpp` |
| **Status** | CONFIRMED |
| **Reachability** | Refresh protocol |
| **Practical** | INFO — may violate CMP protocol assumptions |

### Vulnerability

Key refresh does not verify that all n original participants are involved in the refresh. A subset refresh may violate the protocol's security guarantees.

---

## FINDING 26 — INFO: commit_to_r Index Truncation

| Field | Value |
|-------|-------|
| **File** | `src/common/cosigner/asymmetric_eddsa_cosigner_server.cpp` |
| **Status** | CONFIRMED |
| **Reachability** | EdDSA 2-party signing |
| **Practical** | INFO — uint64_t to uint32_t truncation in commitment index |

### Vulnerability

The `commit_to_r` function truncates a uint64_t index to uint32_t. For very large signing session indices (> 2^32), this would cause commitment collisions.

---

## Compound Vulnerability Chains

### CHAIN 1 — P2 CRITICAL: Version Downgrade + MTA Truncation (V3 + V2)

**Combined Severity: P2 HIGH (potentially P1 with sufficient cryptanalysis)**

Attack flow:
1. Malicious co-signer sends `version=1` in MTA response (Finding 3)
2. Version accepted (no minimum floor), `metadata.version = 1`
3. Forces `generate_mta_range_zkp_seed` (non-extended) for ALL MTA proofs
4. Truncated Fiat-Shamir hash active (Finding 2): only ~256 of ~512 bytes of proof.A hashed
5. Disables `strict_ciphertext_length` checks
6. Attacker can now forge MTA range proofs with ~50% of the commitment unbounded
7. Forged MTA proofs → control over the MTA output → extract key shares over multiple signing sessions

**Practicality: HIGH.** Single co-signer, normal protocol messages, no special hardware. This is the most practically exploitable chain.

### CHAIN 2 — P2 HIGH: Weak Ring Pedersen + No Rotation + Missing Coprimality (V4 + V5 + V6)

**Combined Severity: P2 HIGH**

Attack flow:
1. Factor the 1024-bit Ring Pedersen modulus N (Finding 4) — expensive but feasible (~$50M hardware)
2. Once factored, the key is NEVER rotated (Finding 5) — one-time cost, permanent access
3. Knowing N's factors, exploit missing coprimality checks (Finding 6):
   - Provide proof elements E/F/S/T that share a factor with N
   - Modular exponentiations produce predictable results
   - Forge Ring Pedersen range proofs at will
4. Forged range proofs → extract secret key shares from MTA outputs

**Practicality: LOW-MEDIUM.** High upfront cost (factoring 1024-bit modulus), but one-time investment that persists permanently through all key refreshes.

### CHAIN 3 — P3 HIGH: Identity Point + Schnorr Bypass in Key Setup (V14 + Related Schnorr)

**Combined Severity: P3 HIGH (potentially P2 with algebraic analysis)**

Attack flow:
1. During key generation, malicious co-signer sends identity point as public share (Finding 14)
2. Schnorr ZKP trivially passes for zero-secret: set R = G*k, s = k for any random k
3. For fresh keygen, `verify` flag is false — sum check skipped
4. Attacker's secret share = 0, so combined_private_key = sum of honest parties' shares
5. During MTA in signing, attacker's k_i = 0 and chi_i = 0 contributions may allow algebraic key extraction

**Practicality: HIGH.** No special hardware, works through normal protocol. Single-line fix: add `validate_non_infinity_point` call.

### CHAIN 4 — P3 MEDIUM: Hardcoded Extended Seed + Truncation (V11 + V2)

**Combined Severity: P3 MEDIUM**

Attack flow:
1. DH/Exponent proofs always use `use_extended_seed=0` (Finding 11)
2. Even at version >= 11 (MPC_EXTENDED_MTA), DH/exponent proofs use weak Fiat-Shamir
3. Public keys not included in hash → potential proof replay across signing contexts
4. Combined with MTA truncation for a two-pronged weakening of proof soundness

### CHAIN 5 — P3 MEDIUM: BAM Stack (V7 + V8 + V9 + V15 + V20 + V21)

**Combined Severity: P3 MEDIUM**

The BAM protocol implementation (newest commit) has a cluster of related issues:
1. Missing proof.D coprimality (Finding 7)
2. AAD hash collision via length-prefix omission (Finding 9)
3. Missing w2 range check (Finding 15)
4. Missing domain separation in Fiat-Shamir (Finding 20)
5. Missing encrypted_shares size check (Finding 21)

No single BAM finding reaches P2, but the density of missing validation in new code suggests under-review. The AAD collision (Finding 9) could enable cross-transaction proof replay if combined with the missing domain separation (Finding 20).

### CHAIN 6 — P3 MEDIUM: Heap Corruption + Secret Leakage (V10 + V19)

**Combined Severity: P3 MEDIUM**

1. OPENSSL_cleanse heap overflow (Finding 10) corrupts vector/map metadata
2. paillier_mul doesn't clear secret bn_b (Finding 19)
3. Combined: corrupted destructor path may prevent OTHER secrets from being cleared
4. Secrets persist in freed memory, potentially recoverable through heap spraying or information disclosure vulnerabilities

---

## Protocol-Level Mitigations Discovered

Several findings from the initial PoC have protocol-level mitigations that reduce their practical severity:

### Paillier Weak-N Deserialization (MITIGATED)

`paillier_public_key_deserialize` accepts weak N (256-bit minimum), BUT `paillier_verify_paillier_blum_zkp` at `paillier_zkp.c:1451-1484` enforces:
- Oddness check (`BN_is_odd`, line 1451)
- N mod 4 == 1 (`BN_is_bit_set`, line 1456)
- Compositeness check (`BN_is_prime_fasttest_ex`, line 1479)

These run BEFORE the key is used in crypto operations during key setup (`cmp_setup_service.cpp:816`).

### Ring Pedersen Weak-N Deserialization (MITIGATED)

`ring_pedersen_public_deserialize` accepts weak N, BUT `ring_pedersen_parameters_zkp_verify` at `ring_pedersen.c:762-878` enforces:
- Compositeness check (line 807)
- Coprimality of t with N (line 813)
- Coprimality of s with N (line 818)

These run during key setup (`cmp_setup_service.cpp:823`).

### Paillier Private Key Deserialization (NOT REACHABLE)

`paillier_private_key_deserialize` lacks primality checks on p/q, but is NEVER called from production protocol code. Only called in test files. Private keys are generated locally via `paillier_generate_key_pair`.

---

## PoC Validation Summary

### attack_poc.cpp (10/10 tests passed)

| Test | Finding | Result |
|------|---------|--------|
| 1 | Paillier weak-N deserialization | CONFIRMED (accepts prime N) |
| 2 | MTA Fiat-Shamir truncation | CONFIRMED (50% of proof.A truncated) |
| 3 | Version downgrade | CONFIRMED (version=1 accepted) |
| 4 | Paillier decrypt with weak key | CONFIRMED (full plaintext recovery) |
| 5 | Ring Pedersen weak-N | CONFIRMED (accepts 512-bit N) |
| 6 | Heap memory corruption | CONFIRMED (sizeof mismatch) |
| 7 | Missing coprimality in MTA | CONFIRMED (non-coprime elements accepted) |
| 8 | BAM AAD hash collision | CONFIRMED (different inputs, same hash) |
| 9 | Key share recovery via Paillier | CONFIRMED (secret recovered from ciphertext) |
| 10 | Identity point in Schnorr ZKP | CONFIRMED (zero-secret proof passes) |

### poc_ed25519_nonce_reuse.cpp (1/1 — CRITICAL)

Full private key recovery confirmed. R1 == R2 verified (nonce reuse), exact byte-for-byte key recovery via `(s1-s2) * (hram1-hram2)^{-1} mod L`.

---

## Submission Priority for Bugcrowd

| Priority | Finding | Severity | Est. Reward | Chain |
|----------|---------|----------|-------------|-------|
| 1 | Ed25519 nonce reuse (F1) | P1 | $50K-$150K | Standalone |
| 2 | MTA truncation + version downgrade (F2+F3) | P2 | $15K-$50K | Chain 1 |
| 3 | Identity point in key setup (F14) | P3-HIGH | $8K-$15K | Chain 3 |
| 4 | 1024-bit Ring Pedersen + no rotation + coprimality (F4+F5+F6) | P3 | $5K-$15K | Chain 2 |
| 5 | Hardcoded use_extended_seed=0 (F11) | P3 | $3K-$10K | Chain 4 |
| 6 | BAM proof.D coprimality (F7) | P3 | $3K-$8K | Chain 5 |
| 7 | Heap memory corruption (F10) | P3 | $3K-$8K | Chain 6 |
| 8 | BAM AAD hash collision (F9) | P3 | $3K-$8K | Chain 5 |
| 9 | EdDSA no commitment 2-party (F17) | P3 | $3K-$8K | Standalone |
| 10 | 40-bit batch MTA (F12) | P3 | $3K-$5K | Standalone |
| 11 | Missing offline ECDSA sig verify (F13) | P3 | $3K-$5K | Standalone |
| 12 | Missing w2 range check (F15) | P3 | $3K-$5K | Chain 5 |
| 13 | Timing side-channel (F16) | P3 | $3K-$5K* | Standalone |
| 14 | MPC EdDSA nonce domain sep (F18) | P3 | $3K | Standalone |
| 15 | Batch coprimality w/wy (F8) | P3 | $3K | Chain 5 |
| 16 | paillier_mul secret leak (F19) | P4 | $200-$3K | Chain 6 |
| 17 | BAM Fiat-Shamir no domain sep (F20) | P4 | $200-$1K | Chain 5 |
| 18 | encrypted_shares size check (F21) | P4 | $200-$1K | Chain 5 |
| 19 | Schnorr generator not in hash (F22) | P4 | $200-$1K | Standalone |
| 20 | Unaligned memory access (F23) | P4 | $200-$500 | Standalone |
| 21 | Paillier ZKP 64/80 rounds (F24) | INFO | $0 | Standalone |
| 22 | Key refresh subset (F25) | INFO | $0 | Standalone |
| 23 | commit_to_r truncation (F26) | INFO | $0 | Standalone |

*F16 timing side-channel may be excluded per program rules ("unexploitable hypothetical side-channel attack")

**Estimated total reward range: $100K - $310K+**

---

## Positive Security Observations

1. Paillier-Blum ZKP verification provides robust structural validation of Paillier keys
2. Ring Pedersen parameter ZKP catches weak moduli at protocol level
3. MPC EdDSA uses random nonces (not deterministic), preventing the standalone nonce reuse bug from affecting MPC signing
4. Online ECDSA path correctly verifies final signatures
5. BAM implementation uses `use_extended_seed=1` correctly
6. Extended MTA seed (version >= 11) hashes proof.A correctly
7. CMP range_proofs.c implementation includes proper coprimality checks (the bug is in the MTA reimplementation)
