# Security Audit Verification Results

## Finding 1: MTA Fiat-Shamir Truncation (mta.cpp)

**STATUS: CONFIRMED**

**Evidence:**

In `src/common/cosigner/mta.cpp`, the non-extended seed function at lines 115-154:

```cpp
// Line 128-130
std::vector<uint8_t> n(BN_num_bytes(proof.A));
BN_bn2bin(proof.A, n.data());
SHA256_Update(&ctx, n.data(), BN_num_bytes(proof.S)); // right size of S is ensured during serialization
```

The buffer `n` is allocated to hold `BN_num_bytes(proof.A)` bytes (~512 bytes for a Paillier N^2 element), and `proof.A` is fully serialized into it, but only `BN_num_bytes(proof.S)` bytes (~256 bytes for a Ring Pedersen N element) are fed to SHA256_Update. This truncates approximately 50% of proof.A from the Fiat-Shamir challenge.

Compare with the extended seed function at lines 83-113 (generate_mta_range_zkp_extended_seed):

```cpp
// Line 104
hasher.hash_bn(proof.A, verifier_paillier_pub_n_size * 2, "A");
```

Here proof.A is hashed using the correct size: `verifier_paillier_pub_n_size * 2` (full N^2 size).

**Version Gate:** The extended seed is only used when `version >= MPC_EXTENDED_MTA` (version >= 11), as shown at lines 552-558 and 988-994. A downgraded version forces use of the truncated hash.

**Reachability:** Reachable through the public API via MTA proof generation and verification in both online and offline ECDSA signing flows.

**Exploitability:** Medium-High. Truncating half of proof.A from the Fiat-Shamir hash weakens the binding of the ZKP challenge to the prover's commitment. An attacker who can choose proof.A values where the first 256 bytes collide but the remaining bytes differ can forge proofs. This is mitigated at version >= 11 (MPC_EXTENDED_MTA) but exploitable if version downgrade (Finding 2) is possible.

---

## Finding 2: Version Downgrade

**STATUS: CONFIRMED**

**Evidence:**

In `src/common/cosigner/cmp_ecdsa_online_signing_service.cpp` lines 145-157:

```cpp
if (version > metadata.version)
{
    LOG_FATAL("Min version %d is more than mpc version %d ", version, metadata.version);
    throw_cosigner_exception(cosigner_exception::INTERNAL_ERROR);
}

metadata.version = version;
```

The check only rejects if the incoming `version` is GREATER than `metadata.version`. Any version <= metadata.version is accepted and immediately overwrites metadata.version. The metadata.version is initially set to `MPC_PROTOCOL_VERSION` (= 13, MPC_BAM_ECDSA) at line 97.

The same pattern exists in `src/common/cosigner/cmp_ecdsa_offline_signing_service.cpp` lines 98-104:

```cpp
if ((uint32_t)version > metadata.version)
{
    LOG_FATAL("Min version %d is more than mpc version %d ", version, metadata.version);
    throw_cosigner_exception(cosigner_exception::INTERNAL_ERROR);
}

metadata.version = version;
```

**No minimum version floor exists.** There is a constant `MPC_MIN_SUPPORTED_PROTOCOL_VERSION = 2` defined in `include/cosigner/mpc_globals.h` line 12, but it is NOT checked in either signing service's version acceptance logic.

A malicious co-signer sending `version=1` would pass the check (1 <= 13) and set `metadata.version = 1`, which is below `MPC_EXTENDED_MTA` (11), forcing use of the truncated Fiat-Shamir hash (Finding 1) and disabling strict ciphertext length checks (`strict_ciphertext_length` is set based on `version >= MPC_EXTENDED_MTA`).

**Reachability:** Directly reachable through the public signing API. The `version` parameter is sent by the co-signer during the MTA response phase.

**Exploitability:** High. A single malicious co-signer can force the entire signing session to use weaker cryptographic parameters by sending a low version number.

---

## Finding 3: 1024-bit Ring Pedersen Modulus

**STATUS: CONFIRMED**

**Evidence:**

In `src/common/cosigner/cmp_setup_service.cpp` lines 22-23:

```cpp
static const uint32_t PAILLIER_KEY_SIZE = sizeof(elliptic_curve256_scalar_t) * 8 * 8; // size in bits
static const uint32_t RING_PEDERSEN_KEY_SIZE = sizeof(elliptic_curve256_scalar_t) * 8 * 4; // size in bits
```

Since `sizeof(elliptic_curve256_scalar_t) = 32` (it is `uint8_t[ELLIPTIC_CURVE_FIELD_SIZE]` where `ELLIPTIC_CURVE_FIELD_SIZE = 32`, per `include/crypto/elliptic_curve_algebra/elliptic_curve256_algebra.h` lines 13 and 19):

- `PAILLIER_KEY_SIZE = 32 * 8 * 8 = 2048` bits (correct)
- `RING_PEDERSEN_KEY_SIZE = 32 * 8 * 4 = 1024` bits (half of CMP paper requirement)

The CMP20 paper (Canetti et al., "UC Non-Interactive, Proactive, Threshold ECDSA with Identifiable Aborts") specifies that the Ring Pedersen modulus should be a safe RSA modulus of at least 2048 bits to ensure the commitment scheme is computationally hiding.

**Reachability:** Used in key generation via `cmp_setup_service`. The constant governs all Ring Pedersen key generation for the CMP protocol.

**Exploitability:** Medium. A 1024-bit RSA modulus is considered breakable by well-resourced adversaries (estimated cost: tens of millions of dollars using current hardware). Factoring the Ring Pedersen modulus would allow the attacker to extract the secret lambda and break all Ring Pedersen commitments, undermining the ZKP soundness guarantees.

---

## Finding 4: Key Refresh Missing Auxiliary Key Rotation

**STATUS: CONFIRMED**

**Evidence:**

In `src/common/cosigner/cmp_offline_refresh_service.cpp` lines 86-205, the `refresh_key` function performs exactly two categories of updates:

1. **Private key share update** (lines 154-164): Updates `new_private_key` by adding/subtracting PRF-derived values
2. **Preprocessed data update** (lines 167-199): Updates `k` and `chi` values in `cmp_signature_preprocessed_data`

The function does NOT:
- Regenerate or rotate Paillier keys
- Regenerate or rotate Ring Pedersen keys
- Update any auxiliary key material stored in `auxiliary_keys`
- Call any setup or auxiliary key generation functions

The function ends by storing the new temporary key (line 203) and returning the public key (line 204). No auxiliary key operations appear anywhere in the function or its callees in the refresh flow.

**Reachability:** The `refresh_key` function is part of the public API (`cmp_offline_refresh_service`).

**Exploitability:** Medium. Per the CMP protocol specification, key refresh should rotate all auxiliary parameters (Paillier/Ring Pedersen keys) to maintain proactive security. Without auxiliary key rotation, a compromise of Paillier or Ring Pedersen keys is permanent and cannot be healed by key refresh. This is particularly concerning given the 1024-bit Ring Pedersen modulus (Finding 3).

---

## Finding 5: Missing Coprimality Checks in MTA

**STATUS: CONFIRMED**

**Evidence:**

In `src/common/cosigner/mta.cpp`, the `process_paillier` functions (both batch at lines 1102-1138 and single at lines 1438-1477) check coprimality for:
- `response` vs `_my_paillier->pub.n` (line 1116/1455)
- `proof.A` vs `_my_paillier->pub.n` (line 1122/1461)
- `commitment` vs `_other_paillier->n` (line 1128/1467)
- `proof.By` vs `_other_paillier->n` (line 1134/1473)

However, neither `process_ring_pedersen` function (batch at lines 1248-1342 or single at lines 1344-1436) checks coprimality for:
- `proof.E` vs Ring Pedersen N
- `proof.F` vs Ring Pedersen N
- `proof.S` vs Ring Pedersen N
- `proof.T` vs Ring Pedersen N

Compare with `src/common/crypto/zero_knowledge_proof/range_proofs.c` lines 715-724, which correctly checks:

```c
if (is_coprime_fast(zkpok.S, ring_pedersen->pub.n, ctx) != 1)
{
    status = ZKP_VERIFICATION_FAILED;
    goto cleanup;
}
if (is_coprime_fast(zkpok.T, ring_pedersen->pub.n, ctx) != 1)
{
    status = ZKP_VERIFICATION_FAILED;
    goto cleanup;
}
```

**BAM code:** In `src/common/cosigner/bam_well_formed_proof.cpp`, the only coprimality check is at line 386 for `encrypted_signature` vs `paillier->pub.n`. No Ring Pedersen coprimality checks are present.

**Reachability:** The MTA verification is reached during both online and offline ECDSA signing. The Ring Pedersen proof elements (E, F, S, T) are attacker-controlled values from a co-signer.

**Exploitability:** Medium. If an attacker provides proof elements that share a factor with Ring Pedersen N, the modular exponentiations in the verification equations may produce predictable results, potentially allowing proof forgery. The impact depends on whether the attacker can factor the 1024-bit Ring Pedersen modulus (Finding 3).

---

## Finding 6: Hardcoded use_extended_seed=0 in DH/Exponent Proofs

**STATUS: CONFIRMED**

**Evidence:**

All DH and exponent range proof calls in the signing code use hardcoded `use_extended_seed=0`:

In `src/common/cosigner/mta.cpp` lines 658-672 (MTA request generation):
```cpp
range_proof_diffie_hellman_zkpok_generate(..., /*use_extended_seed=*/0, ...);
range_proof_paillier_exponent_zkpok_generate(..., /*use_extended_seed=*/0, ...);
```

In `src/common/cosigner/cmp_ecdsa_online_signing_service.cpp` line 197 (verification):
```cpp
/*use_extended_seed=*/0);
```

In `src/common/cosigner/cmp_ecdsa_offline_signing_service.cpp` line 143 (verification):
```cpp
/*use_extended_seed=*/0);
```

In `src/common/cosigner/cmp_ecdsa_signing_service.cpp` line 176:
```cpp
/*use_extended_seed=*/0);
```

In contrast, `src/common/cosigner/cmp_setup_service.cpp` lines 231 and 282 DO gate on version:
```cpp
const uint8_t use_extended_seed = (temp_data.version >= fireblocks::common::cosigner::MPC_EXTENDED_MTA) ? 1 : 0;
```

And the BAM code (`bam_ecdsa_cosigner_client.cpp` line 365, `bam_ecdsa_cosigner_server.cpp` line 515) correctly uses `/*use_extended_seed=*/1`.

So the version-dependent extended seed is only applied in setup (key generation) and the newer BAM flow, but NOT in the standard CMP MTA signing flow for DH/exponent proofs, where it is always 0 regardless of version.

Note: The MTA range proofs themselves DO gate on version (lines 552 and 988), but the DH and exponent proofs called alongside them do not.

**Reachability:** Directly reachable through the CMP ECDSA signing API (both online and offline).

**Exploitability:** Medium. Using the non-extended seed means these proofs use a weaker Fiat-Shamir construction that does not include the public keys in the hash. This could allow proofs generated for one context to be replayed in another.

---

## Finding 7: 40-bit Batch MTA Soundness

**STATUS: CONFIRMED**

**Evidence:**

In `src/common/cosigner/mta.h` line 123:
```cpp
static constexpr const size_t BATCH_STATISTICAL_SECURITY = 5;
```

In `src/common/cosigner/mta.cpp` lines 1140-1141, the batch verifier generates random exponents:
```cpp
uint8_t random[2 * BATCH_STATISTICAL_SECURITY];
if (RAND_bytes(random, 2 * BATCH_STATISTICAL_SECURITY * sizeof(uint8_t)) != 1)
```

This generates `2 * 5 = 10` random bytes. Each byte is 8 bits. At line 1172, each random byte is used as a single exponent:
```cpp
if (!BN_set_word(gamma, random[i * 2]))
```

This means each random challenge exponent is a single byte (8 bits, range 0-255). With `BATCH_STATISTICAL_SECURITY = 5` rounds, each using an 8-bit random exponent, the total soundness is 5 * 8 = 40 bits.

For the Ring Pedersen batch verification (lines 1261-1267), random exponents are generated as 64-bit values masked to 40 bits:
```cpp
gamma[0] &= 0xffffffffffULL; // 40bits
gamma[1] &= 0xffffffffffULL; // 40bits
```

The Paillier batch soundness is 40 bits (5 rounds * 8-bit exponents). Standard cryptographic practice recommends at least 80-128 bits of statistical security for ZKP batch verification.

**Reachability:** Used in MTA verification during ECDSA signing when the number of blocks exceeds `MIN_BATCH_SIZE` (= 6, defined at line 135 as `BATCH_STATISTICAL_SECURITY + 1`).

**Exploitability:** Low-Medium. 40-bit soundness means an attacker has a 1-in-2^40 (~1 trillion) chance of passing a forged batch proof. While not trivially breakable, this is significantly below the 80-128 bit standard. In a high-value cryptocurrency context, the expected cost of repeated attempts may be economically justified.

---

## Finding 8: Asymmetric EdDSA Server No Commitment in 2-Party Mode

**STATUS: CONFIRMED**

**Evidence:**

In `src/common/cosigner/asymmetric_eddsa_cosigner_server.cpp` lines 158-168:

```cpp
if (metadata.n == 2)
{
    LOG_INFO("Doing MPC 2/2 no need to send commitments");
    Rs.push_back(sigdata.R);
}
else
{
    ed25519_point_t R;
    memcpy(&R, &sigdata.R.data, sizeof(ed25519_point_t));
    R_commitments.push_back(commit_to_r(txid, i + preprocessed_data_index, my_id, R));
}
```

When `metadata.n == 2` (two-party mode), the server skips the SHA-256 commitment to R and directly sends the R point. In n > 2 mode, it properly commits using `commit_to_r()`.

**Reachability:** Directly reachable through the asymmetric EdDSA signing API when used in 2-party mode.

**Exploitability:** Medium. Without a commitment, the server reveals its R nonce before seeing the client's R contribution. A malicious client who receives the server's R before sending its own can choose its R adaptively. In EdDSA, this allows a rogue-key style attack where the client biases the combined nonce R = R_server + R_client. With enough signing queries, this can leak the server's private key share through lattice-based nonce attacks (e.g., Bleichenbacher-style). The standard mitigation is exactly the commitment that is being skipped.

---

## Summary

| # | Finding | Status | Exploitability |
|---|---------|--------|---------------|
| 1 | MTA Fiat-Shamir Truncation | CONFIRMED | Medium-High |
| 2 | Version Downgrade (No Minimum Floor) | CONFIRMED | High |
| 3 | 1024-bit Ring Pedersen Modulus | CONFIRMED | Medium |
| 4 | Key Refresh Missing Aux Key Rotation | CONFIRMED | Medium |
| 5 | Missing Coprimality Checks in MTA | CONFIRMED | Medium |
| 6 | Hardcoded use_extended_seed=0 | CONFIRMED | Medium |
| 7 | 40-bit Batch MTA Soundness | CONFIRMED | Low-Medium |
| 8 | EdDSA No Commitment in 2-Party | CONFIRMED | Medium |

All 8 findings are confirmed with exact code references. Findings 1, 2, and 6 are interconnected: the version downgrade (Finding 2) can force use of the truncated Fiat-Shamir hash (Finding 1) and is already hardcoded for DH/exponent proofs (Finding 6). Findings 3, 4, and 5 compound each other: the undersized Ring Pedersen modulus (Finding 3) is never rotated (Finding 4) and its elements are not checked for coprimality (Finding 5).
