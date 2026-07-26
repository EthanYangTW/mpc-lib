# Security Audit Verification Report: Fireblocks MPC Library
## Detailed Findings Verification with Reachability Analysis

---

## Finding 1: Paillier Public Key Deserialization Accepts Weak N

**Status: CONFIRMED**

### Code Analysis

File: `src/common/crypto/paillier/paillier.c`

The `MIN_KEY_LEN_IN_BITS` is defined at line 12:
```c
#define MIN_KEY_LEN_IN_BITS 256
```

The `paillier_public_key_deserialize_internal` function (lines 346-378) performs only ONE validation on N:
```c
if (BN_num_bits(pub->n) < MIN_KEY_LEN_IN_BITS)   // line 360
{
    goto cleanup;
}
```

Missing checks on the deserialized N:
- No oddness check (N must be odd for RSA-type moduli)
- No compositeness check (N could be prime)
- No check that N has exactly two large prime factors
- No check that N >= 2^(desired_security_level)
- No coprimality structure validation

However, there IS a higher-level size check in `cmp_setup_service.cpp` line 631-635:
```cpp
if (paillier_public_key_size(paillier.get()) < PAILLIER_KEY_SIZE)  // PAILLIER_KEY_SIZE = 2048 bits
{
    throw_cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
}
```

And during proof verification in `paillier_verify_paillier_blum_zkp` (paillier_zkp.c line 1451-1458):
```c
if (!BN_is_odd(pub->n))                    // oddness check
    return PAILLIER_ERROR_INVALID_KEY;
if (BN_is_bit_set(pub->n, 1) != 0)        // N mod 4 == 1 check
    return PAILLIER_ERROR_INVALID_KEY;
if (0 != BN_is_prime_fasttest_ex(pub->n, 128, ctx, 1, NULL))  // compositeness check
    return PAILLIER_ERROR_INVALID_KEY;
```

### Reachability: EXTERNAL (co-signer can trigger) -- but MITIGATED at protocol level

The deserialization is called in `cmp_setup_service.cpp` line 625 via `deserialize_auxiliary_keys`:
```cpp
paillier.reset(paillier_public_key_deserialize(paillier_public_key.data(), paillier_public_key.size()), paillier_free_public_key);
```

This is called from `verify_and_load_setup_decommitments` (line 760), which processes decommitments received from co-signers during key setup. A co-signer sends their Paillier public key as part of the decommitment.

However, the Paillier Blum ZKP verification (called in `verify_setup_proofs` at line 816) adds the missing checks (oddness, N mod 4 == 1, compositeness). This means:
- The deserialization layer itself is weak (only 256-bit minimum)
- But the protocol enforces 2048-bit minimum AND structural checks via ZKP verification

### Severity: LOW
The deserialization function's weakness is mitigated by the protocol-level ZKP verification. The gap exists between deserialization and verification (the weak key is stored in memory temporarily), but a malicious key would be caught before it is used in any cryptographic operations. However, defense-in-depth would benefit from adding these checks to the deserializer itself.

---

## Finding 2: Ring Pedersen Deserialization Accepts Weak N

**Status: CONFIRMED**

### Code Analysis

File: `src/common/crypto/commitments/ring_pedersen.c`

The `ring_pedersen_public_deserialize_internal` (lines 254-320) checks:
```c
if (BN_num_bits(pub->n) < MIN_KEY_LEN_IN_BITS)  // line 307, MIN_KEY_LEN_IN_BITS = 256
    return 0;

if (BN_cmp(pub->s, pub->n) > 0 || BN_cmp(pub->t, pub->n) > 0)  // line 313
    return 0;
```

Missing checks:
- No oddness check on N
- No compositeness check on N
- No coprimality check between s,t and N
- No check that N has appropriate structure

However, at the protocol level in `cmp_setup_service.cpp` line 643-648:
```cpp
if (ring_pedersen_public_size(ring_pedersen.get()) < RING_PEDERSEN_KEY_SIZE)  // RING_PEDERSEN_KEY_SIZE = 1024 bits
{
    throw_cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
}
```

And the Ring Pedersen parameter ZKP verification (`ring_pedersen_parameters_zkp_verify` in ring_pedersen.c line 762-878) performs:
```c
if (0 != BN_is_prime_fasttest_ex(pub->n, 128, ctx, 1, NULL))  // line 807 - compositeness
    goto cleanup;
if (is_coprime_fast(pub->n, pub->t, ctx) != 1)                 // line 813 - coprimality of t
    goto cleanup;
if (is_coprime_fast(pub->n, pub->s, ctx) != 1)                 // line 818 - coprimality of s
    goto cleanup;
```

### Reachability: EXTERNAL (co-signer can trigger) -- but MITIGATED at protocol level

Same flow as Paillier: deserialized from co-signer input in `verify_and_load_setup_decommitments` (line 760), but Ring Pedersen parameter ZKP verification (line 823) catches weak parameters before they are used.

### Severity: LOW
Same defense-in-depth concern as Finding 1. The protocol-level ZKP adds the missing structural checks, but the deserializer should ideally validate independently.

---

## Finding 3: Schnorr ZKP Accepts Zero Secret / Point at Infinity

**Status: CONFIRMED**

### Code Analysis

File: `src/common/crypto/zero_knowledge_proof/schnorr.c`, lines 137-177

The `schnorr_zkp_verify` function:
```c
zero_knowledge_proof_status schnorr_zkp_verify(const elliptic_curve256_algebra_ctx_t *algebra,
    const uint8_t *prover_id, uint32_t id_len,
    const elliptic_curve256_point_t *public_data, const schnorr_zkp_t *proof)
{
    // ...
    if (!algebra || !prover_id || ! id_len || !public_data || !proof)  // line 146
        return ZKP_INVALID_PARAMETER;

    // Computes c = SHA256(prover_id || proof.R || public_data)
    // Then checks: proof.R == public_data * c + generator * proof.s
    // ...
}
```

There is NO call to `algebra->validate_non_infinity_point(algebra, public_data)` anywhere in this function. If `public_data` is the identity point (secret = 0):
- `points[0] = identity * c = identity`
- The equation becomes `proof.R == identity + G * proof.s == G * proof.s`
- A prover can trivially satisfy this by setting `R = G * k` and `s = k` for any random `k`

### Reachability: EXTERNAL (co-signer can trigger)

The Schnorr ZKP is verified during key setup in `verify_setup_proofs` (`cmp_setup_service.cpp` line 809):
```cpp
auto status = schnorr_zkp_verify(algebra, aad.data(), aad.size(), &i->second.public_share.data, &schnorr);
```

The `i->second.public_share.data` is the co-signer's public key share, received from their decommitment. Looking at `verify_and_load_setup_decommitments` (line 759):
```cpp
memcpy(info.public_share.data, decommit_it->second.share.X.data, sizeof(elliptic_curve256_point_t));
```

The public share is directly copied from the decommitment message -- there is NO `validate_non_infinity_point` call on it anywhere in the CMP setup service.

A malicious co-signer can:
1. Set their public share X to the identity point
2. Generate a valid Schnorr proof (trivially, as shown above)
3. The proof passes verification at line 809
4. Their identity-point share is accepted and summed into the public key (line 212)
5. For fresh key generation, the public key check at lines 210-222 does NOT prevent this (the `verify` flag is false)

Impact: If a co-signer contributes secret=0 (identity public share), they know the combined private key equals the sum of all other honest parties' shares. While they don't learn individual shares, during the signing protocol their k_i and chi_i contributions would also be zero-equivalent, potentially breaking the security guarantees of the MTA protocol and enabling key extraction through algebraic relationships.

### Severity: HIGH
This is a genuine protocol-level vulnerability. A malicious co-signer can claim secret share = 0 with a valid proof, potentially compromising the security of the key generation ceremony.

---

## Finding 4: Paillier Private Key Deserialization Missing Primality Checks

**Status: CONFIRMED (code weakness) -- but NOT REACHABLE externally**

### Code Analysis

File: `src/common/crypto/paillier/paillier.c`, lines 506-578

The `paillier_private_key_deserialize_internal` function:
```c
priv->p = BN_bin2bn(buffer, p_len, NULL);        // line 514
buffer += p_len;
priv->q = BN_bin2bn(buffer, p_len, NULL);        // line 516

// Computes n = p * q, n^2, lambda = (p-1)(q-1), mu = lambda^-1 mod n
// ...

if (BN_num_bits(priv->pub.n) < MIN_KEY_LEN_IN_BITS)  // line 564
    goto cleanup;
```

Missing checks:
- No primality check on p or q (p,q could be composite, enabling attacks)
- No distinctness check (p != q; if p == q then lambda is wrong)
- No check that p,q are safe primes or have appropriate form (8k+3 and 8k+7)
- No n = p*q consistency check (redundant since n is computed, but no validation of the result)
- The `BN_mod_inverse` at line 559 would fail if lambda and n share factors, providing an implicit but weak check

### Reachability: INTERNAL (local storage only)

The `paillier_private_key_deserialize` function is NEVER called from any production `.cpp` file. It is:
- Defined in `paillier.c` (line 581)
- Declared in `paillier.h` (line 54)
- Called only in test files (`test/crypto/paillier/tests.cpp`)

The private key is generated locally via `paillier_generate_key_pair` (which does proper prime generation), stored via `store_auxiliary_keys`, and loaded back. The deserialization would only be used when loading from local (trusted) storage.

### Severity: LOW (INFORMATIONAL)
While the deserialization lacks important validation, it is only reachable from local storage. A threat model where the local storage is compromised would imply the attacker already has access to the secret keys. Defense-in-depth would still benefit from adding primality checks.

---

## Finding 5: Missing Signature Verification in Offline ECDSA

**Status: CONFIRMED**

### Code Analysis

**Offline path** (`cmp_ecdsa_offline_signing_service.cpp`, `ecdsa_offline_signature` function, lines 420-477):

```cpp
for (size_t i = 0; i < count; i++)
{
    recoverable_signature sig = first_player->second[i];
    for (auto it = partial_sigs.begin(); it != partial_sigs.end(); ++it)
    {
        // ... checks r and v consistency ...
        throw_cosigner_exception(algebra->add_scalars(algebra, &sig.s, sig.s, ...));
    }
    make_sig_s_positive(algorithm, algebra, sig);
    sigs.push_back(sig);                                        // line 474
}
return _service.get_id_from_keyid(key_id);                      // line 476
```

There is NO call to `GFp_curve_algebra_verify_signature` in this function. The combined signature is returned WITHOUT verification.

**Online path** (`cmp_ecdsa_online_signing_service.cpp`, `get_cmp_signature` function, lines 426-513):

```cpp
// After summing all s values...
make_sig_s_positive(key_md.algorithm, algebra, sig);

// verify signature                                              // line 481
elliptic_curve256_point_t derived_public_key;
hd_derive_status derivation_status = derive_public_key_generic(...);
// ...
elliptic_curve_algebra_status status = GFp_curve_algebra_verify_signature(  // line 490
    curve, &derived_public_key, &data.message, &sig.r, &sig.s);
if (status != ELLIPTIC_CURVE_ALGEBRA_SUCCESS)
{
    LOG_FATAL("failed to verify signature for block %lu, error %d", i, status);
    throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);  // line 494
}
```

The online path DOES verify the combined signature against the derived public key.

### Reachability: EXTERNAL (co-signer can trigger)

In the offline signing flow:
1. Each party computes partial signatures (`ecdsa_sign` function, lines 290-418)
2. The orchestrator collects all partial signatures and calls `ecdsa_offline_signature`
3. Partial signatures are summed WITHOUT verification
4. The resulting (potentially invalid) signature is returned

A malicious co-signer can send a corrupted partial signature `s_i`. Since there is no final verification, the combined signature will be invalid, and the caller receives it without knowing. In contrast, the online path catches this at line 490-494.

Note: the offline path does NOT have access to the message hash at combination time (it was provided earlier in `ecdsa_sign`), which makes adding verification harder but does not excuse the omission.

### Severity: MEDIUM
The missing verification in the offline path means invalid signatures can be produced and returned without detection. While this may not directly leak secret keys, it enables a denial-of-service attack where a malicious co-signer can force invalid signatures to be broadcast, potentially causing financial loss (failed transactions on-chain with wasted gas fees). The online path correctly includes this check, indicating the omission was unintentional.

---

## Finding 6: Identity Point Accepted in Key Setup

**Status: CONFIRMED**

### Code Analysis

File: `src/common/cosigner/cmp_setup_service.cpp`

The `validate_non_infinity_point` function exists in the elliptic curve algebra layer (`GFp_curve_algebra.c` line 925, `ed25519_algebra.c` line 831) and is used in the BAM cosigner (`bam_ecdsa_cosigner.cpp` line 112):
```cpp
const elliptic_curve_algebra_status st = algebra->validate_non_infinity_point(algebra, &point);
```

However, it is NEVER called in `cmp_setup_service.cpp`. Searching the entire file shows zero invocations of `validate_non_infinity_point`.

In `verify_and_load_setup_decommitments` (lines 730-762):
```cpp
auto& info = players_info.at(i->first);
memcpy(info.public_share.data, decommit_it->second.share.X.data,   // line 759
       sizeof(elliptic_curve256_point_t));
deserialize_auxiliary_keys(i->first, ...);                          // line 760
```

The public share is accepted without any point validation. No check for:
- Point on curve
- Non-infinity
- Valid encoding

The only indirect check is the Schnorr ZKP verification in `verify_setup_proofs` (line 809), but as demonstrated in Finding 3, the Schnorr ZKP passes for the identity point.

In `verify_setup_proofs` (lines 206-223), the sum of public shares is computed:
```cpp
memcpy(pubkey, *algebra->infinity_point(algebra), sizeof(elliptic_curve256_point_t));
bool verify = memcmp(pubkey, metadata.public_key, sizeof(elliptic_curve256_point_t)) != 0;
for (auto i = metadata.players_info.begin(); i != metadata.players_info.end(); ++i)
    throw_cosigner_exception(algebra->add_points(algebra, &pubkey, &pubkey, &i->second.public_share.data));

if (verify)
{
    if (memcmp(pubkey, metadata.public_key, sizeof(elliptic_curve256_point_t)) != 0)
    {
        // Only fails if expected pubkey was pre-set and doesn't match
    }
}
```

For fresh key generation, `verify` is false (metadata.public_key starts as zero/infinity), so the sum check is skipped entirely.

### Reachability: EXTERNAL (co-signer can trigger)

This is directly reachable through the CMP key setup protocol. A co-signer includes their public share in the decommitment message. The vulnerability chain is:

1. Malicious co-signer sends decommitment with X = identity point
2. `verify_and_load_setup_decommitments` accepts it (no infinity check)
3. `verify_setup_proofs` verifies Schnorr ZKP, which passes for identity
4. The identity share is stored in `players_info`
5. For fresh keygen, the public key sum check is skipped

### Severity: HIGH
This is the same vulnerability as Finding 3, viewed from the protocol layer. The missing `validate_non_infinity_point` call is the root cause. Adding this check on received public shares would prevent the attack.

---

## Finding 7: BAM Missing Coprimality Check on proof.D

**Status: CONFIRMED**

### Code Analysis

File: `src/common/cosigner/bam_well_formed_proof.cpp`, `verify_signature_proof` function (lines 372-486)

The `encrypted_signature` IS checked for coprimality (line 386):
```cpp
if (is_coprime_fast(encrypted_signature, paillier->pub.n, ctx) != 1)
{
    throw_cosigner_exception(ZKP_VERIFICATION_FAILED);
}
```

However, `proof.D` is deserialized at line 391 and used at line 475-476:
```cpp
if (!BN_mod_exp_mont(tmp2, encrypted_signature, e_bn, paillier->pub.n2, ctx, paillier->pub.mont_n2) ||
    !BN_mod_mul(tmp2, tmp2, proof.D, paillier->pub.n2, ctx))
```

There is NO `is_coprime_fast(proof.D, paillier->pub.n, ctx)` check before `proof.D` is used in `BN_mod_mul` mod n^2.

The deserialization of proof.D (line 126-129 in `deserialize_well_formed_proof`):
```cpp
if (!BN_bin2bn(ptr, 2 * paillier_size, proof.D))
{
    throw_cosigner_exception(ZKP_VERIFICATION_FAILED);
}
```

Only checks that the binary-to-BIGNUM conversion succeeds. No structural validation of D.

### Reachability: EXTERNAL (in BAM protocol context)

In the BAM protocol, the client generates the well-formed proof (including proof.D) and sends it to the server. The server calls `verify_signature_proof` with the client-supplied data. The client controls proof.D.

The impact depends on the Paillier commitment verification using CRT optimization at line 469:
```cpp
auto ret = paillier_commitment_commit_with_private_internal(paillier, proof.z1, proof.w2, encrypted_share, proof.z2, tmp1, ctx);
```

This computes the expected commitment using CRT (exploiting knowledge of p,q). The result is compared against `tmp2 = encrypted_signature^e * proof.D mod n^2` at line 481.

If proof.D is not coprime to n (i.e., shares a factor with n), it could:
1. Cause the modular arithmetic to behave unexpectedly
2. Potentially allow the proof to pass for invalid underlying values
3. Enable a malicious client to produce a "proof" that the server accepts while the actual encrypted values are inconsistent

However, since the server holds the private key (knows p,q), the immediate risk of factoring n is not applicable. The risk is soundness violation: a malicious client could potentially forge a proof.

### Severity: MEDIUM
The missing coprimality check on proof.D weakens the soundness of the well-formed proof. While exploitation would require careful algebraic analysis of the Paillier commitment scheme under non-coprime inputs, the omission is a clear deviation from the expected validation pattern (compare with the encrypted_signature check at line 386). The BAM protocol is a two-party ECDSA variant, and this affects the server's ability to verify that the client's partial signature was correctly formed.

---

## Summary Table

| # | Finding | Status | Reachability | Severity |
|---|---------|--------|-------------|----------|
| 1 | Paillier Public Key Weak N | CONFIRMED | EXTERNAL (mitigated by ZKP) | LOW |
| 2 | Ring Pedersen Weak N | CONFIRMED | EXTERNAL (mitigated by ZKP) | LOW |
| 3 | Schnorr ZKP Accepts Identity Point | CONFIRMED | EXTERNAL | HIGH |
| 4 | Paillier Private Key No Primality | CONFIRMED | INTERNAL only | LOW (informational) |
| 5 | Missing Sig Verify (Offline ECDSA) | CONFIRMED | EXTERNAL | MEDIUM |
| 6 | Identity Point in Key Setup | CONFIRMED | EXTERNAL | HIGH |
| 7 | BAM Missing Coprimality on proof.D | CONFIRMED | EXTERNAL (BAM protocol) | MEDIUM |

## Priority Recommendations

1. **CRITICAL (Findings 3+6):** Add `validate_non_infinity_point` check on received public shares in `verify_and_load_setup_decommitments` before storing them. This is a single-line fix that blocks the identity point attack.

2. **HIGH (Finding 5):** Add signature verification in `ecdsa_offline_signature` matching the pattern in the online path. This requires passing the message and derived public key context, or restructuring the offline flow to enable verification.

3. **MEDIUM (Finding 7):** Add `is_coprime_fast(proof.D, paillier->pub.n, ctx)` check in `verify_signature_proof` after deserialization, mirroring the existing encrypted_signature check.

4. **LOW (Findings 1,2,4):** Add structural validation checks (oddness, compositeness, primality) to the deserialization functions themselves for defense-in-depth, even though the protocol-level ZKPs currently catch these.
