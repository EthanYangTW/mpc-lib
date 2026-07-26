# Compound/Chain Attack Analysis -- Fireblocks MPC Library

This document identifies attack chains where combining two or more confirmed vulnerabilities produces a more severe attack than any individual finding. Chains are ordered by severity of the combined impact.

---

## CHAIN 1: Version Downgrade + MTA Fiat-Shamir Truncation + Hardcoded use_extended_seed=0 = Full MTA Proof Bypass

**Vulnerabilities:** V3 (version downgrade) + V2 (MTA Fiat-Shamir truncation) + V10 (hardcoded use_extended_seed=0)

**Combined Severity:** CRITICAL (P1) -- Full key recovery via MTA proof forgery

**Prerequisites:** Malicious co-signer in a CMP ECDSA signing quorum.

### Attack Flow

1. **Version Downgrade (V3):** The malicious co-signer sends `version=1` in the `mta_response` call. The code at `cmp_ecdsa_online_signing_service.cpp:145-157` only checks `if (version > metadata.version)` -- there is no minimum floor. The honest party accepts the version and sets `metadata.version = 1`.

2. **Trigger Truncated Hash (V2):** With `version < MPC_EXTENDED_MTA (11)`, the MTA range proof falls back to `generate_mta_range_zkp_seed` instead of the extended variant. At `mta.cpp:128-130`, the seed function hashes `proof.A` (a value in Z_{N^2}, ~4096 bits for 2048-bit Paillier) but only feeds `BN_num_bytes(proof.S)` bytes (~128 bytes for 1024-bit Ring Pedersen) into SHA-256 instead of the full `BN_num_bytes(proof.A)` (~512 bytes). This means roughly 384 bytes (~3072 bits) of `proof.A` are excluded from the Fiat-Shamir challenge. The attacker can freely vary these excluded bytes without changing the challenge, enabling proof manipulation.

3. **Hardcoded Weak DH/Exponent Proofs (V10):** Even if the MTA range proof challenge were fixed, the DH and Exponent proofs used alongside MTA are verified at `cmp_ecdsa_online_signing_service.cpp:197` and `cmp_ecdsa_signing_service.cpp:176` with `use_extended_seed=0` hardcoded, regardless of negotiated version. The non-extended seed includes less data in the Fiat-Shamir hash. This provides a second independent weakness in the proof system.

4. **Exploit:** With manipulable Fiat-Shamir challenges, the attacker can forge MTA proofs for arbitrary ciphertext values. In the MTA protocol, the honest party encrypts `k_i` under Paillier and the co-signer homomorphically computes `gamma_j * k_i + beta_j`. By forging the proof, the attacker controls the homomorphic computation, injecting values that leak `k_i` or the private key share `x_i` through the resulting partial signature. Over multiple signing sessions, the attacker recovers the honest party's key share.

5. **Final Impact:** Full private key recovery. The attacker combines their own key share with the recovered honest party's share to reconstruct the complete private key and steal all funds.

### Why This Chain Is Worse Than Individual Findings

- V3 alone (version downgrade): Merely enables weaker proof parameters, not exploitable by itself.
- V2 alone (truncation): Only reachable if the old hash path is used; modern deployments use version >= 11.
- V10 alone (hardcoded seed): Reduces Fiat-Shamir entropy but may not be independently exploitable.
- Combined: V3 forces the code path where V2 applies, while V10 ensures DH/Exponent proofs are also weak, creating a comprehensive proof forgery capability that leads to key recovery.

---

## CHAIN 2: Version Downgrade + 40-bit Batch Soundness + Missing Coprimality = Batch MTA Proof Forgery

**Vulnerabilities:** V3 (version downgrade) + V11 (40-bit batch MTA soundness) + V6 (missing coprimality checks)

**Combined Severity:** CRITICAL (P1) -- Full key recovery

**Prerequisites:** Malicious co-signer in a CMP ECDSA signing session with >= 4 blocks (to trigger batch verification, since each block has 2 MTA operations, reaching the MIN_BATCH_SIZE of 6).

### Attack Flow

1. **Version Downgrade (V3):** Attacker sends `version=1` to force the truncated Fiat-Shamir hash in MTA proofs (same as Chain 1).

2. **Batch Verification with 40-bit Soundness (V11):** When the signing session has enough blocks (>= 4 blocks = 8 MTA operations >= MIN_BATCH_SIZE=6), the verifier uses `batch_response_verifier`. This verifier uses `BATCH_STATISTICAL_SECURITY = 5` rounds with 8-bit random exponents for Paillier verification (`mta.cpp:1172`), giving only 40-bit soundness. The CMP paper requires 80+ bits.

3. **Missing Coprimality on E/F/S/T (V6):** The batch verifier (`mta.cpp:1116-1134`) checks coprimality for Paillier values (response, proof.A, commitment, proof.By) against the Paillier modulus, but does NOT check coprimality of Ring Pedersen commitments E/F/S/T against the Ring Pedersen modulus N. An attacker supplying E, F, S, or T that share a factor with N can cause the Ring Pedersen verification equation to hold modularly without actually binding the proof. This eliminates the Ring Pedersen component of the proof entirely.

4. **Combined Exploitation:** With the Ring Pedersen binding removed (V6), the truncated Fiat-Shamir hash (V3+V2), and only 40-bit Paillier batch soundness (V11), the attacker must only find values that satisfy the weakened Paillier batch check. With 40-bit soundness, each attempt has probability 2^{-40}. While 2^{40} is not trivially brute-forced in a single session, in a high-value cryptocurrency context with automated signing, the attacker can:
   - Sign many multi-block batches to accumulate attempts.
   - Use the truncated hash to reduce the effective entropy further.
   - With the Ring Pedersen component eliminated, the Paillier check is the only remaining barrier.

5. **Final Impact:** Once a forged MTA proof passes, the attacker controls the additive shares in the MTA protocol, enabling them to extract the honest party's nonce `k_i` or key share `x_i`, leading to full key recovery.

---

## CHAIN 3: 1024-bit Ring Pedersen + Persistent Auxiliary Keys Through Refresh = Permanent Proof Weakness

**Vulnerabilities:** V4 (1024-bit Ring Pedersen) + V5 (key refresh doesn't rotate auxiliary keys)

**Combined Severity:** HIGH (P2) -- Permanent degradation of all MTA proof security, persisting indefinitely

**Prerequisites:** Any attacker with sufficient compute to factor a 1024-bit RSA modulus (estimated at ~$100K-$1M with current cloud GPUs, decreasing over time).

### Attack Flow

1. **Factor the 1024-bit Ring Pedersen Modulus (V4):** The Ring Pedersen modulus is generated at `cmp_setup_service.cpp:576` with `RING_PEDERSEN_KEY_SIZE = 1024` bits. The CMP paper requires 2048 bits. A 1024-bit RSA modulus is within reach of well-resourced adversaries using the Number Field Sieve.

2. **Persist Advantage Through Key Refresh (V5):** `cmp_offline_refresh_service.cpp:86-205` refreshes only the private key share (`x`), nonce (`k`), and chi values. Paillier and Ring Pedersen keys are never regenerated. Even after arbitrarily many key refresh operations, the factored Ring Pedersen modulus remains in use.

3. **Exploit:** With the Ring Pedersen factorization, the attacker knows `lambda` (the secret exponent) and can:
   - Open any Ring Pedersen commitment to arbitrary values.
   - Forge the Ring Pedersen components of all MTA range proofs.
   - The Ring Pedersen commitment is a core binding component in the CMP protocol's MTA proofs -- breaking it undermines the soundness of the entire proof system.

4. **Temporal Amplification:** The attacker can factor the modulus offline over months or years, then exploit it at any future time since the keys are never rotated. Key refresh creates a false sense of security -- administrators may believe refresh mitigates past compromises, but auxiliary key persistence means the fundamental proof infrastructure remains compromised.

5. **Final Impact:** Permanent ability to forge Ring Pedersen commitments in all MTA proofs, enabling manipulation of the additive MTA shares. Combined with V6 (missing coprimality) or V2 (truncated hash), this gives full MTA proof forgery and key recovery.

---

## CHAIN 4: Identity Point as Public Share + Zero-Secret Schnorr Proof = Rogue Key Attack in Setup

**Vulnerabilities:** V13 (identity point accepted as public share) + V14 (Schnorr ZKP accepts zero-secret proofs)

**Combined Severity:** HIGH (P2) -- Full control of aggregate public key during setup

**Prerequisites:** Malicious participant in CMP key generation.

### Attack Flow

1. **Submit Identity Point as Public Share (V13):** During CMP setup round 3 (`cmp_setup_service.cpp:759`), each player's public share is stored: `memcpy(info.public_share.data, decommit_it->second.share.X.data, sizeof(elliptic_curve256_point_t))`. There is no check that this share is not the identity point.

2. **Forge Schnorr Proof for Zero Secret (V14):** At `cmp_setup_service.cpp:809`, `schnorr_zkp_verify` is called to verify the player knows the discrete log of their public share. From `schnorr.c:137-177`, the verification computes `challenge = SHA256(prover_id || R || public_data)` and checks `R == challenge * public_data + s * G`. When `public_data` is the identity point, `challenge * public_data` is also the identity, so the check reduces to `R == s * G`. The attacker can trivially satisfy this by choosing any random `s`, computing `R = s * G`, and providing `(R, s)` as the proof. No actual knowledge of a discrete log is needed.

3. **Rogue Key Attack:** With their public share as the identity point (which acts as the additive identity), the aggregate public key `Q = sum of all shares = Q_honest + O = Q_honest`. The malicious player's contribution is zero, but they can now set their "public share" in a way that biases the aggregate. More critically, if the attacker is the last to submit, they can set their share to `Q_target - sum(other_shares)` to force any desired aggregate public key. The identity point acceptance is the mechanism that lets this fly without detection.

4. **Alternative Attack Path:** In an additive n-of-n scheme with `t == n` (enforced by the setup), the attacker's private share being 0 means their contribution to any signature is 0. They become a passive observer who can see all MTA messages but contributes nothing to security. If the attacker can also compromise MTA proofs (via Chains 1-3), they can recover the honest party's full key.

5. **Final Impact:** The attacker controls key generation, potentially allowing theft of funds deposited to an address the attacker fully controls, or degradation to a 1-of-2 security model where the attacker needs only the honest party's share.

---

## CHAIN 5: Version Downgrade + Missing Offline Signature Verification = Undetected Forgery in Offline Signing

**Vulnerabilities:** V3 (version downgrade) + V12 (missing offline ECDSA signature verification)

**Combined Severity:** HIGH (P2) -- Silent acceptance of invalid signatures

**Prerequisites:** Malicious co-signer in CMP ECDSA offline signing.

### Attack Flow

1. **Version Downgrade (V3):** Attacker sends `version=1` during the offline preprocessing `offline_mta_response` (`cmp_ecdsa_offline_signing_service.cpp:98-104`), forcing weak MTA proofs.

2. **Submit Manipulated Partial Signatures:** With weakened MTA proofs, the attacker can submit partial signatures with manipulated `s` values during `ecdsa_sign`.

3. **No Final Signature Verification (V12):** In `ecdsa_offline_signature` (`cmp_ecdsa_offline_signing_service.cpp:420-477`), the aggregation function sums all partial `s` values and returns the combined signature WITHOUT verifying it against the public key. Compare this to the online flow's `get_cmp_signature` (line 482-495) which performs full ECDSA verification.

4. **Impact:** The resulting invalid signature is returned to the application layer. Depending on the application:
   - The invalid signature may be broadcast to the blockchain, where it will be rejected by validators, causing a denial-of-service for the wallet.
   - The attacker can selectively cause signing failures, blocking specific transactions.
   - In an attack where the forged partial signature leaks information about the honest party's nonce `k_i`, the invalid signature serves as a side channel: the attacker can observe that a specific manipulated value produced a specific (invalid) result, leaking bits of `k_i`.

5. **Contrast with Online Flow:** The online signing flow verifies the final signature and throws FATAL on failure. The offline flow silently returns garbage. This means the offline flow is strictly less secure and can be exploited as a side channel that the online flow would block.

---

## CHAIN 6: Weak Paillier/Ring Pedersen Deserialization + 1024-bit Ring Pedersen = Malicious Parameter Injection

**Vulnerabilities:** V19 (Paillier accepts prime/even/small N) + V20 (Ring Pedersen accepts prime/small N) + V4 (1024-bit Ring Pedersen)

**Combined Severity:** HIGH (P2) -- Compromise of proof system parameters

**Prerequisites:** Malicious participant in CMP key generation or BAM setup.

### Attack Flow

1. **Paillier Deserialization Weakness (V19):** At `paillier.c:346-378`, `paillier_public_key_deserialize_internal` only checks `BN_num_bits(N) >= MIN_KEY_LEN_IN_BITS` (256 bits). It does NOT check:
   - N is odd (an even N means one factor is 2, trivially factorable)
   - N is not a perfect power (N = p^k breaks Paillier)
   - N is not prime (Paillier requires N = p*q)

2. **Ring Pedersen Deserialization Weakness (V20):** At `ring_pedersen.c:254-320`, similar minimal validation. No check for oddness, primality exclusion, or coprimality of s,t with N.

3. **Low Modulus Floor (V4):** Ring Pedersen validation at `cmp_setup_service.cpp:643` only enforces N >= 1024 bits. While setup ZKPs (Paillier-Blum, Ring Pedersen parameters) are supposed to prove well-formedness, V19/V20 let a malicious party submit degenerate values through deserialization paths that may bypass the ZKP checks. For example:
   - A prime N passes the size check but completely breaks both Paillier (phi(N) = N-1, trivially computed) and Ring Pedersen (lambda is trivially the discrete log in Z_N^*).
   - An even N allows trivial factoring (divide by 2).

4. **Bypassing ZKP Verification:** The Paillier-Blum ZKP at `cmp_setup_service.cpp:816` should catch a non-Blum modulus. However, if the ZKP verification itself has implementation flaws (the serialization/deserialization path processes the key BEFORE the ZKP is verified in the protocol flow), a carefully crafted N could survive deserialization and be stored before the ZKP rejects it. The key is stored at `cmp_setup_service.cpp:759-760` in `verify_and_load_setup_decommitments` (round 3), while ZKPs are verified in `verify_setup_proofs` (round 4). If the ZKP fails in round 4, the key metadata with the degenerate N is already stored from round 3. An error in round 4 might leave stale round 3 data.

5. **Final Impact:** If a degenerate N enters the system, the attacker can trivially factor it and compromise all MTA proofs and Ring Pedersen commitments, leading to key share recovery.

---

## CHAIN 7: EdDSA Nonce Reuse + Missing Domain Separation by Hash Algorithm = Cross-Protocol Key Recovery

**Vulnerabilities:** V1 (Ed25519 nonce reuse via use_keccak mismatch) + V17 (MPC EdDSA nonce not domain-separated by hash algorithm)

**Combined Severity:** CRITICAL (P1) -- Full EdDSA private key recovery

**Prerequisites:** A wallet that signs both standard Ed25519 (SHA-512, e.g., Solana) and Keccak-based Ed25519 (e.g., certain Ethereum L2s) messages. A malicious party that can request both signature types, OR an observer of two different signing sessions.

### Attack Flow

1. **Deterministic Nonce is Hash-Algorithm-Independent (V1):** At `ed25519_algebra.c:644-649`, the nonce is computed as `k = SHA512(private_key || message)`. The `use_keccak` flag is only used for the HRAM challenge hash, NOT for nonce derivation. This means signing the same `(key, message)` pair with `use_keccak=0` and `use_keccak=1` produces the same nonce `k` and the same `R = k*G`.

2. **MPC Protocol Propagates the Flaw (V17):** In the MPC EdDSA signing at `asymmetric_eddsa_cosigner_server.cpp:379`, the per-block `EDDSA_KECCAK` flag determines the hash algorithm. The MPC nonce `k_i` for each party is generated independently (`algebra->rand()` at line 154), so V1 doesn't directly apply to the MPC version -- the MPC nonces are random, not deterministic.

   However, V17 notes that the MPC EdDSA nonce generation is not domain-separated by hash algorithm. If the same preprocessed nonce index is used for two signing requests that differ only in the `EDDSA_KECCAK` flag, the same `R` would be produced with different HRAM values. This is a separate path to the same nonce-reuse attack.

3. **Key Recovery:** Given two signatures `(R, s1)` with HRAM `e1` (SHA-512) and `(R, s2)` with HRAM `e2` (Keccak) on the same message:
   - `s1 = k + e1 * x` and `s2 = k + e2 * x`
   - `s1 - s2 = (e1 - e2) * x`
   - `x = (s1 - s2) / (e1 - e2) mod L`
   - Since `e1` and `e2` are publicly computable from `(R, public_key, message)`, the private key is trivially recovered.

4. **Practical Trigger:** In the non-MPC (single-party) Ed25519 implementation at `ed25519_algebra.c:624-669`, if the library is used directly to sign the same message for both a standard Ed25519 chain and a Keccak Ed25519 chain, key recovery is immediate. In the MPC version, the attack requires the same nonce indices to be reused across hash algorithm variants.

5. **Final Impact:** Complete EdDSA private key recovery, enabling theft of all funds on all Ed25519-based chains controlled by that key.

---

## CHAIN 8: EdDSA 2-Party No Commitment + Missing Coprimality/Weak Proofs = Adaptive R Attack

**Vulnerabilities:** V16 (asymmetric EdDSA no commitment in 2-party mode) + V14 (Schnorr accepts zero-secret proofs) + V13 (identity point accepted)

**Combined Severity:** HIGH (P2) -- Biased nonce attack enabling gradual key recovery

**Prerequisites:** Malicious client device in 2-party asymmetric EdDSA signing.

### Attack Flow

1. **No Commitment in 2-Party Mode (V16):** At `asymmetric_eddsa_cosigner_server.cpp:158-161`, when `metadata.n == 2`, the server skips the commitment scheme and sends its `R` directly to the client. The client sees the server's `R` before committing to its own.

2. **Adaptive R Selection:** The malicious client, upon receiving the server's `R_server`, can choose its own `R_client` adaptively. In standard EdDSA, nonces must be committed before R values are revealed to prevent the client from choosing `R_client` based on `R_server`. Without a commitment, the client can:
   - Choose `R_client` to create special relationships between the combined `R = R_server + R_client` and the message hash.
   - Perform a "related nonce" attack: by choosing `R_client = alpha * G - R_server` for strategically chosen `alpha`, the client can create `R = alpha * G`, placing the combined nonce point at a chosen location.

3. **Partial Signature Verification Limitation:** At line 380, the server verifies `verify_client_s` which checks `G^s == R_client + (G^delta + public_share)^HRAM`. This only proves the client used a valid key share and nonce -- it does not prevent the client from choosing the nonce adaptively.

4. **Information Leakage:** Through repeated adaptive R selection across many signing sessions, the client can apply lattice-based attacks (similar to the Minerva or TPM-FAIL attacks) to gradually recover the server's private key share. Each signature leaks a few bits of the server's nonce, and after O(256/leaked_bits) signatures, the full key share is recoverable.

5. **Connection to V13/V14:** If the client's public share was accepted as the identity point during setup (V13, proven via a zero-secret Schnorr proof V14), then `public_share = O` and the client has no actual secret. The HRAM verification at line 380 becomes trivially satisfiable with `s = k_client + e * delta` (where `delta` is derivable from public data). This means the client can always produce valid partial signatures without any actual key material, turning the 2-of-2 scheme into an effective 1-of-1.

6. **Final Impact:** Gradual server key share recovery through adaptive nonce attacks, or immediate bypass of 2-party security if combined with identity point injection.

---

## CHAIN 9: BAM AAD Hash Collision + Missing Domain Separation = Cross-Key/Cross-Transaction Proof Replay

**Vulnerabilities:** V8 (BAM AAD hash collision) + V22 (missing domain separation in BAM Fiat-Shamir hash)

**Combined Severity:** MEDIUM-HIGH (P2-P3) -- ZK proof reuse across different contexts

**Prerequisites:** Malicious BAM ECDSA co-signer.

### Attack Flow

1. **AAD Hash Collision (V8):** At `bam_ecdsa_cosigner.cpp:72-83`, `generate_aad_for_signature` concatenates variable-length fields without length prefixes:
   ```
   SHA256("BAM ECDSA Signature AAD" || key_id || tx_id || server_id || client_id)
   ```
   Since `key_id` and `tx_id` are variable-length strings concatenated directly, there exist collisions. For example:
   - `key_id="AB"`, `tx_id="CD"` produces the same prefix as `key_id="ABC"`, `tx_id="D"`.
   The fixed-size `server_id` and `client_id` (uint64) after the strings make collisions harder to construct but do not eliminate them entirely, since the attacker controls the key_id and tx_id strings.

2. **Missing Domain Separation (V22):** The BAM well-formed proof's Fiat-Shamir hash (`compute_e` in `bam_well_formed_proof.cpp`) uses the `signature_aad` directly. If the same AAD can be produced for two different (key_id, tx_id) pairs, the same Fiat-Shamir challenge `e` results for both contexts, enabling proof replay.

3. **Proof Replay Attack:** An attacker who creates two different key_id/tx_id pairs that collide in AAD can:
   - Generate a valid well-formed proof for one context.
   - Replay the proof in the colliding context.
   - This may allow signing with one key while the system believes a different key was used, or replaying an old signature proof for a new transaction.

4. **Final Impact:** Potential cross-key or cross-transaction proof replay, undermining the binding of proofs to specific signing contexts. While not directly a key recovery attack, it violates the security model's non-transferability guarantees.

---

## CHAIN 10: Heap Corruption + Timing Side Channel = Information Leakage via Crash Oracle

**Vulnerabilities:** V9 (heap memory corruption in destructor) + V15 (timing side-channel in paillier_mul)

**Combined Severity:** MEDIUM (P3) -- Exploitable memory corruption plus information leakage

**Prerequisites:** Ability to trigger signing operations and observe timing/crash behavior.

### Attack Flow

1. **Heap Corruption (V9):** At `cmp_ecdsa_signing_service.h:85`, the destructor `~ecdsa_preprocessing_data()` calls `OPENSSL_cleanse(k.data, sizeof(ecdsa_preprocessing_data))`. The `k.data` field is 32 bytes, but `sizeof(ecdsa_preprocessing_data)` is 350+ bytes (including 6 scalars, 1 point, 1 vector, and 2 maps). This overwrites 318+ bytes of heap memory beyond the `k.data` field.

2. **Crash-Dependent Behavior:** The heap corruption may:
   - Overwrite adjacent heap metadata, causing a crash in `free()`/`delete` during cleanup.
   - Overwrite other sensitive data structures that are still in use.
   - Produce deterministic crashes that depend on the heap layout, which itself depends on the signing data.

3. **Timing Side Channel (V15):** At `paillier.c:1727`, `BN_mod_exp` is called without `BN_FLG_CONSTTIME` on the secret exponent. The timing of Paillier encryption/decryption operations depends on the secret value being encrypted. Combined with heap corruption:
   - If heap corruption crashes the process at a timing-dependent point, the crash/no-crash outcome itself becomes a timing oracle.
   - An attacker who can trigger many signing operations and observe which ones crash can correlate crash patterns with the secret values processed immediately before.

4. **Final Impact:** Partial information leakage about Paillier plaintexts (nonce values, key shares) through a combination of timing side-channels and crash oracles. Not a direct key recovery, but provides side-channel information that could accelerate lattice-based attacks.

---

## CHAIN 11: VSS ID=0 Oracle + Persistent Auxiliary Keys = Long-Term Secret Extraction via Refresh

**Vulnerabilities:** V25 (VSS verify_share accepts ID=0) + V5 (key refresh doesn't rotate auxiliary keys)

**Combined Severity:** MEDIUM (P3) -- Secret commitment oracle surviving refresh operations

**Prerequisites:** Malicious participant who can invoke VSS share verification with crafted inputs.

### Attack Flow

1. **VSS ID=0 Oracle (V25):** When `verifiable_secret_sharing_verify_share` is called with `id=0`, the evaluation point `x` becomes 0. The polynomial `P(x) = a_0 + a_1*x + ... + a_{t-1}*x^{t-1}` evaluates to `P(0) = a_0`, which is the constant term (the secret). The verification then checks `share_proof == coefficient_proofs[0]`, which is `g^{a_0}` (the commitment to the secret). This turns the verification function into an oracle that confirms whether a given point equals the secret's commitment.

2. **Persistence Through Refresh (V5):** The VSS coefficients used during key generation define the polynomial whose constant term is the joint secret. While key refresh changes the additive shares, the coefficient commitments from setup may persist in storage. Since auxiliary keys are never rotated, any VSS-related metadata from the original setup remains valid.

3. **Exploitation:** An attacker who can replay or invoke the VSS verification function with ID=0 can confirm guesses about the secret commitment. While this doesn't directly reveal the discrete log, it provides a verification oracle that leaks information about the polynomial structure.

4. **Final Impact:** The attacker can confirm whether a guessed public key (commitment to the secret) matches the actual secret, facilitating offline brute-force of smaller key spaces or confirming key recovery from other attack channels.

---

## CHAIN 12: Missing BAM w2 Range Check + Missing proof.D Coprimality = BAM Well-Formed Proof Forgery

**Vulnerabilities:** V18 (missing w2 range check) + V7 (missing coprimality in BAM proof.D)

**Combined Severity:** MEDIUM-HIGH (P3 elevated to P2) -- BAM ECDSA proof system compromise

**Prerequisites:** Malicious BAM ECDSA client.

### Attack Flow

1. **No w2 Range Check (V18):** At `bam_well_formed_proof.cpp:400-413`, the verifier checks that `z1` and `z2` are within their expected ranges, but `w2` is NOT range-checked. The prover generates `w2` bounded by a specific bit-length during proof generation, but the verifier accepts arbitrarily large `w2` values. This means the attacker can supply a `w2` that is much larger than expected, which overflows the Paillier commitment verification at line 468.

2. **No proof.D Coprimality (V7):** At `bam_well_formed_proof.cpp:475-476`, `proof.D` is used in `BN_mod_mul` with `paillier->pub.n2` without checking `gcd(D, N) == 1`. If `D` shares a factor with `N`, the attacker learns a factor of `N` (which they already know since they generated it), but more importantly, the modular multiplication becomes degenerate -- the equation can be satisfied even for incorrect values.

3. **Combined Proof Forgery:** With an unbounded `w2` (V18) and a degenerate `proof.D` (V7), the attacker can craft proof values that satisfy both the EC commitment check (line 443-462) and the Paillier commitment check (line 464-485) without actually holding the correct witness values. The EC check binds `z1, z2, w0` to `U, V, e`, while the Paillier check binds `z1, w2, z2` to `D, S, e`. An attacker who can freely choose `w2` and `D` can satisfy the Paillier check independently of the EC check.

4. **Final Impact:** Forgery of BAM well-formed signature proofs. This allows the malicious client to submit encrypted partial signatures that don't correspond to valid ECDSA partial signatures. While the server performs a final signature verification (`bam_ecdsa_cosigner_server.cpp` final round), a carefully crafted forgery could produce a valid-looking signature that steals funds. Alternatively, repeated forgeries leak information about the server's encrypted share through the decrypted output.

---

## CHAIN 13: 1024-bit Ring Pedersen + Missing Coprimality + Truncated Hash = Complete MTA Proof System Bypass

**Vulnerabilities:** V4 (1024-bit Ring Pedersen) + V6 (missing coprimality) + V2 (Fiat-Shamir truncation)

**Combined Severity:** CRITICAL (P1) -- Complete bypass of all MTA proof-of-correctness checks

**Prerequisites:** Well-resourced attacker who can factor 1024-bit RSA modulus; malicious co-signer in CMP ECDSA signing.

### Attack Flow

1. **Factor the 1024-bit Modulus (V4):** With `RING_PEDERSEN_KEY_SIZE = 1024`, the attacker factors the honest party's Ring Pedersen modulus offline.

2. **Forge Ring Pedersen Commitments (V4 + V6):** Knowing the factorization gives the attacker `lambda` (the Ring Pedersen secret). They can now open commitments to any value. Combined with V6 (no coprimality check on E/F/S/T), the attacker can additionally supply E, F, S, T values that share factors with N, making the Ring Pedersen verification equations trivially satisfiable.

3. **Exploit Truncated Fiat-Shamir Hash (V2):** With Ring Pedersen binding eliminated, the Fiat-Shamir challenge is the main remaining defense. The truncation at `mta.cpp:130` reduces the effective entropy of the challenge, making it feasible to find proof values that satisfy the Paillier components.

4. **Temporal Persistence (V5):** Even if the honest party performs key refresh, the Ring Pedersen keys are never rotated (V5), so the factorization remains valid indefinitely.

5. **Final Impact:** The attacker can forge arbitrary MTA proofs, controlling the additive shares in every MTA operation. This gives them full control over the delta and chi values in the honest party's signing computation, enabling extraction of the honest party's private key share within a single signing session.

---

## CHAIN 14: Version Downgrade + Secret Not Cleared + Heap Corruption = Post-Signing Secret Recovery

**Vulnerabilities:** V3 (version downgrade) + V21 (secret not cleared in paillier_mul) + V9 (heap corruption)

**Combined Severity:** LOW-MEDIUM (P3-P4) -- Memory forensics attack

**Prerequisites:** Access to process memory dumps (e.g., via a separate memory disclosure vulnerability, cold boot attack, or core dump analysis).

### Attack Flow

1. **Secret Persistence (V21):** At `paillier.c:1746`, the cleanup path in `paillier_mul` does not cleanse the intermediate BIGNUM values including the plaintext `bn_b`. These values persist in freed memory.

2. **Heap Corruption as Amplifier (V9):** The destructor's `OPENSSL_cleanse` overflow writes 350+ bytes past `k.data`, potentially corrupting heap free-list metadata. This can prevent subsequent memory allocations from overwriting the stale secret data, extending the window during which secrets persist in memory.

3. **Version Downgrade Enables More Signing (V3):** By forcing a version downgrade, the attacker ensures the weaker code paths are used, potentially increasing the number of Paillier operations (due to additional proof rounds or retry logic), each of which leaves stale secrets in memory.

4. **Final Impact:** Secret key shares and nonces may persist in freed memory for extended periods. An attacker with memory access (through a separate vulnerability) can extract these values. This is primarily a defense-in-depth failure rather than a direct remote attack.

---

## CHAIN 15: Schnorr Generator Not in Hash + BAM Domain Separation Missing = Cross-Protocol Proof Replay

**Vulnerabilities:** V24 (Schnorr ZKP missing generator in Fiat-Shamir hash) + V22 (missing domain separation in BAM Fiat-Shamir hash)

**Combined Severity:** LOW-MEDIUM (P3-P4) -- Proof portability across contexts

**Prerequisites:** Attacker who participates in both CMP key generation and BAM key generation for overlapping key IDs.

### Attack Flow

1. **Schnorr Hash Doesn't Include Generator (V24):** The Schnorr ZKP challenge is `SHA256(prover_id || R || public_data)`. The generator point `G` is not included. This means a proof of knowledge of `x` such that `X = x * G_1` on one curve is indistinguishable from a proof on another curve where `X = x * G_2` with a different generator.

2. **BAM Missing Domain Separation (V22):** The BAM Fiat-Shamir hash does not include protocol-specific domain separation, making proofs potentially portable between BAM and CMP contexts.

3. **Cross-Protocol Replay:** A Schnorr proof generated during CMP setup could potentially be replayed in a BAM context (or vice versa) if the prover_id and public_data match, since neither proof system binds to its specific protocol context.

4. **Final Impact:** While the practical exploitability is limited by the need for matching prover IDs and public data across protocols, this violates the principle that ZKPs should be non-transferable. In a multi-tenant system where the same player participates in both CMP and BAM protocols, this could enable proof reuse attacks.

---

## Summary Table

| Chain | Vulnerabilities | Combined Severity | Attack Type | Prerequisites |
|-------|----------------|-------------------|-------------|---------------|
| 1 | V3+V2+V10 | CRITICAL (P1) | Full key recovery via MTA proof forgery | Malicious CMP co-signer |
| 2 | V3+V11+V6 | CRITICAL (P1) | Batch MTA proof forgery | Malicious co-signer, >= 4 signing blocks |
| 7 | V1+V17 | CRITICAL (P1) | EdDSA private key recovery | Same key signs with both hash algorithms |
| 13 | V4+V6+V2 | CRITICAL (P1) | Complete MTA proof bypass | Factor 1024-bit RSA, malicious co-signer |
| 3 | V4+V5 | HIGH (P2) | Permanent proof weakness | Factor 1024-bit RSA |
| 4 | V13+V14 | HIGH (P2) | Rogue key in setup | Malicious setup participant |
| 5 | V3+V12 | HIGH (P2) | Undetected forgery | Malicious offline signing co-signer |
| 6 | V19+V20+V4 | HIGH (P2) | Parameter injection | Malicious setup participant |
| 8 | V16+V14+V13 | HIGH (P2) | Adaptive R / bypass 2-party | Malicious EdDSA client device |
| 12 | V18+V7 | MEDIUM-HIGH (P2-P3) | BAM proof forgery | Malicious BAM client |
| 9 | V8+V22 | MEDIUM-HIGH (P2-P3) | Cross-context proof replay | Malicious BAM co-signer |
| 10 | V9+V15 | MEDIUM (P3) | Crash oracle + timing leak | Observe timing and crashes |
| 11 | V25+V5 | MEDIUM (P3) | Secret oracle via refresh | Invoke VSS verify with crafted ID |
| 14 | V3+V21+V9 | LOW-MEDIUM (P3-P4) | Memory forensics | Memory dump access |
| 15 | V24+V22 | LOW-MEDIUM (P3-P4) | Cross-protocol proof replay | Multi-protocol participant |

---

## Key Observations

### Cross-Protocol Boundaries

- **CMP Setup -> CMP Signing:** Parameters (Paillier, Ring Pedersen) established in setup flow directly into signing. V4 (1024-bit Ring Pedersen) and V19/V20 (weak deserialization) in setup directly enable attacks in signing (Chains 3, 6, 13).

- **CMP Signing -> Key Refresh:** V5 (auxiliary keys persist) means any compromise of Paillier/Ring Pedersen keys in signing survives refresh indefinitely (Chains 3, 11).

- **Online Signing <-> Offline Signing:** V12 (missing verification in offline) means offline signing is strictly weaker than online signing. V3 (version downgrade) applies to both flows. Attackers should target offline signing when possible (Chain 5).

- **CMP <-> BAM:** Both use Paillier and Ring Pedersen primitives. V19/V20 (deserialization weaknesses) affect both protocols. V7 (BAM proof.D coprimality) is BAM-specific but structurally analogous to V6 (CMP MTA coprimality).

### Temporal Attack Patterns

- **Setup-time attacks persist forever:** V4, V13, V14 compromise parameters during setup. V5 ensures these are never refreshed. The attacker can wait years before exploiting.

- **Version downgrade is per-session:** V3 must be applied in each signing session but is reliable (no minimum floor). The honest party has no way to detect or refuse the downgrade.

- **Gradual leakage across sessions:** V15 (timing), V11 (40-bit batch), and V16 (adaptive R) enable attacks that accumulate information across many signing sessions, eventually reaching full key recovery.

### Severity Escalation Patterns

- **Two P3s -> P1:** V4 (1024-bit Ring Pedersen, P3) + V6 (coprimality, P3) + V2 (truncation, P2) = Chain 13 (P1 full key recovery).
- **P4 enables P2:** V3 (version downgrade, P2) is the most powerful enabler -- it activates V2 (truncation) and V10 (weak seed) simultaneously.
- **P3 + P3 -> P2:** V13 (identity point, P3) + V14 (zero-secret Schnorr, P3) = Chain 4 (P2 rogue key attack).
- **P3 + P4 -> P3 with permanence:** V4 (1024-bit, P3) + V5 (no rotation, P3) = Chain 3 (P2 permanent weakness).
