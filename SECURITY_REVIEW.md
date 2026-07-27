# Security Review — mpc-lib

**Target:** `EthanYangTW/mpc-lib` (fork of `fireblocks/mpc-lib`)
**Commit reviewed:** `4e891c4` — *"Added MPC-BAM implementation … expanded test suite"*
**Date:** 2026-07-27
**Reviewer:** automated multi-agent source audit with manual verification of every reported item

> **Handling.** This document describes unpatched vulnerabilities in a library used to
> custody digital assets. Findings 1–5 in particular should be routed through the process in
> `SECURITY.md` rather than a public issue or pull request. Working exploit code for
> findings 3, 7 and 10 lives in `test/poc/`.

---

## 1. Scope and method

Reviewed: the full `src/common/` tree (cryptographic primitives, zero-knowledge proofs,
Paillier, commitments) and `src/common/cosigner/` (CMP/GG-style ECDSA, EdDSA, and the newly
added MPC-BAM protocol orchestration), plus the public headers in `include/`.

Threat model: **a malicious cosigner.** One or more protocol participants are fully
adversarial and control every byte they send. This is the model the library exists to
defend against, so "requires being an authenticated participant" is *in scope*, not a
mitigating factor.

The in-scope sources were confirmed byte-identical to upstream `fireblocks/mpc-lib@main`,
so every finding below concerns real production code.

Each finding was produced by one agent and then independently re-checked. Findings 3, 7 and
10 additionally have executable proofs. Findings whose claimed impact could not be
substantiated were dropped rather than reported — several candidate issues were
investigated and refuted, and those are recorded in §4 so the coverage is auditable.

---

## 2. Summary

| # | Finding | Location | CVSS 3.1 | VRT | Evidence |
|---|---|---|---|---|---|
| 1 | EdDSA round-1 replay → nonce reuse → key recovery | `eddsa_online_signing_service.cpp:254` | 8.1 High † | P1 | code review |
| 2 | Ring-Pedersen parameter verifier fails **open** | `ring_pedersen.c:787-800` | 6.8 Medium | P2 | code review |
| 3 | BAM key generation never binds `client_id` | `bam_ecdsa_cosigner_server.cpp:384` | 8.1 High † | P1 | **PoC** |
| 4 | Heap out-of-bounds read in legacy MtA transcript | `mta.cpp:128-130` | 6.5 Medium | P2 | code review |
| 5 | Peer key sizes only lower-bounded → permanent brick | `cmp_setup_service.cpp:631,643` | 6.5 Medium | P2 | code review |
| 6 | Batch MtA verifier ≈1 bit of soundness | `mta.cpp:1250-1267` | 4.3 Medium | P4 | code review |
| 7 | `~ecdsa_preprocessing_data` cleanses over its members | `cmp_ecdsa_signing_service.h:85` | 6.5 Medium | P3 | **PoC** |
| 8 | Key refresh has no consistency verification | `cmp_offline_refresh_service.cpp:92` | 6.8 Medium | P3 | code review |
| 9 | EdDSA `store_commitments` dereferences `map::end()` | `eddsa_online_signing_service.cpp:152` | 5.3 Medium | P3 | code review |
| 10 | Signing protocol version has no lower bound | `cmp_ecdsa_offline_signing_service.cpp:98` | 4.3 Medium | P4 | **PoC** |
| 11 | Paillier-commitment key generation fails open | `paillier_commitment.c:310-335` | 5.9 Medium | P4 | code review |
| 12 | `damgard_fujisaki` unbalanced `BN_CTX` frame | `damgard_fujisaki.c:264-270` | 4.2 Medium | P5 | code review |

† CVSS computed with `S:U`. With `S:C` — defensible for a custody library, where the
impacted resource (customer funds) sits outside the vulnerable component's security
authority — findings 1 and 3 score **9.6 Critical**. See §5.

**Reachable with no precondition:** 3, 4, 5, 6, 7, 10 (and 9, near-unconditionally).
**Requires a precondition outside the attacker's control:** 1, 2, 8, 11, 12.

---

## 3. Findings

### Finding 1 — EdDSA round-1 replay causes nonce reuse, revealing the private key

**Location:** `src/common/cosigner/eddsa_online_signing_service.cpp:254` (the overwrite),
`:295` (persist), `:158` (the check defeated)
**CVSS:** `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` = 8.1 High · **VRT:** P1

`broadcast_si()` overwrites each block's **secret** per-player nonce point with the
**public** aggregate, in place:

```cpp
// eddsa_online_signing_service.cpp:246-256
for (auto j = Rs.begin(); j != Rs.end(); ++j)
{
    if (first)
    {
        memcpy(data.sig_data[i].R.data, j->second[i].data, sizeof(elliptic_curve256_point_t));
        first = false;
    }
    else
        throw_cosigner_exception(_ed25519->add_points(_ed25519.get(),
            &data.sig_data[i].R.data, &data.sig_data[i].R.data, &j->second[i].data));
}
```

The result is persisted at `:295`, and `data.sig_data[i].k` — the secret nonce scalar — is
never erased. Round 1 authenticates its caller **solely** by checking that the supplied
commitment opens to whatever currently sits in `sig_data[i].R`:

```cpp
// eddsa_online_signing_service.cpp:152-159
auto my_commit = commitments.find(my_id);
assert(my_commit != commitments.end());
for (size_t i = 0; i < data.sig_data.size(); ++i)
    throw_cosigner_exception(commitments_verify_commitment(
        data.sig_data[i].R.data, sizeof(elliptic_curve256_point_t), &my_commit->second[i].data));
```

Before round 2 that value is a secret an attacker cannot commit to, so the check is a real
authenticator. After round 2 it is the public aggregate `R`, and
`commitments_create_commitment_for_data` is an unsalted-input SHA-256 the attacker can
evaluate freely. The check becomes trivially forgeable while `k` is still live.

**Attack.** After a session completes:

1. Attacker holds `s_me,1 = hram₁·x + k_me` and the public `R_agg`.
2. Replay round 1 with `C'_me = {salt', SHA256(salt' ‖ R_agg)}` — passes `:158` — and
   attacker-chosen `R'_j` for the peers.
3. Replay round 2. All decommitments verify. New aggregate `R₂`, new challenge `hram₂ ≠ hram₁`.
4. Victim returns `s_me,2 = hram₂·x + k_me`, reusing `k_me`.
5. `x = (s_me,1 − s_me,2)·(hram₁ − hram₂)⁻¹ mod L`. Since `x = share_me + delta` and `delta`
   derives from the public chaincode and path, `share_me` falls out.
6. Repeat per cosigner: `Σ share` is the master Ed25519 private key.

**Precondition (integrator-side).** Step 2 requires `store_signing_commitments()` to accept a
second write for one `txid`. The in-tree reference persistency throws
(`test/cosigner/eddsa_online_test.cpp:106-112`), but that requirement appears **nowhere** in
the public interface: `include/cosigner/eddsa_online_signing_service.h:55` declares the
method with no doc comment, in contrast to `asymmetric_eddsa_cosigner_server.h:42-45`, which
documents its analogous constraint explicitly. An integrator implementing upsert semantics —
what the method name suggests — gets full key extraction with the library silently
cooperating. The same overwrite also turns a benign crash-and-retry into a same-nonce double
signature.

**Fix.**
1. Keep the per-player nonce point immutable; write the aggregate to a separate field, and
   have `store_commitments` keep verifying against the immutable `R`. This alone defeats the
   attack, since the attacker cannot commit to a secret.
2. Add an explicit round-state field to `eddsa_signing_metadata` and reject round-1 messages
   once the state is past `STARTED`, inside the library.
3. `OPENSSL_cleanse` `sig_data[i].k` the moment `s_i` is produced; refuse to re-sign a block
   whose `s` is already set.
4. Document the write-once requirement on `store_signing_commitments`.

---

### Finding 2 — Ring-Pedersen parameter verifier returns SUCCESS without verifying

**Location:** `src/common/crypto/commitments/ring_pedersen.c:787-800`
**CVSS:** `AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N` = 6.8 Medium · **VRT:** P2

```cpp
zero_knowledge_proof_status status = ZKP_OUT_OF_MEMORY;   // :768
...
status = init_ring_pedersen_param_zkp(&proof, ctx);       // :787 — returns ZKP_SUCCESS (0)
if (status != ZKP_SUCCESS) { goto cleanup; }

t_pow_z = BN_CTX_get(ctx);                                // :794
if (!t_pow_z) { goto cleanup; }                           // :798 — status is still ZKP_SUCCESS

status = ZKP_VERIFICATION_FAILED;                         // :802 — too late
```

`cleanup:` performs no fix-up; it is `drng_free / BN_CTX_end / BN_CTX_free / return status`.
`ZKP_SUCCESS == 0`, so the `goto` at `:798` returns "verified" having verified nothing —
skipping the compositeness test on `n`, both coprimality checks, proof deserialization, and
all 80 `t^{z_i} == A_i·s^{e_i}` equations.

The sibling implementation gets this right, which establishes it as an oversight rather than
a design choice — `damgard_fujisaki_zkp.c:535`:

```cpp
ret = init_damgard_fujisaki_param_zkp(&proof, ctx);
if (ret != ZKP_SUCCESS) { goto cleanup; }
ret = -1; // reset for OpenSSL errors      <-- the line ring_pedersen.c is missing
```

**Impact.** `cmp_setup_service.cpp:823` accepts the peer's ring-Pedersen `(N, s, t)` with no
proof that `s ∈ ⟨t⟩`. The honest party then uses those parameters *as prover* for every CMP
range proof, committing `S = s^x · t^μ` where `x` is its ECDSA key share
(`range_proofs.c:485`, reached via `mta.cpp:114-117`). Πprm is exactly what forbids `s` and
`t` from generating different subgroups; without it an attacker chooses `N = pq` with
`Z*_N ≅ G₁ × G₂`, `|G₁| = d` smooth, `s` generating `G₁` and `t` generating `G₂`. Then
`S^{ord(t)} = (s^{ord(t)})^x` and Pohlig–Hellman recovers `x`.

**Precondition (environmental).** `init_ring_pedersen_param_zkp` performs 160 `BN_CTX_get`
calls; `t_pow_z` is the 161st. Reaching the bug requires the allocator to fail on exactly
that call, which an attacker can only influence indirectly through memory pressure. This is
why the score is 6.8 rather than the ~9 its impact would otherwise warrant.

**Fix.**
```c
status = init_ring_pedersen_param_zkp(&proof, ctx);
if (status != ZKP_SUCCESS) { goto cleanup; }
status = ZKP_OUT_OF_MEMORY;   /* never leave SUCCESS latched across a fallible operation */
t_pow_z = BN_CTX_get(ctx);
if (!t_pow_z) { goto cleanup; }
status = ZKP_VERIFICATION_FAILED;
```
Additionally initialise `status = ZKP_VERIFICATION_FAILED` at `:768` so every path fails
closed by construction.

---

### Finding 3 — BAM key generation never binds the caller's `client_id` — **PoC**

**Location:** `src/common/cosigner/bam_ecdsa_cosigner_server.cpp:384-579`
**CVSS:** `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H` = 8.1 High · **VRT:** P1

`verify_client_proofs_and_decommit_share_with_proof()` accepts a `const uint64_t client_id`
and uses it **only inside `LOG_ERROR` format strings** — all twelve occurrences in the
function body. It never compares it against `server_key_metadata.peer_id`, which round 1
stored (`commit_to_share`, `:306`, via `bam_key_metadata_server(algorithm, setup_id,
client_id, expected_public_key)`).

The check exists everywhere else it is needed — `bam_ecdsa_cosigner_server.cpp:628` for
signing, and `bam_ecdsa_cosigner_client.cpp:104, 315, 489` on the client side:

```cpp
// bam_ecdsa_cosigner_server.cpp:628 — present for signing, absent for key generation
if (server_key_metadata.peer_id != client_id)
{
    LOG_ERROR("Wrong client id for key %s. %" PRIu64 " != %" PRIu64,
              key_id.c_str(), server_key_metadata.peer_id, client_id);
    throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
}
```

**Attack.** All Fiat-Shamir seed inputs are public:
`seed = SHA256("BAM ECDSA Key Generation AAD" ‖ key_id ‖ client_id ‖ server_id)`
(`bam_ecdsa_cosigner.cpp:61-70`). An attacker therefore computes the victim's seed, drives
its own local client library to produce a Damgård–Fujisaki key, share and Schnorr proof
under that seed, and submits round 2. Every proof verifies — they are all checked against
`server_key_metadata.seed`, never against the `client_id` argument.

Critically, **this works against a perfectly authenticating transport.** The attacker does
not spoof its identity: it presents its own true id, and the server accepts it as the
counterparty for someone else's key.

**Impact.** The server encrypts its share for the attacker, sets
`client_public_share = X_attacker`, stores `public_key = S + X_attacker`, backs the key up
and clears the in-progress flag. The intended client can never complete — the replay guard
at `:401` rejects any second round 2 — so the key is permanently unusable to it and any
funds sent to the derived address are unspendable. Where `client_id` is not derived from an
authenticated channel, this escalates to full signing control.

**Proof of concept.** `test/poc/poc_main.cpp::POC_01_bam_keygen_client_id_not_bound` drives a
real key generation through the project's own harness:

```
[PoC 1] stored peer_id ....... 45234523 (victim)
[PoC 1] submitted client_id .. 2809842689 (attacker)
[PoC 1] server accepted ...... YES  <-- VULNERABLE
[PoC 1] attacker completed keygen and holds the client share
[PoC 1] victim locked out by the replay guard: key is unusable to it
```

Adding the `:628` check to `:394` flips the result to `no (rejected)`, confirming the PoC
measures this specific defect.

**Fix.** Insert the `peer_id != client_id` check immediately after
`_key_persistency.load_key_metadata(key_id, server_key_metadata);` at `:394`.

**Related.** `include/cosigner/bam_key_persistency_structures.h:35,37` leave `seed` and
`peer_id` without default initializers, while every neighbouring field has one
(`public_key{0}`, `algorithm{-1}`, `ec_base{{0},{0}}`, `client_public_share{0}`). These two
are the highest-value fields in the struct — the Fiat-Shamir AAD and the only
anti-impersonation identifier — and they are exactly the residual defence this finding
relies on. Add `commitments_sha256_t seed {0};` and `uint64_t peer_id {0};`.

---

### Finding 4 — Heap out-of-bounds read in the legacy MtA Fiat-Shamir transcript

**Location:** `src/common/cosigner/mta.cpp:128-130`
**CVSS:** `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H` = 6.5 Medium · **VRT:** P2

```cpp
std::vector<uint8_t> n(BN_num_bytes(proof.A));
BN_bn2bin(proof.A, n.data());
SHA256_Update(&ctx, n.data(), BN_num_bytes(proof.S)); // right size of S is ensured during serialization
```

The buffer is sized by `A`; the read length comes from `S`. `S` is a ring-Pedersen
commitment modulo the **peer's** modulus (`mta.cpp:513`, using `other.ring_pedersen`), and
nothing enforces the comment's assumption. The same hashing pattern is implemented correctly
elsewhere in the tree — `range_proofs.c:130-141` computes
`max_size = MAX(BN_num_bytes(proof->D), BN_num_bytes(proof->S))` before allocating, under
the very same comment.

**Attack.** Register an oversized ring-Pedersen key at DKG (accepted — see Finding 5),
negotiate a protocol version below `MPC_EXTENDED_MTA` to select the legacy seed (see Finding
10), then send a normal round-1 MtA request. Every honest signer reads past the allocation,
twice per block, for up to `MAX_BLOCKS_TO_SIGN = 1000` blocks per request.

**Impact.** Remote, repeatable memory-safety violation in the signing hot path. This library
targets SGX enclaves, where a read into an unmapped EPC page aborts the enclave — a signing
denial of service. Adjacent heap bytes are folded into a SHA-256 challenge seed; no
practical disclosure path was demonstrated, so the score reflects availability only.

**Fix.** Size the buffer with `MAX` over every BIGNUM hashed, as `range_proofs.c` does; hash
`A` with `BN_num_bytes(proof.A)`. Better, delete the legacy path and always use
`generate_mta_range_zkp_extended_seed`.

---

### Finding 5 — Peer key sizes only lower-bounded, permanently bricking a wallet

**Location:** `src/common/cosigner/cmp_setup_service.cpp:631-635` and `:643-647`
**CVSS:** `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H` = 6.5 Medium · **VRT:** P2

```cpp
if (paillier_public_key_size(paillier.get()) < PAILLIER_KEY_SIZE)            { ...throw... }
if (ring_pedersen_public_size(ring_pedersen.get()) < RING_PEDERSEN_KEY_SIZE) { ...throw... }
```

Both are minimums. No maximum, no equality. A participant registering a Paillier key of any
size other than exactly 2048 bits passes DKG and every setup ZKP.

The mismatch surfaces later: `serialize_mta_range_zkp` is called by the **prover** with
`private_key = own, public_key = peer`, while `deserialize_mta_range_zkp` is called by the
**verifier** with `private_key = own, public_key = prover's` (`mta.cpp:971`, `:1579`) — the
two Paillier roles are swapped relative to serialization. This is invisible only because
every honest key is exactly 2048 bits.

**Impact.** Every MtA response involving that participant fails the header check at
`mta.cpp:271-288`. Because CMP enforces `t == n`, every signature requires that party, so
the wallet can never sign again and the victim cannot recover by excluding them. Permanent,
unrecoverable loss of access to custodied funds. This finding also supplies the precondition
for Finding 4.

**Fix.** Require exact sizes (`== PAILLIER_KEY_SIZE`, `== RING_PEDERSEN_KEY_SIZE`) or a
tight explicitly-supported range, and separately correct the swapped
`private_key`/`public_key` arguments so the encoding is role-correct.

---

### Finding 6 — Batch MtA verifier has ≈1 bit of soundness where 40 are intended

**Location:** `src/common/cosigner/mta.cpp:1250-1267`, `:1282-1307`; contrast `:1394`
**CVSS:** `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N` = 4.3 Medium · **VRT:** P4

```cpp
RAND_bytes(reinterpret_cast<uint8_t*>(&gamma[0]), 2 * sizeof(uint64_t));
gamma[0] &= 0xffffffffffULL; // 40bits
gamma[1] &= 0xffffffffffULL; // 40bits
```

The ring-Pedersen relation `s^{z1}·t^{z3} == E·S^e` is verified only in aggregated form,
`t^{Σγⱼ(λz1ⱼ+z3ⱼ)} == Πⱼ(Eⱼ·Sⱼ^{eⱼ})^{γⱼ}`. A small-exponent test has soundness error
`1/ℓ` against an injected element of order `ℓ`, and `−1 ∈ Z*_n` always has order 2.

**Attack.** A responder sending `E' = n − E`, everything else honest, is rejected
deterministically by the single-response verifier (`:1394`) but accepted by the batch
verifier whenever `γⱼ` is even — probability **1/2**. The batch path is selected
automatically at ≥ 6 blocks (`mta.h:135, 170`), i.e. in normal offline preprocessing.

**Honest limitation.** This was not converted into key extraction. A `−1` factor is
annihilated by Paillier decryption, and the security-critical bindings — the `z1`/`z2`
magnitude checks and `g^{z1} == Bx·X^e`, which pin the multiplier to the discrete log of the
peer's public share — are checked exactly and per-response. What is demonstrable is that the
batch verifier's actual statistical security is ~1 bit where the design intends ~40.

**Fix.** Widening `γ` **does not help** — only `γ mod 2` matters against an order-2 element.
Reject proof elements outside the correct subgroup (Jacobi symbol ≠ 1), or square the bases.

---

### Finding 7 — `~ecdsa_preprocessing_data` cleanses over its own members — **PoC**

**Location:** `include/cosigner/cmp_ecdsa_signing_service.h:85`
**CVSS:** `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H` = 6.5 Medium · **VRT:** P3

```cpp
struct ecdsa_preprocessing_data
{
    elliptic_curve_scalar k;   // first member
    ... gamma, a, b, delta, chi, GAMMA ...
    byte_vector_t mta_request;
    std::map<uint64_t, byte_vector_t> G_proofs;
    std::map<uint64_t, ecdsa_signing_public_data> public_data;
    ~ecdsa_preprocessing_data() {OPENSSL_cleanse(k.data, sizeof(ecdsa_preprocessing_data));}
};
```

`k` is the first member, so this zeroes `sizeof(struct)` bytes from offset 0 — straight over
a `byte_vector_t` and two `std::map`s — **before** their destructors run. On libstdc++,
`~_Rb_tree` then calls `_M_erase` on a nulled root and frees nothing; `~vector` sees a null
pointer and frees nothing. Every allocation the object owns is leaked, and the construct is
undefined behaviour.

**Impact.** One of these is constructed, populated and destroyed per block per round
(`cmp_ecdsa_offline_signing_service.cpp:70, 160, 224, 275`; `online:110`), leaking the K
ciphertext, `n−1` exponent-ZKPOK proofs and `n−1` gamma commitments each time. With
`MAX_BLOCKS_TO_SIGN = 1000` a single request leaks tens of megabytes; a peer that repeatedly
opens and abandons sessions drives unbounded growth in what is typically an enclave with a
small fixed heap. Requires no attacker to *occur* — only to be weaponised.

**Proof of concept.** `POC_02_preprocessing_data_dtor_leaks` uses an A/B heap measurement
rather than a sanitizer, so the result is unambiguous:

```
[PoC 2] 64 objects, ~17920 bytes of owned heap data each
[PoC 2] control (plain containers) heap growth ..... 0 bytes
[PoC 2] ecdsa_preprocessing_data  heap growth ..... 1222896 bytes  <-- VULNERABLE (leaked)
```

Changing `sizeof` to `offsetof(ecdsa_preprocessing_data, mta_request)` drops it to **0 bytes**.

**Fix.** `OPENSSL_cleanse(k.data, offsetof(ecdsa_preprocessing_data, mta_request));`, or
cleanse each scalar individually — `elliptic_curve_scalar` already self-cleanses
(`types.h:63`). Never pass `sizeof` of a class with non-trivial members.

---

### Finding 8 — Key refresh has no consistency or correctness verification

**Location:** `src/common/cosigner/cmp_offline_refresh_service.cpp:92-96`, `:200-205`
**CVSS:** `AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:H` = 6.8 Medium · **VRT:** P3

```cpp
if (encrypted_seeds.size() > metadata.n)   // upper bound ONLY — no equality, ack, or commitment
```

Each party sets `x_i' = x_i + Σ_{j∈S_i}(prf(s_{j→i}) − prf(s_{i→j}))`. The sum over parties
is invariant **only if participation is symmetric** (`j ∈ S_i ⟺ i ∈ S_j`). Nothing enforces
that: the participant set is never acknowledged, never committed, never compared. And unlike
`cmp_setup_service::verify_setup_proofs` (`:206-221`), which re-derives the public key from
the shares, no round proves the refreshed shares still reconstruct `metadata.public_key`.

**Attack.** A malicious party participating in a refresh over `{A, B, P}` sends its round
message to `A` but withholds it from `B`. `B` receives a 2-entry map, passes the bound check,
and refreshes without `P`'s terms while `P` applies its terms for `B`. The uncancelled
`prf(s_{B→P}) − prf(s_{P→B})` shifts the group secret from `x` to `x + Δ` while every party
still stores public key `g^x`. `refresh_key_fast_ack` then commits and overwrites the
backups.

**Impact.** Permanent key destruction. Because the offline signing path never verifies the
aggregated signature, the failure surfaces only as rejected transactions. `P` knows `Δ` but
not `x`, so this is destruction rather than theft.

**Fix.** Require `encrypted_seeds` keys to exactly equal the `players_ids` from the request;
include an ack/commitment over the participant set and `request_id` in the seeds; add a
verification round where each party publishes `g^{x_i'}` with a Schnorr proof and all parties
check `Σ g^{x_i'} == metadata.public_key` before `commit()`.

---

### Finding 9 — EdDSA `store_commitments` dereferences `map::end()`

**Location:** `src/common/cosigner/eddsa_online_signing_service.cpp:152-158`
**CVSS:** `AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H` = 5.3 Medium · **VRT:** P3

```cpp
auto my_commit = commitments.find(my_id);
assert(my_commit != commitments.end()); //should have been validated by the previous for loop
...
commitments_verify_commitment(..., &my_commit->second[i].data);
```

The cited "previous for loop" (`:134-141`) proves `signers_ids ⊆ commitments` — which says
nothing about `my_id` unless `my_id ∈ signers_ids`. Nothing establishes that: `start_signing`
accepts any `players_ids` with `size() >= metadata.t` where each id is in `players_info`
(`:50-63`), and **never checks the receiving node is among them**. `-DNDEBUG` is set for
every non-Debug configuration (`src/common/CMakeLists.txt:69`), so the `assert` is a no-op in
production.

**Impact.** An attacker requests signing on a `t < n` key with a `t`-subset excluding the
victim, then sends commitments keyed by exactly those ids. `find()` returns `end()`;
`my_commit->second` reads past the map's `_Rb_tree_header`, and `[i]` dereferences a garbage
vector pointer passed to `commitments_verify_commitment`. Remote crash of a signing node. Not
a memory *write*, so no code-execution claim is made.

`get_eddsa_signature` already performs exactly this check (`:331-335`), so the omission is an
inconsistency rather than a design decision.

**Fix.** Verify `players_ids` contains `_service.get_id_from_keyid(key_id)` in
`start_signing`, and replace the `assert` in `store_commitments` with a real throw. As
policy, no `assert()` should be the sole guard on a pointer or iterator derived from network
data.

---

### Finding 10 — Signing protocol version has no lower bound — **PoC**

**Location:** `src/common/cosigner/cmp_ecdsa_offline_signing_service.cpp:98-104`;
`cmp_ecdsa_online_signing_service.cpp:145-157`
**CVSS:** `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N` = 4.3 Medium · **VRT:** P4

```cpp
if ((uint32_t)version > metadata.version)
{
    LOG_FATAL("Min version %d is more than mpc version %d ", version, metadata.version);
    throw_cosigner_exception(cosigner_exception::INTERNAL_ERROR);
}
metadata.version = version;
```

Only the upper bound is checked. `metadata.version` starts at `MPC_PROTOCOL_VERSION` (13), so
any value in `[0, 13]` is accepted — including everything below
`MPC_MIN_SUPPORTED_PROTOCOL_VERSION` (2, defined at `mpc_globals.h:12` but never applied
here). Since `version` is the fleet minimum derived from peer-advertised versions, one
cosigner claiming to be an old client downgrades everyone.

Dropping below `MPC_EXTENDED_MTA` (11) flips two security switches: `strict_ciphertext_length`
becomes 0, so peer ciphertext lengths are no longer pinned to `|n²|`; and the legacy
Fiat-Shamir transcript is selected, which omits the ring-Pedersen and both Paillier moduli
from the challenge, hashes variable-length fields without separators, and contains the
out-of-bounds read of Finding 4.

**Proof of concept.** `POC_03_version_downgrade_has_no_floor` confirms versions 0, 1, 2 and
10 are all accepted. This asserts the guard's property directly rather than driving a full
preprocessing session, so it is a demonstration rather than an exploit.

**Fix.** Reject `version < MPC_EXTENDED_MTA`, or at minimum
`version < MPC_MIN_SUPPORTED_PROTOCOL_VERSION`, and remove the legacy paths.

---

### Finding 11 — Paillier-commitment key generation returns SUCCESS after a failed step

**Location:** `src/common/crypto/paillier_commitment/paillier_commitment.c:310-335`
**CVSS:** `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N` = 5.9 Medium · **VRT:** P4

`ret = paillier_commitment_init_montgomery(&priv->pub, ctx);` leaves `ret ==
PAILLIER_SUCCESS`; the subsequent `BN_mod_exp` and `BN_mod_exp_mont` failure branches
`goto cleanup` without setting it, and `cleanup:` only converts when `-1 == ret`. There is no
`ret = PAILLIER_SUCCESS;` on the success path — the function relies on the value latched by
the init call, making every intermediate `goto cleanup` a silent success.

**Impact.** The caller publishes a key in which `priv->pub.s` or `pub.rho` is still a
freshly-`BN_new()`ed zero. The commitment `C = sigma_0^v · rho^r mod N²` then loses hiding:
with `rho = 0`, `C = 0` regardless of `v`; with the `s = 0` variant, `sigma_0 = 1+N` so
`C = 1 + Nv mod N²` and any passive observer recovers `v = (C−1)/N`. Since `v` is the client's
partial-signature plaintext, this is a confidentiality break — though only reachable through
a local allocation failure during key generation, not remotely.

**Fix.** Set `ret = -1;` after the init call and `ret = PAILLIER_SUCCESS;` explicitly on the
success path. Additionally have `paillier_commitment_public_key_deserialize` reject `s`, `t`,
`rho` or `sigma_0` equal to zero and require `s, t < n`, so a degenerate key cannot be loaded
even if one is produced.

---

### Finding 12 — `damgard_fujisaki_verify_commitment_internal` leaves a `BN_CTX` frame open

**Location:** `src/common/crypto/commitments/damgard_fujisaki.c:264-270`
**CVSS:** `AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:L` = 4.2 Medium · **VRT:** P5

```cpp
BN_CTX_start(ctx);
expected_commitment = BN_CTX_get(ctx);
if (!expected_commitment)
{
    return RING_PEDERSEN_OUT_OF_MEMORY;   // no BN_CTX_end(ctx)
}
```

Every other exit goes through `cleanup:`/`BN_CTX_end(ctx)`. `ctx` is caller-owned and shared,
so the caller's own `BN_CTX_end()` pops this function's frame instead of its own, returning
live BIGNUMs to the pool while pointers to them remain in use — silent cross-aliasing of
cryptographic intermediates, and a possible double-release at `BN_CTX_free`. An
allocation-failure-only path with no demonstrated attacker-controlled outcome.

**Fix.** `ret = RING_PEDERSEN_OUT_OF_MEMORY; goto cleanup;`

The same defect exists at `range_proofs.c:2696-2702`
(`range_proof_paillier_large_factors_quadratic_verify_setup`).

---

## 4. Investigated and refuted

Recorded so the coverage is auditable — these looked like findings and are not:

- **Fiat-Shamir soundness across all six ZK proofs.** Each challenge hash was enumerated
  against its statement. All commitments and all prover-chosen statement elements are bound.
  The omission of the verifier's *own* moduli is safe because every verification equation is
  modulus-specific, so a transcript cannot transfer between key sets.
- **Range checks in every verifier.** Present, with constants matching the paper
  (`range_proofs.c:738, 1214, 1899, 2790, 3433, 3438`; `damgard_fujisaki_zkp.c:586`).
- **Damgård–Fujisaki subgroup attack.** A working attack exists on paper — grind `A_i` until
  all 17 challenges are even to smuggle an order-2 element past the parameter proof — but it
  is neutralised because `bam_ecdsa_cosigner_server.cpp:499` commits `x' = x + r·q` with fresh
  random `r`, so the recovered bit carries no information about the share. Worth hardening,
  since the safety property lives in the caller and is unenforced at the ZKP layer.
- **Degenerate ring-Pedersen parameters (`s = t = 1`).** Passes the parameter proof trivially
  but is self-harm: it only weakens the proof for the party that supplied them.
- **BAM identity point as client `X`.** `schnorr_zkp_verify` does accept the point at infinity
  (`SIZEOF_POINT` maps a `0x00` lead byte to a 1-byte encoding), and `X` is the one
  adversary-supplied point not passed through `check_a_valid_point`. No profitable attack
  follows — the resulting key is `g^{x_s}`, whose discrete log the client does not learn.
  Reported as missing hardening only.
- **`assert()` on wire-supplied lengths** in several deserializers. Debug builds only;
  `-DNDEBUG` is set for the default configuration and all paths degrade to a clean failure.
- **Nonce lifecycle in the asymmetric EdDSA and BAM flows.** Commit-then-reveal is genuinely
  enforced, commitments bind player id and slot index, and the load-and-delete contract is
  documented in those headers and honoured by the reference implementations.

## 5. Notes on severity

**CVSS Scope is the dominant variable.** All scores in §2 use `S:U`. If the compromised key
is treated as belonging to a different security authority than the cosigner process — the
natural reading for a custody library — findings 1 and 3 become
`AV:N/AC:L/PR:L/UI:N/S:C/…` = **9.6 Critical**, and 4, 5 and 7 become 7.7 High. Decide this
before quoting numbers; it is a 1.5-point swing on the two most serious items.

**Neither scale captures irreversibility.** Findings 5 and 8 permanently destroy a key with
no recovery path, and both land mid-table alongside recoverable crashes.

**Confidence is not uniform.** Findings 3, 7 and 10 have executable proofs with controlled
before/after validation. Findings 1, 2, 4, 5, 8, 9, 11 and 12 are code review with stated
preconditions and no PoC. Finding 6 is a demonstrable soundness degradation with no
demonstrated extraction. Finding 1 is simultaneously the most severe item here and the one
most likely to be dismissed in triage, because its precondition sits in integrator code — if
only one more PoC is built, it should be that one.

## 6. Reproducing the proofs of concept

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build --target poc_test -j"$(nproc)"
./build/test/poc/poc_test
```

`test/poc/poc_harness.inc` is extracted verbatim from `test/cosigner/bam_test.cpp` so the
protocol is driven exactly as the project's own tests drive it, with no PoC-specific shims.
The PoCs assert the *vulnerable* behaviour, so they pass on unpatched code and fail once the
corresponding fix is applied — that inversion is the validation.
