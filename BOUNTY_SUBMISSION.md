# Missing counterparty identity check in BAM ECDSA key generation permits key-generation hijack

**Component:** `mpc-lib` — MPC-BAM ECDSA key generation, server side
**File:** `src/common/cosigner/bam_ecdsa_cosigner_server.cpp`, function
`bam_ecdsa_cosigner_server::verify_client_proofs_and_decommit_share_with_proof` (lines 384–579)
**Version:** commit `4e891c4` (verified byte-identical to `fireblocks/mpc-lib@main` at time of testing)
**Severity:** High — CVSS 3.1 **8.1** (`AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H`); see *Severity* below
**Classification:** Broken Authentication → Authentication Bypass (Bugcrowd VRT **P1**)
**Status:** Reproducible. Working proof of concept included.

---

## Summary

The second round of BAM ECDSA key generation accepts a `client_id` parameter identifying the
calling party, but never compares it against the `peer_id` recorded for that key during round 1.
The parameter is used only inside log messages.

As a result, **any party able to reach the key-generation endpoint can complete round 2 for a key
that was opened for a different client.** The server accepts the impostor's key share, persists a
public key derived from it, backs the key up, and marks generation complete. The legitimate client
can never complete generation and can never use the key. Funds sent to the resulting address are
permanently unspendable.

The attacker does **not** need to spoof its identity. It authenticates truthfully as itself and the
server accepts it anyway, so transport-level authentication does not mitigate this.

---

## Technical detail

### The missing check

`verify_client_proofs_and_decommit_share_with_proof` accepts the caller's identity:

```cpp
// src/common/cosigner/bam_ecdsa_cosigner_server.cpp:384
void bam_ecdsa_cosigner_server::verify_client_proofs_and_decommit_share_with_proof(
        const std::string& key_id,
        const uint64_t client_id,
        const client_key_shared_data& client_message,
        server_key_shared_data& server_message)
{
    ...
    _key_persistency.load_key_metadata(key_id, server_key_metadata);
    validate_tenant_id_setup(server_key_metadata.setup_id);
    ...
```

Within the 195-line body, `client_id` occurs at lines 403, 415, 421, 433, 439, 451, 459, 481, 519,
549 and 562 — **every occurrence is inside a `LOG_ERROR` format string.** It is never compared to
anything.

Round 1 stored the expected value for exactly this purpose:

```cpp
// src/common/cosigner/bam_ecdsa_cosigner_server.cpp:306  (commit_to_share)
bam_key_metadata_server server_key_metadata(algorithm, setup_id, client_id, expected_public_key);
```
```cpp
// include/cosigner/bam_key_persistency_structures.h:37
uint64_t peer_id;   // server id for the client and client id for the server
```

The check exists in four other places in the same library. Server side, for signing:

```cpp
// src/common/cosigner/bam_ecdsa_cosigner_server.cpp:628
if (server_key_metadata.peer_id != client_id)
{
    LOG_ERROR("Wrong client id for key %s. %" PRIu64 " != %" PRIu64,
              key_id.c_str(), server_key_metadata.peer_id, client_id);
    throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
}
```

and client side at `bam_ecdsa_cosigner_client.cpp:104`, `:315`, `:489`. In the whole server file,
`peer_id` is compared exactly once — at line 628. Key generation has no equivalent.

### No alternative binding exists

Each candidate was checked and none constrains the caller:

| Mechanism | Why it does not bind the caller |
|---|---|
| `validate_tenant_id_setup` | Loads the tenant stored *with the setup* and compares it to the **server's own** `get_current_tenantid()` (`bam_ecdsa_cosigner.cpp:159-164`). Trivially true for any setup the server created. |
| Fiat-Shamir seed | `SHA256(salt ‖ key_id ‖ client_id ‖ server_id)` (`bam_ecdsa_cosigner.cpp:61-70`). All inputs public. The server loads it from its own persistency and verifies the client's proofs against it, making it a public challenge string — anyone can produce valid proofs under it. |
| Commitment `B` | Never appears in the round-2 message; stored client-side only, for the client's own later decommitment check. |
| Persistency lookup | Keyed by `key_id` alone. |
| Replay guard (`:401`) | Fires on `encrypted_server_share` being non-empty — first-come-first-served, no identity component. |

### Attack

Key `K` is opened for victim client `A`. The server has stored `peer_id = A` and
`seed = SHA256(salt ‖ K ‖ A ‖ server_id)`.

1. Attacker `B` computes that seed. All four inputs are public — `key_id` is a UUID that appears in
   logs and orchestration APIs, not a secret.
2. `B` generates its own Damgård–Fujisaki key with a valid parameters proof under that seed, its own
   share `x_B`, `X_B = g^{x_B}`, and a valid Schnorr proof under that seed.
3. `B` calls `verify_client_proofs_and_decommit_share_with_proof(K, B, message_B, …)` — submitting
   under its **own true identity**.
4. Every verification passes; all are checked against `server_key_metadata.seed`, never against
   `client_id`. The server encrypts its share for `B`, decommits `server_public_share`, sets
   `client_public_share = X_B`, stores `public_key = S + X_B`, calls `backup_key`, and calls
   `clear_key_setup_in_progress(K)`.

### Impact

**Permanent, unrecoverable key destruction.**

- The victim `A` can never complete round 2 — the replay guard at `:401` rejects it.
- `A` cannot decrypt the server share: it is encrypted under **`B`'s** Damgård–Fujisaki key.
- The server considers `K` complete and has already backed it up, with a deposit address
  `g^{x_s + x_B}` for which `A` holds nothing usable.
- Any funds sent to that address are unspendable.

**The attacker cannot sign.** Stated explicitly because it bounds the impact: the signing path *does*
check `peer_id != client_id` at `:628`, and `peer_id` remains `A`. `B` holds a share it cannot use
unless it can *additionally* authenticate as `A`. This is a destruction and integrity issue, not
key theft.

### Preconditions

- Ability to reach the server's key-generation round-2 entry point.
- Knowledge of the victim's `key_id` (a UUID; not secret).
- Winning the race against the victim's own round 2.

No knowledge of the victim's share, identity credentials, or the round-1 commitment `B` is required.

---

## Reproduction

A proof of concept is included at `test/poc/`. Its harness (`poc_harness.inc`) is extracted verbatim
from the project's own `test/cosigner/bam_test.cpp`, so the protocol is driven exactly as the
existing tests drive it, with no test-specific shims.

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build --target poc_test -j"$(nproc)"
./build/test/poc/poc_test
```

`POC_01_bam_keygen_client_id_not_bound` runs a complete key generation: the server opens key `K` for
the victim, then a separate attacker instance — its own client, its own persistency — submits round 2
under attacker id `0xA77ACC01`.

Observed output:

```
[PoC 1] key_id ............... f32b2f61-a152-4e63-8aad-89c311675945
[PoC 1] stored peer_id ....... 45234523 (victim)
[PoC 1] submitted client_id .. 2809842689 (attacker)
[PoC 1] server accepted ...... YES  <-- VULNERABLE
[PoC 1] attacker completed keygen and holds the client share
[PoC 1] victim locked out by the replay guard: key is unusable to it
```

The PoC also asserts `attacker_message.X != victim_message.X`, confirming a genuinely different share
was accepted, and asserts that the victim's subsequent legitimate round 2 throws.

**Controlled validation.** Applying the fix below and rebuilding changes the outcome to
`server accepted ...... no (rejected)`, confirming the PoC exercises this specific missing check and
not an unrelated condition. The project's full test suite passes with the fix applied
(`cosigner_test`: 11,051 assertions across 10 test cases, exit 0), showing the check is not
load-bearing for any legitimate flow.

---

## Remediation

Insert the existing check — identical to line 628 — immediately after the metadata load at line 394:

```cpp
_key_persistency.load_key_metadata(key_id, server_key_metadata);

if (server_key_metadata.peer_id != client_id)
{
    LOG_ERROR("Wrong client id for key %s. %" PRIu64 " != %" PRIu64,
              key_id.c_str(), server_key_metadata.peer_id, client_id);
    throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
}

validate_tenant_id_setup(server_key_metadata.setup_id);
```

**Related hardening.** `include/cosigner/bam_key_persistency_structures.h:35,37` leave `seed` and
`peer_id` without default initialisers, while every neighbouring field has one
(`key_metadata_base::public_key{0}`, `algorithm{-1}`, `bam_setup_metadata_base::ec_base{{0},{0}}`,
`bam_key_metadata_server::client_public_share{0}`). These two are the Fiat-Shamir AAD and the only
anti-impersonation identifier — the exact fields this issue depends on. Suggest
`commitments_sha256_t seed {0};` and `uint64_t peer_id {0};`.

---

## Severity

| Vector | Score |
|---|---|
| `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H` | 8.1 High |
| `AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:H/A:H` | 9.6 Critical |

`S:C` is arguable for a custody library, where the impacted resource sits outside the vulnerable
component's own security authority. The `S:U` figure is quoted as the headline to stay conservative.
Scoring `I:L` instead of `I:H`, on the grounds that no signing capability follows, yields 7.1.

Two notes on the rating. Neither CVSS nor VRT captures **irreversibility**: this destroys a key
permanently, with no recovery path, which is not distinguishable in either scale from a recoverable
fault. And `PR:L` reflects that the attacker must be a protocol participant — for an MPC library,
mutual distrust between participants is the entire premise of the design, so this is the intended
threat model rather than a mitigating factor.

---

## Why this survived review

Offered because it explains how a careful team missed it, and why similar code may be worth auditing:

- The parameter **is** used — in a log string — so `-Wunused-parameter` never fires. A genuinely dead
  parameter would have been caught by the compiler.
- The function's name promises *"verify client proofs,"* and it does so thoroughly: Damgård–Fujisaki
  parameters, Schnorr proof, algorithm match, replay guard. It verifies that the proofs are valid.
  It never verifies *whose* they are.

---

## Secondary findings

Reported for completeness; both are lower severity and neither is the basis of this submission.

### S1 — `~ecdsa_preprocessing_data` cleanses over its own non-trivial members

`include/cosigner/cmp_ecdsa_signing_service.h:85`

```cpp
~ecdsa_preprocessing_data() {OPENSSL_cleanse(k.data, sizeof(ecdsa_preprocessing_data));}
```

`k` is the first member, so this zeroes `sizeof(struct)` bytes from offset 0. Measured layout:
`sizeof = 352`, `mta_request` at 232, `G_proofs` at 256, `public_data` at 304 — the cleanse covers a
`byte_vector_t` and two `std::map`s entirely, nulling `vector::_M_start` and both `_Rb_tree` headers
**before** their destructors run. libstdc++ then frees nothing: `_M_deallocate` is guarded by
`if (__p)` and `~_Rb_tree` returns immediately on a null root. Formally undefined behaviour;
practically a deterministic leak.

Mid-protocol `clear()` calls at `cmp_ecdsa_signing_service.cpp:106, 195, 254` bound this on the happy
path, but `vector::clear()` does not release capacity, so `mta_request`'s buffer leaks
unconditionally, and any instance destroyed while still populated leaks in full. Bounded per
operation, unbounded over process lifetime — relevant for a long-running signer with a fixed heap.

`POC_02` measures 1,222,896 bytes retained across 64 instances versus **0 bytes** for identical
containers destroyed normally. Note this PoC populates the containers synthetically rather than
driving a real preprocessing round, so it demonstrates the destructor's property, not a production
leak rate.

Fix: `OPENSSL_cleanse(k.data, offsetof(ecdsa_preprocessing_data, mta_request));`

### S2 — Key refresh performs no participant-set or correctness verification

`src/common/cosigner/cmp_offline_refresh_service.cpp:92`

`if (encrypted_seeds.size() > metadata.n)` is an upper bound only. Each party computes
`x'_P = x_P + Σ_{j∈S_P}[prf(s_{j→P}) − prf(s_{P→j})]`, which preserves the group secret **only if the
participation relation is symmetric**. The participant set is never acknowledged, committed, or
compared, and — unlike `cmp_setup_service.cpp:206-221` — no round verifies that the refreshed shares
still reconstruct `metadata.public_key`. An asymmetric delivery shifts the secret to `x + Δ` while
every party retains public key `g^x`; `refresh_key_fast_ack` then commits and overwrites the backups.

Two related defects: `validate_prfs_sizes` (`:77-84`) can never fire, because both vectors are
`push_back`-ed in the same loop iteration; and the refresh test's public-key assertion
(`test/cosigner/ecdsa_offline_test.cpp:474`) is vacuous, comparing the stored value to itself because
`refresh_key:204` copies `metadata.public_key` straight back out.

This is reachable through a **non-malicious** network partition or orchestration bug as readily as
through an attacker, which is arguably the more compelling framing: a library that verifies ZK proofs
from peers everywhere else should not silently and irrecoverably destroy a key on a delivery
inconsistency.

---

## Disclosure

Reported privately under the process in `SECURITY.md`. No public disclosure, and no publication of
the proof-of-concept code, pending vendor response and a fix. Happy to supply additional detail,
adjust severity scoring, or re-test a candidate patch on request.
