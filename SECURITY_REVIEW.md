# Security Review — mpc-lib — Bounty Submission Assessment

**Target:** `EthanYangTW/mpc-lib` (fork of `fireblocks/mpc-lib`)
**Commit:** `4e891c4`
**Date:** 2026-07-27
**Status:** post-adversarial-verification. Every finding below was re-checked by an
independent reviewer tasked with *refuting* it. Verdicts reflect what survived.

> **Handling.** Route through `SECURITY.md`, not a public issue or PR. Working exploit code
> for Finding 3 is in `test/poc/`.

---

## Bottom line for a bounty submission

**One finding is worth submitting with confidence. One more is worth submitting at low
severity. Everything else is informational or dead.**

| Tier | Findings | Recommendation |
|---|---|---|
| **Submit** | 3 | Unconditional, PoC'd, verified honest. This is the report. |
| **Submit, low** | 7, 8 | Real defects; 7 has a PoC, 8 is reachability-dependent |
| **Informational** | 1, 2, 4, 5, 6, 10, 11, 12 | Real code defects, but impact refuted, gated on uncontrollable conditions, or grants no capability |
| **Withdrawn** | 9 | Refuted outright |

The initial audit produced twelve findings. Adversarial verification confirmed **all twelve
as code defects with accurate line references and no misquotes**, but demolished the *impact*
claims on most of them. That gap — correct code reading, inflated consequence — is the
honest summary of where the first pass went wrong.

---

## TIER 1 — Submit

### Finding 3 — BAM key generation never binds the caller's `client_id`

**`src/common/cosigner/bam_ecdsa_cosigner_server.cpp:384-579`**
**CVSS** `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H` = **8.1 High** (7.1 if scored `I:L`; **9.6
Critical** under `S:C`) · **VRT** P1 · **Verified: defect CONFIRMED, impact CONFIRMED, PoC
judged honest**

`verify_client_proofs_and_decommit_share_with_proof()` accepts a `const uint64_t client_id`
and uses it at eleven sites — `:403, 415, 421, 433, 439, 451, 459, 481, 519, 549, 562` —
**every one inside a `LOG_ERROR` format string.** It is never compared to
`server_key_metadata.peer_id`, which round 1 stored (`commit_to_share`, `:306`).

The check exists everywhere else it is needed: `:628` for signing, and
`bam_ecdsa_cosigner_client.cpp:104, 315, 489` client-side.

```cpp
// bam_ecdsa_cosigner_server.cpp:628 — present for signing, absent for key generation
if (server_key_metadata.peer_id != client_id)
{
    LOG_ERROR("Wrong client id for key %s. %" PRIu64 " != %" PRIu64,
              key_id.c_str(), server_key_metadata.peer_id, client_id);
    throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
}
```

**No alternative binding exists.** The verifier checked each candidate:
- *Tenant* — `validate_tenant_id_setup` compares the setup's stored tenant to the **server's
  own** (`bam_ecdsa_cosigner.cpp:159-164`). Trivially true for any setup the server created.
  Says nothing about the caller.
- *Seed* — `SHA256(salt ‖ key_id ‖ client_id ‖ server_id)`, all inputs public. The server
  loads it from its own persistency and verifies the client's proofs against it, making it a
  public challenge string, not an authenticator.
- *Commitment `B`* — never enters the round-2 message; stored client-side only.
- *Persistency* — keyed by `key_id` alone.
- *Replay guard `:401`* — first-come-first-served, no identity.

**Attack.** The attacker computes the victim's seed from public values, produces its own
Damgård–Fujisaki key, share and Schnorr proof under it, and submits round 2 **under its own
true identity**. Every proof verifies. This works against a perfectly authenticating
transport — the attacker does not spoof anything.

**Impact — permanent key destruction.** The server encrypts its share for the attacker, sets
`client_public_share = X_attacker`, persists `public_key = S + X_attacker`, calls
`backup_key` and clears the in-progress flag. The victim can never complete (replay guard at
`:401`) and cannot decrypt the server share — it is encrypted under the *attacker's* DF key.
Any funds sent to the derived address are unspendable.

**Correction to the initial claim:** the attacker **cannot sign**. `:628` does check
`peer_id`, and `peer_id` remains the victim's. Signing capability follows only if the
attacker can additionally authenticate as the victim. Submit this as key destruction, not
theft — overclaiming here is the fastest way to lose triage credibility.

**Preconditions:** reach the keygen round-2 endpoint; know the victim's `key_id` (a UUID that
appears in logs and orchestration APIs — not a secret); win the race before the victim's
round 2. Nothing else.

**Why it should pay.** The same library performs this exact check at signing time and three
times on the client. It is an oversight, not a trust assumption — and it survived review
precisely because the parameter *is* used, in a log string, so `-Wunused-parameter` never
fired.

**PoC** — `test/poc/poc_main.cpp::POC_01`:
```
[PoC 1] stored peer_id ....... 45234523 (victim)
[PoC 1] submitted client_id .. 2809842689 (attacker)
[PoC 1] server accepted ...... YES  <-- VULNERABLE
[PoC 1] victim locked out by the replay guard: key is unusable to it
```
Adding the `:628` check at `:394` flips it to `no (rejected)`. The verifier confirmed the PoC
does not cheat: the attacker uses a separate `TestSetup`, never touches `victim.client`, and
passes the victim's id only to its own local library — which a real attacker would replace
with a direct SHA-256.

**Fix.** Insert the `peer_id != client_id` check after `load_key_metadata` at `:394`.

**Related hardening.** `include/cosigner/bam_key_persistency_structures.h:35,37` leave `seed`
and `peer_id` uninitialised while every neighbouring field has a default. These are the two
highest-value fields in the struct.

---

## TIER 2 — Submit at low severity

### Finding 7 — `~ecdsa_preprocessing_data` cleanses over its own members

**`include/cosigner/cmp_ecdsa_signing_service.h:85`**
**CVSS** `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L` = **5.3 Medium** · **VRT** P4
**Verified: defect CONFIRMED (layout measured), impact PARTIAL, PoC honest but synthetic**

```cpp
~ecdsa_preprocessing_data() {OPENSSL_cleanse(k.data, sizeof(ecdsa_preprocessing_data));}
```

Measured layout: `sizeof=352`, `mta_request` at 232, `G_proofs` at 256, `public_data` at 304.
The cleanse covers all three containers entirely, zeroing `vector::_M_start` and both
`_Rb_tree` headers **before** the member destructors run. libstdc++ then frees nothing —
`_M_deallocate` is guarded by `if (__p)` and `~_Rb_tree` returns immediately on a null root.
Deterministic leak, formally UB.

**Correction to the initial claim — the leak is bounded, not catastrophic.**
`cmp_ecdsa_signing_service.cpp` calls `clear()` at `:106`, `:195`, `:254`, so on the happy
path most map nodes are freed normally. But `vector::clear()` does not release capacity, so
`mta_request`'s buffer leaks **unconditionally**, and any object destroyed while still
populated — every short-lived local in the `create_mta_request` / `create_mta_response` /
`verify_block_and_get_delta` loops — leaks in full. Bounded per operation, unbounded over
process lifetime. My earlier "tens of megabytes per request" figure was wrong.

**PoC** — `POC_02` measures 1,222,896 bytes retained across 64 objects vs **0 bytes** for
identical containers destroyed normally; the fix drops it to 0. The verifier judged the A/B
fair but noted it fabricates container contents rather than driving a real preprocessing
round, so it demonstrates the destructor's property, not the production leak rate. Disclose
that when submitting.

**Fix.** `OPENSSL_cleanse(k.data, offsetof(ecdsa_preprocessing_data, mta_request));`

### Finding 8 — Key refresh has no consistency or correctness verification

**`src/common/cosigner/cmp_offline_refresh_service.cpp:92-96`**
**CVSS** `AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:H` = **6.8 Medium** · **VRT** P3
**Verified: defect CONFIRMED, impact PARTIAL — reachability is integrator-dependent**

`if (encrypted_seeds.size() > metadata.n)` — upper bound only. Each party computes
`x'_P = x_P + Σ_{j∈S_P}[prf(s_{j→P}) − prf(s_{P→j})]`, which is sum-invariant **only if the
participation relation is symmetric**. Nothing enforces symmetry: the participant set is
never acked, never committed, never compared. Unlike `cmp_setup_service.cpp:206-221`, no
round proves the refreshed shares still reconstruct `metadata.public_key`.

The verifier found two supporting defects worth including in the submission:
- `validate_prfs_sizes` (`:77-84`) **can never fire** — both vectors are `push_back`-ed in
  the same loop iteration, so their sizes are equal by construction.
- The refresh test's public-key assertion (`test/cosigner/ecdsa_offline_test.cpp:474`) is
  **vacuous** — it compares the stored value to itself, because `refresh_key:204` copies
  `metadata.public_key` straight back out.

**Best framing for submission:** this is equally triggerable by a **non-malicious network
partition or orchestration bug**. A library that verifies ZK proofs from peers everywhere
else should not silently and irrecoverably destroy a key on a delivery inconsistency —
`refresh_key_fast_ack` backs up the already-broken share after `commit()`.

**Expect pushback** that the orchestration layer is contractually required to fan out one
identical matrix (which the reference test does). The counter is that the library uses `>`
rather than `==`, deliberately accepting partial participant sets that are only safe under a
symmetry it never verifies.

---

## TIER 3 — Informational, do not submit as vulnerabilities

Real code defects with accurate line references. Each has its impact claim refuted or its
trigger placed outside attacker control. Submitting these as vulnerabilities will cost
credibility on Finding 3.

| # | Location | Defect | Why it does not land |
|---|---|---|---|
| 1 | `eddsa_online_signing_service.cpp:254` | No round-ordering guard; `:158` is a self-consistency check, not authentication; `k` survives into a second `broadcast_si` | Gated on integrator persistency accepting a second `store_signing_commitments`. The library's **own test asserts this must throw** (`eddsa_online_test.cpp:198`). **My stated root cause was wrong**: `R_me` is broadcast in round 2 regardless and the commitment salt is attacker-chosen, so removing the `:254` overwrite does not stop the attack |
| 2 | `ring_pedersen.c:787-800` | Verifier returns `ZKP_SUCCESS` on the `BN_CTX_get` failure path, skipping all 80 equations. Sibling `damgard_fujisaki_zkp.c:535` has the missing `ret = -1` | Crypto chain **is** real and unmasked (`bn_randomize_with_factor` is BAM-only, not CMP), but the trigger is one specific `OPENSSL_malloc` failure at the 161st `BN_CTX_get`. Not attacker-influenced, not remotely inducible |
| 4 | `mta.cpp:128-130` | Buffer sized by `BN_num_bytes(proof.A)`, read length `BN_num_bytes(proof.S)` | Needs RP modulus **> ~4096 bits** (2× Paillier) **and** negotiated version **< 11**. Prover-side only — the verify side uses its own 1024-bit key. No disclosure: the bytes feed only a SHA-256 seed |
| 5 | `cmp_setup_service.cpp:631,643` | Sizes lower-bounded only; `serialize`/`deserialize` Paillier args transposed (`mta.cpp:971,1579`), plus a third symptom at `:308` | **Grants zero new capability.** CMP enforces `t == n`, so the "attacker" is a mandatory signer who can already brick the wallet by declining to sign. Self-DoS with extra steps. Real cost is an upgradability lock-in and a silent trap for a misconfigured honest party |
| 6 | `mta.cpp:1261-1267` | Batch ring-Pedersen check uses one accumulator with one 40-bit γ; `E' = n − E` passes with probability 1/2 where the single verifier rejects it deterministically | **Impact refuted.** `−E` is a *legitimate* commitment — the prover gains a proof it already had. The only constructible order-2 element is `−1`; `±w` requires factoring the modulus. Verifier-equivalence hygiene, not a soundness break. (The Paillier half of the same batch uses 5 accumulators — that asymmetry is the real smell) |
| 10 | `cmp_ecdsa_offline_signing_service.cpp:98` | Upper bound only; `[0,13]` accepted. **`MPC_MIN_SUPPORTED_PROTOCOL_VERSION` is referenced nowhere in the codebase except its own definition** — a floor was intended and never implemented | Exploitability depends entirely on how the integrator derives `version`. My PoC 3 was **tautological** — it reimplemented the guard as a lambda and asserted the lambda behaves like itself, never touching library code. Being removed |
| 11 | `paillier_commitment.c:310-335` | No `ret = PAILLIER_SUCCESS` on the success path; intermediate `goto cleanup` returns latched success | **My impact claim contained an algebra error.** With `s == 0`, `sigma_0 = (1+N)·0^N = 0`, **not** `1+N` — so an observer learns one bit ("is v zero"), not `v`. Neutralised twice over: the reduced-form serialization omits `rho`/`sigma_0` and the client recomputes them, and the client's DF parameter proof rejects `s == 0` |
| 12 | `damgard_fujisaki.c:264-270` | One exit skips `BN_CTX_end` | **Mechanism runs backwards.** A *surplus* `BN_CTX_start` holds BIGNUMs longer, never releases them early — premature release requires *more* ends than starts. And the ctx is not shared: the sole caller (`range_proofs.c:3521`) owns it and frees it one line later |

---

## WITHDRAWN

### Finding 9 — EdDSA `store_commitments` dereferences `map::end()` — **REFUTED**

`t != n` is rejected at every public key-creation entry point —
`cmp_setup_service.cpp:62, :355, :446`, all logging *"CMP protocol doesn't support threshold
signatures"*. The only unchecked overload is `private:` and reachable solely from those three.
So `players_ids == players_info` always, a `t`-subset excluding the victim is arithmetically
impossible, and `commitments.find(my_id)` can never return `end()`. The `assert` is genuinely
redundant, exactly as its trailing comment claims. The original claim never checked whether
`t < n` was reachable. It is not.

---

## Also refuted during the initial audit

Recorded so coverage is auditable: Fiat-Shamir binding across all six ZK proofs (complete);
range checks in every verifier (present, constants correct); the Damgård–Fujisaki subgroup
attack (works on paper, neutralised by `bn_randomize_with_factor` masking in the BAM caller);
degenerate ring-Pedersen parameters (self-harm only); the BAM identity-point Schnorr
acceptance (no profitable attack); `assert()` on wire lengths (Debug builds only); nonce
lifecycle in the asymmetric EdDSA and BAM flows (commit-then-reveal genuinely enforced).

---

## Submission advice

**Lead with Finding 3 alone.** It is unconditional, PoC'd, independently verified as honest,
and the missing check demonstrably exists four times elsewhere in the same library. Attach
Findings 7 and 8 as secondary items. Everything in Tier 3 belongs in a "hardening notes"
appendix at most.

**Two scoring decisions to settle before submitting.** CVSS Scope moves Finding 3 between 8.1
and 9.6 — `S:C` is defensible for a custody library, since the impacted resource sits outside
the vulnerable component's security authority, but expect the vendor to argue `S:U`. And
neither CVSS nor VRT captures irreversibility: Findings 3 and 8 destroy a key permanently.

**Anticipate the "requires an authenticated participant" objection.** For an MPC library that
objection is invalid — mutual distrust between participants is the entire premise. Say so
explicitly and early.

## Reproducing

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build --target poc_test -j"$(nproc)"
./build/test/poc/poc_test
```

`test/poc/poc_harness.inc` is extracted verbatim from `test/cosigner/bam_test.cpp`, so the
protocol is driven exactly as the project's own tests drive it. The PoCs assert the
*vulnerable* behaviour: they pass on unpatched code and fail once the fix is applied — that
inversion is the validation.
