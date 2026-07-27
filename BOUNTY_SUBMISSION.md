# mpc-lib — Vulnerability Reports

**Target:** `fireblocks/mpc-lib` · **Commit tested:** `4e891c4` (verified byte-identical to `main`)
**Channel:** HackerOne `fireblocks_mpc`, per `SECURITY.md`
**Date:** 2026-07-27

Three separate reports. File them individually — they are distinct defects with distinct fixes.

| # | Report | Severity | Evidence |
|---|---|---|---|
| 1 | BAM server never binds the caller to `key_id` or `client_id` | **High**, CVSS 8.1 | PoC, two attack paths |
| 2 | Destructive load precedes the identity check when finalising a signature | **Medium**, CVSS 6.5 | source-verified |
| 3 | `ring_pedersen_parameters_zkp_verify` can return SUCCESS having verified nothing | **Medium** (impact: critical) | PoC, incl. key recovery |

Build and run all proofs:
```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build -j"$(nproc)"
./build/test/poc/poc_test                            # reports 1
./build/test/poc/poc_ring_pedersen_failopen          # report 3, the fail-open
./build/test/poc/poc_ring_pedersen_trapdoor          # report 3, the key recovery
./build/test/poc/poc_ring_pedersen_oom_grooming      # report 3, negative result
```

---

# Report 1 — The BAM server never binds the caller to the key it is operating on

**Files:** `src/common/cosigner/bam_ecdsa_cosigner_server.cpp` — `commit_to_share` (:291), `verify_client_proofs_and_decommit_share_with_proof` (:384)
**CVSS 3.1:** `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H` = **8.1 High**
**Escalates to fund theft** where the host allows attacker-influenced `key_id`s — see *Escalation*.

## Summary

Of five public entry points on `bam_ecdsa_cosigner_server` that touch a key, **exactly one** checks that
the caller is the party the key belongs to. Both key-generation rounds accept `key_id` and `client_id`
as unvalidated parameters.

| Entry point | Binds caller? |
|---|---|
| `generate_setup_with_proof` (:41) | no |
| `generate_share_and_commit` → `commit_to_share` (:291) | **no** |
| `verify_client_proofs_and_decommit_share_with_proof` (:384) | **no** |
| `generate_signature_share` (:581) | yes — `:628` |
| `verify_partial_signature_and_output_signature` (:675) | yes — `:694`, but see Report 2 |
| `get_public_key` (:930) | no, and no tenant check either |

By contrast the client side binds its peer consistently (`bam_ecdsa_cosigner_client.cpp:104`, `:315`,
`:489`). BAM also makes **zero** calls to `platform_service::get_id_from_keyid`, against 26 across the
CMP and EdDSA services, and the client explicitly discards its own identity with `(void)client_id;` at
`bam_ecdsa_cosigner_client.cpp:313`. This is a systemic pattern, not a single slip.

## Path A — round-2 hijack (permanent key destruction)

`verify_client_proofs_and_decommit_share_with_proof` accepts `client_id` and uses it at eleven sites —
`:403, 415, 421, 433, 439, 451, 459, 481, 519, 549, 562` — **every one inside a `LOG_ERROR` format
string.** It is never compared to `server_key_metadata.peer_id`, which round 1 stored at `:306`.

The check exists at `:628` for signing:

```cpp
if (server_key_metadata.peer_id != client_id)
{
    LOG_ERROR("Wrong client id for key %s. %" PRIu64 " != %" PRIu64,
              key_id.c_str(), server_key_metadata.peer_id, client_id);
    throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
}
```

All Fiat-Shamir seed inputs are public — `SHA256(salt ‖ key_id ‖ client_id ‖ server_id)`
(`bam_ecdsa_cosigner.cpp:61-70`) — so an attacker computes the victim's seed, produces its own
Damgård–Fujisaki key, share and Schnorr proof under it, and submits round 2 **under its own true
identity**. Everything verifies. The server encrypts its share for the attacker, sets
`client_public_share = X_attacker`, stores `public_key = S + X_attacker`, calls `backup_key`, and calls
`clear_key_setup_in_progress` — affirmatively reporting the key healthy.

The victim can never complete (replay guard, `:401`) and cannot decrypt the server share, which is
bound to the attacker's Damgård–Fujisaki key. `get_public_key` (:930) then serves the address with no
client involvement and no tenant check. Nothing anywhere reconciles `client_public_share` against what
the real client holds; the divergence surfaces only at first signing, and **only on the client** — the
server never learns.

**Bound on Path A, tested not assumed:** the attacker cannot sign (`:628` still holds `peer_id` = victim),
and cannot learn the server's share — it is encrypted under the server's own `paillier_commitment` key,
as the code states at `:490`: *"The client never sees x' … so it cannot reduce mod q to recover x."*

```
[PoC 1] stored peer_id ....... 45234523 (victim)
[PoC 1] submitted client_id .. 2809842689 (attacker)
[PoC 1] server accepted ...... YES  <-- VULNERABLE
[PoC 1] victim locked out by the replay guard: key is unusable to it
[PoC 1] attacker can then sign ... no (blocked by the peer_id check at :628)
```

## Path B — round-1 pre-emption (a fully signable attacker-controlled key)

`commit_to_share` has one identity check in its entire body:

```cpp
// bam_ecdsa_cosigner_server.cpp:300
if (client_id == server_id) { ...throw... }
```

It then stores `peer_id = client_id` at `:306`. **A party that reaches round 1 first becomes the
legitimate `peer_id`** — so round 2 passes honestly and `:628` passes too. The attacker ends up with a
fully signable key at a `key_id` of its own choosing, and that `key_id` is then permanently unavailable
to its intended owner.

```
[PoC 4] attacker-chosen key_id ... a390604e-b594-4755-b780-617f3f47f63d
[PoC 4] keygen as attacker ....... completed (peer_id is now the attacker)
[PoC 4] attacker produced a VALID signature under that key_id  <-- not merely destruction
[PoC 4] legitimate owner can still claim that key_id ... no (key_id permanently taken)
```

The signature is verified against the derived public key by the project's own `verify_ecdsa_signature`.

**This is why fixing `:384` alone does not fix the class.** With a `peer_id` check added to round 2, an
attacker that pre-empts round 1 still owns the key outright.

The tenant check does not constrain Path B. `validate_tenant_id_setup` (`bam_ecdsa_cosigner.cpp:159-164`)
compares the **setup's** stored tenant against the current context — and in Path B the attacker supplies
its *own* `setup_id`, so the comparison is between its own tenant and itself. Structurally, BAM binds
tenants to *setups*, never to *keys*: `cmp_key_persistency.h` provides `key_exist` (:51) and
`get_tenantid_from_keyid` (:54); `bam_key_persistency_common.h` provides **neither**. The library cannot
ask who owns a key, or whether a key already exists.

## Escalation

Path B converts to **fund theft** if an attacker can claim a `key_id` the platform later attributes to a
customer: the attacker holds a signable key at that identifier, and `get_public_key` serves its address.
Whether that is reachable depends on host-side `key_id` allocation, which I cannot see. I found no
`key_id` derivation, sequencing, or disclosure inside the library — it is caller-supplied throughout,
never echoed in any wire struct, and enters the protocol only SHA-256'd into the seed. **The separation
between "attacker's key" and "customer's key" therefore rests entirely on host-side `key_id` allocation,
with no library-side defence.** Similarly, whether Path B can clobber an *existing funded* key depends
solely on the host implementing `store_key_metadata(..., overwrite=false)` as a hard reject — the library
never checks, `store_key` has no overwrite parameter at all, and BAM has no `key_exist` to call.

## Remediation

1. `:394` — add the `:628` check to round 2.
2. `:300` — bind the caller in round 1: verify the caller is entitled to both `client_id` and `key_id`
   before `store_key_metadata`.
3. Add `key_exist()` and a key→tenant lookup to `bam_key_persistency_common`, and bind the tenant check
   to the *key* rather than the setup, as CMP does.
4. `bam_key_persistency_structures.h:35,37` — `seed` and `peer_id` have no default initialisers while
   every neighbouring field does. `peer_id` carries the sole remaining defence at `:628`.

---

# Report 2 — Signing state is destroyed before the caller's identity is checked

**File:** `src/common/cosigner/bam_ecdsa_cosigner_server.cpp:686` vs `:694`
**CVSS 3.1:** `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H` = **6.5 Medium**
**Evidence:** source-verified; not proven by execution.

```cpp
auto server_signature_data_ptr = _tx_persistency.load_signature_data_and_delete(tx_id);   // :686 DESTRUCTIVE
auto& server_signature_data = *server_signature_data_ptr;
const auto& key_id = server_signature_data.key_id;
_key_persistency.load_key_metadata(key_id, server_key_metadata);
validate_tenant_id_setup(server_key_metadata.setup_id);

if (client_id != server_signature_data.client_signer_id)                                  // :694 TOO LATE
{
    ...throw...
}
```

The load is destructive and runs eight lines before the identity check. Any authenticated party that
knows an in-flight `tx_id` deletes the server's ephemeral signing state; the rejection then throws, but
the state is already gone and the legitimate client's round 2 fails.

Same defect class as Report 1 — a check placed after a side effect — but unlike Report 1 this reaches
**existing, fully generated, potentially funded keys.** Gated on knowledge of an in-flight `tx_id`.

**Fix:** move the `client_id` comparison before the destructive load, using a non-destructive read.

---

# Report 3 — `ring_pedersen_parameters_zkp_verify` can return SUCCESS having verified nothing

**File:** `src/common/crypto/commitments/ring_pedersen.c:794-799`
**CVSS 3.1 (if triggered):** `AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N` = **6.8 Medium**
**Argued on impact and triviality of fix, not on likelihood.** Read the *Honest limitation* section first.

```c
zero_knowledge_proof_status status = ZKP_OUT_OF_MEMORY;   // :768
...
status = init_ring_pedersen_param_zkp(&proof, ctx);       // :787 — returns ZKP_SUCCESS (== 0)
if (status != ZKP_SUCCESS) { goto cleanup; }

t_pow_z = BN_CTX_get(ctx);                                // :794
if (!t_pow_z) { goto cleanup; }                           // :798 — status is STILL ZKP_SUCCESS

status = ZKP_VERIFICATION_FAILED;                         // :802 — one line too late
```

`cleanup:` is `drng_free / BN_CTX_end / BN_CTX_free / return status`, with no fix-up. On that branch the
function returns "verified" having executed **zero** checks — not the compositeness test on `n`, not the
coprimality checks, not one of the 80 `t^{z_i} == A_i·s^{e_i}` equations.

`init_ring_pedersen_param_zkp` makes exactly 160 `BN_CTX_get` calls. `BN_POOL_ITEM` was measured at 400
bytes holding 16 BIGNUMs, so 160 gets fill exactly 10 blocks and the 161st — `t_pow_z` — is the **only**
get in the function that must `OPENSSL_malloc`. It is an independent failure point, not one shielded by
earlier failures.

**This site is unique in the codebase.** Every analogous verifier — `range_proofs.c:688`, `:1197`,
`:1831`, `diffie_hellman_log.c:100` — performs its extra `BN_CTX_get`s *before* the `init_*` call and
sets the failure default immediately after. So does the direct sibling, `damgard_fujisaki_zkp.c:535`
(`ret = -1; // reset for OpenSSL errors`). The ordering is correct everywhere else.

## Demonstrated impact: full long-term key-share recovery

```
  t mod p = 1   (so t^mu = 1 mod p -- the blinder is inert mod p)
  gcd(s,N)==1 yes | gcd(t,N)==1 yes | N composite yes | |N|=1024 yes
  s in <t> ? NO  <-- ONLY the 80-round ZKP catches this
  normal -> ZKP_VERIFICATION_FAILED | 11th malloc fails -> ZKP_SUCCESS  <== trapdoor planted
  true key share x : 8B0501860A522552D1086BA529FC18D8CDE36D70D80DB35AA624B91CD0B5B0D5
  recovered        : 8B0501860A522552D1086BA529FC18D8CDE36D70D80DB35AA624B91CD0B5B0D5
  RESULT: LONG-TERM ECDSA KEY SHARE FULLY RECOVERED
```

`cmp_ecdsa_signing_service.cpp:117` passes the long-term share into `mta::answer_mta_request`
(`mta.cpp:755` → `:761`), which commits `S = s^x · t^μ` under the **peer's** ring-Pedersen parameters
(`mta.cpp:513`). With `s ∉ ⟨t⟩` and `t ≡ 1 (mod p)`, the blinder is inert mod p and Pohlig–Hellman
returns `x`. Note the masking that protects the BAM path (`bn_randomize_with_factor`) is **not** present
on the CMP MtA path.

Two aggravating facts: parameters are validated **once at DKG and never revalidated**, so a single
fail-open compromises the key for its entire lifetime; and `verify_setup_proofs` runs *after*
`store_key_metadata`, so a failed ceremony does not roll back stored peer parameters.

An `LD_PRELOAD` shim failing only the 11th 400-byte allocation inside the verifier, run against the
project's own DKG test:

```
LD_PRELOAD=.../inject.so ./cosigner_test setup
  → All tests passed (138 assertions in 1 test case)
  [INJECT] pool items seen inside ring_pedersen_parameters_zkp_verify: 11 ; injection fired: YES
```

A real 3-player CMP DKG **completes successfully and silently** with a peer's ring-Pedersen parameters
never verified. No log line, no exception — on `ZKP_SUCCESS` the loop simply continues.

## Honest limitation — this is not remotely triggerable

I investigated whether an attacker could induce the allocation failure using the unbounded leak in
`cmp_ecdsa_signing_service.h:85` (Appendix A) as a memory-exhaustion primitive. **It does not work**, for
four independent reasons, and `poc_ring_pedersen_oom_grooming` is committed as the negative result:

1. With Linux's default `vm.overcommit_memory = 0` and no `RLIMIT_AS` in the repo, a 400-byte malloc
   essentially never returns NULL. The leak produces an **OOM kill**, not a fail-open.
2. The window is one chunk wide: sweeping heap headroom, `K=0–10` → `ZKP_OUT_OF_MEMORY`, **`K=11` →
   `ZKP_SUCCESS`**, `K=12–24` → `ZKP_VERIFICATION_FAILED`.
3. The leak primitive is ~19 KB per abandoned session and monotonic — 46× too coarse to position a
   ~416-byte window.
4. A 3-player DKG makes 240,019 mallocs; the fail-open site is #45,279, behind the round's heaviest
   allocator (Paillier keygen + Blum ZKP). A first failure lands there with overwhelming probability.
   ≈1 in 40,000 even granting everything else.

So: **do not treat this as a remote key-extraction vulnerability.** The claim is narrower and still worth
acting on — a one-line ordering bug is the only thing between an allocation hiccup and total key
compromise, in a regime (`RLIMIT_AS`, strict overcommit, containerised or embedded signers) that real
deployments do use.

## Remediation

```c
t_pow_z = BN_CTX_get(ctx);
if (!t_pow_z)
{
    status = ZKP_OUT_OF_MEMORY;   /* add; or hoist line 802 above the get */
    goto cleanup;
}
```
Also initialise `status = ZKP_VERIFICATION_FAILED` at `:768` so every path fails closed by construction.

**Independently:** validate `(N, s, t)` structurally, not only via the proof. `(N, s=1, t=1)` is accepted
by the entire pipeline with **no memory pressure at all** — `A_i = 1, z_i = 0` satisfies all 80 equations
— which I confirmed executably. Its own impact is self-harm, but it shows the ZKP is not a substitute for
sanity checks. Recommend rejecting `s,t ∈ {0,1}`, `s == t`, and raising the 1024-bit floor
(`RING_PEDERSEN_KEY_SIZE`); note `ring_pedersen_public_deserialize_internal:313` uses `BN_cmp(s,n) > 0`,
so `s == n` (i.e. `s ≡ 0`) currently slips through.

---

# Appendix A — Secondary findings

**A1 — `~ecdsa_preprocessing_data` cleanses over its own non-trivial members.**
`include/cosigner/cmp_ecdsa_signing_service.h:85`. `k` is the first member, so
`OPENSSL_cleanse(k.data, sizeof(ecdsa_preprocessing_data))` zeroes 352 bytes from offset 0, over
`mta_request` (offset 232) and the maps at 256 and 304, **before** their destructors run. libstdc++ frees
nothing. Mid-protocol `clear()` calls at `cmp_ecdsa_signing_service.cpp:106, 195, 254` bound it, but
`vector::clear()` does not release capacity so `mta_request` leaks unconditionally, and any instance
destroyed while populated leaks in full. `POC_02` measures 1,222,896 bytes retained across 64 instances
versus 0 for identical containers destroyed normally. Fix:
`OPENSSL_cleanse(k.data, offsetof(ecdsa_preprocessing_data, mta_request));`

**A2 — Key refresh performs no participant-set or correctness verification.**
`cmp_offline_refresh_service.cpp:92` bounds `encrypted_seeds.size()` only from above. The refresh is
sum-invariant only under symmetric participation, which is never acked, committed or compared, and no
round verifies the refreshed shares still reconstruct `metadata.public_key` (contrast
`cmp_setup_service.cpp:206-221`). Reachable through an ordinary network partition as readily as through
an attacker. Two supporting defects: `validate_prfs_sizes` (:77-84) can never fire, both vectors being
`push_back`-ed in the same iteration; and the test assertion at `ecdsa_offline_test.cpp:474` is vacuous,
comparing the stored public key to itself.

# Appendix B — Unverified lead

`ring_pedersen_param_zkp_serialized_size` computes `n_len * 2 * 80` in `int`, with `n_len` derived from
an attacker-supplied blob with no upper bound; a ~27 MB `N` wraps the product mod 2^32, potentially
letting a small `proof_len` pass the equality gate at `:771`. **Not confirmed.** `BN_is_prime_fasttest_ex`
on such an `N` runs first and would hang effectively forever, so this likely lands as unbounded-CPU DoS
rather than the out-of-bounds read it superficially suggests. Flagged for your own assessment; I am not
claiming it.

# Appendix C — Claims investigated and withdrawn

Listed so you can calibrate the rest. Each was developed, tested, and abandoned:

- **EdDSA nonce reuse via round-1 replay** — the library's own test asserts a replayed
  `store_signing_commitments` must throw (`eddsa_online_test.cpp:198`), and the causal chain was
  misattributed: `R_me` is broadcast in round 2 regardless and the commitment salt is attacker-chosen.
- **EdDSA `map::end()` dereference** — refuted. `t != n` is rejected at every public key-creation entry
  point (`cmp_setup_service.cpp:62, :355, :446`), so the required `t`-subset cannot exist.
- **Batch MtA soundness (1/2 vs 2^-40)** — the inequivalence is real, but `−E` is a legitimate
  commitment: the prover gains a proof it already had, and the only constructible order-2 element is
  `−1`. Hygiene, not a break.
- **Paillier key-size mismatch bricking a wallet** — real defect, no new capability: CMP enforces
  `t == n`, so the attacker is a mandatory signer who can already refuse to sign.
- **Paillier-commitment fail-open leaking the plaintext** — the algebra was wrong. With `s == 0`,
  `sigma_0 = 0`, not `1+N`; an observer learns one bit, and it is neutralised by the reduced-form
  serialization and the client's Damgård–Fujisaki parameter proof.
- **`damgard_fujisaki` unbalanced `BN_CTX`** — mechanism runs backwards; a surplus `BN_CTX_start` holds
  BIGNUMs longer, never releases them early, and the ctx is owned and freed by its sole caller.
- **Leak → OOM → fail-open chain** — retracted, with the negative-result PoC committed. See Report 3.

---

## Disclosure

Reported privately per `SECURITY.md`. No public disclosure and no publication of proof-of-concept code
pending vendor response and a fix. Happy to supply further detail, adjust scoring, or re-test a candidate
patch.
