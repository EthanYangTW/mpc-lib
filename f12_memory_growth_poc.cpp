/*
 * F12: Memory Growth Monitor PoC
 *
 * Demonstrates that heap memory grows monotonically as signing sessions
 * accumulate, because the destructor bug leaks container allocations.
 *
 * Reads /proc/self/status (VmRSS) and mallinfo2() to show real memory
 * growth in real-time. No ASAN needed — this shows the leak using the
 * OS's own accounting.
 *
 * Build:
 *   g++ -g -std=c++17 -I include -I src/common -I build/src/common \
 *       -o f12_memory_growth_poc f12_memory_growth_poc.cpp \
 *       -L build/src/common -lcosigner -lssl -lcrypto -lpthread -ldl -luuid \
 *       -Wl,-rpath,build/src/common
 *
 * Run:
 *   LD_LIBRARY_PATH=build/src/common ./f12_memory_growth_poc
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <vector>
#include <malloc.h>

#include <openssl/rand.h>
#include <openssl/crypto.h>

#include "cosigner/cmp_ecdsa_signing_service.h"
#include "cosigner/mpc_globals.h"

using namespace fireblocks::common::cosigner;

static long get_vm_rss_kb()
{
    FILE* f = fopen("/proc/self/status", "r");
    if (!f) return -1;
    char line[256];
    long rss = -1;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "VmRSS:", 6) == 0) {
            sscanf(line + 6, "%ld", &rss);
            break;
        }
    }
    fclose(f);
    return rss;
}

static size_t get_heap_used()
{
    struct mallinfo2 mi = mallinfo2();
    return mi.uordblks;
}

static void simulate_signing_session()
{
    ecdsa_preprocessing_data* data = new ecdsa_preprocessing_data();
    RAND_bytes(data->k.data, sizeof(elliptic_curve256_scalar_t));
    RAND_bytes(data->gamma.data, sizeof(elliptic_curve256_scalar_t));
    RAND_bytes(data->a.data, sizeof(elliptic_curve256_scalar_t));
    RAND_bytes(data->b.data, sizeof(elliptic_curve256_scalar_t));

    data->mta_request.resize(512);
    RAND_bytes(data->mta_request.data(), 512);

    byte_vector_t proof1(256, 0xAA);
    byte_vector_t proof2(256, 0xBB);
    data->G_proofs[1] = proof1;
    data->G_proofs[2] = proof2;

    ecdsa_signing_public_data pd;
    RAND_bytes(pd.A.data, sizeof(elliptic_curve256_point_t));
    pd.gamma_commitment.resize(64, 0xCC);
    data->public_data[1] = pd;
    data->public_data[2] = pd;

    delete data;
    // BUG: destructor zeroes vector/map internals before ~vector/~map run
    // Result: heap buffers allocated by containers are never freed
}

int main()
{
    printf("=== F12: MEMORY GROWTH MONITOR ===\n");
    printf("Bug: ~ecdsa_preprocessing_data() { OPENSSL_cleanse(k.data, sizeof(ecdsa_preprocessing_data)); }\n");
    printf("Each signing session leaks ~832+ bytes of heap memory.\n");
    printf("Watching RSS and heap usage grow in real-time.\n\n");

    long baseline_rss = get_vm_rss_kb();
    size_t baseline_heap = get_heap_used();

    printf("%-12s  %10s  %10s  %10s  %10s\n",
           "Sessions", "Heap (KB)", "Heap Delta", "RSS (KB)", "RSS Delta");
    printf("%-12s  %10s  %10s  %10s  %10s\n",
           "--------", "---------", "----------", "--------", "---------");

    printf("%-12d  %10.1f  %10.1f  %10ld  %10ld\n",
           0, baseline_heap / 1024.0, 0.0, baseline_rss, 0L);

    int checkpoints[] = {100, 500, 1000, 2000, 5000, 10000, 20000, 50000};
    int next_checkpoint = 0;
    int total_sessions = 50000;

    for (int i = 1; i <= total_sessions; i++) {
        simulate_signing_session();

        if (next_checkpoint < 8 && i == checkpoints[next_checkpoint]) {
            long rss = get_vm_rss_kb();
            size_t heap = get_heap_used();
            printf("%-12d  %10.1f  %10.1f  %10ld  %10ld\n",
                   i,
                   heap / 1024.0,
                   (heap - baseline_heap) / 1024.0,
                   rss,
                   rss - baseline_rss);
            fflush(stdout);
            next_checkpoint++;
        }
    }

    long final_rss = get_vm_rss_kb();
    size_t final_heap = get_heap_used();

    printf("\n=== RESULTS ===\n");
    printf("Baseline heap:  %.1f KB\n", baseline_heap / 1024.0);
    printf("Final heap:     %.1f KB\n", final_heap / 1024.0);
    printf("Heap leaked:    %.1f KB (%.1f MB)\n",
           (final_heap - baseline_heap) / 1024.0,
           (final_heap - baseline_heap) / (1024.0 * 1024.0));
    printf("Leak per session: ~%zu bytes\n",
           (final_heap - baseline_heap) / total_sessions);
    printf("\n");
    printf("RSS baseline:   %ld KB\n", baseline_rss);
    printf("RSS final:      %ld KB\n", final_rss);
    printf("RSS growth:     %ld KB (%.1f MB)\n",
           final_rss - baseline_rss,
           (final_rss - baseline_rss) / 1024.0);
    printf("\n");

    long rss_growth = final_rss - baseline_rss;
    size_t heap_growth = final_heap - baseline_heap;
    long growth = (rss_growth > 0) ? rss_growth * 1024 : (long)heap_growth;

    if (growth > 1024) {
        double growth_kb = growth / 1024.0;
        long per_session = growth / total_sessions;
        printf("[PASS] Memory grew by %.1f KB over %d sessions — memory is leaking\n",
               growth_kb, total_sessions);
        printf("       ~%ld bytes leaked per signing session\n", per_session);
        printf("\n");
        printf("In an SGX enclave with limited EPC memory (~128MB typical):\n");
        double sessions_to_exhaust = (128.0 * 1024 * 1024) / (double)per_session;
        printf("  Estimated sessions to exhaust 128MB EPC: %.0f\n", sessions_to_exhaust);
        printf("  At 10 signing sessions/minute: %.0f minutes (%.1f hours)\n",
               sessions_to_exhaust / 10, sessions_to_exhaust / 600);
    } else {
        printf("[FAIL] No significant memory growth detected\n");
    }

    return 0;
}
