#include <tests/catch.hpp>
#include "cosigner/bam_ecdsa_cosigner_client.h"
#include "cosigner/bam_ecdsa_cosigner_server.h"
#include "cosigner/bam_key_persistency_client.h"
#include "cosigner/bam_key_persistency_server.h"
#include "cosigner/bam_tx_persistency_server.h"
#include "cosigner/bam_tx_persistency_client.h"
#include "cosigner/platform_service.h"
#include "crypto/elliptic_curve_algebra/elliptic_curve256_algebra.h"
#include "crypto/GFp_curve_algebra/GFp_curve_algebra.h"
#include "blockchain/mpc/hd_derive.h"
#include "../../src/common/cosigner/utils.h"

#include <map>
#include <set>
#include <string>
#include <iostream>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/rand.h>
#include <uuid/uuid.h>
#include "crypto/paillier_commitment/paillier_commitment.h"
#include "crypto/commitments/damgard_fujisaki.h"
#ifndef UUID_STR_LEN
#define UUID_STR_LEN 37
#endif

namespace fbc = fireblocks::common::cosigner;

static const constexpr uint64_t server_id = 3213454843;
static const constexpr uint64_t client_id = 45234523;

static std::string get_tenant_id()
{
    static std::string _tenant_id;
    if (_tenant_id.size() == 0)
    {
        uuid_t uid;
        _tenant_id.resize(UUID_STR_LEN);
        uuid_generate_random(uid);
        uuid_unparse(uid, _tenant_id.data());
    }

    return _tenant_id;
}

template <class KeyMetadataType, class TempDataType>
class test_bam_key_persistency
{
public:
    bool key_exist(const std::string& key_id) const
    {
        return _keyStore.count(key_id) != 0;
    }

    void store_key(const std::string& key_id, const cosigner_sign_algorithm algorithm,  const elliptic_curve256_scalar_t& private_key)
    {
        _keyStore[key_id].first = algorithm;
        memcpy(_keyStore[key_id].second, private_key, sizeof(elliptic_curve256_scalar_t));
    }

    void load_key(const std::string& key_id, cosigner_sign_algorithm& algorithm, elliptic_curve256_scalar_t& private_key) const
    {
        const auto it = _keyStore.find(key_id);
        if (it == _keyStore.end())
        {
            throw fbc::cosigner_exception(fbc::cosigner_exception::BAD_KEY);
        }


        memcpy(private_key, it->second.second, sizeof(elliptic_curve256_scalar_t));
        algorithm = it->second.first;
    }

    void store_key_metadata(const std::string& key_id, const KeyMetadataType& metadata, const bool overwrite)
    {
        auto it = _metadata_store.find(key_id);
        if (it != _metadata_store.end())
        {
            if (!overwrite)
            {
                throw fbc::cosigner_exception(fbc::cosigner_exception::BAD_KEY);
            }
            it->second = metadata;
        }
        else
        {
            _metadata_store[key_id] = metadata;
        }
    }
    void load_key_metadata(const std::string& key_id, KeyMetadataType& metadata) const
    {
        const auto it = _metadata_store.find(key_id);
        if (it == _metadata_store.end())
        {
            throw fbc::cosigner_exception(fbc::cosigner_exception::BAD_KEY);
        }
        metadata = it->second;
    }

    void store_temp_data(const std::string& key_id, const TempDataType& data)
    {
        auto it = _temp_data.find(key_id);
        if (it != _temp_data.end())
        {
            throw fbc::cosigner_exception(fbc::cosigner_exception::BAD_KEY);
        }
        else
        {
            if constexpr (std::is_array_v<TempDataType>) // For fixed-size arrays like uint8_t[32]
            {
                memcpy(_temp_data[key_id], data, sizeof(TempDataType));
            }
            else
            {
                _temp_data[key_id] = data;  // For structs like bam_signature_metadata_server
            }
        }
    }

    void load_and_delete_temp_data(const std::string& key_id, TempDataType& data)
    {
        auto it = _temp_data.find(key_id);
        if (it == _temp_data.end())
        {
            throw fbc::cosigner_exception(fbc::cosigner_exception::BAD_KEY);
        }

        if constexpr (std::is_array_v<TempDataType>)  // If it's a fixed-size array
        {
            memcpy(data, it->second, sizeof(TempDataType));
        }
        else  // If it's a complex structure
        {
            data = it->second;
        }

        _temp_data.erase(it);
    }

    void store_tenant_id_for_setup(const std::string& setup_id, const std::string& tenant_id)
    {
        _setup_tenant[setup_id] = tenant_id;
    }
    void load_tenant_id_for_setup(const std::string& setup_id, std::string& tenant_id) const
    {
        const auto it = _setup_tenant.find(setup_id);
        if (it == _setup_tenant.end())
        {
            throw fbc::cosigner_exception(fbc::cosigner_exception::BAD_KEY);
        }
        tenant_id = it->second;
    }


private:

    std::map<std::string, std::pair<cosigner_sign_algorithm, elliptic_curve256_scalar_t>> _keyStore;
    std::map<std::string, KeyMetadataType> _metadata_store;
    std::map<std::string, TempDataType> _temp_data;
    std::map<std::string, std::string> _setup_tenant;
};

class test_bam_key_persistency_client : public fbc::bam_key_persistency_client, public fbc::bam_tx_persistency_client
{
public:

    virtual ~test_bam_key_persistency_client()  = default;

    virtual void store_tenant_id_for_setup(const std::string& setup_id, const std::string& tenant_id) override
    {
        _store.store_tenant_id_for_setup(setup_id, tenant_id);
    }
    virtual void load_tenant_id_for_setup(const std::string& setup_id, std::string& tenant_id) const override
    {
        _store.load_tenant_id_for_setup(setup_id, tenant_id);
    }

    virtual void store_key(const std::string& key_id, const cosigner_sign_algorithm algorithm,  const elliptic_curve256_scalar_t& private_key) override
    {
        _store.store_key(key_id, algorithm, private_key);
    }

    virtual void load_key(const std::string& key_id, cosigner_sign_algorithm& algorithm, elliptic_curve256_scalar_t& private_key) const override
    {
        _store.load_key(key_id, algorithm, private_key);
    }

    virtual void store_key_metadata(const std::string& key_id, const fbc::bam_key_metadata_client& metadata, const bool overwrite) override
    {
        _store.store_key_metadata(key_id, metadata, overwrite);
    }

    virtual void load_key_metadata(const std::string& key_id, fbc::bam_key_metadata_client& metadata) const override
    {
        _store.load_key_metadata(key_id, metadata);
    }

    virtual void store_key_temp_data(const std::string& key_id, const fbc::bam_temp_key_data_client& auxilary_key_client) override
    {
        _store.store_temp_data(key_id, auxilary_key_client);
    }

    virtual void load_key_temp_data_and_delete(const std::string& key_id, fbc::bam_temp_key_data_client& auxilary_key_client) override
    {
        _store.load_and_delete_temp_data(key_id, auxilary_key_client);
    }
    virtual void store_signature_data(const std::string& tx_id, const fbc::bam_client_signature_data& signature_data) override
    {
        const std::string data_key = "txid_" + tx_id;

        auto it = _sig_data.find(data_key);
        if (it != _sig_data.end())
        {
            throw fbc::cosigner_exception(fbc::cosigner_exception::BAD_KEY);
        }
        else
        {
            _sig_data[data_key] = signature_data;
        }
    }
    virtual void load_signature_data_and_delete(const std::string& tx_id, fbc::bam_client_signature_data& signature_data) override
    {
        const std::string data_key = "txid_" + tx_id;
        auto it = _sig_data.find(data_key);
        if (it == _sig_data.end())
        {
            throw fbc::cosigner_exception(fbc::cosigner_exception::BAD_KEY);
        }
        signature_data = it->second;
        _sig_data.erase(it);
    }
    virtual bool delete_temporary_tx_data(const std::string& tx_id) override { return true; }
    virtual bool delete_temporary_key_data(const std::string& key_id) override { return true; }
    virtual bool delete_key_data(const std::string& key_id) override{ return true; }
    virtual bool delete_setup_data(const std::string& setup_id) override { return true; }
    virtual bool backup_key(const std::string&) const override { return true; }

private:
    test_bam_key_persistency<fbc::bam_key_metadata_client, fbc::bam_temp_key_data_client> _store;
    std::map<std::string, fbc::bam_client_signature_data> _sig_data;
};


class test_bam_key_persistency_server : public fbc::bam_key_persistency_server, public fbc::bam_tx_persistency_server
{
public:

    virtual ~test_bam_key_persistency_server()  = default;

    virtual void store_tenant_id_for_setup(const std::string& setup_id, const std::string& tenant_id) override
    {
        _store.store_tenant_id_for_setup(setup_id, tenant_id);
    }
    virtual void load_tenant_id_for_setup(const std::string& setup_id, std::string& tenant_id) const override
    {
        _store.load_tenant_id_for_setup(setup_id, tenant_id);
    }

    virtual void store_key(const std::string& key_id, const cosigner_sign_algorithm algorithm,  const elliptic_curve256_scalar_t& private_key) override
    {
        _store.store_key(key_id, algorithm, private_key);
    }

    virtual void load_key(const std::string& key_id, cosigner_sign_algorithm& algorithm, elliptic_curve256_scalar_t& private_key) const override
    {
        _store.load_key(key_id, algorithm, private_key);
    }

    virtual void store_key_metadata(const std::string& key_id, const fbc::bam_key_metadata_server& metadata, const bool overwrite) override
    {
        _store.store_key_metadata(key_id, metadata, overwrite);
    }

    virtual void load_key_metadata(const std::string& key_id, fbc::bam_key_metadata_server& metadata) const override
    {
        _store.load_key_metadata(key_id, metadata);
    }

    void store_signature_data(const std::string& tx_id, const std::shared_ptr<fbc::bam_server_signature_data>& signature_data) override
    {
        _store.store_temp_data("txid_" + tx_id, *signature_data);
    }

    std::shared_ptr<fbc::bam_server_signature_data> load_signature_data_and_delete(const std::string& tx_id) override
    {
        auto signature_data_ptr = std::make_shared<fbc::bam_server_signature_data>();
        auto &signature_data = *signature_data_ptr;
        _store.load_and_delete_temp_data("txid_" + tx_id, signature_data);
        return signature_data_ptr;
    }
    virtual bool delete_temporary_tx_data(const std::string& tx_id) override { return true; }
    virtual bool delete_temporary_key_data(const std::string& key_id) override { return true; }
    virtual bool delete_key_data(const std::string& key_id) override { return true; }
    virtual bool delete_setup_data(const std::string& setup_id) override { return true; }

    virtual void store_setup_auxilary_key(const std::string& setup_id,  const fbc::bam_setup_auxilary_key_server& setup_aux_key) override
    {
        auto it = _setup_aux_key_map.find(setup_id);
        if (it != _setup_aux_key_map.end())
        {
            throw fbc::cosigner_exception(fbc::cosigner_exception::BAD_KEY);
        }
        else
        {
            _setup_aux_key_map[setup_id] = setup_aux_key;
        }

    }

    void load_setup_auxilary_key(const std::string& setup_id, fbc::bam_setup_auxilary_key_server& setup_aux_key) const override
    {
        const auto it = _setup_aux_key_map.find(setup_id);
        if (it == _setup_aux_key_map.end())
        {
            throw fbc::cosigner_exception(fbc::cosigner_exception::BAD_KEY);
        }
        setup_aux_key = it->second;
    }

    virtual void store_setup_metadata(const std::string& setup_id,  const fbc::bam_setup_metadata_server& setup_metadata) override
    {
        auto it = _setup_metadata.find(setup_id);
        if (it != _setup_metadata.end())
        {
            throw fbc::cosigner_exception(fbc::cosigner_exception::BAD_KEY);
        }
        else
        {
            _setup_metadata[setup_id] = setup_metadata;
        }
    }
    virtual void load_setup_metadata(const std::string& setup_id, fbc::bam_setup_metadata_server& setup_metadata) const override
    {
        const auto it = _setup_metadata.find(setup_id);
        if (it == _setup_metadata.end())
        {
            throw fbc::cosigner_exception(fbc::cosigner_exception::BAD_KEY);
        }
        setup_metadata = it->second;
    }

    virtual bool backup_key(const std::string& key_id) const override { return true; }

private:
    test_bam_key_persistency<fbc::bam_key_metadata_server, fbc::bam_server_signature_data> _store;
    std::map<std::string, fbc::bam_setup_auxilary_key_server> _setup_aux_key_map;
    std::map<std::string, fbc::bam_setup_metadata_server> _setup_metadata;
};


class test_bam_platform_service : public fbc::platform_service
{
public:
    ~test_bam_platform_service() = default;
    void gen_random(size_t len, uint8_t* random_data) const override
    {
        RAND_bytes(random_data, len);
    }
    bool backup_key(const std::string& key_id, cosigner_sign_algorithm algorithm, const elliptic_curve256_scalar_t& private_key, const fbc::cmp_key_metadata& metadata, const fbc::auxiliary_keys& aux) override {return true;}

    void derive_initial_share(const fbc::share_derivation_args& derive_from, cosigner_sign_algorithm algorithm, elliptic_curve256_scalar_t* key) const override {assert(0);}
    void on_start_signing(const std::string& key_id, const std::string& txid, const fbc::signing_data& data, const std::string& metadata_json, const std::set<std::string>& players, const signing_type signature_type) override {};
    bool is_client_id(uint64_t player_id) const override {return false;}
    virtual const std::string get_current_tenantid() const override
    {
        return get_tenant_id();
    }

    virtual uint64_t get_id_from_keyid(const std::string& key_id) const override
    {
        return 0;
    }

    virtual void fill_signing_info_from_metadata(const std::string& metadata, std::vector<uint32_t>& flags) const override
    {
        if (metadata != "")
        {
            flags[0] = fbc::POSITIVE_R;
        }
    }
    void fill_eddsa_signing_info_from_metadata(std::vector<fbc::eddsa_signature_data>& info, const std::string& metadata) const override
    {
        // Stub for tests
    }
    
    void fill_bam_signing_info_from_metadata(std::vector<fbc::bam_signing_properties>& info, const std::string& metadata) const override
    {
        if (metadata != "")
        {
            for (auto& sig : info)
                sig.flags = fbc::POSITIVE_R;
        }
    }
    virtual fbc::byte_vector_t encrypt_for_player(const uint64_t id, const fbc::byte_vector_t& data, const std::optional<std::string>& verify_modulus = std::nullopt) const override { return data; }
    virtual fbc::byte_vector_t decrypt_message(const fbc::byte_vector_t& encrypted_data) const override { return encrypted_data; }
    virtual void prepare_for_signing(const std::string& key_id, const std::string tx_id) override {};
    virtual void mark_key_setup_in_progress(const std::string& key_id) const override {};
    virtual void clear_key_setup_in_progress(const std::string& key_id) const override {};

};

void bam_key_generation(const std::string& setup_id,
                        const std::string& key_id,
                        uint64_t client_id,
                        uint64_t server_id,
                        fbc::bam_ecdsa_cosigner_server& server,
                        fbc::bam_ecdsa_cosigner_client& client,
                        const cosigner_sign_algorithm algorithm,
                        elliptic_curve256_point_t& client_share,
                        elliptic_curve256_point_t& server_share)
{
    fbc::bam_ecdsa_cosigner::client_key_shared_data client_message;
    fbc::bam_ecdsa_cosigner::server_key_shared_data server_message;
    fbc::bam_ecdsa_cosigner::generated_public_key generated_public_key;

    // Step 1.
    commitments_sha256_t B;
    fbc::bam_ecdsa_cosigner::server_setup_shared_data setup;


    REQUIRE_NOTHROW(server.generate_setup_with_proof(setup_id, get_tenant_id(), algorithm, setup));

    REQUIRE_NOTHROW(client.start_new_key_generation(setup_id, key_id, get_tenant_id(), server_id, client_id, algorithm));
    REQUIRE_NOTHROW(server.generate_share_and_commit(setup_id, key_id, server_id, client_id, algorithm, B));

    // Step 2.
    REQUIRE_NOTHROW(client.verify_setup_proof_store_key_commitment_generate_key_proof(setup_id, key_id, server_id, setup, B, client_message));

    // Step 3.
    REQUIRE_NOTHROW(server.verify_client_proofs_and_decommit_share_with_proof(key_id, client_id, client_message, server_message));

    // Step 4.
    REQUIRE_NOTHROW(client.verify_key_decommitment_and_proofs(key_id, server_id, client_id, server_message, generated_public_key));

    // return public key
    memcpy(client_share, client_message.X, sizeof(elliptic_curve256_point_t));
    memcpy(server_share, server_message.server_public_share, sizeof(elliptic_curve256_point_t));
}

void bam_key_sign(const std::string& setup_id,
                  const std::string& key_id,
                  const std::string& tx_id,
                  const uint64_t client_id,
                  const fbc::signing_data& data_to_sign,
                  const std::string& metadata,
                  fbc::bam_ecdsa_cosigner_server& server,
                  fbc::bam_ecdsa_cosigner_client& client,
                  fbc::recoverable_signature& full_signature,
                  const cosigner_sign_algorithm algorithm)
{
    std::vector<fbc::bam_ecdsa_cosigner::server_signature_shared_data> server_shares;
    std::vector<fbc::bam_ecdsa_cosigner::client_partial_signature_data> partial_signatures;
    std::vector<fbc::recoverable_signature> full_signatures;
    cosigner_sign_algorithm signature_algorithm;

    REQUIRE_NOTHROW(client.prepare_for_signature(key_id, tx_id, 0, server_id, client_id, data_to_sign, metadata, std::set<std::string>()));
    REQUIRE_NOTHROW(server.generate_signature_share(key_id, tx_id, 0, server_id, client_id, algorithm, data_to_sign, metadata, std::set<std::string>(), server_shares));
    REQUIRE_NOTHROW(client.compute_partial_signature(tx_id, server_shares, partial_signatures));
    REQUIRE_NOTHROW(server.verify_partial_signature_and_output_signature(tx_id, client_id, partial_signatures, full_signatures, signature_algorithm));
    REQUIRE(signature_algorithm == algorithm);
    memcpy(&full_signature, &full_signatures[0], sizeof(fbc::recoverable_signature));
}


void verify_ecdsa_signature(const cosigner_sign_algorithm algorithm,
                            const elliptic_curve256_point_t& X1,
                            const elliptic_curve256_point_t& X2,
                            const fbc::recoverable_signature& signature,
                            const fbc::signing_data& data_to_sign,
                            const bool isPositiveR)
{
    elliptic_curve256_algebra_ctx_t *ctx = NULL;

    // Initialize context based on the curve specified by algorithm
    switch (algorithm) {
        case ECDSA_SECP256K1:
            ctx = elliptic_curve256_new_secp256k1_algebra();
            break;
        case ECDSA_SECP256R1:
            ctx = elliptic_curve256_new_secp256r1_algebra();
            break;
        case ECDSA_STARK:
            ctx = elliptic_curve256_new_stark_algebra();
            break;
        default:
            throw std::runtime_error("unsupported algorithm");  // Unsupported algorithm
    }

    if (!ctx)
    {
        throw std::runtime_error("Failed to initialize context");
    }

    // Declare necessary variables
    elliptic_curve256_scalar_t s_inv;
    elliptic_curve256_scalar_t u1;
    elliptic_curve256_scalar_t u2;
    elliptic_curve256_point_t U1, U2;
    elliptic_curve256_point_t R;
    elliptic_curve256_scalar_t r;
    elliptic_curve256_point_t X;

    REQUIRE(ELLIPTIC_CURVE_ALGEBRA_SUCCESS == ctx->add_points(ctx, &X, &X1, &X2));


    REQUIRE(HD_DERIVE_SUCCESS == derive_public_key_generic(ctx, X, X, data_to_sign.chaincode, &data_to_sign.blocks[0].path[0], (uint32_t)data_to_sign.blocks[0].path.size()));

    // Step 1: Calculate s_inv, the modular inverse of signature.s
    REQUIRE(ELLIPTIC_CURVE_ALGEBRA_SUCCESS == ctx->inverse(ctx, &s_inv, &signature.s));

    // Step 2: Calculate u1 = (hash * s_inv) mod n
    REQUIRE(ELLIPTIC_CURVE_ALGEBRA_SUCCESS == ctx->mul_scalars(ctx, &u1, data_to_sign.blocks[0].data.data(), data_to_sign.blocks[0].data.size(), s_inv, sizeof(elliptic_curve256_scalar_t)));

    // Step 3: Calculate u2 = (signature.r * s_inv) mod n
    REQUIRE(ELLIPTIC_CURVE_ALGEBRA_SUCCESS == ctx->mul_scalars(ctx, &u2, signature.r, sizeof(elliptic_curve256_scalar_t), s_inv, sizeof(elliptic_curve256_scalar_t)));

   // Step 4: Calculate U2 = u2 * G (generator multiplication)
    REQUIRE(ELLIPTIC_CURVE_ALGEBRA_SUCCESS == ctx->generator_mul(ctx, &U1, &u1));

    // Step 5: Calculate U1 = u1 * Q (public key multiplication)
    REQUIRE(ELLIPTIC_CURVE_ALGEBRA_SUCCESS == ctx->point_mul(ctx, &U2, &X, &u2));

    // Step 6: Calculate R = U1 + U2
    REQUIRE(ELLIPTIC_CURVE_ALGEBRA_SUCCESS == ctx->add_points(ctx, &R, &U1, &U2));

    // Step 7: Extract the x-coordinate of R and compare it with signature.r
    REQUIRE(ELLIPTIC_CURVE_ALGEBRA_SUCCESS == GFp_curve_algebra_get_point_projection((const GFp_curve_algebra_ctx_t *)ctx->ctx, &r, &R, NULL));

    const uint8_t* message = data_to_sign.blocks[0].data.data();

    REQUIRE(ELLIPTIC_CURVE_ALGEBRA_SUCCESS == GFp_curve_algebra_verify_signature((const GFp_curve_algebra_ctx_t *)ctx->ctx, &X, reinterpret_cast<const elliptic_curve256_scalar_t*>(message), &signature.r, &signature.s));

    REQUIRE(memcmp(signature.r, r, sizeof(elliptic_curve256_scalar_t)) == 0);

    if (isPositiveR)
    {
        REQUIRE(fbc::bam_ecdsa_cosigner::is_positive(algorithm, signature.r));
    }

    // Clean up context
    elliptic_curve256_algebra_ctx_free(ctx);
}


std::ostream& operator<<(std::ostream& os, const fbc::bam_ecdsa_cosigner::client_key_shared_data& data)
{
    os << "client_key_shared_data {"
       << "\n  X: " << fbc::HexStr(std::begin(data.X), std::end(data.X))
       << "\n  damgard_fujisaki_pub: " << fbc::HexStr(data.damgard_fujisaki_pub.begin(), data.damgard_fujisaki_pub.end())
       << "\n  damgard_fujisaki_proof: " << fbc::HexStr(data.damgard_fujisaki_proof.begin(), data.damgard_fujisaki_proof.end())
       << "\n  schnorr_proof: " << fbc::HexStr(data.schnorr_proof.begin(), data.schnorr_proof.end())
       << "\n}";
    return os;
}


std::ostream& operator<<(std::ostream& os, const fbc::bam_ecdsa_cosigner::server_key_shared_data& data) {
    os << "server_key_shared_data {"
       << "\n  server_public_share: " << fbc::HexStr(std::begin(data.server_public_share), std::end(data.server_public_share))
       << "\n  encrypted_server_share: " << fbc::HexStr(data.encrypted_server_share.begin(), data.encrypted_server_share.end())
       << "\n  enc_dlog_proof: " << fbc::HexStr(data.enc_dlog_proof.begin(), data.enc_dlog_proof.end())
       << "\n}";
    return os;
}


struct TestSetup
{
    test_bam_key_persistency_client persistencyClient;
    test_bam_key_persistency_server persistencyServer;
    test_bam_platform_service platform;
    fbc::bam_ecdsa_cosigner_server server{ platform, persistencyServer, persistencyServer};
    fbc::bam_ecdsa_cosigner_client client{ platform, persistencyClient, persistencyClient};
};

