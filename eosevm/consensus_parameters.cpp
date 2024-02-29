#include "consensus_parameters.hpp"

#if not defined(ANTELOPE)
#include <silkworm/core/common/assert.hpp>
#include <silkworm/core/common/endian.hpp>
#endif

namespace eosevm {
bool operator==(const eosevm::GasFeeParameters& a, const eosevm::GasFeeParameters& b) { 
    return a.gas_codedeposit == b.gas_codedeposit && a.gas_newaccount == b.gas_newaccount && 
    a.gas_sset == b.gas_sset && a.gas_txcreate == b.gas_txcreate && a.gas_txnewaccount == b.gas_txnewaccount; 
}

bool operator==(const eosevm::ConsensusParameters& a, const eosevm::ConsensusParameters& b) { 
    return a.min_gas_price == b.min_gas_price && a.gas_fee_parameters == b.gas_fee_parameters; }


#if not defined(ANTELOPE)
[[nodiscard]] silkworm::Bytes GasFeeParameters::encode() const noexcept  {
    silkworm::Bytes ret(40, '\0');
    silkworm::endian::store_big_u64(&ret[0], gas_txnewaccount);
    silkworm::endian::store_big_u64(&ret[8], gas_newaccount);
    silkworm::endian::store_big_u64(&ret[16], gas_txcreate);
    silkworm::endian::store_big_u64(&ret[24], gas_codedeposit);
    silkworm::endian::store_big_u64(&ret[32], gas_sset);

    return ret;
}

std::optional<GasFeeParameters> GasFeeParameters::decode(silkworm::ByteView encoded) noexcept {
    SILKWORM_ASSERT(encoded.length() >= 40);
    GasFeeParameters feeParams;
    feeParams.gas_txnewaccount = silkworm::endian::load_big_u64(&encoded[0]);
    feeParams.gas_newaccount = silkworm::endian::load_big_u64(&encoded[8]);
    feeParams.gas_txcreate = silkworm::endian::load_big_u64(&encoded[16]);
    feeParams.gas_codedeposit = silkworm::endian::load_big_u64(&encoded[24]);
    feeParams.gas_sset = silkworm::endian::load_big_u64(&encoded[32]);

    return feeParams;
}
#endif

#if not defined(ANTELOPE)
[[nodiscard]] silkworm::Bytes ConsensusParameters::encode() const noexcept  {
    SILKWORM_ASSERT(min_gas_price.has_value());
    SILKWORM_ASSERT(gas_fee_parameters.has_value());
    constexpr size_t size_before_fee_param = 2 * sizeof(uint64_t);
    auto value = gas_fee_parameters->encode();
    silkworm::Bytes ret(value.length() + size_before_fee_param, '\0');
    // Always store as latest supported version: currently 0.
    silkworm::endian::store_big_u64(&ret[0], 0);
    silkworm::endian::store_big_u64(&ret[sizeof(uint64_t)], *min_gas_price);
    std::memcpy(&ret[size_before_fee_param], &value[0], value.length());
    return ret;
};

std::optional<ConsensusParameters> ConsensusParameters::decode(silkworm::ByteView encoded) noexcept {
    SILKWORM_ASSERT(encoded.length() > sizeof(uint64_t));
    ConsensusParameters config{};
    const auto version = silkworm::endian::load_big_u64(&encoded[0]);

    // Parse according to version. For now, only 0.
    switch (version) {
        case 0: {
            constexpr size_t size_before_fee_param = 2 * sizeof(uint64_t);
            SILKWORM_ASSERT(encoded.length() > size_before_fee_param);
            config.min_gas_price = silkworm::endian::load_big_u64(&encoded[sizeof(uint64_t)]);
            config.gas_fee_parameters = GasFeeParameters::decode(silkworm::ByteView{&encoded[size_before_fee_param], encoded.length() - size_before_fee_param});
            break;
            }
        default: SILKWORM_ASSERT(version <= 0);
    }

    return config;
}
#endif

} // namespace eosevm