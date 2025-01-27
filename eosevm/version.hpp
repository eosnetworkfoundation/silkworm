#pragma once

#include <silkworm/core/types/block.hpp>
#include <silkworm/core/common/endian.hpp>
#include <eosevm/assert.hpp>
namespace eosevm {

enum version : uint64_t {
    EVM_VERSION_0 = 0,
    EVM_VERSION_1 = 1,
    EVM_VERSION_2 = 2,
    EVM_VERSION_3 = 3,
};

static constexpr uint64_t max_eos_evm_version = EVM_VERSION_3;

using NonceType=silkworm::BlockHeader::NonceType;

inline NonceType version_to_nonce(uint64_t version) {
    NonceType nonce;
    silkworm::endian::store_big_u64(nonce.data(), version);
    return nonce;
}

inline uint64_t nonce_to_version(const NonceType& nonce) {
    // The nonce will be treated as big-endian number for now.
    return silkworm::endian::load_big_u64(nonce.data());
}

inline evmc_revision version_to_evmc_revision(uint64_t version) {
    switch (version) {
        case EVM_VERSION_0: return EVMC_ISTANBUL;
        case EVM_VERSION_1: return EVMC_SHANGHAI;
        case EVM_VERSION_2: return EVMC_SHANGHAI;
        case EVM_VERSION_3: return EVMC_SHANGHAI;
    }
    auto msg = "Unknown EOSEVM version: " + std::to_string(version);
    EOSEVM_ABORT(msg.c_str());
    return static_cast<evmc_revision>(0);
}

} // namespace eosevm
