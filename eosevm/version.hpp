#pragma once

#include <silkworm/core/types/block.hpp>
#include <silkworm/core/common/endian.hpp>

namespace eosevm {

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
        case 0: return EVMC_ISTANBUL;
        case 1: return EVMC_ISTANBUL;
    }
    auto msg = "Unknown EOSEVM version: " + std::to_string(version);
    #ifdef ANTELOPE
    eosio::check(false, msg.c_str());
    #else
    silkworm::abort_due_to_assertion_failure(msg.c_str(), __FILE__, __LINE__);
    #endif
    return static_cast<evmc_revision>(0);
}

} // namespace eosevm