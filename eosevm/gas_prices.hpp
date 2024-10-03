#pragma once
#include <algorithm>

#if not defined(ANTELOPE)
#include <silkworm/core/common/base.hpp>
#endif

namespace eosevm {

struct gas_prices {
    uint64_t overhead_price;
    uint64_t storage_price;

    #if not defined(ANTELOPE)
    // Encode for storage in db.
    [[nodiscard]] silkworm::Bytes encode() const noexcept;

    // Decode from storage in db.
    static std::optional<gas_prices> decode(silkworm::ByteView encoded) noexcept;
    evmc::bytes32 hash() const noexcept;
    #endif

    friend bool operator==(const gas_prices&, const gas_prices&);
};

inline uint64_t calculate_base_fee_per_gas(uint64_t overhead_price, uint64_t storage_price) {
    return std::max(overhead_price, storage_price);
}

} // namespace eosevm
