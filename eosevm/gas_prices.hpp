#pragma once
#include <algorithm>

#if not defined(ANTELOPE)
#include <silkworm/core/rlp/decode.hpp>
#include <silkworm/core/common/assert.hpp>
#include <silkworm/core/common/endian.hpp>
#include <silkworm/core/common/util.hpp>
#endif

namespace eosevm {

struct gas_prices {
    uint64_t overhead_price{0};
    uint64_t storage_price{0};

    friend bool operator==(const gas_prices&, const gas_prices&);
};

inline uint64_t calculate_base_fee_per_gas(uint64_t overhead_price, uint64_t storage_price) {
    return std::max(overhead_price, storage_price);
}

} // namespace eosevm

#if not defined(ANTELOPE)
namespace silkworm { namespace rlp {
    silkworm::Bytes encode(silkworm::Bytes& to, const eosevm::gas_prices& out);
    DecodingResult decode(silkworm::ByteView& from, eosevm::gas_prices& to, Leftover mode) noexcept;
}}
#endif
