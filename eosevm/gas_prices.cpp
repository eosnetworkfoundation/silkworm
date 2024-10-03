#include "gas_prices.hpp"

#if not defined(ANTELOPE)
#include <silkworm/core/common/assert.hpp>
#include <silkworm/core/common/endian.hpp>
#include <silkworm/core/common/util.hpp>
#endif

namespace eosevm {

bool operator==(const eosevm::gas_prices& a, const eosevm::gas_prices& b) {
    return a.overhead_price == b.overhead_price && a.storage_price == b.storage_price;
}

#if not defined(ANTELOPE)
[[nodiscard]] silkworm::Bytes gas_prices::encode() const noexcept  {
    silkworm::Bytes ret(16, '\0');
    silkworm::endian::store_big_u64(&ret[0], overhead_price);
    silkworm::endian::store_big_u64(&ret[8], storage_price);
    return ret;
}

std::optional<gas_prices> gas_prices::decode(silkworm::ByteView encoded) noexcept {
    SILKWORM_ASSERT(encoded.length() >= 16);
    gas_prices prices;
    prices.overhead_price= silkworm::endian::load_big_u64(&encoded[0]);
    prices.storage_price = silkworm::endian::load_big_u64(&encoded[8]);
    return prices;
}

[[nodiscard]] evmc::bytes32 gas_prices::hash() const noexcept  {
    auto encoded = this->encode();
    evmc::bytes32 header_hash = std::bit_cast<evmc_bytes32>(silkworm::keccak256(encoded));
    return header_hash;
}
#endif

} // namespace eosevm
