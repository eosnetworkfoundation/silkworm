#include "gas_prices.hpp"

namespace eosevm {

bool operator==(const eosevm::gas_prices& a, const eosevm::gas_prices& b) {
    return a.overhead_price == b.overhead_price && a.storage_price == b.storage_price;
}

} // namespace eosevm

#if not defined(ANTELOPE)
namespace silkworm { namespace rlp {

    silkworm::Bytes encode(silkworm::Bytes& to, const eosevm::gas_prices& out) {
        encode(to, out.overhead_price);
        encode(to, out.storage_price);
        return to;
    }

    DecodingResult decode(silkworm::ByteView& from, eosevm::gas_prices& to, Leftover) noexcept{
        decode(from, to.overhead_price);
        decode(from, to.storage_price);
        return {};
    }

} }  //namespace silkworm::rlp

#endif
