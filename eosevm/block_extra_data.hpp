#pragma once

#include <optional>

namespace eosevm {

struct block_extra_data {
    std::optional<evmc::bytes32> consensus_parameter_index;
};

} // namespace eosevm

namespace silkworm { namespace rlp {
    silkworm::Bytes encode(const eosevm::block_extra_data&);
    DecodingResult decode(silkworm::ByteView& from, eosevm::block_extra_data& to) noexcept;
}}  // namespace silkworm::rlp
