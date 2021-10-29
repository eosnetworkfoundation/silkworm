/*
   Copyright 2021 The Silkworm Authors

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

#include "engine.hpp"

#include <silkworm/common/endian.hpp>

namespace silkworm::consensus {

ValidationResult ConsensusEngineClique::validate_block_header(const BlockHeader& header, State& state,
                                                              bool with_future_timestamp_check) {
    auto err{base::validate_block_header(header, state, with_future_timestamp_check)};
    if (err != ValidationResult::kOk) {
        return err;
    }

}

ValidationResult ConsensusEngineClique::validate_seal(const BlockHeader& header) {
    throw std::runtime_error(std::string(__FUNCTION__) + " not yet implemented");
}

void ConsensusEngineClique::finalize(IntraBlockState& state, const Block& block, const evmc_revision& revision) {
    throw std::runtime_error(std::string(__FUNCTION__) + " not yet implemented");
}

}  // namespace silkworm::consensus
