/*
   Copyright 2022 The Silkworm Authors

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

#pragma once

#include <vector>

#include <silkworm/core/chain/config.hpp>
#include <silkworm/core/execution/processor.hpp>
#include <silkworm/core/protocol/rule_set.hpp>
#include <silkworm/core/state/state.hpp>
#include <silkworm/core/types/block.hpp>
#include <silkworm/core/types/receipt.hpp>

namespace silkworm {

/** @brief Executes a given block and writes resulting changes into the state.
 *
 * Preconditions:
 *  validate_block_header & pre_validate_block_body must return kOk;
 *  transaction senders must be already populated.
 *
 * Warning: This method does not verify state root;
 * pre-Byzantium receipt root isn't validated either.
 *
 * For better performance use ExecutionProcessor directly and set EVM state_pool & analysis_cache.
 *
 * @param state The Ethereum state at the beginning of the block.
 */
[[nodiscard]] inline ValidationResult execute_block(const Block& block, State& state,
                                                    const ChainConfig& chain_config, const evmone::gas_parameters& gas_params, const gas_prices_t& gas_prices) noexcept {
    auto rule_set{protocol::rule_set_factory(chain_config)};
    if (!rule_set) {
        return ValidationResult::kUnknownProtocolRuleSet;
    }
    ExecutionProcessor processor{block, *rule_set, state, chain_config, gas_prices};
    std::vector<Receipt> receipts;
    return processor.execute_and_write_block(receipts, gas_params);
}

}  // namespace silkworm
