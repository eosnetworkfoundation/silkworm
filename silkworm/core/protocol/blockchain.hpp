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

#include <unordered_map>
#include <vector>

#include <evmc/evmc.h>

#include <silkworm/core/execution/evm.hpp>
#include <silkworm/core/protocol/rule_set.hpp>
#include <silkworm/core/state/state.hpp>
#include <silkworm/core/types/receipt.hpp>
#include <silkworm/core/execution/processor.hpp>

namespace silkworm::protocol {

/**
 * Reference implementation of Ethereum blockchain logic.
 * Used for running Ethereum EL tests; the real node will use staged sync instead
 * (https://github.com/ledgerwatch/erigon/blob/devel/eth/stagedsync/README.md)
 */
class Blockchain {
  public:
    //! Creates a new instance of Blockchain.
    /**
     * In the beginning the state must have the genesis allocation.
     * Later on the state may only be modified by the created instance of Blockchain.
     */
    explicit Blockchain(State& state, const ChainConfig& config, const Block& genesis_block, const evmone::gas_parameters& gas_params, const gas_prices_t& gas_prices);

    // Not copyable nor movable
    Blockchain(const Blockchain&) = delete;
    Blockchain& operator=(const Blockchain&) = delete;

    ValidationResult insert_block(Block& block, bool check_state_root);

    ObjectPool<evmone::ExecutionState>* state_pool{nullptr};

    evmc_vm* exo_evm{nullptr};

  private:
    ValidationResult execute_block(const Block& block, bool check_state_root);

    void prime_state_with_genesis(const Block& genesis_block);

    void re_execute_canonical_chain(uint64_t ancestor, uint64_t tip);

    void unwind_last_changes(uint64_t ancestor, uint64_t tip);

    [[nodiscard]] std::vector<BlockWithHash> intermediate_chain(uint64_t block_number, evmc::bytes32 hash,
                                                                uint64_t canonical_ancestor) const;

    [[nodiscard]] uint64_t canonical_ancestor(const BlockHeader& header, const evmc::bytes32& hash) const;

    State& state_;
    const ChainConfig& config_;
    RuleSetPtr rule_set_;
    std::unordered_map<evmc::bytes32, ValidationResult> bad_blocks_;
    std::vector<Receipt> receipts_;
    evmone::gas_parameters gas_params_;
    gas_prices_t gas_prices_;
};

}  // namespace silkworm::protocol
