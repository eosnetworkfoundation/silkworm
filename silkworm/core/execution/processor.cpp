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

#include "processor.hpp"

#include <cassert>

#include <silkworm/core/chain/dao.hpp>
#include <silkworm/core/protocol/intrinsic_gas.hpp>
#include <silkworm/core/protocol/param.hpp>
#include <silkworm/core/trie/vector_root.hpp>

namespace silkworm {

ExecutionProcessor::ExecutionProcessor(const Block& block, protocol::IRuleSet& rule_set, State& state,
                                       const ChainConfig& config, const evmone::gas_parameters& gas_params)
    : state_{state}, rule_set_{rule_set}, evm_{block, state_, config, gas_params} {
    evm_.beneficiary = rule_set.get_beneficiary(block.header);
}

void ExecutionProcessor::execute_transaction(const Transaction& txn, Receipt& receipt) noexcept {
    assert(protocol::validate_transaction(txn, state_, available_gas()) == ValidationResult::kOk);

    // Optimization: since receipt.logs might have some capacity, let's reuse it.
    std::swap(receipt.logs, state_.logs());

    state_.clear_journal_and_substate();

    assert(txn.from);
    state_.access_account(*txn.from);

    if (txn.to) {
        state_.access_account(*txn.to);
        // EVM itself increments the nonce for contract creation
        state_.set_nonce(*txn.from, txn.nonce + 1);
    }

    for (const AccessListEntry& ae : txn.access_list) {
        state_.access_account(ae.account);
        for (const evmc::bytes32& key : ae.storage_keys) {
            state_.access_storage(ae.account, key);
        }
    }

    const evmc_revision rev{evm_.revision()};
    if (rev >= EVMC_SHANGHAI) {
        // EIP-3651: Warm COINBASE
        state_.access_account(evm_.beneficiary);
    }

    // EIP-1559 normal gas cost
    const intx::uint256 base_fee_per_gas{evm_.block().header.base_fee_per_gas.value_or(0)};
    const intx::uint256 effective_gas_price{txn.effective_gas_price(base_fee_per_gas)};
    state_.subtract_from_balance(*txn.from, txn.gas_limit * effective_gas_price);

    // EIP-4844 data gas cost (calc_data_fee)
    const intx::uint256 data_gas_price{evm_.block().header.data_gas_price().value_or(0)};
    state_.subtract_from_balance(*txn.from, txn.total_data_gas() * data_gas_price);

    const auto eos_evm_version = evm_.get_eos_evm_version();
    const auto& gas_params = evm_.get_gas_params();

    const intx::uint128 g0{protocol::intrinsic_gas(txn, rev, eos_evm_version, gas_params)};
    assert(g0 <= UINT64_MAX);  // true due to the precondition (transaction must be valid)

    const CallResult vm_res{evm_.execute(txn, txn.gas_limit - static_cast<uint64_t>(g0))};
    uint64_t gas_used{0};
    if(eos_evm_version < 3) {
        gas_used = txn.gas_limit - refund_gas(txn, vm_res.gas_left, vm_res.gas_refund);

        // award the fee recipient
        const intx::uint256 price{evm_.config().protocol_rule_set == protocol::RuleSetType::kTrust ? effective_gas_price : txn.priority_fee_per_gas(base_fee_per_gas)};
        state_.add_to_balance(evm_.beneficiary, price * gas_used);
    } else {
        uint64_t storage_gas_consumed{vm_res.storage_gas_consumed};
        const bool contract_creation{!txn.to};
        auto gas_left = vm_res.gas_left;
        if(contract_creation) {
            if( vm_res.status == EVMC_SUCCESS ) {
                storage_gas_consumed += gas_params.G_txcreate; //correct storage gas consumed to account for initial G_txcreate storage gas
            } else {
                gas_left += gas_params.G_txcreate;
            }
        }

        evmone::gas_state_t vm_res_gas_state(eos_evm_version, static_cast<int64_t>(vm_res.gas_refund),
             static_cast<int64_t>(storage_gas_consumed), static_cast<int64_t>(vm_res.storage_gas_refund), static_cast<int64_t>(vm_res.speculative_cpu_gas_consumed));

        gas_left += static_cast<uint64_t>(vm_res_gas_state.collapse());
        gas_used = txn.gas_limit - gas_left;
        assert(vm_res_gas_state.cpu_gas_refund() == 0);
        const auto total_storage_gas_consumed = vm_res_gas_state.storage_gas_consumed();
        assert(gas_used > static_cast<uint64_t>(total_storage_gas_consumed));
        const auto total_cpu_gas_consumed = gas_used - static_cast<uint64_t>(total_storage_gas_consumed);
        (void)total_cpu_gas_consumed;

        // award the fee recipient
        const intx::uint256 price{evm_.config().protocol_rule_set == protocol::RuleSetType::kTrust ? effective_gas_price : txn.priority_fee_per_gas(base_fee_per_gas)};
        state_.add_to_balance(evm_.beneficiary, price * gas_used);
        state_.add_to_balance(*txn.from, price * gas_left);
    }

    state_.destruct_suicides();
    if (rev >= EVMC_SPURIOUS_DRAGON) {
        state_.destruct_touched_dead();
    }

    state_.finalize_transaction();

    cumulative_gas_used_ += gas_used;

    receipt.type = txn.type;
    receipt.success = vm_res.status == EVMC_SUCCESS;
    receipt.cumulative_gas_used = cumulative_gas_used_;
    receipt.bloom = logs_bloom(state_.logs());
    std::swap(receipt.logs, state_.logs());
}

uint64_t ExecutionProcessor::available_gas() const noexcept {
    return evm_.block().header.gas_limit - cumulative_gas_used_;
}

uint64_t ExecutionProcessor::refund_gas(const Transaction& txn, uint64_t gas_left, uint64_t gas_refund) noexcept {
    const evmc_revision rev{evm_.revision()};
    const auto version = evm_.get_eos_evm_version();
    assert(version < 3);
    if( version < 2 ) {
        const uint64_t max_refund_quotient{rev >= EVMC_LONDON ? protocol::kMaxRefundQuotientLondon
                                                            : protocol::kMaxRefundQuotientFrontier};
        const uint64_t max_refund{(txn.gas_limit - gas_left) / max_refund_quotient};
        uint64_t refund = std::min(gas_refund, max_refund);
        gas_left += refund;
    } else {
        gas_left += gas_refund;
        if( gas_left > txn.gas_limit - silkworm::protocol::fee::kGTransaction ) {
            gas_left = txn.gas_limit - silkworm::protocol::fee::kGTransaction;
        }
    }

    const intx::uint256 base_fee_per_gas{evm_.block().header.base_fee_per_gas.value_or(0)};
    const intx::uint256 effective_gas_price{txn.effective_gas_price(base_fee_per_gas)};
    state_.add_to_balance(*txn.from, gas_left * effective_gas_price);

    return gas_left;
}

ValidationResult ExecutionProcessor::execute_block_no_post_validation(std::vector<Receipt>& receipts) noexcept {
    const Block& block{evm_.block()};

    // Avoid calling dao_block() when the ruleset is kTrust to prevent triggering an assertion in the dao_block function
    if (evm_.config().protocol_rule_set != protocol::RuleSetType::kTrust && block.header.number == evm_.config().dao_block()) {
        dao::transfer_balances(state_);
    }

    cumulative_gas_used_ = 0;

    receipts.resize(block.transactions.size());
    auto receipt_it{receipts.begin()};
    for (const auto& txn : block.transactions) {
        if(is_reserved_address(*txn.from)) {
            //must mirror contract's initial state of reserved address
            state_.set_balance(*txn.from, txn.value + intx::uint256(txn.gas_limit) * txn.max_fee_per_gas);
            state_.set_nonce(*txn.from, txn.nonce);
        }
        const ValidationResult err{protocol::validate_transaction(txn, state_, available_gas())};
        if (err != ValidationResult::kOk) {
            return err;
        }
        execute_transaction(txn, *receipt_it);
        state_.reset_reserved_objects();
        ++receipt_it;
    }

    rule_set_.finalize(state_, block);

    if (evm_.revision() >= EVMC_SPURIOUS_DRAGON) {
        state_.destruct_touched_dead();
    }

    return ValidationResult::kOk;
}

ValidationResult ExecutionProcessor::execute_and_write_block(std::vector<Receipt>& receipts) noexcept {
    if (const ValidationResult res{execute_block_no_post_validation(receipts)}; res != ValidationResult::kOk) {
        return res;
    }

    const auto& header{evm_.block().header};

    if (evm_.config().protocol_rule_set != protocol::RuleSetType::kTrust && cumulative_gas_used_ != header.gas_used) {
        return ValidationResult::kWrongBlockGas;
    }

    if (evm_.config().protocol_rule_set != protocol::RuleSetType::kTrust && evm_.revision() >= EVMC_BYZANTIUM) {
        static constexpr auto kEncoder = [](Bytes& to, const Receipt& r) { rlp::encode(to, r); };
        evmc::bytes32 receipt_root{trie::root_hash(receipts, kEncoder)};
        if (receipt_root != header.receipts_root) {
            return ValidationResult::kWrongReceiptsRoot;
        }
    }

    Bloom bloom{};  // zero initialization
    for (const Receipt& receipt : receipts) {
        join(bloom, receipt.bloom);
    }
    if (evm_.config().protocol_rule_set != protocol::RuleSetType::kTrust && bloom != header.logs_bloom) {
        return ValidationResult::kWrongLogsBloom;
    }

    state_.write_to_db(header.number);

    return ValidationResult::kOk;
}

}  // namespace silkworm
