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

#include <functional>
#include <stack>
#include <vector>

#include <evmone/baseline.hpp>
#include <evmone/execution_state.hpp>
#include <intx/intx.hpp>

#include <silkworm/core/chain/config.hpp>
#include <silkworm/core/common/lru_cache.hpp>
#include <silkworm/core/common/object_pool.hpp>
#include <silkworm/core/common/util.hpp>
#include <silkworm/core/state/intra_block_state.hpp>
#include <silkworm/core/types/block.hpp>

namespace silkworm {
struct ExecutionResult {
  // inclusion_fee+overhead_fee+storage_fee == receipt.cumulative_gas_used*effective_price
  uint64_t discounted_storage_gas_consumed{0};
  uint64_t cpu_gas_consumed{0};
  intx::uint256 overhead_fee;  //approx. => cpu_gas_consumed * overhead_price
  intx::uint256 inclusion_fee; //approx. => cpu_gas_consumed * inclusion_price
  intx::uint256 storage_fee;   //exactly => discounted_storage_gas_consumed * effective_price
};

struct CallResult {
    evmc_status_code status{EVMC_SUCCESS};
    uint64_t gas_left{0};
    uint64_t gas_refund{0};
    uint64_t storage_gas_consumed{0};
    uint64_t storage_gas_refund{0};
    uint64_t speculative_cpu_gas_consumed{0};
    Bytes data;
};

class EvmTracer {
  public:
    virtual ~EvmTracer() = default;

    virtual void on_execution_start(evmc_revision rev, const evmc_message& msg, evmone::bytes_view code) noexcept = 0;

    virtual void on_instruction_start(uint32_t pc, const intx::uint256* stack_top, int stack_height,
                                      int64_t gas, const evmone::ExecutionState& state,
                                      const IntraBlockState& intra_block_state) noexcept = 0;

    virtual void on_execution_end(const evmc_result& result, const IntraBlockState& intra_block_state) noexcept = 0;

    virtual void on_creation_completed(const evmc_result& result, const IntraBlockState& intra_block_state) noexcept = 0;

    virtual void on_precompiled_run(const evmc_result& result, int64_t gas,
                                    const IntraBlockState& intra_block_state) noexcept = 0;

    virtual void on_reward_granted(const CallResult& result, const IntraBlockState& intra_block_state) noexcept = 0;
};

using EvmTracers = std::vector<std::reference_wrapper<EvmTracer>>;

using AnalysisCache = lru_cache<evmc::bytes32, std::shared_ptr<evmone::baseline::CodeAnalysis>>;

using FilterFunction = std::function<bool(const evmc_message&)>;

class EVM {
  public:
    // Not copyable nor movable
    EVM(const EVM&) = delete;
    EVM& operator=(const EVM&) = delete;

    EVM(const Block& block, IntraBlockState& state, const ChainConfig& config)
    noexcept;

    ~EVM();

    [[nodiscard]] const Block& block() const noexcept { return block_; }

    [[nodiscard]] const ChainConfig& config() const noexcept { return config_; }

    IntraBlockState& state() noexcept { return state_; }
    [[nodiscard]] const IntraBlockState& state() const noexcept { return state_; }

    // Precondition: txn.from must be recovered
    CallResult execute(const Transaction& txn, uint64_t gas, const evmone::gas_parameters& gas_params) noexcept;

    [[nodiscard]] evmc_revision revision() const noexcept;

    void add_tracer(EvmTracer& tracer) noexcept;
    [[nodiscard]] const EvmTracers& tracers() const noexcept { return tracers_; };

    bool account_exists(const evmc::address& address) const noexcept;

    AnalysisCache* analysis_cache{nullptr};                   // provide one for better performance
    ObjectPool<evmone::ExecutionState>* state_pool{nullptr};  // ditto

    evmc_vm* exo_evm{nullptr};  // it's possible to use an exogenous EVMC VM

    evmc::address beneficiary;  // block.header.beneficiary by default; may be overridden for Clique

    void set_message_filter(std::optional<FilterFunction> message_filter) {
      message_filter_ = message_filter;
    }

    uint64_t get_eos_evm_version()const {
      return eos_evm_version_;
    }

  private:
    friend class EvmHost;

    evmc::Result create(const evmc_message& message) noexcept;

    evmc::Result call(const evmc_message& message) noexcept;

    evmc_result execute(const evmc_message& message, ByteView code, const evmc::bytes32* code_hash) noexcept;

    evmc_result execute_with_baseline_interpreter(evmc_revision rev, const evmc_message& message, ByteView code,
                                                  const evmc::bytes32* code_hash) noexcept;

    gsl::owner<evmone::ExecutionState*> acquire_state() const noexcept;
    void release_state(gsl::owner<evmone::ExecutionState*> state) const noexcept;

    const Block& block_;
    IntraBlockState& state_;
    const ChainConfig& config_;
    const Transaction* txn_{nullptr};
    std::vector<evmc::bytes32> block_hashes_{};
    EvmTracers tracers_;

    evmc_vm* evm1_{nullptr};
    std::optional<FilterFunction> message_filter_;

    evmone::gas_parameters gas_params_;
    uint64_t eos_evm_version_=0;
};

class EvmHost : public evmc::Host {
  public:
    explicit EvmHost(EVM& evm) noexcept : evm_{evm} {}

    [[nodiscard]] bool account_exists(const evmc::address& address) const noexcept override;

    evmc_access_status access_account(const evmc::address& address) noexcept override;

    evmc_access_status access_storage(const evmc::address& address, const evmc::bytes32& key) noexcept override;

    [[nodiscard]] evmc::bytes32 get_storage(const evmc::address& address, const evmc::bytes32& key) const noexcept override;

    evmc_storage_status set_storage(const evmc::address& address, const evmc::bytes32& key,
                                    const evmc::bytes32& value) noexcept override;

    [[nodiscard]] evmc::uint256be get_balance(const evmc::address& address) const noexcept override;

    [[nodiscard]] size_t get_code_size(const evmc::address& address) const noexcept override;

    [[nodiscard]] evmc::bytes32 get_code_hash(const evmc::address& address) const noexcept override;

    size_t copy_code(const evmc::address& address, size_t code_offset, uint8_t* buffer_data,
                     size_t buffer_size) const noexcept override;

    bool selfdestruct(const evmc::address& address, const evmc::address& beneficiary) noexcept override;

    evmc::Result call(const evmc_message& message) noexcept override;

    [[nodiscard]] evmc_tx_context get_tx_context() const noexcept override;

    [[nodiscard]] evmc::bytes32 get_block_hash(int64_t block_number) const noexcept override;

    void emit_log(const evmc::address& address, const uint8_t* data, size_t data_size, const evmc::bytes32 topics[],
                  size_t num_topics) noexcept override;

  private:
    EVM& evm_;
};

}  // namespace silkworm
