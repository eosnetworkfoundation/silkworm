#pragma once

#include <silkworm/core/execution/evm.hpp>
#include <silkworm/core/types/gas_prices.hpp>

namespace eosevm {

std::tuple<silkworm::ExecutionResult, intx::uint256, uint64_t, uint64_t> gas_refund_v3(uint64_t eos_evm_version, const silkworm::CallResult& vm_res, const silkworm::Transaction& txn,
    const evmone::gas_parameters scaled_gas_params, const intx::uint256& price, const silkworm::gas_prices_t& gas_prices, const intx::uint256& inclusion_price);

} // namespace eosevm
