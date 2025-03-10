#include "refund_v3.hpp"

namespace eosevm {

std::tuple<silkworm::ExecutionResult, intx::uint256, uint64_t, uint64_t> gas_refund_v3(uint64_t eos_evm_version, const silkworm::CallResult& vm_res, const silkworm::Transaction& txn,
    const evmone::gas_parameters scaled_gas_params, const intx::uint256& price, const silkworm::gas_prices_t& gas_prices, const intx::uint256& inclusion_price) {

    uint64_t storage_gas_consumed{vm_res.storage_gas_consumed};
    const bool contract_creation{!txn.to};
    auto gas_left = vm_res.gas_left;
    if(contract_creation) {
        if( vm_res.status == EVMC_SUCCESS ) {
            storage_gas_consumed += scaled_gas_params.G_txcreate; //correct storage gas consumed to account for initial G_txcreate storage gas
        } else {
            gas_left += scaled_gas_params.G_txcreate;
        }
    }

    evmone::gas_state_t vm_res_gas_state(eos_evm_version, static_cast<int64_t>(vm_res.gas_refund),
            static_cast<int64_t>(storage_gas_consumed), static_cast<int64_t>(vm_res.storage_gas_refund), static_cast<int64_t>(vm_res.speculative_cpu_gas_consumed));

    gas_left += static_cast<uint64_t>(vm_res_gas_state.collapse());
    auto gas_used = txn.gas_limit - gas_left;
    assert(vm_res_gas_state.cpu_gas_refund() == 0);
    const auto total_storage_gas_consumed = static_cast<uint64_t>(vm_res_gas_state.storage_gas_consumed());
    assert(gas_used > total_storage_gas_consumed);
    const auto total_cpu_gas_consumed = gas_used - total_storage_gas_consumed;

    silkworm::ExecutionResult res;
    res.cpu_gas_consumed = total_cpu_gas_consumed;
    res.discounted_storage_gas_consumed = static_cast<uint64_t>(total_storage_gas_consumed);
    res.inclusion_fee = intx::uint256(total_cpu_gas_consumed)*inclusion_price;
    res.storage_fee = intx::uint256(total_storage_gas_consumed)*price;

    auto final_fee = price * gas_used;
    if(gas_prices.storage_price >= gas_prices.overhead_price) {
        intx::uint256 gas_refund = intx::uint256(total_cpu_gas_consumed);
        gas_refund *= intx::uint256(gas_prices.storage_price-gas_prices.overhead_price);
        if(price > 0) {
            gas_refund /= price;
        } else {
            gas_refund = 0;
        }

        SILKWORM_ASSERT(gas_refund <= gas_used);
        gas_left += static_cast<uint64_t>(gas_refund);
        assert(txn.gas_limit >= gas_left);
        gas_used = txn.gas_limit - gas_left;
        SILKWORM_ASSERT(gas_used >= total_storage_gas_consumed);
        final_fee = price * gas_used;

        assert(final_fee >= res.storage_fee);
        const auto overhead_and_inclusion_fee = final_fee - res.storage_fee;
        if( overhead_and_inclusion_fee >= res.inclusion_fee ) {
            res.overhead_fee = overhead_and_inclusion_fee - res.inclusion_fee;
        } else {
            res.inclusion_fee = overhead_and_inclusion_fee;
            res.overhead_fee = 0;
        }
    } else {
        res.overhead_fee = final_fee - res.inclusion_fee - res.storage_fee;
    }

    assert(final_fee == res.inclusion_fee + res.storage_fee + res.overhead_fee);
    return std::make_tuple(res, final_fee, gas_used, gas_left);
}

} // namespace eosevm
