/*
   Copyright 2023 The Silkworm Authors

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

#include "estimate_gas_oracle.hpp"
#include <silkworm/silkrpc/core/gas_parameters.hpp>

#include <string>

#include <boost/asio/compose.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <silkworm/infra/common/log.hpp>
#include <silkworm/silkrpc/core/blocks.hpp>
#include <eosevm/version.hpp>
namespace silkworm::rpc {

boost::asio::awaitable<intx::uint256> EstimateGasOracle::estimate_gas(const Call& call, const silkworm::Block& block) {
    SILK_DEBUG << "EstimateGasOracle::estimate_gas called";

    auto block_number = block.header.number;

    uint64_t hi;
    uint64_t lo = kTxGas - 1;

    if (call.gas.value_or(0) >= kTxGas) {
        SILK_DEBUG << "Set HI with gas in args: " << call.gas.value_or(0);
        hi = call.gas.value();
    } else {
        const auto header = co_await block_header_provider_(block_number);
        hi = header.gas_limit;
        SILK_DEBUG << "Evaluate HI with gas in block " << header.gas_limit;
    }

    intx::uint256 gas_price = call.gas_price.value_or(0);
    if (gas_price != 0) {
        evmc::address from = call.from.value_or(evmc::address{0});

        std::optional<silkworm::Account> account{co_await account_reader_(from, block_number + 1)};

        intx::uint256 balance = account->balance;
        SILK_DEBUG << "balance for address 0x" << from << ": 0x" << intx::hex(balance);
        if (call.value.value_or(0) > balance) {
            // TODO(sixtysixter) what is the right error code?
            throw EstimateGasException{-1, "insufficient funds for transfer"};
        }
        auto available = balance - call.value.value_or(0);
        auto allowance = available / gas_price;
        SILK_DEBUG << "allowance: " << allowance << ", available: 0x" << intx::hex(available) << ", balance: 0x" << intx::hex(balance);
        if (hi > allowance) {
            SILK_WARN << "gas estimation capped by limited funds: original " << hi
                      << ", balance 0x" << intx::hex(balance)
                      << ", sent " << intx::hex(call.value.value_or(0))
                      << ", gasprice " << intx::hex(gas_price)
                      << ", allowance " << allowance;
            hi = uint64_t(allowance);
        }
    }

    if (hi > kGasCap) {
        SILK_WARN << "caller gas above allowance, capping: requested " << hi << ", cap " << kGasCap;
        hi = kGasCap;
    }
    auto cap = hi;

    SILK_DEBUG << "hi: " << hi << ", lo: " << lo << ", cap: " << cap;

    const auto [eos_evm_version, gas_params, gas_prices_orig] = co_await load_gas_parameters(tx_database_, &config_, block);
    silkworm::Transaction transaction{call.to_transaction()};

    // If conservative gas estimation is signaled, assert that inclusion_price is zero and adjust gas_prices if neccesary
    silkworm::gas_prices_t gas_prices = gas_prices_orig;
    if( eos_evm_version >= eosevm::EVM_VERSION_3 && call.gas.has_value() && call.gas.value() == 0 ) {
        auto base_fee_per_gas = gas_prices.get_base_price();
        auto inclusion_price = std::min(transaction.max_priority_fee_per_gas, transaction.max_fee_per_gas >= base_fee_per_gas ? transaction.max_fee_per_gas - base_fee_per_gas : 0);
        if( inclusion_price > 0 ) {
            throw EstimateGasException{-32000, "inclusion_price must be 0"};
        }
        if(gas_prices.storage_price != gas_prices.overhead_price) {
            gas_prices.storage_price = base_fee_per_gas;
            gas_prices.overhead_price = base_fee_per_gas;
        }
    }

    auto this_executor = co_await boost::asio::this_coro::executor;
    auto exec_result = co_await boost::asio::async_compose<decltype(boost::asio::use_awaitable), void(ExecutionResult)>(
        [&](auto&& self) {
            boost::asio::post(workers_, [&, self = std::move(self)]() mutable {
                auto state = transaction_.create_state(this_executor, tx_database_, block_number);
                EVMExecutor executor{config_, workers_, state};

                ExecutionResult result{evmc_status_code::EVMC_SUCCESS};
                if(!transaction.from.has_value()) transaction.from = evmc::address{0};
                while (lo + 1 < hi) {
                    auto mid = (hi + lo) / 2;
                    transaction.gas_limit = mid;

                    result = try_execution(executor, block, transaction, eos_evm_version, gas_params, gas_prices);

                    if(result.pre_check_error && !result.pre_check_error.value().starts_with("intrinsic gas too low")) {
                        boost::asio::post(this_executor, [result, self = std::move(self)]() mutable {
                            self.complete(result);
                        });
                        return;
                    }

                    if (result.success()) {
                        hi = mid;
                    } else {
                        lo = mid;
                    }
                }

                if (hi == cap) {
                    transaction.gas_limit = hi;
                    result = try_execution(executor, block, transaction, eos_evm_version, gas_params, gas_prices);
                    SILK_DEBUG << "HI == cap tested again with " << (result.success() ? "succeed" : "failed");
                } else {
                    result.pre_check_error = std::nullopt;
                    result.error_code = EVMC_SUCCESS;
                }

                boost::asio::post(this_executor, [result, self = std::move(self)]() mutable {
                    self.complete(result);
                });
            });
        },
        boost::asio::use_awaitable);

    if (exec_result.success() == false) {
        throw_exception(exec_result, cap);
    }

    SILK_DEBUG << "EstimateGasOracle::estimate_gas returns " << hi;
    co_return hi;
}

ExecutionResult EstimateGasOracle::try_execution(EVMExecutor& executor, const silkworm::Block& block, const silkworm::Transaction& transaction, uint64_t eos_evm_version, const evmone::gas_parameters& gas_params, const silkworm::gas_prices_t& gas_prices) {
    executor.reset_all();
    return executor.call(block, transaction, gas_params, gas_prices, eos_evm_version, {}, true, false);
}

void EstimateGasOracle::throw_exception(ExecutionResult& result, uint64_t cap) {
    if (result.pre_check_error) {
        SILK_DEBUG << "result error " << result.pre_check_error.value();
        throw EstimateGasException{-32000, result.pre_check_error.value()};
    }
    if(result.error_code != evmc_status_code::EVMC_OUT_OF_GAS) {
        const auto error_message = EVMExecutor::get_error_message(result.error_code.value(), result.data, true);
        SILK_DEBUG << "result message " << error_message << ", code " << result.error_code.value();
        if (result.data.empty()) {
            throw EstimateGasException{-32000, error_message};
        } else {
            throw EstimateGasException{3, error_message, result.data};
        }
    }
    throw EstimateGasException{-1, "gas required exceeds allowance (" + std::to_string(cap) + ")"};
}
}  // namespace silkworm::rpc
