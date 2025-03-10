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

#pragma once

#include <functional>
#include <optional>
#include <string>
#include <vector>

#include <silkworm/infra/concurrency/coroutine.hpp>

#include <boost/asio/awaitable.hpp>

#include <silkworm/core/chain/config.hpp>
#include <silkworm/core/common/util.hpp>
#include <silkworm/core/types/block.hpp>
#include <silkworm/silkrpc/core/blocks.hpp>
#include <silkworm/silkrpc/core/evm_executor.hpp>
#include <silkworm/silkrpc/core/rawdb/accessors.hpp>
#include <silkworm/silkrpc/ethdb/transaction.hpp>
#include <silkworm/silkrpc/ethdb/transaction_database.hpp>
#include <silkworm/silkrpc/types/call.hpp>
#include <silkworm/silkrpc/types/transaction.hpp>

namespace silkworm::rpc {

const std::uint64_t kTxGas = 21'000;
const std::uint64_t kGasCap = 100'000'000;

using BlockHeaderProvider = std::function<boost::asio::awaitable<silkworm::BlockHeader>(uint64_t)>;
using AccountReader = std::function<boost::asio::awaitable<std::optional<silkworm::Account>>(const evmc::address&, uint64_t)>;

struct EstimateGasException : public std::exception {
  public:
    EstimateGasException(int64_t error_code, std::string const& message)
        : error_code_{error_code}, message_{message}, data_{} {}

    EstimateGasException(int64_t error_code, std::string const& message, silkworm::Bytes const& data)
        : error_code_{error_code}, message_{message}, data_{data} {}

    virtual ~EstimateGasException() noexcept {}

    int64_t error_code() const {
        return error_code_;
    }

    const std::string& message() const {
        return message_;
    }

    const silkworm::Bytes& data() const {
        return data_;
    }

    virtual const char* what() const noexcept {
        return message_.c_str();
    }

  private:
    int64_t error_code_;
    std::string message_;
    silkworm::Bytes data_;
};

class EstimateGasOracle {
  public:
    explicit EstimateGasOracle(const BlockHeaderProvider& block_header_provider, const AccountReader& account_reader,
                               const silkworm::ChainConfig& config, boost::asio::thread_pool& workers, ethdb::Transaction& tx, ethdb::TransactionDatabase& tx_database)
        : block_header_provider_(block_header_provider), account_reader_{account_reader}, config_{config}, workers_{workers}, transaction_{tx}, tx_database_{tx_database} {}
    virtual ~EstimateGasOracle() {}

    EstimateGasOracle(const EstimateGasOracle&) = delete;
    EstimateGasOracle& operator=(const EstimateGasOracle&) = delete;

    boost::asio::awaitable<intx::uint256> estimate_gas(const Call& call, const silkworm::Block& latest_block);

  protected:
    virtual ExecutionResult try_execution(EVMExecutor& executor, const silkworm::Block& _block, const silkworm::Transaction& transaction, uint64_t eos_evm_version, const evmone::gas_parameters& gas_params, const silkworm::gas_prices_t& gas_prices);

  private:
    void throw_exception(ExecutionResult& result, uint64_t cap);

    const BlockHeaderProvider& block_header_provider_;
    const AccountReader& account_reader_;
    const silkworm::ChainConfig& config_;
    boost::asio::thread_pool& workers_;
    ethdb::Transaction& transaction_;
    ethdb::TransactionDatabase& tx_database_;
};

}  // namespace silkworm::rpc
