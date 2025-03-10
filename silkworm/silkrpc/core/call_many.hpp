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

#include <map>
#include <stack>
#include <string>
#include <vector>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/thread_pool.hpp>
#include <nlohmann/json.hpp>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wattributes"
#include <silkworm/core/execution/evm.hpp>
#pragma GCC diagnostic pop
#include <silkworm/core/state/intra_block_state.hpp>
#include <silkworm/silkrpc/common/block_cache.hpp>
#include <silkworm/silkrpc/core/evm_executor.hpp>
#include <silkworm/silkrpc/core/rawdb/accessors.hpp>
#include <silkworm/silkrpc/ethdb/kv/state_cache.hpp>
#include <silkworm/silkrpc/ethdb/transaction_database.hpp>
#include <silkworm/silkrpc/types/block.hpp>
#include <silkworm/silkrpc/types/call.hpp>
#include <silkworm/silkrpc/types/transaction.hpp>
#include <silkworm/silkrpc/core/gas_parameters.hpp>
#include <silkworm/core/types/gas_prices.hpp>

namespace silkworm::rpc::call {

struct CallManyResult {
    std::optional<std::string> error{std::nullopt};
    std::vector<std::vector<nlohmann::json>> results;
};

class CallExecutor {
  public:
    explicit CallExecutor(
        ethdb::Transaction& transaction,
        BlockCache& block_cache,
        boost::asio::thread_pool& workers)
        : transaction_(transaction), block_cache_(block_cache), workers_{workers} {}
    virtual ~CallExecutor() = default;

    CallExecutor(const CallExecutor&) = delete;
    CallExecutor& operator=(const CallExecutor&) = delete;

    boost::asio::awaitable<CallManyResult> execute(const Bundles& bundles, const SimulationContext& context, const AccountsOverrides& accounts_overrides, std::optional<std::uint64_t> timeout);

    CallManyResult executes_all_bundles(const silkworm::ChainConfig* config,
                                        const silkworm::BlockWithHash& block,
                                        ethdb::TransactionDatabase& tx_database,
                                        const Bundles& bundles,
                                        std::optional<std::uint64_t> opt_timeout,
                                        const AccountsOverrides& accounts_overrides,
                                        int32_t transaction_index,
                                        boost::asio::any_io_executor& executor,
                                        const evmone::gas_parameters& gas_params,
                                        const silkworm::gas_prices_t& gas_prices,
                                        uint64_t eos_evm_version);

  private:
    ethdb::Transaction& transaction_;
    BlockCache& block_cache_;
    boost::asio::thread_pool& workers_;
};
}  // namespace silkworm::rpc::call
