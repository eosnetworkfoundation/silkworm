#pragma once

#include <cstdint>
#include <tuple>

#include <boost/asio/awaitable.hpp>
#include <evmone/execution_state.hpp>
#include <silkworm/core/chain/config.hpp>
#include <silkworm/silkrpc/ethdb/transaction_database.hpp>

using silkworm::rpc::ethdb::TransactionDatabase;
using boost::asio::awaitable;

namespace silkworm {

    awaitable<std::tuple<uint64_t, evmone::gas_parameters>> load_gas_parameters(TransactionDatabase& tx_database, const silkworm::ChainConfig* chain_config_ptr, const silkworm::Block& header);

}
