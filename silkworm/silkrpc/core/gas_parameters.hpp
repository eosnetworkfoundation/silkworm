#pragma once

#include <cstdint>
#include <tuple>

#include <boost/asio/awaitable.hpp>
#include <evmone/execution_state.hpp>
#include <silkworm/core/chain/config.hpp>
#include <silkworm/silkrpc/core/rawdb/accessors.hpp>
#include <silkworm/core/types/gas_prices.hpp>

using silkworm::rpc::core::rawdb::DatabaseReader;
using boost::asio::awaitable;

namespace silkworm {

    awaitable<std::tuple<uint64_t, evmone::gas_parameters, silkworm::gas_prices_t>> load_gas_parameters(const DatabaseReader& tx_database, const silkworm::ChainConfig* chain_config_ptr, const silkworm::Block& header);

}
