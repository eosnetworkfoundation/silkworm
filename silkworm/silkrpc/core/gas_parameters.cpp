#include <silkworm/silkrpc/core/rawdb/chain.hpp>
#include <silkworm/silkrpc/core/gas_parameters.hpp>
namespace silkworm {

awaitable<std::tuple<uint64_t, evmone::gas_parameters, silkworm::gas_prices_t>> load_gas_parameters(const DatabaseReader& tx_database, const silkworm::ChainConfig* chain_config_ptr, const silkworm::Block& block) {

    auto eos_evm_version = chain_config_ptr->eos_evm_version(block.header);
    evmone::gas_parameters gas_params;
    silkworm::gas_prices_t gas_prices;
    if(eos_evm_version > 0) {
        auto block_index = block.get_consensus_parameter_index();
        auto gas_price_index = block.get_gas_prices_index();
        auto consensus_params = co_await silkworm::rpc::core::rawdb::read_consensus_parameters(tx_database, block_index);
        if(consensus_params.has_value() && consensus_params->gas_fee_parameters.has_value()) {
            gas_params=evmone::gas_parameters(
              consensus_params->gas_fee_parameters->gas_txnewaccount,
              consensus_params->gas_fee_parameters->gas_newaccount,
              consensus_params->gas_fee_parameters->gas_txcreate,
              consensus_params->gas_fee_parameters->gas_codedeposit,
              consensus_params->gas_fee_parameters->gas_sset
            );
        }
        if(eos_evm_version >= 3 && gas_price_index.has_value()) {
            auto gp = co_await silkworm::rpc::core::rawdb::read_gas_prices(tx_database, *gas_price_index);
            if(gp.has_value()) {
                gas_prices.overhead_price = gp->overhead_price;
                gas_prices.storage_price = gp->storage_price;
            }
        }
    }

    co_return std::make_tuple(eos_evm_version, gas_params, gas_prices);
}

}
