#include <silkworm/silkrpc/core/gas_parameters.hpp>
#include <silkworm/silkrpc/core/rawdb/chain.hpp>

namespace silkworm {

awaitable<std::tuple<uint64_t, evmone::gas_parameters>> load_gas_parameters(TransactionDatabase& tx_database, const silkworm::ChainConfig* chain_config_ptr, const silkworm::Block& block) {

    auto eos_evm_version = chain_config_ptr->eos_evm_version(block.header);
    evmone::gas_parameters gas_params;
    if(eos_evm_version > 0 && block.consensus_parameter_index.has_value()) {
        auto consensus_params = co_await silkworm::rpc::core::rawdb::read_consensus_parameters(tx_database, block.consensus_parameter_index.value());
        if(consensus_params.has_value() && consensus_params->gas_fee_parameters.has_value()) {
            gas_params=evmone::gas_parameters(
              consensus_params->gas_fee_parameters->gas_txnewaccount,
              consensus_params->gas_fee_parameters->gas_newaccount,
              consensus_params->gas_fee_parameters->gas_txcreate,
              consensus_params->gas_fee_parameters->gas_codedeposit,
              consensus_params->gas_fee_parameters->gas_sset
            );
        }
    }

    co_return std::make_tuple(eos_evm_version, gas_params);
}

}
