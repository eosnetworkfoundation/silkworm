#include "consensus_parameters.hpp"

namespace eosevm {
bool operator==(const eosevm::GasFeeParameters& a, const eosevm::GasFeeParameters& b) { 
    return a.gas_codedeposit == b.gas_codedeposit && a.gas_newaccount == b.gas_newaccount && 
    a.gas_sset == b.gas_sset && a.gas_txcreate == b.gas_txcreate && a.gas_txnewaccount == b.gas_txnewaccount; 
}

bool operator==(const eosevm::ConsensusParameters& a, const eosevm::ConsensusParameters& b) { 
    return a.min_gas_price == b.min_gas_price && a.gas_fee_parameters == b.gas_fee_parameters; }
} // namespace eosevm
