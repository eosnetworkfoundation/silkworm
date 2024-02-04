#include "consensus_parameters.hpp"

namespace eosevm {
bool operator==(const eosevm::GasFeeParameters& a, const eosevm::GasFeeParameters& b) { return a.to_json() == b.to_json(); }
bool operator==(const eosevm::ConsensusParameters& a, const eosevm::ConsensusParameters& b) { return a.to_json() == b.to_json(); }
} // namespace eosevm
