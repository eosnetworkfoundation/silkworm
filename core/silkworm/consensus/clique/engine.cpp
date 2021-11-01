/*
   Copyright 2021 The Silkworm Authors

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

#include "engine.hpp"

#include <silkworm/common/endian.hpp>

namespace silkworm::consensus {

ValidationResult ConsensusEngineClique::validate_block_header(const BlockHeader& header, State& state,
                                                              bool with_future_timestamp_check) {
    auto err{base::validate_block_header(header, state, with_future_timestamp_check)};
    if (err != ValidationResult::kOk) {
        return err;
    }

    // Checkpoint blocks need to enforce zero beneficiary
    const bool is_check_point{(header.number % kEpochLength) == 0};
    if (is_check_point && header.beneficiary) {
        return ValidationResult::kInvalidCheckPointBeneficiary;
    }

    // Nonces must be 0x00..0 or 0xff..f, zeroes enforced on checkpoints
    auto nonce_u64{endian::load_big_u64(header.nonce.data())};
    if (nonce_u64 && nonce_u64 != UINT64_MAX) {
        return ValidationResult::kInvalidVote;
    }
    if (is_check_point && nonce_u64) {
        return ValidationResult::kInvalidCheckPointVote;
    }

    // Check that the extra-data contains both the vanity and signature
    if (header.extra_data.length() < kVanityLen) {
        return ValidationResult::kMissingVanity;
    }
    if (header.extra_data.length() < kVanityLen + kSignatureLen) {
        return ValidationResult::kMissingSignature;
    }

    // Ensure that the extra-data contains a signer list on checkpoint, but none otherwise
    auto signers_bytes_len{header.extra_data.length() - kVanityLen - kSignatureLen};
    if (is_check_point) {
        if (signers_bytes_len % kAddressLength != 0) {
            return ValidationResult::kInvalidCheckPointSigners;
        }
    } else {
        if (signers_bytes_len) {
            return ValidationResult::kInvalidExtraSigners;
        }
    }

    // Ensure that the mix digest is zero as we don't have fork protection currently
    if (header.mix_hash) {
        return ValidationResult::kInvalidMixHash;
    }

    // Ensure that the block doesn't contain any uncles which are meaningless in PoA
    if (header.ommers_hash != kEmptyListHash) {
        return ValidationResult::kWrongOmmersHash;
    }

    // Ensure that the block's difficulty is meaningful (may not be correct at this point)
    if (header.number) {
        if (!header.difficulty || header.difficulty > 2) {
            return ValidationResult::kInvalidDifficulty;
        }
    }

    // Ensure time interval amongst this header and its ancestor is not shorter than
    // minimum interval
    const std::optional<BlockHeader> parent{get_parent_header(state, header)};
    if (parent->timestamp + kMinBlockInterval > header.timestamp) {
        return ValidationResult::kInvalidTimestamp;
    }

    // If the block is a checkpoint block, verify the signer list
    // matches the list of voted signers for current epoch
    // TODO (Andrea)
}

ValidationResult ConsensusEngineClique::validate_seal(const BlockHeader& header) {
    throw std::runtime_error(std::string(__FUNCTION__) + " not yet implemented");
}

void ConsensusEngineClique::finalize(IntraBlockState& state, const Block& block, const evmc_revision& revision) {
    throw std::runtime_error(std::string(__FUNCTION__) + " not yet implemented");
}

}  // namespace silkworm::consensus
