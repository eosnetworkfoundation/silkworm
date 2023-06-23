/*
   Copyright 2022 The Silkworm Authors

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

#include <silkworm/consensus/engine.hpp>

#include <silkworm/consensus/validation.hpp>
#include <silkworm/state/intra_block_state.hpp>
#include <silkworm/state/state.hpp>
#include <silkworm/types/receipt.hpp>

namespace silkworm::consensus {

using silkworm::Block;
using silkworm::BlockState;
using silkworm::BlockHeader;
using silkworm::ChainConfig;

class TrustEngine : public IEngine {
  public:
    explicit TrustEngine(const ChainConfig& chain_config) { (void)chain_config; }

    ValidationResult pre_validate_block_body(const Block& block, const BlockState& state) override {
        (void)block;
        (void)state;
        return ValidationResult::kOk;
    }

    ValidationResult validate_ommers(const Block& block, const BlockState& state) override {
        (void)block;
        (void)state;
        return ValidationResult::kOk;
    }

    ValidationResult validate_block_header(const BlockHeader& header, const BlockState& state,
                                                   bool with_future_timestamp_check) override {
        (void)header;
        (void)state;
        (void)with_future_timestamp_check;
        return ValidationResult::kOk;
    }

    ValidationResult validate_seal(const BlockHeader& header) override {
        (void)header;
        return ValidationResult::kOk;
    }

    void finalize(IntraBlockState& state, const Block& block, evmc_revision revision) override {
        (void)state;
        (void)block;
        (void)revision;
    }

    evmc::address get_beneficiary(const BlockHeader& header) override {
        return header.beneficiary;
    }
};

}  // namespace silkworm::consensus
