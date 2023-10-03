#pragma once

#include <silkworm/core/protocol/rule_set.hpp>

namespace silkworm::protocol {

class TrustRuleSet : public IRuleSet {
  public:
    explicit TrustRuleSet(const ChainConfig& chain_config){
        (void)chain_config;
    }

    ValidationResult validate_seal(const BlockHeader& header) override {
        (void)header;
        return ValidationResult::kOk;
    };

    void initialize(EVM& evm) override {
        (void)evm;
    }

    BlockReward compute_reward(const Block& block) override {
        (void)block;
        return {};
    }

    void finalize(IntraBlockState& state, const Block& block) override {
        (void)state;
        (void)block;
    }

    //! \brief Performs validation of block body that can be done prior to sender recovery and execution.
    //! \brief See [YP] Sections 4.3.2 "Holistic Validity" and 11.1 "Ommer Validation".
    //! \param [in] block: block to pre-validate.
    //! \param [in] state: current state.
    //! \note Shouldn't be used for genesis block.
    ValidationResult pre_validate_block_body(const Block& block, const BlockState& state) override {
        (void)block;
        (void)state;
        return ValidationResult::kOk;
    }

    //! \brief See [YP] Section 4.3.4 "Block Header Validity".
    //! \param [in] header: header to validate.
    //! \param [in] with_future_timestamp_check : whether to check header timestamp is in the future wrt host current
    //! time \see https://github.com/torquem-ch/silkworm/issues/448
    //! \note Shouldn't be used for genesis block.
    ValidationResult validate_block_header(const BlockHeader& header, const BlockState& state,
                                           bool with_future_timestamp_check) override {
        (void)header;
        (void)state;
        (void)with_future_timestamp_check;
        return ValidationResult::kOk;
    }

    //! \brief Performs validation of block ommers only.
    //! \brief See [YP] Sections 11.1 "Ommer Validation".
    //! \param [in] block: block to validate.
    //! \param [in] state: current state.
    ValidationResult validate_ommers(const Block& block, const BlockState& state) override {
        (void)block;
        (void)state;
        return ValidationResult::kOk;
    }

    //! \brief See [YP] Section 11.3 "Reward Application".
    //! \param [in] header: Current block to get beneficiary from
    evmc::address get_beneficiary(const BlockHeader& header) override {
        return header.beneficiary;
    };

    //! \brief Returns parent header (if any) of provided header
    static std::optional<BlockHeader> get_parent_header(const BlockState& state, const BlockHeader& header) {
        (void)state;
        (void)header;
        return {};
    }
};

}  // namespace silkworm::protocol
