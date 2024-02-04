#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <string_view>
#include <tuple>
#include <string>

#include <intx/intx.hpp>

#if not defined(ANTELOPE)
#include <nlohmann/json.hpp>
#endif

#include <silkworm/core/common/util.hpp>
#include <silkworm/core/common/assert.hpp>
#include <silkworm/core/types/block.hpp>

namespace eosevm {

struct GasFeeParameters {
    // gas_txnewaccount = account_bytes * gas_per_byte
    uint64_t gas_txnewaccount;
    // gas_newaccount = account_bytes * gas_per_byte
    uint64_t gas_newaccount;
    // gas_txcreate = gas_create = contract_fixed_bytes * gas_per_byte
    uint64_t gas_txcreate;
    // gas_codedeposit = gas_per_byte
    uint64_t gas_codedeposit;
    // gas_sset = 100 + storage_slot_bytes * gas_per_byte 
    uint64_t gas_sset;

    #if not defined(ANTELOPE)
    [[nodiscard]] nlohmann::json to_json() const noexcept  {
        nlohmann::json ret;
        ret["gasTxnewaccount"] = gas_txnewaccount;
        ret["gasNewaccount"] = gas_newaccount;
        ret["gasTxcreate"] = gas_txcreate;
        ret["gasCodedeposit"] = gas_codedeposit;
        ret["gasSset"] = gas_sset;

        return ret;
    }
    #endif

    //! \brief Try parse a JSON object into strongly typed ChainConfig
    //! \remark Should this return std::nullopt the parsing has failed
    #if not defined(ANTELOPE)

    static std::optional<GasFeeParameters> from_json(const nlohmann::json& json) noexcept {
        GasFeeParameters feeParams;

        if (!json.contains("gasTxnewaccount") || !json.contains("gasNewaccount") || !json.contains("gasTxcreate") || 
            !json.contains("gasCodedeposit") || !json.contains("gasSset")) {
            // Faii if any of the parameters are missing.
            return std::nullopt;
        }
        
        feeParams.gas_txnewaccount = json["gasTxnewaccount"].get<uint64_t>();
        feeParams.gas_newaccount = json["gasNewaccount"].get<uint64_t>();
        feeParams.gas_txcreate = json["gasTxcreate"].get<uint64_t>();
        feeParams.gas_codedeposit = json["gasCodedeposit"].get<uint64_t>();
        feeParams.gas_sset = json["gasSset"].get<uint64_t>();

        return feeParams;
    }

    #endif

    friend bool operator==(const GasFeeParameters&, const GasFeeParameters&);
};

struct ConsensusParameters {
    std::optional<intx::uint256>  min_gas_price;
    std::optional<GasFeeParameters> gas_fee_parameters;

    //! \brief Return the JSON representation of this object
    #if not defined(ANTELOPE)
    [[nodiscard]] nlohmann::json to_json() const noexcept  {

        nlohmann::json ret;
        if (min_gas_price) {
            ret["minGasPrice"] = intx::to_string(min_gas_price.value());
        }
        if (gas_fee_parameters) {
            ret["gasFeeParameters"] = gas_fee_parameters.value().to_json();
        }

        return ret;
    };
    #endif

    //! \brief Try parse a JSON object into strongly typed ChainConfig
    //! \remark Should this return std::nullopt the parsing has failed
    #if not defined(ANTELOPE)
    static std::optional<ConsensusParameters> from_json(const nlohmann::json& json) noexcept {
        ConsensusParameters config{};
        if (json.contains("minGasPrice")) {
                config.min_gas_price = intx::from_string<intx::uint256>(json["minGasPrice"].get<std::string>());
        }
        
        if (json.contains("gasFeeParameters")) {
            // Can be nullopt if parsing GasFeeParameters failed.
            config.gas_fee_parameters = GasFeeParameters::from_json(json["gasFeeParameters"]);
        }

        return config;
    }
    #endif

    friend bool operator==(const ConsensusParameters&, const ConsensusParameters&);
};
} // namespace eosevm