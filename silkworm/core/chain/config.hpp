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

#include <cstdint>
#include <map>
#include <optional>
#include <string_view>
#include <tuple>

#include <evmc/evmc.h>
#include <intx/intx.hpp>

#if not defined(ANTELOPE)
#include <nlohmann/json.hpp>
#endif

#include <silkworm/core/common/util.hpp>
#include <silkworm/core/common/assert.hpp>

namespace silkworm {

struct BlockHeader;

namespace protocol {

    //! \see IRuleSet
    enum class RuleSetType {
        kNoProof,
        kEthash,
        kClique,
        kAuRa,
        kTrust,
    };

}  // namespace protocol

struct ChainConfig {
    //! \brief Returns the chain identifier
    //! \see https://eips.ethereum.org/EIPS/eip-155
    uint64_t chain_id{0};

    //! \brief Holds the hash of genesis block
    std::optional<evmc::bytes32> genesis_hash;

    //! \brief Returns the type of the (pre-Merge) protocol rule set
    protocol::RuleSetType protocol_rule_set{protocol::RuleSetType::kNoProof};

    const std::optional<BlockNum>& homestead_block() const{
        SILKWORM_ASSERT(protocol_rule_set != protocol::RuleSetType::kTrust);
        return _homestead_block;
    }

    const std::optional<BlockNum>& dao_block() const{
        SILKWORM_ASSERT(protocol_rule_set != protocol::RuleSetType::kTrust);
        return _dao_block;
    }

    const std::optional<BlockNum>& tangerine_whistle_block() const{
        SILKWORM_ASSERT(protocol_rule_set != protocol::RuleSetType::kTrust);
        return _tangerine_whistle_block;
    }

    const std::optional<BlockNum>& spurious_dragon_block() const{
        SILKWORM_ASSERT(protocol_rule_set != protocol::RuleSetType::kTrust);
        return _spurious_dragon_block;
    }

    const std::optional<BlockNum>& byzantium_block() const{
        SILKWORM_ASSERT(protocol_rule_set != protocol::RuleSetType::kTrust);
        return _byzantium_block;
    }

    const std::optional<BlockNum>& constantinople_block() const{
        SILKWORM_ASSERT(protocol_rule_set != protocol::RuleSetType::kTrust);
        return _constantinople_block;
    }

    const std::optional<BlockNum>& petersburg_block() const{
        SILKWORM_ASSERT(protocol_rule_set != protocol::RuleSetType::kTrust);
        return _petersburg_block;
    }

    const std::optional<BlockNum>& istanbul_block() const{
        SILKWORM_ASSERT(protocol_rule_set != protocol::RuleSetType::kTrust);
        return _istanbul_block;
    }

    const std::optional<BlockNum>& muir_glacier_block() const{
        SILKWORM_ASSERT(protocol_rule_set != protocol::RuleSetType::kTrust);
        return _muir_glacier_block;
    }

    const std::optional<BlockNum>& berlin_block() const{
        SILKWORM_ASSERT(protocol_rule_set != protocol::RuleSetType::kTrust);
        return _berlin_block;
    }

    const std::optional<BlockNum>& london_block() const{
        SILKWORM_ASSERT(protocol_rule_set != protocol::RuleSetType::kTrust);
        return _london_block;
    }

    const std::optional<BlockNum>& arrow_glacier_block() const{
        SILKWORM_ASSERT(protocol_rule_set != protocol::RuleSetType::kTrust);
        return _arrow_glacier_block;
    }

    const std::optional<BlockNum>& gray_glacier_block() const{
        SILKWORM_ASSERT(protocol_rule_set != protocol::RuleSetType::kTrust);
        return _gray_glacier_block;
    }

    const std::optional<intx::uint256>& terminal_total_difficulty() const{
        SILKWORM_ASSERT(protocol_rule_set != protocol::RuleSetType::kTrust);
        return _terminal_total_difficulty;
    }

    const std::optional<BlockTime>& shanghai_time() const{
        SILKWORM_ASSERT(protocol_rule_set != protocol::RuleSetType::kTrust);
        return _shanghai_time;
    }

    const std::optional<BlockTime>& cancun_time() const{
        SILKWORM_ASSERT(protocol_rule_set != protocol::RuleSetType::kTrust);
        return _cancun_time;
    }

    const std::optional<BlockTime>& merge_netsplit_block() const{
        SILKWORM_ASSERT(protocol_rule_set != protocol::RuleSetType::kTrust);
        return _merge_netsplit_block;
    }

    // https://github.com/ethereum/execution-specs/tree/master/network-upgrades/mainnet-upgrades
    std::optional<BlockNum> _homestead_block{std::nullopt};
    std::optional<BlockNum> _dao_block{std::nullopt};
    std::optional<BlockNum> _tangerine_whistle_block{std::nullopt};
    std::optional<BlockNum> _spurious_dragon_block{std::nullopt};
    std::optional<BlockNum> _byzantium_block{std::nullopt};
    std::optional<BlockNum> _constantinople_block{std::nullopt};
    std::optional<BlockNum> _petersburg_block{std::nullopt};
    std::optional<BlockNum> _istanbul_block{std::nullopt};
    std::optional<BlockNum> _muir_glacier_block{std::nullopt};
    std::optional<BlockNum> _berlin_block{std::nullopt};
    std::optional<BlockNum> _london_block{std::nullopt};
    std::optional<BlockNum> _arrow_glacier_block{std::nullopt};
    std::optional<BlockNum> _gray_glacier_block{std::nullopt};

    //! \brief PoW to PoS switch
    //! \see EIP-3675: Upgrade consensus to Proof-of-Stake
    std::optional<intx::uint256> _terminal_total_difficulty{std::nullopt};
    std::optional<BlockNum> _merge_netsplit_block{std::nullopt};  // FORK_NEXT_VALUE in EIP-3675

    // Starting from Shanghai, forks are triggered by block time rather than number
    std::optional<BlockTime> _shanghai_time{std::nullopt};
    std::optional<BlockTime> _cancun_time{std::nullopt};

    // EOSEVM version
    std::optional<uint64_t> _version{std::nullopt};

    //! \brief Returns the revision level at given block number
    //! \details In other words, on behalf of Json chain config data
    //! returns whether specific HF have occurred
    [[nodiscard]] evmc_revision determine_revision_by_block(uint64_t block_number, uint64_t block_time) const noexcept;

    [[nodiscard]] evmc_revision revision(const BlockHeader& header) const noexcept;

    [[nodiscard]] std::vector<BlockNum> distinct_fork_numbers() const;
    [[nodiscard]] std::vector<BlockTime> distinct_fork_times() const;
    [[nodiscard]] std::vector<uint64_t> distinct_fork_points() const;

    //! \brief Return the JSON representation of this object
    #if not defined(ANTELOPE)
    [[nodiscard]] nlohmann::json to_json() const noexcept;
    #endif

    /*Sample JSON input:
    {
            "chainId":1,
            "homesteadBlock":1150000,
            "daoForkBlock":1920000,
            "eip150Block":2463000,
            "eip155Block":2675000,
            "byzantiumBlock":4370000,
            "constantinopleBlock":7280000,
            "petersburgBlock":7280000,
            "istanbulBlock":9069000,
            "muirGlacierBlock":9200000,
            "berlinBlock":12244000
    }
    */
    //! \brief Try parse a JSON object into strongly typed ChainConfig
    //! \remark Should this return std::nullopt the parsing has failed
    #if not defined(ANTELOPE)
    static std::optional<ChainConfig> from_json(const nlohmann::json& json) noexcept;
    #endif

    friend bool operator==(const ChainConfig&, const ChainConfig&);
};

std::ostream& operator<<(std::ostream& out, const ChainConfig& obj);

inline constexpr ChainConfig kEOSEVMMainnetConfig{
    .chain_id = 17777,
    .protocol_rule_set = protocol::RuleSetType::kTrust,
    ._homestead_block = 0,
    ._dao_block = 0,
    ._tangerine_whistle_block = 0,
    ._spurious_dragon_block = 0,
    ._byzantium_block = 0,
    ._constantinople_block = 0,
    ._petersburg_block = 0,
    ._istanbul_block = 0,
};

inline constexpr ChainConfig kEOSEVMOldTestnetConfig{
    .chain_id = 15555,
    .protocol_rule_set = protocol::RuleSetType::kTrust,
    ._homestead_block = 0,
    ._dao_block = 0,
    ._tangerine_whistle_block = 0,
    ._spurious_dragon_block = 0,
    ._byzantium_block = 0,
    ._constantinople_block = 0,
    ._petersburg_block = 0,
    ._istanbul_block = 0,
};

inline constexpr ChainConfig kEOSEVMTestnetConfig{
    .chain_id = 15557,
    .protocol_rule_set = protocol::RuleSetType::kTrust,
    ._homestead_block = 0,
    ._dao_block = 0,
    ._tangerine_whistle_block = 0,
    ._spurious_dragon_block = 0,
    ._byzantium_block = 0,
    ._constantinople_block = 0,
    ._petersburg_block = 0,
    ._istanbul_block = 0,
};

inline constexpr ChainConfig kEOSEVMLocalTestnetConfig{
    .chain_id = 25555,
    .protocol_rule_set = protocol::RuleSetType::kTrust,
    ._homestead_block = 0,
    ._dao_block = 0,
    ._tangerine_whistle_block = 0,
    ._spurious_dragon_block = 0,
    ._byzantium_block = 0,
    ._constantinople_block = 0,
    ._petersburg_block = 0,
    ._istanbul_block = 0,
};

inline constexpr evmc::bytes32 kMainnetGenesisHash{0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3_bytes32};
inline constexpr ChainConfig kMainnetConfig{
    .chain_id = 1,
    .protocol_rule_set = protocol::RuleSetType::kEthash,
    ._homestead_block = 1'150'000,
    ._dao_block = 1'920'000,
    ._tangerine_whistle_block = 2'463'000,
    ._spurious_dragon_block = 2'675'000,
    ._byzantium_block = 4'370'000,
    ._constantinople_block = 7'280'000,
    ._petersburg_block = 7'280'000,
    ._istanbul_block = 9'069'000,
    ._muir_glacier_block = 9'200'000,
    ._berlin_block = 12'244'000,
    ._london_block = 12'965'000,
    ._arrow_glacier_block = 13'773'000,
    ._gray_glacier_block = 15'050'000,
    ._terminal_total_difficulty = intx::from_string<intx::uint256>("58750000000000000000000"),
    ._shanghai_time = 1681338455,
};

inline constexpr evmc::bytes32 kGoerliGenesisHash{0xbf7e331f7f7c1dd2e05159666b3bf8bc7a8a3a9eb1d518969eab529dd9b88c1a_bytes32};
inline constexpr ChainConfig kGoerliConfig{
    .chain_id = 5,
    .protocol_rule_set = protocol::RuleSetType::kClique,
    ._homestead_block = 0,
    ._tangerine_whistle_block = 0,
    ._spurious_dragon_block = 0,
    ._byzantium_block = 0,
    ._constantinople_block = 0,
    ._petersburg_block = 0,
    ._istanbul_block = 1'561'651,
    ._berlin_block = 4'460'644,
    ._london_block = 5'062'605,
    ._terminal_total_difficulty = 10790000,
    ._shanghai_time = 1678832736,
};

inline constexpr evmc::bytes32 kSepoliaGenesisHash{0x25a5cc106eea7138acab33231d7160d69cb777ee0c2c553fcddf5138993e6dd9_bytes32};
inline constexpr ChainConfig kSepoliaConfig{
    .chain_id = 11155111,
    .protocol_rule_set = protocol::RuleSetType::kEthash,
    ._homestead_block = 0,
    ._tangerine_whistle_block = 0,
    ._spurious_dragon_block = 0,
    ._byzantium_block = 0,
    ._constantinople_block = 0,
    ._petersburg_block = 0,
    ._istanbul_block = 0,
    ._muir_glacier_block = 0,
    ._berlin_block = 0,
    ._london_block = 0,
    ._terminal_total_difficulty = 17000000000000000,
    ._merge_netsplit_block = 1'735'371,
    ._shanghai_time = 1677557088,
};

//! \brief Looks up a known chain config provided its chain ID
std::optional<std::pair<const std::string, const ChainConfig*>> lookup_known_chain(uint64_t chain_id) noexcept;

//! \brief Looks up a known chain config provided its chain identifier (eg. "mainnet")
std::optional<std::pair<const std::string, const ChainConfig*>> lookup_known_chain(std::string_view identifier) noexcept;

//! \brief Returns a map known chains names mapped to their respective chain ids
std::map<std::string, uint64_t> get_known_chains_map() noexcept;

}  // namespace silkworm
