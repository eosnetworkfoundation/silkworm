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

#include "config.hpp"

#include <algorithm>
#include <functional>
#include <set>

#include <silkworm/core/common/as_range.hpp>
#include <silkworm/core/types/block.hpp>
#include <eosevm/version.hpp>

namespace silkworm {

static std::vector<std::pair<std::string, const ChainConfig*>> kKnownChainConfigs{
    {"mainnet", new ChainConfig(get_kMainnetConfig())},
    {"goerli", new ChainConfig(get_kGoerliConfig())},
    {"sepolia", new ChainConfig(get_kSepoliaConfig())},
};

constexpr const char* kTerminalTotalDifficulty{"terminalTotalDifficulty"};

#if not defined(ANTELOPE)

static inline void member_to_json(nlohmann::json& json, const std::string& key, const std::optional<uint64_t>& source) {
    if (source.has_value()) {
        json[key] = source.value();
    }
}

static inline void read_json_config_member(const nlohmann::json& json, const std::string& key,
                                           std::optional<uint64_t>& target) {
    if (json.contains(key)) {
        target = json[key].get<uint64_t>();
    }
}

nlohmann::json ChainConfig::to_json() const noexcept {
    nlohmann::json ret;

    ret["chainId"] = chain_id;

    nlohmann::json empty_object(nlohmann::json::value_t::object);
    switch (protocol_rule_set) {
        case protocol::RuleSetType::kEthash:
            ret.emplace("ethash", empty_object);
            break;
        case protocol::RuleSetType::kClique:
            ret.emplace("clique", empty_object);
            break;
        case protocol::RuleSetType::kAuRa:
            ret.emplace("aura", empty_object);
            break;
        case protocol::RuleSetType::kTrust:
            ret.emplace("trust", empty_object);
            break;
        default:
            break;
    }

    member_to_json(ret, "homesteadBlock", _homestead_block);
    member_to_json(ret, "daoForkBlock", _dao_block);
    member_to_json(ret, "eip150Block", _tangerine_whistle_block);
    member_to_json(ret, "eip155Block", _spurious_dragon_block);
    member_to_json(ret, "byzantiumBlock", _byzantium_block);
    member_to_json(ret, "constantinopleBlock", _constantinople_block);
    member_to_json(ret, "petersburgBlock", _petersburg_block);
    member_to_json(ret, "istanbulBlock", _istanbul_block);
    member_to_json(ret, "muirGlacierBlock", _muir_glacier_block);
    member_to_json(ret, "berlinBlock", _berlin_block);
    member_to_json(ret, "londonBlock", _london_block);
    member_to_json(ret, "arrowGlacierBlock", _arrow_glacier_block);
    member_to_json(ret, "grayGlacierBlock", _gray_glacier_block);

    if (_terminal_total_difficulty) {
        // TODO (Andrew) geth probably treats terminalTotalDifficulty as a JSON number
        ret[kTerminalTotalDifficulty] = to_string(*_terminal_total_difficulty);
    }

    member_to_json(ret, "mergeNetsplitBlock", _merge_netsplit_block);
    member_to_json(ret, "shanghaiTime", _shanghai_time);
    member_to_json(ret, "cancunTime", _cancun_time);

    if (genesis_hash.has_value()) {
        ret["genesisBlockHash"] = to_hex(*genesis_hash, /*with_prefix=*/true);
    }

    member_to_json(ret, "version", _version);

    return ret;
}

std::optional<ChainConfig> ChainConfig::from_json(const nlohmann::json& json) noexcept {
    if (json.is_discarded() || !json.contains("chainId") || !json["chainId"].is_number()) {
        return std::nullopt;
    }

    ChainConfig config{};
    config.chain_id = json["chainId"].get<uint64_t>();

    if (json.contains("ethash")) {
        config.protocol_rule_set = protocol::RuleSetType::kEthash;
    } else if (json.contains("clique")) {
        config.protocol_rule_set = protocol::RuleSetType::kClique;
    } else if (json.contains("aura")) {
        config.protocol_rule_set = protocol::RuleSetType::kAuRa;
    } else if (json.contains("trust")) {
        config.protocol_rule_set = protocol::RuleSetType::kTrust;
    } else {
        config.protocol_rule_set = protocol::RuleSetType::kNoProof;
    }

    read_json_config_member(json, "homesteadBlock", config._homestead_block);
    read_json_config_member(json, "daoForkBlock", config._dao_block);
    read_json_config_member(json, "eip150Block", config._tangerine_whistle_block);
    read_json_config_member(json, "eip155Block", config._spurious_dragon_block);
    read_json_config_member(json, "byzantiumBlock", config._byzantium_block);
    read_json_config_member(json, "constantinopleBlock", config._constantinople_block);
    read_json_config_member(json, "petersburgBlock", config._petersburg_block);
    read_json_config_member(json, "istanbulBlock", config._istanbul_block);
    read_json_config_member(json, "muirGlacierBlock", config._muir_glacier_block);
    read_json_config_member(json, "berlinBlock", config._berlin_block);
    read_json_config_member(json, "londonBlock", config._london_block);
    read_json_config_member(json, "arrowGlacierBlock", config._arrow_glacier_block);
    read_json_config_member(json, "grayGlacierBlock", config._gray_glacier_block);

    if (json.contains(kTerminalTotalDifficulty)) {
        // We handle terminalTotalDifficulty serialized both as JSON string *and* as JSON number
        if (json[kTerminalTotalDifficulty].is_string()) {
            /* This is still present to maintain compatibility with previous Silkworm format */
            config._terminal_total_difficulty =
                intx::from_string<intx::uint256>(json[kTerminalTotalDifficulty].get<std::string>());
        } else if (json[kTerminalTotalDifficulty].is_number()) {
            /* This is for compatibility with Erigon that uses a JSON number */
            // nlohmann::json treats JSON numbers that overflow 64-bit unsigned integer as floating-point numbers and
            // intx::uint256 cannot currently be constructed from a floating-point number or string in scientific notation
            config._terminal_total_difficulty =
                from_string_sci<intx::uint256>(json[kTerminalTotalDifficulty].dump().c_str());
        }
    }

    read_json_config_member(json, "mergeNetsplitBlock", config._merge_netsplit_block);
    read_json_config_member(json, "shanghaiTime", config._shanghai_time);
    read_json_config_member(json, "cancunTime", config._cancun_time);

    /* Note ! genesis_hash is purposely omitted. It must be loaded from db after the
     * effective genesis block has been persisted */

    read_json_config_member(json, "version", config._version);

    return config;
}

bool operator==(const ChainConfig& a, const ChainConfig& b) { return a.to_json() == b.to_json(); }

std::ostream& operator<<(std::ostream& out, const ChainConfig& obj) { return out << obj.to_json(); }

#endif

evmc_revision ChainConfig::determine_revision_by_block(uint64_t block_number, uint64_t block_time) const noexcept {
    if (_cancun_time && block_time >= _cancun_time) return EVMC_CANCUN;
    if (_shanghai_time && block_time >= _shanghai_time) return EVMC_SHANGHAI;

    if (_london_block && block_number >= _london_block) return EVMC_LONDON;
    if (_berlin_block && block_number >= _berlin_block) return EVMC_BERLIN;
    if (_istanbul_block && block_number >= _istanbul_block) return EVMC_ISTANBUL;
    if (_petersburg_block && block_number >= _petersburg_block) return EVMC_PETERSBURG;
    if (_constantinople_block && block_number >= _constantinople_block) return EVMC_CONSTANTINOPLE;
    if (_byzantium_block && block_number >= _byzantium_block) return EVMC_BYZANTIUM;
    if (_spurious_dragon_block && block_number >= _spurious_dragon_block) return EVMC_SPURIOUS_DRAGON;
    if (_tangerine_whistle_block && block_number >= _tangerine_whistle_block) return EVMC_TANGERINE_WHISTLE;
    if (_homestead_block && block_number >= _homestead_block) return EVMC_HOMESTEAD;

    return EVMC_FRONTIER;
}

evmc_revision ChainConfig::revision(const BlockHeader& header) const noexcept {
    if(protocol_rule_set != protocol::RuleSetType::kTrust) {
        return determine_revision_by_block(header.number, header.timestamp);
    }
    auto evm_version = eos_evm_version(header);
    return eosevm::version_to_evmc_revision(evm_version);
}

uint64_t ChainConfig::eos_evm_version(const BlockHeader& header) const noexcept {
    uint64_t evm_version = 0;
    if(protocol_rule_set == protocol::RuleSetType::kTrust) {
        if(header.number == 0) {
            evm_version = _version.has_value() ? *_version : 0;
        } else {
            evm_version = eosevm::nonce_to_version(header.nonce);
        }
    }
    return evm_version;
}

std::vector<BlockNum> ChainConfig::distinct_fork_numbers() const {
    std::set<BlockNum> ret;

    // Add forks identified by *block number* in ascending order
    ret.insert(_homestead_block.value_or(0));
    ret.insert(_dao_block.value_or(0));
    ret.insert(_tangerine_whistle_block.value_or(0));
    ret.insert(_spurious_dragon_block.value_or(0));
    ret.insert(_byzantium_block.value_or(0));
    ret.insert(_constantinople_block.value_or(0));
    ret.insert(_petersburg_block.value_or(0));
    ret.insert(_istanbul_block.value_or(0));
    ret.insert(_muir_glacier_block.value_or(0));
    ret.insert(_berlin_block.value_or(0));
    ret.insert(_london_block.value_or(0));
    ret.insert(_arrow_glacier_block.value_or(0));
    ret.insert(_gray_glacier_block.value_or(0));
    ret.insert(_merge_netsplit_block.value_or(0));

    ret.erase(0);  // Block 0 is not a fork number
    return {ret.cbegin(), ret.cend()};
}

std::vector<BlockTime> ChainConfig::distinct_fork_times() const {
    std::set<BlockTime> ret;

    // Add forks identified by *block timestamp* in ascending order
    ret.insert(_shanghai_time.value_or(0));
    ret.insert(_cancun_time.value_or(0));

    ret.erase(0);  // Block 0 is not a fork timestamp
    return {ret.cbegin(), ret.cend()};
}

std::vector<uint64_t> ChainConfig::distinct_fork_points() const {
    auto numbers{distinct_fork_numbers()};
    auto times{distinct_fork_times()};

    std::vector<uint64_t> points;
    points.resize(numbers.size() + times.size());
    std::move(numbers.begin(), numbers.end(), points.begin());
    std::move(times.begin(), times.end(), points.begin() + (numbers.end() - numbers.begin()));

    return points;
}

std::optional<std::pair<const std::string, const ChainConfig*>> lookup_known_chain(const uint64_t chain_id) noexcept {
    auto it{
        as_range::find_if(kKnownChainConfigs, [&chain_id](const std::pair<std::string, const ChainConfig*>& x) -> bool {
            return x.second->chain_id == chain_id;
        })};

    if (it == kKnownChainConfigs.end()) {
        ChainConfig *_config = new ChainConfig(get_kEOSEVMConfigTemplate(chain_id));
        kKnownChainConfigs.emplace_back("eosevm", _config);
        auto it2{
        as_range::find_if(kKnownChainConfigs, [&chain_id](const std::pair<std::string, const ChainConfig*>& x) -> bool {
            return x.second->chain_id == chain_id;
        })};
        if (it2 == kKnownChainConfigs.end()) // should not happen
            return std::nullopt;
        else
            return std::make_pair(it2->first, it2->second);
    }
    return std::make_pair(it->first, it->second);
}

std::optional<std::pair<const std::string, const ChainConfig*>> lookup_known_chain(const std::string_view identifier) noexcept {
    auto it{
        as_range::find_if(kKnownChainConfigs, [&identifier](const std::pair<std::string, const ChainConfig*>& x) -> bool {
            return iequals(x.first, identifier);
        })};

    if (it == kKnownChainConfigs.end()) {
        return std::nullopt;
    }
    return std::make_pair(it->first, it->second);
}

std::map<std::string, uint64_t> get_known_chains_map() noexcept {
    std::map<std::string, uint64_t> ret;
    as_range::for_each(kKnownChainConfigs, [&ret](const std::pair<std::string, const ChainConfig*>& x) -> void {
        ret[x.first] = x.second->chain_id;
    });
    return ret;
}

}  // namespace silkworm
