#pragma once
#include <cstdint>
#include <array>
#include <list>
#include <optional>
#include <ostream>

#include <nlohmann/json.hpp>

namespace evm_json_file {

inline std::string hex(uint8_t b) noexcept
{
    static constexpr auto hex_digits = "0123456789abcdef";
    return {hex_digits[b >> 4], hex_digits[b & 0xf]};
}

template <typename T, size_t N>
inline std::string hex(const std::array<T,N>& bs)
{
    static_assert(N % 2 == 0, "N must be even");
    std::string str;
    str.reserve(N * 2);
    for (const auto b : bs)
        str += hex(b);
    return str;
}

using b20 = std::array<uint8_t, 20>;
using b32 = std::array<uint8_t, 32>;

struct storage {
    b32  key;
    b32  value;
};

bool operator<(const storage& lhs, const storage& rhs) {
    return lhs.key < rhs.key;
}

struct account {
    b20                address;
    uint64_t           nonce;
    b32                balance;
    std::optional<b32> code_hash;
    std::list<storage> slots;
};

bool operator<(const account& lhs, const account& rhs) {
    return lhs.address < rhs.address;
}

nlohmann::json to_json(const account& a) {
    nlohmann::json j;
    j["address"] = hex(a.address);
    j["nonce"] = a.nonce;
    j["balance"] = hex(a.balance);

    if (a.code_hash.has_value()) {
        j["code_hash"] = hex(a.code_hash.value());
    }

    if(a.slots.size())
        j["slots"] = nlohmann::json::array();

    for (const auto& s : a.slots) {
        nlohmann::json slot;
        slot["key"] = hex(s.key);
        slot["value"] = hex(s.value);
        j["slots"].push_back(slot);
    }

    return j;
}

} //namespace evm_json_file

std::ostream& operator<<(std::ostream& os, const evm_json_file::account& a) {
    os << to_json(a).dump(2);
    return os;
}

std::ostream& operator<<(std::ostream& os, const std::list<evm_json_file::account>& accounts) {
    nlohmann::json j;
    j["accounts"] = nlohmann::json::array();
    for(const auto& acct : accounts) {
        j["accounts"].push_back(to_json(acct));
    }
    os << j.dump(2);
    return os;
}
