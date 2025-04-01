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

// The most common and basic macros, concepts, types, and constants.

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <tuple>

#include <evmc/evmc.hpp>
#include <intx/intx.hpp>

#if defined(__wasm__)
#define SILKWORM_THREAD_LOCAL static
#else
#define SILKWORM_THREAD_LOCAL thread_local
#endif

namespace silkworm {

using namespace evmc::literals;

template <typename T>
struct is_vector : std::false_type {};

template <typename U>
struct is_vector<std::vector<U>> : std::true_type {};

template <typename T>
constexpr bool is_vector_v = is_vector<T>::value;

template <typename T>
constexpr bool UnsignedIntegral = (std::is_integral_v<T> && !std::is_signed_v<T> ) || std::is_same_v<T, intx::uint128>
          || std::is_same_v<T, intx::uint256> || std::is_same_v<T, intx::uint512>;

using Bytes = evmc::bytes;

class ByteView : public evmc::bytes_view {
  public:
    constexpr ByteView() noexcept = default;
    
    // NOLINTNEXTLINE(google-explicit-constructor, hicpp-explicit-conversions)
    constexpr ByteView(const evmc::bytes_view& other) noexcept
        : evmc::bytes_view{other.data(), other.length()} {}

    // NOLINTNEXTLINE(google-explicit-constructor, hicpp-explicit-conversions)
    ByteView(const Bytes& str) noexcept : evmc::bytes_view{str.data(), str.length()} {}

    constexpr ByteView(const uint8_t* data, size_type length) noexcept
        : evmc::bytes_view{data, length} {}

    template <size_t N>
    // NOLINTNEXTLINE(google-explicit-constructor, hicpp-explicit-conversions)
    constexpr ByteView(const uint8_t (&array)[N]) noexcept : evmc::bytes_view{array, N} {}

    template <size_t N>
    // NOLINTNEXTLINE(google-explicit-constructor, hicpp-explicit-conversions)
    constexpr ByteView(const std::array<uint8_t, N>& array) noexcept
        : evmc::bytes_view{array.data(), N} {}

    template <size_t Extent>
    // NOLINTNEXTLINE(google-explicit-constructor, hicpp-explicit-conversions)
    constexpr ByteView(std::span<const uint8_t, Extent> span) noexcept
        : evmc::bytes_view{span.data(), span.size()} {}

    bool is_null() const noexcept { return data() == nullptr; }
};

using BlockNum = uint64_t;
using BlockNumRange = std::pair<BlockNum, BlockNum>;
using BlockTime = uint64_t;

inline constexpr size_t kAddressLength{20};

inline constexpr size_t kHashLength{32};

inline constexpr size_t kExtraSealSize{65};

// Keccak-256 hash of an empty string, KEC("").
inline constexpr evmc::bytes32 kEmptyHash{0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470_bytes32};

// Keccak-256 hash of the RLP of an empty list, KEC("\xc0").
inline constexpr evmc::bytes32 kEmptyListHash{
    0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347_bytes32};

// Root hash of an empty trie.
inline constexpr evmc::bytes32 kEmptyRoot{0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421_bytes32};

// https://en.wikipedia.org/wiki/Binary_prefix
inline constexpr uint64_t kKibi{1024};
inline constexpr uint64_t kMebi{1024 * kKibi};
inline constexpr uint64_t kGibi{1024 * kMebi};
inline constexpr uint64_t kTebi{1024 * kGibi};

inline constexpr uint64_t kGiga{1'000'000'000};   // = 10^9
inline constexpr uint64_t kEther{kGiga * kGiga};  // = 10^18

constexpr uint64_t operator"" _Kibi(unsigned long long x) { return x * kKibi; }
constexpr uint64_t operator"" _Mebi(unsigned long long x) { return x * kMebi; }
constexpr uint64_t operator"" _Gibi(unsigned long long x) { return x * kGibi; }
constexpr uint64_t operator"" _Tebi(unsigned long long x) { return x * kTebi; }

}  // namespace silkworm
