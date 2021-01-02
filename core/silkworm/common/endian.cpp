/*
   Copyright 2020 The Silkworm Authors

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

#include "endian.hpp"

namespace silkworm::endian {

#if __BYTE_ORDER == __LITTLE_ENDIAN

uint32_t load_big_u32(uint8_t const* bytes) noexcept {
    uint32_t x;
    std::memcpy(&x, bytes, sizeof(x));
    return bswap32(x);
}

uint64_t load_big_u64(uint8_t const* bytes) noexcept {
    uint64_t x;
    std::memcpy(&x, bytes, sizeof(x));
    return bswap64(x);
}

void store_big_u32(uint8_t* dst, uint32_t value) noexcept {
    uint32_t x{ bswap32(value) };
    std::memcpy(dst, &x, sizeof(x));
}

void store_big_u64(uint8_t* dst, uint64_t value) noexcept {
    uint64_t x{ bswap64(value) };
    std::memcpy(dst, &x, sizeof(x));
}

#else

uint32_t load_big_u32(uint8_t const* bytes) noexcept {
    uint32_t x;
    std::memcpy(&x, bytes, sizeof(x));
    return x;
}

uint64_t load_big_u64(uint8_t const* bytes) noexcept {
    uint64_t x;
    std::memcpy(&x, bytes, sizeof(x));
    return x;
}

void store_big_u32(uint8_t* dst, uint32_t value) noexcept { std::memcpy(dst, &value, sizeof(value)); }

void store_big_u64(uint8_t* dst, uint64_t value) noexcept { std::memcpy(dst, &value, sizeof(value)); }

#endif

} // namespace silkworm::endian
