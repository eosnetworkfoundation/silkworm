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

#if defined(ANTELOPE)
#include <eosio/eosio.hpp>
#include <eosio/crypto.hpp>
#include <silkworm/core/common/endian.hpp>
#endif

#include "precompile.hpp"

#if not defined(ANTELOPE)
#include <gmp.h>
#include <bit>
#endif

#include <algorithm>
#include <cstring>
#include <limits>

#include <silkworm/core/crypto/ecdsa.h>
#include <silkworm/core/crypto/secp256k1n.hpp>
#include <silkworm/core/types/hash.hpp>

#if defined(ANTELOPE)
namespace eosio {
   namespace internal_use_do_not_use {
    extern "C" {
      __attribute__((eosio_wasm_import))
      int32_t alt_bn128_add( const char* op1, uint32_t op1_len, const char* op2, uint32_t op2_len, char* result, uint32_t result_len);

      __attribute__((eosio_wasm_import))
      int32_t alt_bn128_mul( const char* g1, uint32_t g1_len, const char* scalar, uint32_t scalar_len, char* result, uint32_t result_len);

      __attribute__((eosio_wasm_import))
      int32_t alt_bn128_pair( const char* pairs, uint32_t pairs_len);

      __attribute__((eosio_wasm_import))
      int32_t mod_exp( const char* base, uint32_t base_len, const char* exp, uint32_t exp_len, const char* mod, uint32_t mod_len, char* result, uint32_t result_len);

      __attribute__((eosio_wasm_import))
      int32_t blake2_f( uint32_t rounds, const char* state, uint32_t state_len, const char* msg, uint32_t msg_len,
                  const char* t0_offset, uint32_t t0_len, const char* t1_offset, uint32_t t1_len, int32_t final, char* result, uint32_t result_len);

      __attribute__((eosio_wasm_import))
      void sha3( const char* data, uint32_t data_len, char* hash, uint32_t hash_len, int32_t keccak );
   }
  }
}
#else
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"
#pragma GCC diagnostic ignored "-Wshadow"
#pragma GCC diagnostic ignored "-Wconversion"
#pragma GCC diagnostic ignored "-Wsign-conversion"
#include <libff/algebra/curves/alt_bn128/alt_bn128_pairing.hpp>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libff/common/profiling.hpp>
#pragma GCC diagnostic pop

#include <silkworm/core/common/endian.hpp>
#include <silkworm/core/crypto/blake2b.h>
#include <silkworm/core/crypto/kzg.hpp>
#include <silkworm/core/crypto/rmd160.h>
#include <silkworm/core/crypto/sha256.h>
#endif

namespace silkworm::precompile {

static void right_pad(Bytes& str, const size_t min_size) noexcept {
    if (str.length() < min_size) {
        str.resize(min_size, '\0');
    }
}

uint64_t ecrec_gas(ByteView, evmc_revision) noexcept { return 3'000; }

std::optional<Bytes> ecrec_run(ByteView input) noexcept {
    Bytes d{input};
    right_pad(d, 128);

    const auto v{intx::be::unsafe::load<intx::uint256>(&d[32])};
    const auto r{intx::be::unsafe::load<intx::uint256>(&d[64])};
    const auto s{intx::be::unsafe::load<intx::uint256>(&d[96])};

    const bool homestead{false};  // See EIP-2
    if (!is_valid_signature(r, s, homestead)) {
        return Bytes{};
    }

    if (v != 27 && v != 28) {
        return Bytes{};
    }

    Bytes out(32, 0);
    #if defined(ANTELOPE)
    if (!silkworm_recover_address(&out[12], &d[0], &d[64], v != 27)) {
        return Bytes{};
    }
    #else
    static secp256k1_context* context{secp256k1_context_create(SILKWORM_SECP256K1_CONTEXT_FLAGS)};
    if (!silkworm_recover_address(&out[12], &d[0], &d[64], v != 27, context)) {
        return Bytes{};
    }
    #endif
    return out;
}

uint64_t sha256_gas(ByteView input, evmc_revision) noexcept {
    return 60 + 12 * ((input.length() + 31) / 32);
}

std::optional<Bytes> sha256_run(ByteView input) noexcept {
    Bytes out(32, 0);
    #if defined(ANTELOPE)
    auto res = eosio::sha256((const char*)input.data(), input.length()).extract_as_byte_array();
    memcpy(out.data(), res.data(), 32);
    #else
    silkworm_sha256(out.data(), input.data(), input.length(), /*use_cpu_extensions=*/true);
    #endif
    return out;
}

uint64_t rip160_gas(ByteView input, evmc_revision) noexcept {
    return 600 + 120 * ((input.length() + 31) / 32);
}

std::optional<Bytes> rip160_run(ByteView input) noexcept {
    Bytes out(32, 0);
    SILKWORM_ASSERT(input.length() <= std::numeric_limits<uint32_t>::max());
    #if defined(ANTELOPE)
    auto res = eosio::ripemd160((const char*)input.data(), input.length()).extract_as_byte_array();
    memcpy(&out[12], res.data(), res.size());
    #else
    silkworm_rmd160(&out[12], input.data(), static_cast<uint32_t>(input.length()));
    #endif
    return out;
}

uint64_t id_gas(ByteView input, evmc_revision) noexcept {
    return 15 + 3 * ((input.length() + 31) / 32);
}

std::optional<Bytes> id_run(ByteView input) noexcept {
    return Bytes{input};
}

static intx::uint256 mult_complexity_eip198(const intx::uint256& x) noexcept {
    const intx::uint256 x_squared{x * x};
    if (x <= 64) {
        return x_squared;
    } else if (x <= 1024) {
        return (x_squared >> 2) + 96 * x - 3072;
    } else {
        return (x_squared >> 4) + 480 * x - 199680;
    }
}

static intx::uint256 mult_complexity_eip2565(const intx::uint256& max_length) noexcept {
    const intx::uint256 words{(max_length + 7) >> 3};  // ⌈max_length/8⌉
    return words * words;
}

uint64_t expmod_gas(ByteView input_view, evmc_revision rev) noexcept {
    const uint64_t min_gas{rev < EVMC_BERLIN ? 0 : 200u};

    Bytes input{input_view};
    right_pad(input, 3 * 32);

    intx::uint256 base_len256{intx::be::unsafe::load<intx::uint256>(&input[0])};
    intx::uint256 exp_len256{intx::be::unsafe::load<intx::uint256>(&input[32])};
    intx::uint256 mod_len256{intx::be::unsafe::load<intx::uint256>(&input[64])};

    if (base_len256 == 0 && mod_len256 == 0) {
        return min_gas;
    }

    if (intx::count_significant_words(base_len256) > 1 || intx::count_significant_words(exp_len256) > 1 ||
        intx::count_significant_words(mod_len256) > 1) {
        return UINT64_MAX;
    }

    uint64_t base_len64{static_cast<uint64_t>(base_len256)};
    uint64_t exp_len64{static_cast<uint64_t>(exp_len256)};

    input.erase(0, 3 * 32);

    intx::uint256 exp_head{0};  // first 32 bytes of the exponent
    if (input.length() > base_len64) {
        input.erase(0, static_cast<size_t>(base_len64));
        right_pad(input, 3 * 32);
        if (exp_len64 < 32) {
            input.erase(static_cast<size_t>(exp_len64));
            input.insert(0, 32 - static_cast<size_t>(exp_len64), '\0');
        }
        exp_head = intx::be::unsafe::load<intx::uint256>(input.data());
    }
    unsigned bit_len{256 - clz(exp_head)};

    intx::uint256 adjusted_exponent_len{0};
    if (exp_len256 > 32) {
        adjusted_exponent_len = 8 * (exp_len256 - 32);
    }
    if (bit_len > 1) {
        adjusted_exponent_len += bit_len - 1;
    }

    if (adjusted_exponent_len < 1) {
        adjusted_exponent_len = 1;
    }

    const intx::uint256 max_length{std::max(mod_len256, base_len256)};

    intx::uint256 gas;
    if (rev < EVMC_BERLIN) {
        gas = mult_complexity_eip198(max_length) * adjusted_exponent_len / 20;
    } else {
        gas = mult_complexity_eip2565(max_length) * adjusted_exponent_len / 3;
    }

    if (intx::count_significant_words(gas) > 1) {
        return UINT64_MAX;
    } else {
        return std::max(min_gas, static_cast<uint64_t>(gas));
    }
}

std::optional<Bytes> expmod_run(ByteView input_view) noexcept {
    Bytes input{input_view};
    right_pad(input, 3 * 32);

    uint64_t base_len{endian::load_big_u64(&input[24])};
    input.erase(0, 32);

    uint64_t exponent_len{endian::load_big_u64(&input[24])};
    input.erase(0, 32);

    uint64_t modulus_len{endian::load_big_u64(&input[24])};
    input.erase(0, 32);

    if (modulus_len == 0) {
        return Bytes{};
    }

    right_pad(input, static_cast<size_t>(base_len + exponent_len + modulus_len));
    #if defined(ANTELOPE)
    auto base_data     = (const char*)input.data();
    auto exponent_data = base_data + base_len;
    auto modulus_data  = exponent_data + exponent_len;

    Bytes out(static_cast<size_t>(modulus_len), 0);

    auto err = eosio::internal_use_do_not_use::mod_exp(base_data, base_len, exponent_data, exponent_len, modulus_data, modulus_len, (char*)out.data(), modulus_len);
    if(err < 0) {
        return std::nullopt;
    }

    return out;
    #else
    mpz_t base;
    mpz_init(base);
    if (base_len) {
        mpz_import(base, base_len, 1, 1, 0, 0, input.data());
        input.erase(0, static_cast<size_t>(base_len));
    }

    mpz_t exponent;
    mpz_init(exponent);
    if (exponent_len) {
        mpz_import(exponent, exponent_len, 1, 1, 0, 0, input.data());
        input.erase(0, static_cast<size_t>(exponent_len));
    }

    mpz_t modulus;
    mpz_init(modulus);
    mpz_import(modulus, modulus_len, 1, 1, 0, 0, input.data());

    Bytes out(static_cast<size_t>(modulus_len), 0);

    if (mpz_sgn(modulus) == 0) {
        mpz_clear(modulus);
        mpz_clear(exponent);
        mpz_clear(base);

        return out;
    }

    mpz_t result;
    mpz_init(result);

    mpz_powm(result, base, exponent, modulus);

    // export as little-endian
    mpz_export(out.data(), nullptr, -1, 1, 0, 0, result);
    // and convert to big-endian
    std::reverse(out.begin(), out.end());

    mpz_clear(result);
    mpz_clear(modulus);
    mpz_clear(exponent);
    mpz_clear(base);

    return out;
    #endif
}

#if not defined(ANTELOPE)
// Utility functions for zkSNARK related precompiled contracts.
// See Yellow Paper, Appendix E "Precompiled Contracts", as well as
// EIP-196: Precompiled contracts for addition and scalar multiplication on the elliptic curve alt_bn128
// EIP-197: Precompiled contracts for optimal ate pairing check on the elliptic curve alt_bn128
using Scalar = libff::bigint<libff::alt_bn128_q_limbs>;

// Must be called prior to invoking any other method.
// May be called many times from multiple threads.
static void init_libff() noexcept {
    // magic static
    [[maybe_unused]] static bool initialized = []() noexcept {
        libff::inhibit_profiling_info = true;
        libff::inhibit_profiling_counters = true;
        libff::alt_bn128_pp::init_public_params();
        return true;
    }();
}

static Scalar to_scalar(const uint8_t bytes_be[32]) noexcept {
    mpz_t m;
    mpz_init(m);
    mpz_import(m, 32, /*order=*/1, /*size=*/1, /*endian=*/0, /*nails=*/0, bytes_be);
    Scalar out{m};
    mpz_clear(m);
    return out;
}

// Notation warning: Yellow Paper's p is the same libff's q.
// Returns x < p (YP notation).
static bool valid_element_of_fp(const Scalar& x) noexcept {
    return mpn_cmp(x.data, libff::alt_bn128_modulus_q.data, libff::alt_bn128_q_limbs) < 0;
}

static std::optional<libff::alt_bn128_G1> decode_g1_element(const uint8_t bytes_be[64]) noexcept {
    Scalar x{to_scalar(bytes_be)};
    if (!valid_element_of_fp(x)) {
        return {};
    }

    Scalar y{to_scalar(bytes_be + 32)};
    if (!valid_element_of_fp(y)) {
        return {};
    }

    if (x.is_zero() && y.is_zero()) {
        return libff::alt_bn128_G1::zero();
    }

    libff::alt_bn128_G1 point{x, y, libff::alt_bn128_Fq::one()};
    if (!point.is_well_formed()) {
        return {};
    }
    return point;
}

static std::optional<libff::alt_bn128_Fq2> decode_fp2_element(const uint8_t bytes_be[64]) noexcept {
    // big-endian encoding
    Scalar c0{to_scalar(bytes_be + 32)};
    Scalar c1{to_scalar(bytes_be)};

    if (!valid_element_of_fp(c0) || !valid_element_of_fp(c1)) {
        return {};
    }

    return libff::alt_bn128_Fq2{c0, c1};
}

static std::optional<libff::alt_bn128_G2> decode_g2_element(const uint8_t bytes_be[128]) noexcept {
    std::optional<libff::alt_bn128_Fq2> x{decode_fp2_element(bytes_be)};
    if (!x) {
        return {};
    }

    std::optional<libff::alt_bn128_Fq2> y{decode_fp2_element(bytes_be + 64)};
    if (!y) {
        return {};
    }

    if (x->is_zero() && y->is_zero()) {
        return libff::alt_bn128_G2::zero();
    }

    libff::alt_bn128_G2 point{*x, *y, libff::alt_bn128_Fq2::one()};
    if (!point.is_well_formed()) {
        return {};
    }

    if (!(libff::alt_bn128_G2::order() * point).is_zero()) {
        // wrong order, doesn't belong to the subgroup G2
        return {};
    }

    return point;
}

static Bytes encode_g1_element(libff::alt_bn128_G1 p) noexcept {
    Bytes out(64, '\0');
    if (p.is_zero()) {
        return out;
    }

    p.to_affine_coordinates();

    auto x{p.X.as_bigint()};
    auto y{p.Y.as_bigint()};

    // Here we convert little-endian data to big-endian output
    static_assert(sizeof(x.data) == 32);

    std::memcpy(&out[0], y.data, 32);
    std::memcpy(&out[32], x.data, 32);

    std::reverse(out.begin(), out.end());
    return out;
}
#endif

uint64_t bn_add_gas(ByteView, evmc_revision rev) noexcept {
    return rev >= EVMC_ISTANBUL ? 150 : 500;
}

std::optional<Bytes> bn_add_run(ByteView input_view) noexcept {
    Bytes input{input_view};
    right_pad(input, 128);
    #if defined(ANTELOPE)
    auto op1_data = (const char*)input.data();
    auto op2_data = op1_data + 64;

    Bytes out(64, 0);
    auto err = eosio::internal_use_do_not_use::alt_bn128_add( op1_data, 64, op2_data, 64, (char *)out.data(), 64);
    if(err < 0) {
        return std::nullopt;
    }

    return out;
    #else
    init_libff();

    std::optional<libff::alt_bn128_G1> x{decode_g1_element(input.data())};
    if (!x) {
        return std::nullopt;
    }

    std::optional<libff::alt_bn128_G1> y{decode_g1_element(&input[64])};
    if (!y) {
        return std::nullopt;
    }

    libff::alt_bn128_G1 sum{*x + *y};
    return encode_g1_element(sum);
    #endif
}

uint64_t bn_mul_gas(ByteView, evmc_revision rev) noexcept {
    return rev >= EVMC_ISTANBUL ? 6'000 : 40'000;
}

std::optional<Bytes> bn_mul_run(ByteView input_view) noexcept {
    Bytes input{input_view};
    right_pad(input, 96);

    #if defined(ANTELOPE)
    auto point_data  = (const char*)input.data();
    auto scalar_data = point_data + 64;

    Bytes out(64, 0);
    auto err = eosio::internal_use_do_not_use::alt_bn128_mul( point_data, 64, scalar_data, 32, (char *)out.data(), 64);
    if(err < 0) {
        return std::nullopt;
    }

    return out;
    #else
    init_libff();

    std::optional<libff::alt_bn128_G1> x{decode_g1_element(input.data())};
    if (!x) {
        return std::nullopt;
    }

    Scalar n{to_scalar(&input[64])};

    libff::alt_bn128_G1 product{n * *x};
    return encode_g1_element(product);
    #endif
}

static constexpr size_t kSnarkvStride{192};

uint64_t snarkv_gas(ByteView input, evmc_revision rev) noexcept {
    uint64_t k{input.length() / kSnarkvStride};
    return rev >= EVMC_ISTANBUL ? 34'000 * k + 45'000 : 80'000 * k + 100'000;
}

std::optional<Bytes> snarkv_run(ByteView input) noexcept {
    if (input.length() % kSnarkvStride != 0) {
        return std::nullopt;
    }
    size_t k{input.length() / kSnarkvStride};

    #if defined(ANTELOPE)
    auto err = eosio::internal_use_do_not_use::alt_bn128_pair( (const char*)input.data(), input.length());
    if(err < 0) {
        return std::nullopt;
    }

    Bytes out(32, 0);
    if (err == 0) {
        out[31] = 1;
    }
    return out;
    #else
    init_libff();
    using namespace libff;

    static const auto one{alt_bn128_Fq12::one()};
    auto accumulator{one};

    for (size_t i{0}; i < k; ++i) {
        std::optional<alt_bn128_G1> a{decode_g1_element(&input[i * kSnarkvStride])};
        if (!a) {
            return std::nullopt;
        }
        std::optional<alt_bn128_G2> b{decode_g2_element(&input[i * kSnarkvStride + 64])};
        if (!b) {
            return std::nullopt;
        }

        if (a->is_zero() || b->is_zero()) {
            continue;
        }

        accumulator = accumulator * alt_bn128_miller_loop(alt_bn128_precompute_G1(*a), alt_bn128_precompute_G2(*b));
    }

    Bytes out(32, 0);
    if (alt_bn128_final_exponentiation(accumulator) == one) {
        out[31] = 1;
    }
    return out;
    #endif
}

uint64_t blake2_f_gas(ByteView input, evmc_revision) noexcept {
    if (input.length() < 4) {
        // blake2_f_run will fail anyway
        return 0;
    }
    return endian::load_big_u32(input.data());
}

std::optional<Bytes> blake2_f_run(ByteView input) noexcept {
    if (input.length() != 213) {
        return std::nullopt;
    }
    uint8_t f{input[212]};
    if (f != 0 && f != 1) {
        return std::nullopt;
    }

    #if defined(ANTELOPE)
    auto rounds    = silkworm::endian::load_big_u32(input.data());
    auto state     = (const char *)input.data() + 4;
    auto message   = state + 64;
    auto t0_offset = message + 128;
    auto t1_offset = t0_offset + 8;

    Bytes out(64, 0);
    auto err = eosio::internal_use_do_not_use::blake2_f(rounds, state, 64, message, 128, t0_offset, 8, t1_offset, 8, (bool)f, (char *)out.data(), 64);
    if(err < 0) {
        return std::nullopt;
    }
    return out;
    #else
    SilkwormBlake2bState state{};
    if (f) {
        state.f[0] = std::numeric_limits<uint64_t>::max();
    }

    static_assert(std::endian::native == std::endian::little);
    static_assert(sizeof(state.h) == 8 * 8);
    std::memcpy(&state.h, &input[4], 8 * 8);

    uint8_t block[SILKWORM_BLAKE2B_BLOCKBYTES];
    std::memcpy(block, &input[68], SILKWORM_BLAKE2B_BLOCKBYTES);

    std::memcpy(&state.t, &input[196], 8 * 2);

    uint32_t r{endian::load_big_u32(input.data())};
    silkworm_blake2b_compress(&state, block, r);

    Bytes out(8 * 8, 0);
    std::memcpy(&out[0], &state.h[0], 8 * 8);
    return out;
    #endif
}

uint64_t point_evaluation_gas(ByteView, evmc_revision) noexcept {
    return 50000;
}

#ifndef ANTELOPE
// https://eips.ethereum.org/EIPS/eip-4844#point-evaluation-precompile
std::optional<Bytes> point_evaluation_run(ByteView input) noexcept {
    if (input.length() != 192) {
        return std::nullopt;
    }

    std::span<const uint8_t, 32> versioned_hash{&input[0], 32};
    std::span<const uint8_t, 32> z{&input[32], 32};
    std::span<const uint8_t, 32> y{&input[64], 32};
    std::span<const uint8_t, 48> commitment{&input[96], 48};
    std::span<const uint8_t, 48> proof{&input[144], 48};

    if (kzg_to_versioned_hash(commitment) != ByteView{versioned_hash}) {
        return std::nullopt;
    }

    if (!verify_kzg_proof(commitment, z, y, proof)) {
        return std::nullopt;
    }

    return from_hex(
        "0000000000000000000000000000000000000000000000000000000000001000"
        "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001");
}
#endif

bool is_precompile(const evmc::address& address, evmc_revision rev) noexcept {
    static_assert(std::size(kContracts) < 256);
    static constexpr evmc::address kMaxOneByteAddress{0x00000000000000000000000000000000000000ff_address};
    if (address > kMaxOneByteAddress) {
        return false;
    }

    const uint8_t num{address.bytes[kAddressLength - 1]};
    if (num >= std::size(kContracts) || !kContracts[num]) {
        return false;
    }

    return kContracts[num]->added_in <= rev;
}

}  // namespace silkworm::precompile
