/*
 * Copyright 2021 Benjamin Edgington
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef ANTELOPE
#include "kzg.hpp"

#include <blst.h>

#include <silkworm/core/crypto/sha256.h>
#include <silkworm/core/protocol/param.hpp>

// Based on https://github.com/ethereum/c-kzg-4844/blob/main/src/c_kzg_4844.c
// and modified for Silkworm.

namespace silkworm {

///////////////////////////////////////////////////////////////////////////////
// Types
///////////////////////////////////////////////////////////////////////////////

using G1 = blst_p1;
using G2 = blst_p2;
using Fr = blst_fr;

///////////////////////////////////////////////////////////////////////////////
// Constants
///////////////////////////////////////////////////////////////////////////////

// KZG_SETUP_G2[1] printed by cmd/dev/kzg_g2_uncompress
// See https://github.com/ethereum/consensus-specs/blob/dev/specs/deneb/polynomial-commitments.md#trusted-setup
// TODO(yperbasis): change to the final value when known
static const G2 kKzgSetupG2_1{};

///////////////////////////////////////////////////////////////////////////////
// Helper Functions
///////////////////////////////////////////////////////////////////////////////

Hash kzg_to_versioned_hash(ByteView kzg) {
    Hash hash;
    silkworm_sha256(hash.bytes, kzg.data(), kzg.length(), /*use_cpu_extensions=*/true);
    hash.bytes[0] = protocol::kBlobCommitmentVersionKzg;
    return hash;
}

/**
 * Multiply a G1 group element by a field element.
 *
 * @param[out] out @p a * @p b
 * @param[in]  a   The G1 group element
 * @param[in]  b   The multiplier
 */
static void g1_mul(G1* out, const G1* a, const Fr* b) {
    blst_scalar s;
    blst_scalar_from_fr(&s, b);
    /* The last argument is the number of bits in the scalar */
    blst_p1_mult(out, a, s.b, 8 * sizeof(blst_scalar));
}

/**
 * Multiply a G2 group element by a field element.
 *
 * @param[out] out @p a * @p b
 * @param[in]  a   The G2 group element
 * @param[in]  b   The multiplier
 */
static void g2_mul(G2* out, const G2* a, const Fr* b) {
    blst_scalar s;
    blst_scalar_from_fr(&s, b);
    /* The last argument is the number of bits in the scalar */
    blst_p2_mult(out, a, s.b, 8 * sizeof(blst_scalar));
}

/**
 * Subtraction of G1 group elements.
 *
 * @param[out] out @p a - @p b
 * @param[in]  a   A G1 group element
 * @param[in]  b   The G1 group element to be subtracted
 */
static void g1_sub(G1* out, const G1* a, const G1* b) {
    G1 bneg = *b;
    blst_p1_cneg(&bneg, true);
    blst_p1_add_or_double(out, a, &bneg);
}

/**
 * Subtraction of G2 group elements.
 *
 * @param[out] out @p a - @p b
 * @param[in]  a   A G2 group element
 * @param[in]  b   The G2 group element to be subtracted
 */
static void g2_sub(G2* out, const G2* a, const G2* b) {
    G2 bneg = *b;
    blst_p2_cneg(&bneg, true);
    blst_p2_add_or_double(out, a, &bneg);
}

/**
 * Perform pairings and test whether the outcomes are equal in G_T.
 *
 * Tests whether `e(a1, a2) == e(b1, b2)`.
 *
 * @param[in] a1 A G1 group point for the first pairing
 * @param[in] a2 A G2 group point for the first pairing
 * @param[in] b1 A G1 group point for the second pairing
 * @param[in] b2 A G2 group point for the second pairing
 *
 * @retval true  The pairings were equal
 * @retval false The pairings were not equal
 */
static bool pairings_verify(
    const G1* a1, const G2* a2, const G1* b1, const G2* b2) {
    blst_fp12 loop0, loop1, gt_point;
    blst_p1_affine aa1, bb1;
    blst_p2_affine aa2, bb2;

    /*
     * As an optimisation, we want to invert one of the pairings,
     * so we negate one of the points.
     */
    G1 a1neg = *a1;
    blst_p1_cneg(&a1neg, true);

    blst_p1_to_affine(&aa1, &a1neg);
    blst_p1_to_affine(&bb1, b1);
    blst_p2_to_affine(&aa2, a2);
    blst_p2_to_affine(&bb2, b2);

    blst_miller_loop(&loop0, &aa2, &aa1);
    blst_miller_loop(&loop1, &bb2, &bb1);

    blst_fp12_mul(&gt_point, &loop0, &loop1);
    blst_final_exp(&gt_point, &gt_point);

    return blst_fp12_is_one(&gt_point);
}

///////////////////////////////////////////////////////////////////////////////
// BLS12-381 Helper Functions
///////////////////////////////////////////////////////////////////////////////

/**
 * Convert untrusted bytes to a trusted and validated BLS scalar field
 * element.
 *
 * @param[out] out The field element to store the deserialized data
 * @param[in]  b   A 32-byte array containing the serialized field element
 */
static bool bytes_to_bls_field(Fr* out, std::span<const uint8_t, 32> b) {
    blst_scalar tmp;
    blst_scalar_from_bendian(&tmp, b.data());
    if (!blst_scalar_fr_check(&tmp)) {
        return false;
    }
    blst_fr_from_scalar(out, &tmp);
    return true;
}

/**
 * Perform BLS validation required by the types KZGProof and KZGCommitment.
 *
 * @remark This function deviates from the spec because it returns (via an
 *     output argument) the g1 point. This way is more efficient (faster)
 *     but the function name is a bit misleading.
 *
 * @param[out]  out The output g1 point
 * @param[in]   b   The proof/commitment bytes
 */
static bool validate_kzg_g1(G1* out, std::span<const uint8_t, 48> b) {
    blst_p1_affine p1_affine;

    /* Convert the bytes to a p1 point */
    /* The uncompress routine checks that the point is on the curve */
    if (blst_p1_uncompress(&p1_affine, b.data()) != BLST_SUCCESS) {
        return false;
    }
    blst_p1_from_affine(out, &p1_affine);

    /* The point at infinity is accepted! */
    if (blst_p1_is_inf(out)) {
        return true;
    }

    /* The point must be on the right subgroup */
    return blst_p1_in_g1(out);
}

///////////////////////////////////////////////////////////////////////////////
// KZG Functions
///////////////////////////////////////////////////////////////////////////////

/**
 * Helper function: Verify KZG proof claiming that `p(z) == y`.
 *
 * Given a @p commitment to a polynomial, a @p proof for @p z, and the
 * claimed value @p y at @p z, verify the claim.
 *
 * @param[in]  commitment The commitment to a polynomial
 * @param[in]  z          The point at which the proof is to be checked
 *                        (opened)
 * @param[in]  y          The claimed value of the polynomial at @p z
 * @param[in]  proof      A proof of the value of the polynomial at the
 *                        point @p z
 * @return `true` if the proof is valid, `false` if not
 */
static bool verify_kzg_proof_impl(
    const G1* commitment,
    const Fr* z,
    const Fr* y,
    const G1* proof) {
    G2 x_g2, X_minus_z;
    G1 y_g1, P_minus_y;

    /* Calculate: X_minus_z */
    g2_mul(&x_g2, blst_p2_generator(), z);
    g2_sub(&X_minus_z, &kKzgSetupG2_1, &x_g2);

    /* Calculate: P_minus_y */
    g1_mul(&y_g1, blst_p1_generator(), y);
    g1_sub(&P_minus_y, commitment, &y_g1);

    /* Verify: P - y = Q * (X - z) */
    return pairings_verify(&P_minus_y, blst_p2_generator(), proof, &X_minus_z);
}

bool verify_kzg_proof(
    std::span<const uint8_t, 48> commitment,
    std::span<const uint8_t, 32> z,
    std::span<const uint8_t, 32> y,
    std::span<const uint8_t, 48> proof) {
    Fr z_fr, y_fr;
    G1 commitment_g1, proof_g1;

    if (!validate_kzg_g1(&commitment_g1, commitment)) {
        return false;
    }
    if (!bytes_to_bls_field(&z_fr, z)) {
        return false;
    }
    if (!bytes_to_bls_field(&y_fr, y)) {
        return false;
    }
    if (!validate_kzg_g1(&proof_g1, proof)) {
        return false;
    }

    return verify_kzg_proof_impl(
        &commitment_g1, &z_fr, &y_fr, &proof_g1);
}

}  // namespace silkworm
#else
#include <silkworm/core/common/base.hpp>
#include <eosio/eosio.hpp>
#include <eosio/crypto.hpp>
#include <eosio/crypto_bls_ext.hpp>

using namespace eosio;

#define C(x) static_cast<char>(x)
static constexpr bls_fp BLS12_381_FP_B = {
    C(0x04), C(0x00), C(0x00), C(0x00), C(0x00), C(0x00), C(0x00), C(0x00),
    C(0x00), C(0x00), C(0x00), C(0x00), C(0x00), C(0x00), C(0x00), C(0x00),
    C(0x00), C(0x00), C(0x00), C(0x00), C(0x00), C(0x00), C(0x00), C(0x00),
    C(0x00), C(0x00), C(0x00), C(0x00), C(0x00), C(0x00), C(0x00), C(0x00),
    C(0x00), C(0x00), C(0x00), C(0x00), C(0x00), C(0x00), C(0x00), C(0x00),
    C(0x00), C(0x00), C(0x00), C(0x00), C(0x00), C(0x00), C(0x00), C(0x00)
};

static constexpr bls_fp BLS12_381_FP_P = {
    C(0xab), C(0xaa), C(0xff), C(0xff), C(0xff), C(0xff), C(0xfe), C(0xb9),
    C(0xff), C(0xff), C(0x53), C(0xb1), C(0xfe), C(0xff), C(0xab), C(0x1e),
    C(0x24), C(0xf6), C(0xb0), C(0xf6), C(0xa0), C(0xd2), C(0x30), C(0x67),
    C(0xbf), C(0x12), C(0x85), C(0xf3), C(0x84), C(0x4b), C(0x77), C(0x64),
    C(0xd7), C(0xac), C(0x4b), C(0x43), C(0xb6), C(0xa7), C(0x1b), C(0x4b),
    C(0x9a), C(0xe6), C(0x7f), C(0x39), C(0xea), C(0x11), C(0x01), C(0x1a)
};

static constexpr bls_s BLS12_381_FP_P_PLUS_1_OVER_4 = {
    C(0xa6), C(0xf9), C(0x5f), C(0x8e), C(0x7a), C(0x44), C(0x80), C(0x06),
    C(0x35), C(0xeb), C(0xd2), C(0x90), C(0xed), C(0xe9), C(0xc6), C(0x92),
    C(0xaf), C(0x44), C(0xe1), C(0x3c), C(0xe1), C(0xd2), C(0x1d), C(0xd9),
    C(0x89), C(0x3d), C(0xac), C(0x3d), C(0xa8), C(0x34), C(0xcc), C(0xd9),
    C(0xff), C(0xff), C(0x54), C(0xac), C(0xff), C(0xff), C(0xaa), C(0x07),
    C(0xab), C(0xea), C(0xff), C(0xff), C(0xff), C(0xbf), C(0x7f), C(0xee),
    C(0x00), C(0x00), C(0x00), C(0x00), C(0x00), C(0x00), C(0x00), C(0x00),
    C(0x00), C(0x00), C(0x00), C(0x00), C(0x00), C(0x00), C(0x00), C(0x00)
};

static constexpr bls_fp BLS12_381_FP_HALF_P = {
    C(0x56), C(0xd5), C(0xff), C(0xff), C(0xff), C(0x7f), C(0xff), C(0xdc),
    C(0xff), C(0xff), C(0xa9), C(0x58), C(0xff), C(0xff), C(0x55), C(0x0f),
    C(0x12), C(0x7b), C(0x58), C(0x7b), C(0x50), C(0x69), C(0x98), C(0xb3),
    C(0x5f), C(0x89), C(0xc2), C(0x79), C(0xc2), C(0xa5), C(0x3b), C(0xb2),
    C(0x6b), C(0xd6), C(0xa5), C(0x21), C(0xdb), C(0xd3), C(0x8d), C(0x25),
    C(0x4d), C(0xf3), C(0xbf), C(0x1c), C(0xf5), C(0x88), C(0x00), C(0x0d)
};

static constexpr bls_g1 G1_ZERO{};

static constexpr bls_scalar BLS12_381_Z_SQUARED = {
    C(0x01), C(0x00), C(0x02), C(0x00), C(0x00), C(0x00), C(0xe5), C(0xe9),
    C(0x01), C(0xc0), C(0xdf), C(0x1d), C(0xd8), C(0x63), C(0xeb), C(0xbe),
    C(0x00), C(0x00), C(0x00), C(0x00), C(0x00), C(0x00), C(0x00), C(0x00),
    C(0x00), C(0x00), C(0x00), C(0x00), C(0x00), C(0x00), C(0x00), C(0x00)
};

static constexpr bls_fp BLS12_381_BETA = {
    C(0xe8), C(0x0e), C(0x5d), C(0x67), C(0x74), C(0x25), C(0x3a), C(0xb3),
    C(0x71), C(0x97), C(0x8d), C(0x41), C(0x5d), C(0x5e), C(0x1e), C(0x58),
    C(0xbf), C(0x69), C(0x61), C(0x99), C(0x8d), C(0x85), C(0x0d), C(0xaa),
    C(0x85), C(0xde), C(0xd4), C(0x63), C(0x86), C(0x40), C(0x02), C(0xec),
    C(0x99), C(0xe6), C(0x7f), C(0x39), C(0xea), C(0x11), C(0x01), C(0x1a),
    C(0x00), C(0x00), C(0x00), C(0x00), C(0x00), C(0x00), C(0x00), C(0x00)
};

static constexpr bls_scalar BLS12_381_SCALAR_R = {
    C(0x01), C(0x00), C(0x00), C(0x00), C(0xff), C(0xff), C(0xff), C(0xff),
    C(0xfe), C(0x5b), C(0xff), C(0xff), C(0x02), C(0xa4), C(0xbd), C(0x53),
    C(0x05), C(0xd8), C(0xa1), C(0x09), C(0x08), C(0xd8), C(0x39), C(0x33),
    C(0x48), C(0x7d), C(0x9d), C(0x29), C(0x53), C(0xa7), C(0xed), C(0x73),
};
//#pragma GCC diagnostic pop

void bls_g1_sigma(const bls_g1& p, bls_g1& result) {
    result = p;
    bls_fp_mul(reinterpret_cast<const bls_fp&>(p[0]), BLS12_381_BETA, reinterpret_cast<bls_fp&>(result[0]));
}

// Scott’s method => [z²]P == σ²(P)
bool blst_p1_in_g1(const bls_g1& p) {
    bls_g1 a, b;

    // a = [z²]P
    bls_g1_weighted_sum(&p, &BLS12_381_Z_SQUARED, 1, a);

    // b = σ²(P)
    bls_g1_sigma(p, b); //  σ(P)
    bls_g1_sigma(b, b); // σ²(P)

    return a == b;
}

template <typename T>
struct extent_traits {
    static constexpr size_t value = T::size();
};

template <typename T, size_t N>
struct extent_traits<std::span<T, N>> {
    static constexpr size_t value = N;
};

template <typename T, size_t N>
struct extent_traits<std::array<T, N>> {
    static constexpr size_t value = N;
};

template <typename T>
bool all_zero_from_offset(const T& value, size_t offset) {
    if (offset >= extent_traits<T>::value) return false;
    static const uint8_t zeros[extent_traits<T>::value] = {0};
    size_t length = extent_traits<T>::value - offset;
    return memcmp(value.data() + offset, zeros, length) == 0;
}
template <typename Dest, typename Orig>
void to_little_endian(const Orig& source, Dest& result) {
    static_assert(extent_traits<Dest>::value >= extent_traits<Orig>::value, "dest size too small");
    std::reverse_copy(source.begin(), source.end(), result.begin());
}

uint16_t _add(const bls_fp& a, const bls_fp& b, bls_fp& result) {
    uint16_t carry = 0;
    for (size_t i = 0; i < 48; ++i) {
        uint16_t sum = static_cast<uint8_t>(a[i]) + static_cast<uint8_t>(b[i]) + carry;
        result[i] = static_cast<char>(sum & C(0xFF));
        carry = sum >> 8;
    }
    return carry;
}

uint16_t _sub(const bls_fp& a, const bls_fp& b, bls_fp& result) {
    uint16_t borrow = 0;
    for (size_t i = 0; i < 48; ++i) {
        uint16_t diff = static_cast<uint8_t>(a[i]) - static_cast<uint8_t>(b[i]) - borrow;
        result[i] = static_cast<char>(diff & C(0xFF));
        borrow = (diff >> 8) & 1;
    }
    return borrow;
}

template <typename T>
int bls_cmp(const T& a, const T& b) {
    for (int i = extent_traits<T>::value; i >= 0; --i) {
        uint8_t a_byte = static_cast<uint8_t>(a[i]);
        uint8_t b_byte = static_cast<uint8_t>(b[i]);
        if (a_byte < b_byte) return 1;
        if (a_byte > b_byte) return -1;
    }
    return 0;
}

void bls_fp_add(const bls_fp& a, const bls_fp& b, bls_fp& result) {

    uint16_t carry = _add(a, b, result);

    bool needs_reduction = carry > 0;
    if (!needs_reduction) {
        needs_reduction = bls_cmp(result, BLS12_381_FP_P) <= 0; // result >= p
    }

    if (needs_reduction) {
        _sub(result, BLS12_381_FP_P, result);
    }
}

void bls_fp_sub(const bls_fp& a, const bls_fp& b, bls_fp& result) {
    uint16_t borrow = _sub(a, b, result);
    if (borrow > 0) {
        _add(result, BLS12_381_FP_P, result);
    }
}

void bls_fp_neg(const bls_fp& a, bls_fp& result) {
    _sub(BLS12_381_FP_P, a, result);
}

bool is_lexicographically_largest(const bls_fp& y) {
    bls_fp tmp{};
    uint16_t borrow = _sub(y, BLS12_381_FP_HALF_P, tmp);
    return borrow == 0; // true when y >= BLS12_381_FP_HALF_P
}

int32_t blst_p1_uncompress(bls_g1& out, std::span<const uint8_t, 48> compressed)
{
    const uint8_t c0 = compressed[0];

    bool is_compressed = (c0 & C(0x80)) != 0;
    if(!is_compressed) return -1; // bad encoding

    bool is_infinite = (c0 & C(0x40)) != 0;
    if (is_infinite) {
        if((c0 & C(0x3f)) != 0 || !all_zero_from_offset(compressed, 1)) return -1; //bad encoding
        std::memset(out.data(), 0, out.size());
        return 0;
    }

    bls_fp x;
    to_little_endian(compressed, x);
    x[47] &= C(0x1f); //clear 3 top bits

    if( bls_cmp(x, BLS12_381_FP_P) <= 0 ) return -1; //x must be less than P    

    // Subgroup check: (0,±2) is not in group
    if( x == bls_fp{} ) return -1;

    // Compute alpha = x^3 + 4 in Fp
    bls_fp alpha{};
    // alpha = x^2
    int32_t rc = bls_fp_mul(x, x, alpha);
    if (rc != 0) return -1;

    // alpha = alpha * x  ( = x^3 )
    rc = bls_fp_mul( alpha, x, alpha );
    if (rc != 0) return -1;

    // alpha = alpha + 4
    bls_fp_add(alpha, BLS12_381_FP_B, alpha);

    // y = alpha^((p+1)/4)
    bls_fp y{};
    rc = bls_fp_exp(alpha, BLS12_381_FP_P_PLUS_1_OVER_4, y);
    if (rc != 0) return rc;

    // check y^2 == alpha
    bls_fp tmp{};
    rc = bls_fp_mul( y, y, tmp );
    if (rc != 0) return rc;
    if( tmp != alpha ) return -1;

    bool sign_of_y = (c0 & C(0x20)) != 0;
     if (is_lexicographically_largest(y) ^ sign_of_y) {
        bls_fp_neg(y, y);
    }

    // build output [ x(48 bytes) | y(48 bytes) ]
    std::memcpy(out.data(),    x.data(), 48);
    std::memcpy(out.data()+48, y.data(), 48);

    return 0;
}

bool blst_p1_is_inf(const bls_g1& p) {
    return p == G1_ZERO;
}

namespace silkworm {

Bytes kzg_to_versioned_hash(ByteView kzg) {
    Bytes out(32, 0);
    auto res = eosio::sha256((const char*)kzg.data(), kzg.length()).extract_as_byte_array();
    memcpy(out.data(), res.data(), 32);
    out[0] = C(0x01);
    return out;
}

static bool validate_kzg_g1(bls_g1& out, std::span<const uint8_t, 48> b) {

    /* Convert the bytes to a p1 point */
    /* The uncompress routine checks that the point is on the curve */
    if (blst_p1_uncompress(out, b) != 0) {
        return false;
    }

    /* The point at infinity is accepted! */
    if (blst_p1_is_inf(out)) {
        return true;
    }

    /* The point must be on the right subgroup */
    return blst_p1_in_g1(out);
}


static bool bytes_to_bls_scalar(std::span<const uint8_t, 32> b, bls_scalar& out) {
    to_little_endian(b, out);
    if(bls_cmp(out, BLS12_381_SCALAR_R) <= 0) { // out >= r
        return false;
    }
    return true;// out < r
}

void bls_g2_neg(const bls_g2& p, bls_g2& result) {
    std::memcpy(result.data(), p.data(), 96); // x unchanged

    bls_fp neg_y0;
    bls_fp_neg(reinterpret_cast<const bls_fp&>(p[96]), neg_y0);
    
    bls_fp neg_y1;
    bls_fp_neg(reinterpret_cast<const bls_fp&>(p[144]), neg_y1);
    
    std::memcpy(result.data() + 96, neg_y0.data(), 48);  // y_0
    std::memcpy(result.data() + 144, neg_y1.data(), 48); // y_1
}

int32_t bls_g2_sub(const bls_g2& a, const bls_g2& b, bls_g2& result) {
    bls_g2 neg_b;
    bls_g2_neg(b, neg_b);
    return bls_g2_add(a, neg_b, result);
}

void bls_g1_neg(const bls_g1& p, bls_g1& result) {
    std::memcpy(result.data(), p.data(), 48);

    bls_fp neg_y;
    bls_fp_neg(reinterpret_cast<const bls_fp&>(p[48]), neg_y);
    
    std::memcpy(result.data() + 48, neg_y.data(), 48);
}

int32_t bls_g1_sub(const bls_g1& a, const bls_g1& b, bls_g1& result) {
    bls_g1 neg_b;
    bls_g1_neg(b, neg_b);
    return bls_g1_add(a, neg_b, result);
}

static constexpr bls_g1 BLS12_381_G1_GENERATOR = {
    // x (bytes 0–47)
    C(0xbb), C(0x6c), C(0x2c), C(0xb2), C(0xad), C(0x00), C(0xaf), C(0xfb), C(0x1a), C(0x7a), C(0xf9), C(0x3f), C(0xe8), C(0x55), C(0x6c), C(0x58),
    C(0xac), C(0x1b), C(0x17), C(0x3f), C(0x3a), C(0x4e), C(0xa1), C(0x05), C(0xb9), C(0x74), C(0x97), C(0x4f), C(0x8c), C(0x68), C(0xc3), C(0x0f),
    C(0xac), C(0xa9), C(0x4f), C(0x8c), C(0x63), C(0x95), C(0x26), C(0x94), C(0xd7), C(0x97), C(0x31), C(0xa7), C(0xd3), C(0xf1), C(0x17), C(0x00),
    // y (bytes 48–95)
    C(0xe1), C(0xe7), C(0xc5), C(0x46), C(0x29), C(0x23), C(0xaa), C(0x0c), C(0xe4), C(0x8a), C(0x88), C(0xa2), C(0x44), C(0x7c), C(0xc0), C(0x3d),
    C(0xdd), C(0xb3), C(0x04), C(0x2c), C(0xcb), C(0x18), C(0xdb), C(0x00), C(0xf6), C(0x0a), C(0xd0), C(0xd5), C(0x95), C(0xe0), C(0xf5), C(0xfc),
    C(0xe4), C(0x8a), C(0x1d), C(0x74), C(0xed), C(0x30), C(0x9e), C(0xa0), C(0xf1), C(0xa0), C(0xaa), C(0xe3), C(0x81), C(0xf4), C(0xb3), C(0x08)
};

static constexpr bls_g2 BLS12_381_G2_GENERATOR = {
    // x_0 (bytes 0–47)
    C(0xb8), C(0x1b), C(0x12), C(0xc8), C(0x6c), C(0x05), C(0x48), C(0xd4), C(0xef), C(0xbb), C(0x05), C(0xa8), C(0x26), C(0x03), C(0xac), C(0x70),
    C(0x77), C(0xd1), C(0xe3), C(0x7a), C(0x64), C(0x0b), C(0x51), C(0xb4), C(0x02), C(0x3b), C(0x40), C(0xfa), C(0xd4), C(0x7a), C(0xe4), C(0xc6),
    C(0x51), C(0x10), C(0xc5), C(0x2d), C(0x27), C(0x05), C(0x08), C(0x26), C(0x91), C(0x0a), C(0x8f), C(0xf0), C(0xb2), C(0xa2), C(0x4a), C(0x02),
    // x_1 (bytes 48–95)
    C(0x7e), C(0x2b), C(0x04), C(0x5d), C(0x05), C(0x7d), C(0xac), C(0xe5), C(0x57), C(0x5d), C(0x94), C(0x13), C(0x12), C(0xf1), C(0x4c), C(0x33),
    C(0x49), C(0x50), C(0x7f), C(0xdc), C(0xbb), C(0x61), C(0xda), C(0xb5), C(0x1a), C(0xb6), C(0x20), C(0x99), C(0xd0), C(0x6b), C(0x59), C(0x65),
    C(0x4f), C(0x27), C(0x88), C(0xa0), C(0xd3), C(0xac), C(0x7d), C(0x60), C(0x9f), C(0x71), C(0x52), C(0x60), C(0x2b), C(0xe0), C(0x13), C(0x00),
    // y_0 (bytes 96–143)
    C(0x01), C(0x28), C(0xb8), C(0x60), C(0x48), C(0x35), C(0x19), C(0x9e), C(0x28), C(0xca), C(0xba), C(0xc3), C(0x9c), C(0xac), C(0x23), C(0xc9),
    C(0x12), C(0xd1), C(0x60), C(0x51), C(0x69), C(0x9a), C(0x42), C(0x6d), C(0xa7), C(0xd3), C(0xbd), C(0x8c), C(0xaa), C(0x9b), C(0xfd), C(0xad),
    C(0x1a), C(0x35), C(0x2e), C(0xda), C(0xc6), C(0xcd), C(0xc9), C(0x8c), C(0x11), C(0x6e), C(0x7d), C(0x72), C(0x27), C(0xd5), C(0xe5), C(0x0c),
    // y_1 (bytes 144–191)
    C(0xbe), C(0x79), C(0xf7), C(0x05), C(0xff), C(0x75), C(0x90), C(0xaa), C(0x1a), C(0xda), C(0xc1), C(0xce), C(0x75), C(0xd2), C(0x70), C(0xf3),
    C(0xb3), C(0x9a), C(0x99), C(0x2e), C(0x57), C(0xab), C(0x92), C(0x74), C(0x26), C(0xaf), C(0x63), C(0xa7), C(0x85), C(0x7e), C(0x28), C(0x3e),
    C(0xcb), C(0x99), C(0x8b), C(0xc2), C(0x2b), C(0xb0), C(0xd2), C(0xac), C(0x32), C(0xcc), C(0x34), C(0xa7), C(0x2e), C(0xa0), C(0xc4), C(0x06)
};

static constexpr bls_g2 KZG_SETUP_G2_1 = {
    // x_0 (bytes 0–47)
    C(0xeb), C(0x17), C(0x48), C(0x2b), C(0x7f), C(0x3e), C(0xee), C(0x57), C(0x09), C(0x44), C(0x68), C(0xbb), C(0x73), C(0xec), C(0x1e), C(0xe6),
    C(0xd2), C(0xfe), C(0xe0), C(0x8b), C(0x1e), C(0x00), C(0x1e), C(0x65), C(0xeb), C(0x91), C(0x39), C(0xeb), C(0x31), C(0xd5), C(0x6d), C(0xa8),
    C(0x69), C(0x11), C(0x31), C(0x23), C(0x19), C(0xe6), C(0xae), C(0x73), C(0xe1), C(0x21), C(0x8e), C(0xc1), C(0x10), C(0x42), C(0xd2), C(0x15),
    // x_1 (bytes 48–95)
    C(0x54), C(0x16), C(0x93), C(0x24), C(0xf5), C(0x7a), C(0x1c), C(0xaa), C(0x9b), C(0x5a), C(0xdd), C(0x5e), C(0x79), C(0x2a), C(0x49), C(0xc8),
    C(0xd8), C(0xc3), C(0x1a), C(0x28), C(0x62), C(0x0d), C(0x16), C(0x21), C(0xd0), C(0x46), C(0x5b), C(0x68), C(0xec), C(0x56), C(0xb3), C(0x74),
    C(0x1b), C(0xab), C(0x70), C(0x1c), C(0xdc), C(0x19), C(0x4e), C(0xec), C(0xdb), C(0x21), C(0xc5), C(0x89), C(0xbb), C(0x85), C(0x75), C(0x0a),
    // y_0 (bytes 96–143)
    C(0xeb), C(0xa4), C(0x9e), C(0xcc), C(0x51), C(0x21), C(0x39), C(0xf8), C(0x16), C(0xc1), C(0x5d), C(0x41), C(0x5c), C(0xbc), C(0x5d), C(0x3f),
    C(0x12), C(0x56), C(0x53), C(0x7c), C(0x62), C(0x7d), C(0x27), C(0x04), C(0x9c), C(0xa3), C(0x6a), C(0x4f), C(0x8b), C(0x7d), C(0xe4), C(0x80),
    C(0xdd), C(0x92), C(0x19), C(0xa5), C(0xaa), C(0x8a), C(0xf9), C(0x94), C(0xa6), C(0x2a), C(0xb4), C(0x95), C(0x47), C(0x12), C(0xca), C(0x11),
    // y_1 (bytes 144–191)
    C(0xf0), C(0x91), C(0xdd), C(0x01), C(0x2d), C(0x08), C(0xef), C(0xc8), C(0x1b), C(0x18), C(0x68), C(0x3b), C(0xff), C(0xb1), C(0xff), C(0x60),
    C(0xc4), C(0x52), C(0x00), C(0x33), C(0x9c), C(0xd2), C(0x8f), C(0xbe), C(0x3d), C(0x41), C(0xad), C(0x28), C(0xc8), C(0xa7), C(0xbf), C(0x76),
    C(0xf7), C(0x0a), C(0x40), C(0x14), C(0x5f), C(0x3d), C(0x09), C(0xc2), C(0x6d), C(0xda), C(0x16), C(0xd7), C(0xbd), C(0x47), C(0xf4), C(0x0d)
};

static bool verify_kzg_proof_impl(
    const bls_g1& commitment,
    const bls_scalar& z,
    const bls_scalar& y,
    const bls_g1& proof) {
    bls_g2 x_g2, X_minus_z;
    bls_g1 y_g1, P_minus_y;

    /* Calculate: X_minus_z */
    int32_t res = bls_g2_weighted_sum(&BLS12_381_G2_GENERATOR, &z, 1, x_g2);
    if(res != 0) return false;
    res = bls_g2_sub(KZG_SETUP_G2_1, x_g2, X_minus_z);
    if(res != 0) return false;

    /* Calculate: P_minus_y */
    res = bls_g1_weighted_sum(&BLS12_381_G1_GENERATOR, &y, 1, y_g1);
    if(res != 0) return false;
    res = bls_g1_sub(commitment, y_g1, P_minus_y);
    if(res != 0) return false;

    const bls_g1 g1_points[] = {P_minus_y, proof};
    const bls_g2 g2_points[] = {BLS12_381_G2_GENERATOR, X_minus_z};

    bls_gt r{};
    res = bls_pairing(g1_points, g2_points, 2, r);
    if(res != 0) return false;

    // check r == bls_gt{1}
    return all_zero_from_offset(r, 1) && r[0] == 1;
}

bool verify_kzg_proof(
    std::span<const uint8_t, 48> commitment,
    std::span<const uint8_t, 32> z,
    std::span<const uint8_t, 32> y,
    std::span<const uint8_t, 48> proof) {

    bls_scalar z_scalar, y_scalar;
    bls_g1 commitment_g1, proof_g1;

    if (!validate_kzg_g1(commitment_g1, commitment)) {
        return false;
    }

    if (!bytes_to_bls_scalar(z, z_scalar)) {
        return false;
    }
    if (!bytes_to_bls_scalar(y, y_scalar)) {
        return false;
    }
    if (!validate_kzg_g1(proof_g1, proof)) {
        return false;
    }

    return verify_kzg_proof_impl(
        commitment_g1, z_scalar, y_scalar, proof_g1);

    return false;
}

} //namespace silkworm

#endif