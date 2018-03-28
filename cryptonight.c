/*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program.  If not, see <http://www.gnu.org/licenses/>.
*
*/
#pragma once

#include "cryptonight.h"
#include "CryptoNight_monero.h"
#include "crypto/hash-ops.h"
#include <memory.h>
#include <stdio.h>
#include <assert.h>

#ifdef __GNUC__
#include <x86intrin.h>
static inline uint64_t _umul128(uint64_t a, uint64_t b, uint64_t* hi)
{
	unsigned __int128 r = (unsigned __int128)a * (unsigned __int128)b;
	*hi = r >> 64;
	return (uint64_t)r;
}
#define _mm256_set_m128i(v0, v1)  _mm256_insertf128_si256(_mm256_castsi128_si256(v1), (v0), 1)
#else
#include <intrin.h>
#include <stdint.h>
#endif // __GNUC__

#if !defined(_LP64) && !defined(_WIN64)
// #error You are trying to do a 32-bit build. This will all end in tears. I know it.
#endif

#define INIT_SIZE_BLK   8
#define AES_BLOCK_SIZE  16
#define INIT_SIZE_BYTE (INIT_SIZE_BLK * AES_BLOCK_SIZE)

#pragma pack(push, 1)
union cn_slow_hash_state {
	union hash_state hs;
	struct {
		uint8_t k[64];
		uint8_t init[INIT_SIZE_BYTE];
	};
};
#pragma pack(pop)

void keccak(const uint8_t *in, int inlen, uint8_t *md, int mdlen);
void keccakf(uint64_t st[25], int rounds);
extern void(*const extra_hashes[4])(const void *, size_t, char *);

__m128i soft_aesenc(__m128i in, __m128i key);
__m128i soft_aeskeygenassist(__m128i key, uint8_t rcon);

#ifdef _WIN64
#define _mm_cvtsi128_si64_x64_x86(in, out) out = _mm_cvtsi128_si64((in))
#define _umul128_x86_x64(Multiplier, Multiplicand, HighProduct, out) out = _umul128(Multiplier, Multiplicand, HighProduct)
#else

static_assert((sizeof(unsigned int) * 2) == sizeof(uint64_t), "(sizeof(unsigned int) * 2) != sizeof(uint64_t)");

#if 0
unsigned int lo = _mm_cvtsi128_si32(in);
unsigned int hi = _mm_cvtsi128_si32(_mm_srli_epi64(in, 32));
return (uint64_t)hi << 32 | lo;
#else

#define _mm_cvtsi128_si64_x64_x86(in, out) { out = 0; \
*(unsigned int *)&out = _mm_cvtsi128_si32(in); \
*((unsigned int *)&out + 1) = _mm_cvtsi128_si32(_mm_srli_epi64(in, 32)); \
}
#endif

#include <stdint.h>

#ifdef _MSC_VER
#  include <intrin.h>
#else
// MSVC doesn't optimize 32x32 => 64b multiplication without its intrinsic
// But good compilers can just use this to get a single mul instruction
static inline
uint64_t __emulu(uint32_t x, uint32_t y) {
	return x * (uint64_t)y;
}
#endif

// This is still pretty ugly with MSVC, branching on the carry
//  and using XMM store / integer reload to zero a register!
// But at least it inlines 4 mul instructions
//  instead of calling a generic 64x64 => 64b multiply helper function
#define _umul128_x86_x64(_Multiplier, _Multiplicand, _HighProduct, out) {\
	/* _Multiplier   = ab = a * 2^32 + b									 \
	   _Multiplicand = cd = c * 2^32 + d									 \
	   ab * cd = a * c * 2^64 + (a * d + b * c) * 2^32 + b * d*/		 \
	uint64_t a = _Multiplier >> 32;										 \
	uint64_t b = (uint32_t)_Multiplier; /* & 0xFFFFFFFF;	*/				 \
	uint64_t c = _Multiplicand >> 32;									 \
	uint64_t d = (uint32_t)_Multiplicand; /* & 0xFFFFFFFF;*/				 \
																		 \
    /* uint64_t ac = __emulu(a, c);*/	                                 \
	uint64_t ad = __emulu(a, d);										 \
	/* uint64_t bc = __emulu(b, c); */									 \
	uint64_t bd = __emulu(b, d);										 \
																		 \
	uint64_t adbc = ad + __emulu(b, c);									 \
	uint64_t adbc_carry = (adbc < ad); /* ? 1 : 0;*/					 \
									   /* MSVC gets confused by the ternary and makes worse code than using a boolean in an integer context for 1 : 0 \
    _Multiplier * _Multiplicand = _HighProduct * 2 ^ 64 + product_lo*/           \
	uint64_t product_lo = bd + (adbc << 32);                             \
	uint64_t product_lo_carry = (product_lo < bd); /* ? 1 : 0;*/           \
	*_HighProduct = __emulu(a, c) + (adbc >> 32) + (adbc_carry << 32) + product_lo_carry; \
	out = product_lo;}

// The above compiles badly in 64-bit mode
// This compiles to a single mul or mulx
#if defined(__x86_64__) && defined(__GNUC__)
uint64_t umul128_gcc(uint64_t multiplier, uint64_t multiplicand,
	uint64_t *product_hi) {
	unsigned __int128 a = multiplier, b = multiplicand;
	unsigned __int128 prod = a*b;
	*product_hi = prod >> 64;
	return prod;
}
#endif

#endif // _WIN64

// This will shift and xor tmp1 into itself as 4 32-bit vals such as
// sl_xor(a1 a2 a3 a4) = a1 (a2^a1) (a3^a2^a1) (a4^a3^a2^a1)
static inline __m128i sl_xor(__m128i tmp1)
{
	__m128i tmp4;
	tmp4 = _mm_slli_si128(tmp1, 0x04);
	tmp1 = _mm_xor_si128(tmp1, tmp4);
	tmp4 = _mm_slli_si128(tmp4, 0x04);
	tmp1 = _mm_xor_si128(tmp1, tmp4);
	tmp4 = _mm_slli_si128(tmp4, 0x04);
	tmp1 = _mm_xor_si128(tmp1, tmp4);
	return tmp1;
}

static inline void aes_genkey_sub(const uint8_t rcon, __m128i* xout0, __m128i* xout2)
{
	__m128i xout1;
	switch (rcon)
	{
	case 0x01:
		xout1 = _mm_aeskeygenassist_si128(*xout2, 0x01);
		break;
	case 0x02:
		xout1 = _mm_aeskeygenassist_si128(*xout2, 0x02);
		break;
	case 0x04:
		xout1 = _mm_aeskeygenassist_si128(*xout2, 0x04);
		break;
	case 0x08:
		xout1 = _mm_aeskeygenassist_si128(*xout2, 0x08);
		break;
	default:
		return;
		break;
	}

	xout1 = _mm_shuffle_epi32(xout1, 0xFF); // see PSHUFD, set all elems to 4th elem
	*xout0 = sl_xor(*xout0);
	*xout0 = _mm_xor_si128(*xout0, xout1);
	xout1 = _mm_aeskeygenassist_si128(*xout0, 0x00);
	xout1 = _mm_shuffle_epi32(xout1, 0xAA); // see PSHUFD, set all elems to 3rd elem
	*xout2 = sl_xor(*xout2);
	*xout2 = _mm_xor_si128(*xout2, xout1);
}

static inline void soft_aes_genkey_sub(__m128i* xout0, __m128i* xout2, uint8_t rcon)
{
	__m128i xout1 = soft_aeskeygenassist(*xout2, rcon);
	xout1 = _mm_shuffle_epi32(xout1, 0xFF); // see PSHUFD, set all elems to 4th elem
	*xout0 = sl_xor(*xout0);
	*xout0 = _mm_xor_si128(*xout0, xout1);
	xout1 = soft_aeskeygenassist(*xout0, 0x00);
	xout1 = _mm_shuffle_epi32(xout1, 0xAA); // see PSHUFD, set all elems to 3rd elem
	*xout2 = sl_xor(*xout2);
	*xout2 = _mm_xor_si128(*xout2, xout1);
}

static inline void aes_genkey(int SOFT_AES, const __m128i* memory, __m128i* k0, __m128i* k1, __m128i* k2, __m128i* k3,
	__m128i* k4, __m128i* k5, __m128i* k6, __m128i* k7, __m128i* k8, __m128i* k9)
{
	__m128i xout0, xout2;

	xout0 = _mm_load_si128(memory);
	xout2 = _mm_load_si128(memory + 1);
	*k0 = xout0;
	*k1 = xout2;

	if (SOFT_AES)
		soft_aes_genkey_sub(&xout0, &xout2, 0x01);
	else
		aes_genkey_sub(0x01, &xout0, &xout2);
	*k2 = xout0;
	*k3 = xout2;

	if (SOFT_AES)
		soft_aes_genkey_sub(&xout0, &xout2, 0x02);
	else
		aes_genkey_sub(0x02, &xout0, &xout2);
	*k4 = xout0;
	*k5 = xout2;

	if (SOFT_AES)
		soft_aes_genkey_sub(&xout0, &xout2, 0x04);
	else
		aes_genkey_sub(0x04, &xout0, &xout2);
	*k6 = xout0;
	*k7 = xout2;

	if (SOFT_AES)
		soft_aes_genkey_sub(&xout0, &xout2, 0x08);
	else
		aes_genkey_sub(0x08, &xout0, &xout2);
	*k8 = xout0;
	*k9 = xout2;
}

static inline void aes_round(__m128i key, __m128i* x0, __m128i* x1, __m128i* x2, __m128i* x3, __m128i* x4, __m128i* x5, __m128i* x6, __m128i* x7)
{
	*x0 = _mm_aesenc_si128(*x0, key);
	*x1 = _mm_aesenc_si128(*x1, key);
	*x2 = _mm_aesenc_si128(*x2, key);
	*x3 = _mm_aesenc_si128(*x3, key);
	*x4 = _mm_aesenc_si128(*x4, key);
	*x5 = _mm_aesenc_si128(*x5, key);
	*x6 = _mm_aesenc_si128(*x6, key);
	*x7 = _mm_aesenc_si128(*x7, key);
}

static inline void soft_aes_round(__m128i key, __m128i* x0, __m128i* x1, __m128i* x2, __m128i* x3, __m128i* x4, __m128i* x5, __m128i* x6, __m128i* x7)
{
	*x0 = soft_aesenc(*x0, key);
	*x1 = soft_aesenc(*x1, key);
	*x2 = soft_aesenc(*x2, key);
	*x3 = soft_aesenc(*x3, key);
	*x4 = soft_aesenc(*x4, key);
	*x5 = soft_aesenc(*x5, key);
	*x6 = soft_aesenc(*x6, key);
	*x7 = soft_aesenc(*x7, key);
}

void cn_explode_scratchpad(size_t MEM, int SOFT_AES, int PREFETCH, const __m128i* input, __m128i* output)
{
	// This is more than we have registers, compiler will assign 2 keys on the stack
	__m128i xin0, xin1, xin2, xin3, xin4, xin5, xin6, xin7;
	__m128i k0, k1, k2, k3, k4, k5, k6, k7, k8, k9;

	aes_genkey(SOFT_AES, input, &k0, &k1, &k2, &k3, &k4, &k5, &k6, &k7, &k8, &k9);

	xin0 = _mm_load_si128(input + 4);
	xin1 = _mm_load_si128(input + 5);
	xin2 = _mm_load_si128(input + 6);
	xin3 = _mm_load_si128(input + 7);
	xin4 = _mm_load_si128(input + 8);
	xin5 = _mm_load_si128(input + 9);
	xin6 = _mm_load_si128(input + 10);
	xin7 = _mm_load_si128(input + 11);

	for (size_t i = 0; i < MEM / sizeof(__m128i); i += 8)
	{
		if (SOFT_AES)
		{
			soft_aes_round(k0, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
			soft_aes_round(k1, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
			soft_aes_round(k2, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
			soft_aes_round(k3, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
			soft_aes_round(k4, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
			soft_aes_round(k5, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
			soft_aes_round(k6, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
			soft_aes_round(k7, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
			soft_aes_round(k8, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
			soft_aes_round(k9, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
		}
		else
		{
			aes_round(k0, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
			aes_round(k1, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
			aes_round(k2, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
			aes_round(k3, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
			aes_round(k4, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
			aes_round(k5, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
			aes_round(k6, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
			aes_round(k7, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
			aes_round(k8, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
			aes_round(k9, &xin0, &xin1, &xin2, &xin3, &xin4, &xin5, &xin6, &xin7);
		}

		_mm_store_si128(output + i + 0, xin0);
		_mm_store_si128(output + i + 1, xin1);
		_mm_store_si128(output + i + 2, xin2);
		_mm_store_si128(output + i + 3, xin3);

		if (PREFETCH)
			_mm_prefetch((const char*)output + i + 0, _MM_HINT_T2);

		_mm_store_si128(output + i + 4, xin4);
		_mm_store_si128(output + i + 5, xin5);
		_mm_store_si128(output + i + 6, xin6);
		_mm_store_si128(output + i + 7, xin7);

		if (PREFETCH)
			_mm_prefetch((const char*)output + i + 4, _MM_HINT_T2);
	}
}

void cn_implode_scratchpad(size_t MEM, int SOFT_AES, int PREFETCH, const __m128i* input, __m128i* output)
{
	// This is more than we have registers, compiler will assign 2 keys on the stack
	__m128i xout0, xout1, xout2, xout3, xout4, xout5, xout6, xout7;
	__m128i k0, k1, k2, k3, k4, k5, k6, k7, k8, k9;

	aes_genkey(SOFT_AES, output + 2, &k0, &k1, &k2, &k3, &k4, &k5, &k6, &k7, &k8, &k9);

	xout0 = _mm_load_si128(output + 4);
	xout1 = _mm_load_si128(output + 5);
	xout2 = _mm_load_si128(output + 6);
	xout3 = _mm_load_si128(output + 7);
	xout4 = _mm_load_si128(output + 8);
	xout5 = _mm_load_si128(output + 9);
	xout6 = _mm_load_si128(output + 10);
	xout7 = _mm_load_si128(output + 11);

	for (size_t i = 0; i < MEM / sizeof(__m128i); i += 8)
	{
		if (PREFETCH)
			_mm_prefetch((const char*)input + i + 0, _MM_HINT_NTA);

		xout0 = _mm_xor_si128(_mm_load_si128(input + i + 0), xout0);
		xout1 = _mm_xor_si128(_mm_load_si128(input + i + 1), xout1);
		xout2 = _mm_xor_si128(_mm_load_si128(input + i + 2), xout2);
		xout3 = _mm_xor_si128(_mm_load_si128(input + i + 3), xout3);

		if (PREFETCH)
			_mm_prefetch((const char*)input + i + 4, _MM_HINT_NTA);

		xout4 = _mm_xor_si128(_mm_load_si128(input + i + 4), xout4);
		xout5 = _mm_xor_si128(_mm_load_si128(input + i + 5), xout5);
		xout6 = _mm_xor_si128(_mm_load_si128(input + i + 6), xout6);
		xout7 = _mm_xor_si128(_mm_load_si128(input + i + 7), xout7);

		if (SOFT_AES)
		{
			soft_aes_round(k0, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			soft_aes_round(k1, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			soft_aes_round(k2, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			soft_aes_round(k3, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			soft_aes_round(k4, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			soft_aes_round(k5, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			soft_aes_round(k6, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			soft_aes_round(k7, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			soft_aes_round(k8, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			soft_aes_round(k9, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
		}
		else
		{
			aes_round(k0, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			aes_round(k1, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			aes_round(k2, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			aes_round(k3, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			aes_round(k4, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			aes_round(k5, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			aes_round(k6, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			aes_round(k7, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			aes_round(k8, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
			aes_round(k9, &xout0, &xout1, &xout2, &xout3, &xout4, &xout5, &xout6, &xout7);
		}
	}

	_mm_store_si128(output + 4, xout0);
	_mm_store_si128(output + 5, xout1);
	_mm_store_si128(output + 6, xout2);
	_mm_store_si128(output + 7, xout3);
	_mm_store_si128(output + 8, xout4);
	_mm_store_si128(output + 9, xout5);
	_mm_store_si128(output + 10, xout6);
	_mm_store_si128(output + 11, xout7);
}

void cryptonight_hash(size_t ITERATIONS, size_t MEM, int SOFT_AES, int PREFETCH,
	int VARIANT, const void* input, size_t len, void* output, cryptonight_ctx *ctx0)
{
	keccak((const uint8_t *)input, len, ctx0->hash_state, 200);

	VARIANT1_INIT();

	// Optim - 99% time boundary
	cn_explode_scratchpad(MEM, SOFT_AES, PREFETCH, (__m128i*)ctx0->hash_state, (__m128i*)ctx0->long_state);

	uint8_t* l0 = ctx0->long_state;
	uint64_t* h0 = (uint64_t*)ctx0->hash_state;

	uint64_t al0 = h0[0] ^ h0[4];
	uint64_t ah0 = h0[1] ^ h0[5];
	__m128i bx0 = _mm_set_epi64x(h0[3] ^ h0[7], h0[2] ^ h0[6]);

	uint64_t idx0 = h0[0] ^ h0[4];

	// Optim - 90% time boundary
	for (size_t i = 0; i < ITERATIONS; i++)
	{
		__m128i cx;
		cx = _mm_load_si128((__m128i *)&l0[idx0 & 0x1FFFF0]);

		if (SOFT_AES)
			cx = soft_aesenc(cx, _mm_set_epi64x(ah0, al0));
		else
			cx = _mm_aesenc_si128(cx, _mm_set_epi64x(ah0, al0));

		_mm_store_si128((__m128i *)&l0[idx0 & 0x1FFFF0], _mm_xor_si128(bx0, cx));

		VARIANT1_1(&l0[idx0 & 0x1FFFF0]);

		_mm_cvtsi128_si64_x64_x86(cx, idx0);
		bx0 = cx;

		if (PREFETCH)
			_mm_prefetch((const char*)&l0[idx0 & 0x1FFFF0], _MM_HINT_T0);

		uint64_t hi, lo, cl, ch;
		cl = ((uint64_t*)&l0[idx0 & 0x1FFFF0])[0];
		ch = ((uint64_t*)&l0[idx0 & 0x1FFFF0])[1];

		_umul128_x86_x64(idx0, cl, &hi, lo);

		al0 += hi;
		ah0 += lo;
		VARIANT1_2(ah0, 0)
			((uint64_t*)&l0[idx0 & 0x1FFFF0])[0] = al0;
		((uint64_t*)&l0[idx0 & 0x1FFFF0])[1] = ah0;
		VARIANT1_2(ah0, 0)
			ah0 ^= ch;
		al0 ^= cl;
		idx0 = al0;

		if (PREFETCH)
			_mm_prefetch((const char*)&l0[idx0 & 0x1FFFF0], _MM_HINT_T0);
	}

	// Optim - 90% time boundary
	cn_implode_scratchpad(MEM, SOFT_AES, PREFETCH, (__m128i*)ctx0->long_state, (__m128i*)ctx0->hash_state);

	// Optim - 99% time boundary

	keccakf((uint64_t*)ctx0->hash_state, 24);
	extra_hashes[ctx0->hash_state[0] & 3](ctx0->hash_state, 200, (char*)output);
}

void cryptonight_fast_hash(const char *input, char *output, uint32_t len) {
	union hash_state state;
	hash_process(&state, (const uint8_t *)input, len);
	memcpy(output, &state, HASH_SIZE);
}
