#ifndef _LIBVEC_HH_
#define _LIBVEC_HH_

#ifdef __MIC__

#include <immintrin.h>
typedef __m512i i32vec;
typedef __mmask16 vmask;
#define i32vec_set_all(x) _mm512_set1_epi32(x)
#define i32vec_set_base_st(base, st) _mm512_set_epi32((base) + (st) * 15, (base) + (st) * 14, (base) + (st) * 13, (base) + (st) * 12, (base) + (st) * 11, (base) + (st) * 10, (base) + (st) * 9, (base) + (st) * 8, (base) + (st) * 7, (base) + (st) * 6, (base) + (st) * 5, (base) + (st) * 4, (base) + (st) * 3, (base) + (st) * 2, (base) + (st) * 1, (base))
#define i32vec_set(e15, e14, e13, e12, e11, e10, e9, e8, e7, e6, e5, e4, e3, e2, e1, e0) _mm512_set_epi32(e15, e14, e13, e12, e11, e10, e9, e8, e7, e6, e5, e4, e3, e2, e1, e0)
#define i32vec_set_zero() _mm512_setzero_epi32()

#define i32vec_mask_mov(dest, mask, src) _mm512_mask_mov_epi32(dest, mask, src)

#define mask2int(x) _mm512_mask2int(x)
#define int2mask(x) _mm512_int2mask(x)
#define mask_or(x, y) _mm512_kor(x, y)
#define mask_and(x, y) _mm512_kand(x, y)
#define mask_not(x) _mm512_knot(x)

#define i32vec_and(x, y) _mm512_and_epi32(x, y)
#define i32vec_or(x, y) _mm512_or_epi32(x, y)
#define i32vec_xor(x, y) _mm512_xor_epi32(x, y)
#define i32vec_andnot(x, y) _mm512_andnot_epi32(x, y)

#define i32vec_mask_and(x, y, mask, def) _mm512_mask_and_epi32(def, mask, x, y)
#define i32vec_mask_or(x, y, mask, def) _mm512_mask_or_epi32(def, mask, x, y)
#define i32vec_mask_xor(x, y, mask, def) _mm512_mask_xor_epi32(def, mask, x, y)
#define i32vec_mask_andnot(x, y, mask, def) _mm512_mask_andnot_epi32(def, mask, x, y)

// Bitwise shift
#define i32vec_lshift_vec(x, y) _mm512_sllv_epi32(x, y) // Logical l-shift elements in x by elements in y
#define i32vec_lrshift_vec(x, y) _mm512_srlv_epi32(x, y) // Logical r-shift elements in x by elements in y
#define i32vec_arshift_vec(x, y) _mm512_srav_epi32(x, y) // Arithmetic r-shift elements in x by elements in y
#define i32vec_lshift_i32(x, y) _mm512_slli_epi32(x, y) // Logical l-shift elements in x by y
#define i32vec_lrshift_i32(x, y) _mm512_srli_epi32(x, y) // Logical r-shift elements in x by y
#define i32vec_arshift_i32(x, y) _mm512_srai_epi32(x, y) // Arithmetic r-shift elements in x by y

// Masked variants
#define i32vec_mask_lshift_vec(x, y, mask, def) _mm512_mask_sllv_epi32(def, mask, x, y)
#define i32vec_mask_lrshift_vec(x, y, mask, def) _mm512_mask_srlv_epi32(def, mask, x, y)
#define i32vec_mask_arshift_vec(x, y, mask, def) _mm512_mask_srav_epi32(def, mask, x, y)
#define i32vec_mask_lshift_i32(x, y, mask, def) _mm512_mask_slli_epi32(def, mask, x, y)
#define i32vec_mask_lrshift_i32(x, y, mask, def) _mm512_mask_srli_epi32(def, mask, x, y)
#define i32vec_mask_arshift_i32(x, y, mask, def) _mm512_mask_srai_epi32(def, mask, x, y)

#define i32vec_add(x, y) _mm512_add_epi32(x, y)
#define i32vec_mul(x, y) _mm512_mullo_epi32(x, y)
#define i32vec_mul_high(x, y) _mm512_mulhi_epi32(x, y)
#define i32vec_adc(x, y, carry_in, p_carry_out) _mm512_adc_epi32(x, carry_in, y, p_carry_out)
#define i32vec_sub(x, y) _mm512_sub_epi32(x, y)
#define i32vec_mask_add(x, y, mask, def) _mm512_mask_add_epi32(def, mask, x, y)
#define i32vec_mask_mul(x, y, mask, def) _mm512_mask_mullo_epi32(def, mask, x, y)
#define i32vec_mask_mul_high(x, y, mask, def) _mm512_mask_mulhi_epi32(def, mask, x, y)
#define i32vec_mask_adc(x, y, mask, carry_in, p_carry_out) _mm512_mask_adc_epi32(x, mask, carry_in, y, p_carry_out) // Resulting vector element falls back to value in x if mask element is not set
#define i32vec_mask_sub(x, y, mask, def) _mm512_mask_sub_epi32(def, mask, x, y)


// mask[i] <- 1 iff 'x[i] OP y[i]'
#define i32vec_eq(x, y) _mm512_cmp_epi32_mask(x, y, _MM_CMPINT_EQ)
#define i32vec_ne(x, y) _mm512_cmp_epi32_mask(x, y, _MM_CMPINT_NE)
#define i32vec_gt(x, y) _mm512_cmp_epi32_mask(x, y, _MM_CMPINT_GT)
#define i32vec_ge(x, y) _mm512_cmp_epi32_mask(x, y, _MM_CMPINT_GE)
#define i32vec_lt(x, y) _mm512_cmp_epi32_mask(x, y, _MM_CMPINT_LT)
#define i32vec_le(x, y) _mm512_cmp_epi32_mask(x, y, _MM_CMPINT_LE)

// mask[i] <- 1 iff 'x[i] OP y[i]' && mask[i] == 1
#define i32vec_mask_eq(x, y, mask) _mm512_mask_cmp_epi32_mask(mask, x, y, _MM_CMPINT_EQ)
#define i32vec_mask_ne(x, y, mask) _mm512_mask_cmp_epi32_mask(mask, x, y, _MM_CMPINT_NE)
#define i32vec_mask_gt(x, y, mask) _mm512_mask_cmp_epi32_mask(mask, x, y, _MM_CMPINT_GT)
#define i32vec_mask_ge(x, y, mask) _mm512_mask_cmp_epi32_mask(mask, x, y, _MM_CMPINT_GE)
#define i32vec_mask_lt(x, y, mask) _mm512_mask_cmp_epi32_mask(mask, x, y, _MM_CMPINT_LT)
#define i32vec_mask_le(x, y, mask) _mm512_mask_cmp_epi32_mask(mask, x, y, _MM_CMPINT_LE)

// ------ Begin integer 1B scale gathers
#define i32vec_gather(base, index) _mm512_i32extgather_epi32(index, base, _MM_UPCONV_EPI32_NONE, 1, _MM_HINT_NONE)
#define i32vec_gather_u16(base, index) _mm512_i32extgather_epi32(index, base, _MM_UPCONV_EPI32_UINT16, 1, _MM_HINT_NONE)
#define i32vec_gather_i16(base, index) _mm512_i32extgather_epi32(index, base, _MM_UPCONV_EPI32_IINT16, 1, _MM_HINT_NONE)
#define i32vec_gather_u8(base, index) _mm512_i32extgather_epi32(index, base, _MM_UPCONV_EPI32_UINT8, 1, _MM_HINT_NONE)
#define i32vec_gather_i8(base, index) _mm512_i32extgather_epi32(index, base, _MM_UPCONV_EPI32_SINT8, 1, _MM_HINT_NONE)

    // Non-temporal gathers (Load to cache as least priority in LRU)
#define i32vec_gather_nt(base, index) _mm512_i32extgather_epi32(index, base, _MM_UPCONV_EPI32_NONE, 1, _MM_HINT_NT)
#define i32vec_gather_u8_nt(base, index) _mm512_i32extgather_epi32(index, base, _MM_UPCONV_EPI32_UINT8, 1, _MM_HINT_NT)
#define i32vec_gather_i8_nt(base, index) _mm512_i32extgather_epi32(index, base, _MM_UPCONV_EPI32_SINT8, 1, _MM_HINT_NT)
#define i32vec_gather_u16_nt(base, index) _mm512_i32extgather_epi32(index, base, _MM_UPCONV_EPI32_UINT16, 1, _MM_HINT_NT)
#define i32vec_gather_i16_nt(base, index) _mm512_i32extgather_epi32(index, base, _MM_UPCONV_EPI32_IINT16, 1, _MM_HINT_NT)


    // Masked gathers
#define i32vec_mask_gather(base, index, mask, def) _mm512_mask_i32extgather_epi32(def, mask, index, base, _MM_UPCONV_EPI32_NONE, 1, _MM_HINT_NONE) // The same as above
#define i32vec_mask_gather_u16(base, index, mask, def) _mm512_mask_i32extgather_epi32(def, mask, index, base, _MM_UPCONV_EPI32_UINT16, 1, _MM_HINT_NONE)
#define i32vec_mask_gather_i16(base, index, mask, def) _mm512_mask_i32extgather_epi32(def, mask, index, base, _MM_UPCONV_EPI32_IINT16, 1, _MM_HINT_NONE)
#define i32vec_mask_gather_u8(base, index, mask, def) _mm512_mask_i32extgather_epi32(def, mask, index, base, _MM_UPCONV_EPI32_UINT8, 1, _MM_HINT_NONE)
#define i32vec_mask_gather_i8(base, index, mask, def) _mm512_mask_i32extgather_epi32(def, mask, index, base, _MM_UPCONV_EPI32_SINT8, 1, _MM_HINT_NONE)

    // Masked non-temporal gathers (Load to cache as least priority in LRU)
#define i32vec_mask_gather_nt(base, index, mask, def) _mm512_mask_i32extgather_epi32(def, mask, index, base, _MM_UPCONV_EPI32_NONE, 1, _MM_HINT_NT) // The same as above
#define i32vec_mask_gather_u16_nt(base, index, mask, def) _mm512_mask_i32extgather_epi32(def, mask, index, base, _MM_UPCONV_EPI32_UINT16, 1, _MM_HINT_NT)
#define i32vec_mask_gather_i16_nt(base, index, mask, def) _mm512_mask_i32extgather_epi32(def, mask, index, base, _MM_UPCONV_EPI32_IINT16, 1, _MM_HINT_NT)
#define i32vec_mask_gather_u8_nt(base, index, mask, def) _mm512_mask_i32extgather_epi32(def, mask, index, base, _MM_UPCONV_EPI32_UINT8, 1, _MM_HINT_NT)
#define i32vec_mask_gather_i8_nt(base, index, mask, def) _mm512_mask_i32extgather_epi32(def, mask, index, base, _MM_UPCONV_EPI32_SINT8, 1, _MM_HINT_NT)

// ------ End 1B-scale gathers

// ------ Begin 2B-scale Integer gathers
#define i32vec_gather_s2(base, index) _mm512_i32extgather_epi32(index, base, _MM_UPCONV_EPI32_NONE, 2, _MM_HINT_NONE)
#define i32vec_gather_u16_s2(base, index) _mm512_i32extgather_epi32(index, base, _MM_UPCONV_EPI32_UINT16, 2, _MM_HINT_NONE)
#define i32vec_gather_i16_s2(base, index) _mm512_i32extgather_epi32(index, base, _MM_UPCONV_EPI32_IINT16, 2, _MM_HINT_NONE)
#define i32vec_gather_u8_s2(base, index) _mm512_i32extgather_epi32(index, base, _MM_UPCONV_EPI32_UINT8, 2, _MM_HINT_NONE)
#define i32vec_gather_i8_s2(base, index) _mm512_i32extgather_epi32(index, base, _MM_UPCONV_EPI32_SINT8, 2, _MM_HINT_NONE)

// Non-temporal integer gathers (Load to cache as least priority in LRU)
#define i32vec_gather_nt_s2(base, index) _mm512_i32extgather_epi32(index, base, _MM_UPCONV_EPI32_NONE, 2, _MM_HINT_NT) // The same as above
#define i32vec_gather_u8_nt_s2(base, index) _mm512_i32extgather_epi32(index, base, _MM_UPCONV_EPI32_UINT8, 2, _MM_HINT_NT)
#define i32vec_gather_i8_nt_s2(base, index) _mm512_i32extgather_epi32(index, base, _MM_UPCONV_EPI32_SINT8, 2, _MM_HINT_NT)
#define i32vec_gather_u16_nt_s2(base, index) _mm512_i32extgather_epi32(index, base, _MM_UPCONV_EPI32_UINT16, 2, _MM_HINT_NT)
#define i32vec_gather_i16_nt_s2(base, index) _mm512_i32extgather_epi32(index, base, _MM_UPCONV_EPI32_IINT16, 2, _MM_HINT_NT)


// Masked integer gathers
#define i32vec_mask_gather_s2(base, index, mask, def) _mm512_mask_i32extgather_epi32(def, mask, index, base, _MM_UPCONV_EPI32_NONE, 2, _MM_HINT_NONE) // The same as above
#define i32vec_mask_gather_u16_s2(base, index, mask, def) _mm512_mask_i32extgather_epi32(def, mask, index, base, _MM_UPCONV_EPI32_UINT16, 2, _MM_HINT_NONE)
#define i32vec_mask_gather_i16_s2(base, index, mask, def) _mm512_mask_i32extgather_epi32(def, mask, index, base, _MM_UPCONV_EPI32_IINT16, 2, _MM_HINT_NONE)
#define i32vec_mask_gather_u8_s2(base, index, mask, def) _mm512_mask_i32extgather_epi32(def, mask, index, base, _MM_UPCONV_EPI32_UINT8, 2, _MM_HINT_NONE)
#define i32vec_mask_gather_i8_s2(base, index, mask, def) _mm512_mask_i32extgather_epi32(def, mask, index, base, _MM_UPCONV_EPI32_SINT8, 2, _MM_HINT_NONE)

// Masked non-temporal integer gathers (Load to cache as least priority in LRU)
#define i32vec_mask_gather_nt_s2(base, index, mask, def) _mm512_mask_i32extgather_epi32(def, mask, index, base, _MM_UPCONV_EPI32_NONE, 2, _MM_HINT_NT) // The same as above
#define i32vec_mask_gather_u16_nt_s2(base, index, mask, def) _mm512_mask_i32extgather_epi32(def, mask, index, base, _MM_UPCONV_EPI32_UINT16, 2, _MM_HINT_NT)
#define i32vec_mask_gather_i16_nt_s2(base, index, mask, def) _mm512_mask_i32extgather_epi32(def, mask, index, base, _MM_UPCONV_EPI32_IINT16, 2, _MM_HINT_NT)
#define i32vec_mask_gather_u8_nt_s2(base, index, mask, def) _mm512_mask_i32extgather_epi32(def, mask, index, base, _MM_UPCONV_EPI32_UINT8, 2, _MM_HINT_NT)
#define i32vec_mask_gather_i8_nt_s2(base, index, mask, def) _mm512_mask_i32extgather_epi32(def, mask, index, base, _MM_UPCONV_EPI32_SINT8, 2, _MM_HINT_NT)

// ------ End 2B-scale integer gathers

// ------ Begin 4B-scale Integer gathers
#define i32vec_gather_s4(base, index) _mm512_i32extgather_epi32(index, base, _MM_UPCONV_EPI32_NONE, 4, _MM_HINT_NONE)
#define i32vec_gather_u16_s4(base, index) _mm512_i32extgather_epi32(index, base, _MM_UPCONV_EPI32_UINT16, 4, _MM_HINT_NONE)
#define i32vec_gather_i16_s4(base, index) _mm512_i32extgather_epi32(index, base, _MM_UPCONV_EPI32_IINT16, 4, _MM_HINT_NONE)
#define i32vec_gather_u8_s4(base, index) _mm512_i32extgather_epi32(index, base, _MM_UPCONV_EPI32_UINT8, 4, _MM_HINT_NONE)
#define i32vec_gather_i8_s4(base, index) _mm512_i32extgather_epi32(index, base, _MM_UPCONV_EPI32_SINT8, 4, _MM_HINT_NONE)

// Non-temporal integer gathers (Load to cache as least priority in LRU)
#define i32vec_gather_nt_s4(base, index) _mm512_i32extgather_epi32(index, base, _MM_UPCONV_EPI32_NONE, 4, _MM_HINT_NT) // The same as above
#define i32vec_gather_u8_nt_s4(base, index) _mm512_i32extgather_epi32(index, base, _MM_UPCONV_EPI32_UINT8, 4, _MM_HINT_NT)
#define i32vec_gather_i8_nt_s4(base, index) _mm512_i32extgather_epi32(index, base, _MM_UPCONV_EPI32_SINT8, 4, _MM_HINT_NT)
#define i32vec_gather_u16_nt_s4(base, index) _mm512_i32extgather_epi32(index, base, _MM_UPCONV_EPI32_UINT16, 4, _MM_HINT_NT)
#define i32vec_gather_i16_nt_s4(base, index) _mm512_i32extgather_epi32(index, base, _MM_UPCONV_EPI32_IINT16, 4, _MM_HINT_NT)


// Masked integer gathers
#define i32vec_mask_gather_s4(base, index, mask, def) _mm512_mask_i32extgather_epi32(def, mask, index, base, _MM_UPCONV_EPI32_NONE, 4, _MM_HINT_NONE) // The same as above
#define i32vec_mask_gather_u16_s4(base, index, mask, def) _mm512_mask_i32extgather_epi32(def, mask, index, base, _MM_UPCONV_EPI32_UINT16, 4, _MM_HINT_NONE)
#define i32vec_mask_gather_i16_s4(base, index, mask, def) _mm512_mask_i32extgather_epi32(def, mask, index, base, _MM_UPCONV_EPI32_IINT16, 4, _MM_HINT_NONE)
#define i32vec_mask_gather_u8_s4(base, index, mask, def) _mm512_mask_i32extgather_epi32(def, mask, index, base, _MM_UPCONV_EPI32_UINT8, 4, _MM_HINT_NONE)
#define i32vec_mask_gather_i8_s4(base, index, mask, def) _mm512_mask_i32extgather_epi32(def, mask, index, base, _MM_UPCONV_EPI32_SINT8, 4, _MM_HINT_NONE)

// Masked non-temporal integer gathers (Load to cache as least priority in LRU)
#define i32vec_mask_gather_nt_s4(base, index, mask, def) _mm512_mask_i32extgather_epi32(def, mask, index, base, _MM_UPCONV_EPI32_NONE, 4, _MM_HINT_NT) // The same as above
#define i32vec_mask_gather_u16_nt_s4(base, index, mask, def) _mm512_mask_i32extgather_epi32(def, mask, index, base, _MM_UPCONV_EPI32_UINT16, 4, _MM_HINT_NT)
#define i32vec_mask_gather_i16_nt_s4(base, index, mask, def) _mm512_mask_i32extgather_epi32(def, mask, index, base, _MM_UPCONV_EPI32_IINT16, 4, _MM_HINT_NT)
#define i32vec_mask_gather_u8_nt_s4(base, index, mask, def) _mm512_mask_i32extgather_epi32(def, mask, index, base, _MM_UPCONV_EPI32_UINT8, 4, _MM_HINT_NT)
#define i32vec_mask_gather_i8_nt_s4(base, index, mask, def) _mm512_mask_i32extgather_epi32(def, mask, index, base, _MM_UPCONV_EPI32_SINT8, 4, _MM_HINT_NT)

// ------ End 4B-scale integer gathers

// ------ Begin 8B-scale Integer gathers
#define i32vec_gather_s8(base, index) _mm512_i32extgather_epi32(index, base, _MM_UPCONV_EPI32_NONE, 8, _MM_HINT_NONE)
#define i32vec_gather_u16_s8(base, index) _mm512_i32extgather_epi32(index, base, _MM_UPCONV_EPI32_UINT16, 8, _MM_HINT_NONE)
#define i32vec_gather_i16_s8(base, index) _mm512_i32extgather_epi32(index, base, _MM_UPCONV_EPI32_IINT16, 8, _MM_HINT_NONE)
#define i32vec_gather_u8_s8(base, index) _mm512_i32extgather_epi32(index, base, _MM_UPCONV_EPI32_UINT8, 8, _MM_HINT_NONE)
#define i32vec_gather_i8_s8(base, index) _mm512_i32extgather_epi32(index, base, _MM_UPCONV_EPI32_SINT8, 8, _MM_HINT_NONE)

// Non-temporal integer gathers (Load to cache as least priority in LRU)
#define i32vec_gather_nt_s8(base, index) _mm512_i32extgather_epi32(index, base, _MM_UPCONV_EPI32_NONE, 8, _MM_HINT_NT) // The same as above
#define i32vec_gather_u8_nt_s8(base, index) _mm512_i32extgather_epi32(index, base, _MM_UPCONV_EPI32_UINT8, 8, _MM_HINT_NT)
#define i32vec_gather_i8_nt_s8(base, index) _mm512_i32extgather_epi32(index, base, _MM_UPCONV_EPI32_SINT8, 8, _MM_HINT_NT)
#define i32vec_gather_u16_nt_s8(base, index) _mm512_i32extgather_epi32(index, base, _MM_UPCONV_EPI32_UINT16, 8, _MM_HINT_NT)
#define i32vec_gather_i16_nt_s8(base, index) _mm512_i32extgather_epi32(index, base, _MM_UPCONV_EPI32_IINT16, 8, _MM_HINT_NT)


// Masked integer gathers
#define i32vec_mask_gather_s8(base, index, mask, def) _mm512_mask_i32extgather_epi32(def, mask, index, base, _MM_UPCONV_EPI32_NONE, 8, _MM_HINT_NONE) // The same as above
#define i32vec_mask_gather_u16_s8(base, index, mask, def) _mm512_mask_i32extgather_epi32(def, mask, index, base, _MM_UPCONV_EPI32_UINT16, 8, _MM_HINT_NONE)
#define i32vec_mask_gather_i16_s8(base, index, mask, def) _mm512_mask_i32extgather_epi32(def, mask, index, base, _MM_UPCONV_EPI32_IINT16, 8, _MM_HINT_NONE)
#define i32vec_mask_gather_u8_s8(base, index, mask, def) _mm512_mask_i32extgather_epi32(def, mask, index, base, _MM_UPCONV_EPI32_UINT8, 8, _MM_HINT_NONE)
#define i32vec_mask_gather_i8_s8(base, index, mask, def) _mm512_mask_i32extgather_epi32(def, mask, index, base, _MM_UPCONV_EPI32_SINT8, 8, _MM_HINT_NONE)

// Masked non-temporal integer gathers (Load to cache as least priority in LRU)
#define i32vec_mask_gather_nt_s8(base, index, mask, def) _mm512_mask_i32extgather_epi32(def, mask, index, base, _MM_UPCONV_EPI32_NONE, 8, _MM_HINT_NT) // The same as above
#define i32vec_mask_gather_u16_nt_s8(base, index, mask, def) _mm512_mask_i32extgather_epi32(def, mask, index, base, _MM_UPCONV_EPI32_UINT16, 8, _MM_HINT_NT)
#define i32vec_mask_gather_i16_nt_s8(base, index, mask, def) _mm512_mask_i32extgather_epi32(def, mask, index, base, _MM_UPCONV_EPI32_IINT16, 8, _MM_HINT_NT)
#define i32vec_mask_gather_u8_nt_s8(base, index, mask, def) _mm512_mask_i32extgather_epi32(def, mask, index, base, _MM_UPCONV_EPI32_UINT8, 8, _MM_HINT_NT)
#define i32vec_mask_gather_i8_nt_s8(base, index, mask, def) _mm512_mask_i32extgather_epi32(def, mask, index, base, _MM_UPCONV_EPI32_SINT8, 8, _MM_HINT_NT)

// ------ End 8B-scale integer gathers

// ------ Begin integer 1B scale scatters
#define i32vec_scatter(base, index, src) _mm512_i32extscatter_epi32(base, index, src, _MM_DOWNCONV_EPI32_NONE, 1, _MM_HINT_NONE)
#define i32vec_scatter_u16(base, index, src) _mm512_i32extscatter_epi32(base, index, src, _MM_DOWNCONV_EPI32_UINT16, 1, _MM_HINT_NONE)
#define i32vec_scatter_i16(base, index, src) _mm512_i32extscatter_epi32(base, index, src, _MM_DOWNCONV_EPI32_IINT16, 1, _MM_HINT_NONE)
#define i32vec_scatter_u8(base, index, src) _mm512_i32extscatter_epi32(base, index, src, _MM_DOWNCONV_EPI32_UINT8, 1, _MM_HINT_NONE)
#define i32vec_scatter_i8(base, index, src) _mm512_i32extscatter_epi32(base, index, src, _MM_DOWNCONV_EPI32_SINT8, 1, _MM_HINT_NONE)

    // Non-temporal scatters (Load to cache as least priority in LRU)
#define i32vec_scatter_nt(base, index, src) _mm512_i32extscatter_epi32(base, index, src, _MM_DOWNCONV_EPI32_NONE, 1, _MM_HINT_NT)
#define i32vec_scatter_u8_nt(base, index, src) _mm512_i32extscatter_epi32(base, index, src, _MM_DOWNCONV_EPI32_UINT8, 1, _MM_HINT_NT)
#define i32vec_scatter_i8_nt(base, index, src) _mm512_i32extscatter_epi32(base, index, src, _MM_DOWNCONV_EPI32_SINT8, 1, _MM_HINT_NT)
#define i32vec_scatter_u16_nt(base, index, src) _mm512_i32extscatter_epi32(base, index, src, _MM_DOWNCONV_EPI32_UINT16, 1, _MM_HINT_NT)
#define i32vec_scatter_i16_nt(base, index, src) _mm512_i32extscatter_epi32(base, index, src, _MM_DOWNCONV_EPI32_IINT16, 1, _MM_HINT_NT)


    // Masked scatters
#define i32vec_mask_scatter(base, index, src, mask) _mm512_mask_i32extscatter_epi32(base, mask, index, src, _MM_DOWNCONV_EPI32_NONE, 1, _MM_HINT_NONE) // The same as above
#define i32vec_mask_scatter_u16(base, index, src, mask) _mm512_mask_i32extscatter_epi32(base, mask, index, src, _MM_DOWNCONV_EPI32_UINT16, 1, _MM_HINT_NONE)
#define i32vec_mask_scatter_i16(base, index, src, mask) _mm512_mask_i32extscatter_epi32(base, mask, index, src, _MM_DOWNCONV_EPI32_IINT16, 1, _MM_HINT_NONE)
#define i32vec_mask_scatter_u8(base, index, src, mask) _mm512_mask_i32extscatter_epi32(base, mask, index, src, _MM_DOWNCONV_EPI32_UINT8, 1, _MM_HINT_NONE)
#define i32vec_mask_scatter_i8(base, index, src, mask) _mm512_mask_i32extscatter_epi32(base, mask, index, src, _MM_DOWNCONV_EPI32_SINT8, 1, _MM_HINT_NONE)

    // Masked non-temporal scatters (Load to cache as least priority in LRU)
#define i32vec_mask_scatter_nt(base, index, src, mask) _mm512_mask_i32extscatter_epi32(base, mask, index, src, _MM_DOWNCONV_EPI32_NONE, 1, _MM_HINT_NT) // The same as above
#define i32vec_mask_scatter_u16_nt(base, index, src, mask) _mm512_mask_i32extscatter_epi32(base, mask, index, src, _MM_DOWNCONV_EPI32_UINT16, 1, _MM_HINT_NT)
#define i32vec_mask_scatter_i16_nt(base, index, src, mask) _mm512_mask_i32extscatter_epi32(base, mask, index, src, _MM_DOWNCONV_EPI32_IINT16, 1, _MM_HINT_NT)
#define i32vec_mask_scatter_u8_nt(base, index, src, mask) _mm512_mask_i32extscatter_epi32(base, mask, index, src, _MM_DOWNCONV_EPI32_UINT8, 1, _MM_HINT_NT)
#define i32vec_mask_scatter_i8_nt(base, index, src, mask) _mm512_mask_i32extscatter_epi32(base, mask, index, src, _MM_DOWNCONV_EPI32_SINT8, 1, _MM_HINT_NT)

// ------ End 1B-scale scatters

// ------ Begin 2B-scale Integer scatters
#define i32vec_scatter_s2(base, index, src) _mm512_i32extscatter_epi32(base, index, src, _MM_DOWNCONV_EPI32_NONE, 2, _MM_HINT_NONE)
#define i32vec_scatter_u16_s2(base, index, src) _mm512_i32extscatter_epi32(base, index, src, _MM_DOWNCONV_EPI32_UINT16, 2, _MM_HINT_NONE)
#define i32vec_scatter_i16_s2(base, index, src) _mm512_i32extscatter_epi32(base, index, src, _MM_DOWNCONV_EPI32_IINT16, 2, _MM_HINT_NONE)
#define i32vec_scatter_u8_s2(base, index, src) _mm512_i32extscatter_epi32(base, index, src, _MM_DOWNCONV_EPI32_UINT8, 2, _MM_HINT_NONE)
#define i32vec_scatter_i8_s2(base, index, src) _mm512_i32extscatter_epi32(base, index, src, _MM_DOWNCONV_EPI32_SINT8, 2, _MM_HINT_NONE)

// Non-temporal integer scatters (Load to cache as least priority in LRU)
#define i32vec_scatter_nt_s2(base, index, src) _mm512_i32extscatter_epi32(base, index, src, _MM_DOWNCONV_EPI32_NONE, 2, _MM_HINT_NT) // The same as above
#define i32vec_scatter_u8_nt_s2(base, index, src) _mm512_i32extscatter_epi32(base, index, src, _MM_DOWNCONV_EPI32_UINT8, 2, _MM_HINT_NT)
#define i32vec_scatter_i8_nt_s2(base, index, src) _mm512_i32extscatter_epi32(base, index, src, _MM_DOWNCONV_EPI32_SINT8, 2, _MM_HINT_NT)
#define i32vec_scatter_u16_nt_s2(base, index, src) _mm512_i32extscatter_epi32(base, index, src, _MM_DOWNCONV_EPI32_UINT16, 2, _MM_HINT_NT)
#define i32vec_scatter_i16_nt_s2(base, index, src) _mm512_i32extscatter_epi32(base, index, src, _MM_DOWNCONV_EPI32_IINT16, 2, _MM_HINT_NT)


// Masked integer scatters
#define i32vec_mask_scatter_s2(base, index, src, mask) _mm512_mask_i32extscatter_epi32(base, mask, index, src, _MM_DOWNCONV_EPI32_NONE, 2, _MM_HINT_NONE) // The same as above
#define i32vec_mask_scatter_u16_s2(base, index, src, mask) _mm512_mask_i32extscatter_epi32(base, mask, index, src, _MM_DOWNCONV_EPI32_UINT16, 2, _MM_HINT_NONE)
#define i32vec_mask_scatter_i16_s2(base, index, src, mask) _mm512_mask_i32extscatter_epi32(base, mask, index, src, _MM_DOWNCONV_EPI32_IINT16, 2, _MM_HINT_NONE)
#define i32vec_mask_scatter_u8_s2(base, index, src, mask) _mm512_mask_i32extscatter_epi32(base, mask, index, src, _MM_DOWNCONV_EPI32_UINT8, 2, _MM_HINT_NONE)
#define i32vec_mask_scatter_i8_s2(base, index, src, mask) _mm512_mask_i32extscatter_epi32(base, mask, index, src, _MM_DOWNCONV_EPI32_SINT8, 2, _MM_HINT_NONE)

// Masked non-temporal integer scatters (Load to cache as least priority in LRU)
#define i32vec_mask_scatter_nt_s2(base, index, src, mask) _mm512_mask_i32extscatter_epi32(base, mask, index, src, _MM_DOWNCONV_EPI32_NONE, 2, _MM_HINT_NT) // The same as above
#define i32vec_mask_scatter_u16_nt_s2(base, index, src, mask) _mm512_mask_i32extscatter_epi32(base, mask, index, src, _MM_DOWNCONV_EPI32_UINT16, 2, _MM_HINT_NT)
#define i32vec_mask_scatter_i16_nt_s2(base, index, src, mask) _mm512_mask_i32extscatter_epi32(base, mask, index, src, _MM_DOWNCONV_EPI32_IINT16, 2, _MM_HINT_NT)
#define i32vec_mask_scatter_u8_nt_s2(base, index, src, mask) _mm512_mask_i32extscatter_epi32(base, mask, index, src, _MM_DOWNCONV_EPI32_UINT8, 2, _MM_HINT_NT)
#define i32vec_mask_scatter_i8_nt_s2(base, index, src, mask) _mm512_mask_i32extscatter_epi32(base, mask, index, src, _MM_DOWNCONV_EPI32_SINT8, 2, _MM_HINT_NT)

// ------ End 2B-scale integer scatters

// ------ Begin 4B-scale Integer scatters
#define i32vec_scatter_s4(base, index, src) _mm512_i32extscatter_epi32(base, index, src, _MM_DOWNCONV_EPI32_NONE, 4, _MM_HINT_NONE)
#define i32vec_scatter_u16_s4(base, index, src) _mm512_i32extscatter_epi32(base, index, src, _MM_DOWNCONV_EPI32_UINT16, 4, _MM_HINT_NONE)
#define i32vec_scatter_i16_s4(base, index, src) _mm512_i32extscatter_epi32(base, index, src, _MM_DOWNCONV_EPI32_IINT16, 4, _MM_HINT_NONE)
#define i32vec_scatter_u8_s4(base, index, src) _mm512_i32extscatter_epi32(base, index, src, _MM_DOWNCONV_EPI32_UINT8, 4, _MM_HINT_NONE)
#define i32vec_scatter_i8_s4(base, index, src) _mm512_i32extscatter_epi32(base, index, src, _MM_DOWNCONV_EPI32_SINT8, 4, _MM_HINT_NONE)

// Non-temporal integer scatters (Load to cache as least priority in LRU)
#define i32vec_scatter_nt_s4(base, index, src) _mm512_i32extscatter_epi32(base, index, src, _MM_DOWNCONV_EPI32_NONE, 4, _MM_HINT_NT) // The same as above
#define i32vec_scatter_u8_nt_s4(base, index, src) _mm512_i32extscatter_epi32(base, index, src, _MM_DOWNCONV_EPI32_UINT8, 4, _MM_HINT_NT)
#define i32vec_scatter_i8_nt_s4(base, index, src) _mm512_i32extscatter_epi32(base, index, src, _MM_DOWNCONV_EPI32_SINT8, 4, _MM_HINT_NT)
#define i32vec_scatter_u16_nt_s4(base, index, src) _mm512_i32extscatter_epi32(base, index, src, _MM_DOWNCONV_EPI32_UINT16, 4, _MM_HINT_NT)
#define i32vec_scatter_i16_nt_s4(base, index, src) _mm512_i32extscatter_epi32(base, index, src, _MM_DOWNCONV_EPI32_IINT16, 4, _MM_HINT_NT)


// Masked integer scatters
#define i32vec_mask_scatter_s4(base, index, src, mask) _mm512_mask_i32extscatter_epi32(base, mask, index, src, _MM_DOWNCONV_EPI32_NONE, 4, _MM_HINT_NONE) // The same as above
#define i32vec_mask_scatter_u16_s4(base, index, src, mask) _mm512_mask_i32extscatter_epi32(base, mask, index, src, _MM_DOWNCONV_EPI32_UINT16, 4, _MM_HINT_NONE)
#define i32vec_mask_scatter_i16_s4(base, index, src, mask) _mm512_mask_i32extscatter_epi32(base, mask, index, src, _MM_DOWNCONV_EPI32_IINT16, 4, _MM_HINT_NONE)
#define i32vec_mask_scatter_u8_s4(base, index, src, mask) _mm512_mask_i32extscatter_epi32(base, mask, index, src, _MM_DOWNCONV_EPI32_UINT8, 4, _MM_HINT_NONE)
#define i32vec_mask_scatter_i8_s4(base, index, src, mask) _mm512_mask_i32extscatter_epi32(base, mask, index, src, _MM_DOWNCONV_EPI32_SINT8, 4, _MM_HINT_NONE)

// Masked non-temporal integer scatters (Load to cache as least priority in LRU)
#define i32vec_mask_scatter_nt_s4(base, index, src, mask) _mm512_mask_i32extscatter_epi32(base, mask, index, src, _MM_DOWNCONV_EPI32_NONE, 4, _MM_HINT_NT) // The same as above
#define i32vec_mask_scatter_u16_nt_s4(base, index, src, mask) _mm512_mask_i32extscatter_epi32(base, mask, index, src, _MM_DOWNCONV_EPI32_UINT16, 4, _MM_HINT_NT)
#define i32vec_mask_scatter_i16_nt_s4(base, index, src, mask) _mm512_mask_i32extscatter_epi32(base, mask, index, src, _MM_DOWNCONV_EPI32_IINT16, 4, _MM_HINT_NT)
#define i32vec_mask_scatter_u8_nt_s4(base, index, src, mask) _mm512_mask_i32extscatter_epi32(base, mask, index, src, _MM_DOWNCONV_EPI32_UINT8, 4, _MM_HINT_NT)
#define i32vec_mask_scatter_i8_nt_s4(base, index, src, mask) _mm512_mask_i32extscatter_epi32(base, mask, index, src, _MM_DOWNCONV_EPI32_SINT8, 4, _MM_HINT_NT)

// ------ End 4B-scale integer scatters

// ------ Begin 8B-scale Integer scatters
#define i32vec_scatter_s8(base, index, src) _mm512_i32extscatter_epi32(base, index, src, _MM_DOWNCONV_EPI32_NONE, 8, _MM_HINT_NONE)
#define i32vec_scatter_u16_s8(base, index, src) _mm512_i32extscatter_epi32(base, index, src, _MM_DOWNCONV_EPI32_UINT16, 8, _MM_HINT_NONE)
#define i32vec_scatter_i16_s8(base, index, src) _mm512_i32extscatter_epi32(base, index, src, _MM_DOWNCONV_EPI32_IINT16, 8, _MM_HINT_NONE)
#define i32vec_scatter_u8_s8(base, index, src) _mm512_i32extscatter_epi32(base, index, src, _MM_DOWNCONV_EPI32_UINT8, 8, _MM_HINT_NONE)
#define i32vec_scatter_i8_s8(base, index, src) _mm512_i32extscatter_epi32(base, index, src, _MM_DOWNCONV_EPI32_SINT8, 8, _MM_HINT_NONE)

// Non-temporal integer scatters (Load to cache as least priority in LRU)
#define i32vec_scatter_nt_s8(base, index, src) _mm512_i32extscatter_epi32(base, index, src, _MM_DOWNCONV_EPI32_NONE, 8, _MM_HINT_NT) // The same as above
#define i32vec_scatter_u8_nt_s8(base, index, src) _mm512_i32extscatter_epi32(base, index, src, _MM_DOWNCONV_EPI32_UINT8, 8, _MM_HINT_NT)
#define i32vec_scatter_i8_nt_s8(base, index, src) _mm512_i32extscatter_epi32(base, index, src, _MM_DOWNCONV_EPI32_SINT8, 8, _MM_HINT_NT)
#define i32vec_scatter_u16_nt_s8(base, index, src) _mm512_i32extscatter_epi32(base, index, src, _MM_DOWNCONV_EPI32_UINT16, 8, _MM_HINT_NT)
#define i32vec_scatter_i16_nt_s8(base, index, src) _mm512_i32extscatter_epi32(base, index, src, _MM_DOWNCONV_EPI32_IINT16, 8, _MM_HINT_NT)


// Masked integer scatters
#define i32vec_mask_scatter_s8(base, index, src, mask) _mm512_mask_i32extscatter_epi32(base, mask, index, src, _MM_DOWNCONV_EPI32_NONE, 8, _MM_HINT_NONE) // The same as above
#define i32vec_mask_scatter_u16_s8(base, index, src, mask) _mm512_mask_i32extscatter_epi32(base, mask, index, src, _MM_DOWNCONV_EPI32_UINT16, 8, _MM_HINT_NONE)
#define i32vec_mask_scatter_i16_s8(base, index, src, mask) _mm512_mask_i32extscatter_epi32(base, mask, index, src, _MM_DOWNCONV_EPI32_IINT16, 8, _MM_HINT_NONE)
#define i32vec_mask_scatter_u8_s8(base, index, src, mask) _mm512_mask_i32extscatter_epi32(base, mask, index, src, _MM_DOWNCONV_EPI32_UINT8, 8, _MM_HINT_NONE)
#define i32vec_mask_scatter_i8_s8(base, index, src, mask) _mm512_mask_i32extscatter_epi32(base, mask, index, src, _MM_DOWNCONV_EPI32_SINT8, 8, _MM_HINT_NONE)

// Masked non-temporal integer scatters (Load to cache as least priority in LRU)
#define i32vec_mask_scatter_nt_s8(base, index, src, mask) _mm512_mask_i32extscatter_epi32(base, mask, index, src, _MM_DOWNCONV_EPI32_NONE, 8, _MM_HINT_NT) // The same as above
#define i32vec_mask_scatter_u16_nt_s8(base, index, src, mask) _mm512_mask_i32extscatter_epi32(base, mask, index, src, _MM_DOWNCONV_EPI32_UINT16, 8, _MM_HINT_NT)
#define i32vec_mask_scatter_i16_nt_s8(base, index, src, mask) _mm512_mask_i32extscatter_epi32(base, mask, index, src, _MM_DOWNCONV_EPI32_IINT16, 8, _MM_HINT_NT)
#define i32vec_mask_scatter_u8_nt_s8(base, index, src, mask) _mm512_mask_i32extscatter_epi32(base, mask, index, src, _MM_DOWNCONV_EPI32_UINT8, 8, _MM_HINT_NT)
#define i32vec_mask_scatter_i8_nt_s8(base, index, src, mask) _mm512_mask_i32extscatter_epi32(base, mask, index, src, _MM_DOWNCONV_EPI32_SINT8, 8, _MM_HINT_NT)

// ------ End 8B-scale integer scatters

// ------ Begin store instructions
#define i32vec_store(base, src) _mm512_extstore_epi32(base, src, _MM_DOWNCONV_EPI32_NONE, _MM_HINT_NONE)
#define i32vec_store_u16(base, src) _mm512_extstore_epi32(base, src, _MM_DOWNCONV_EPI32_UINT16, _MM_HINT_NONE)
#define i32vec_store_i16(base, src) _mm512_extstore_epi32(base, src, _MM_DOWNCONV_EPI32_SINT16, _MM_HINT_NONE)
#define i32vec_store_u8(base, src) _mm512_extstore_epi32(base, src, _MM_DOWNCONV_EPI32_UINT8, _MM_HINT_NONE)
#define i32vec_store_i8(base, src) _mm512_extstore_epi32(base, src, _MM_DOWNCONV_EPI32_SINT8, _MM_HINT_NONE)
    // Non-temporal variant
#define i32vec_store_nt(base, src) _mm512_extstore_epi32(base, src, _MM_DOWNCONV_EPI32_NONE, _MM_HINT_NT)
#define i32vec_store_u16_nt(base, src) _mm512_extstore_epi32(base, src, _MM_DOWNCONV_EPI32_UINT16, _MM_HINT_NT)
#define i32vec_store_i16_nt(base, src) _mm512_extstore_epi32(base, src, _MM_DOWNCONV_EPI32_SINT16, _MM_HINT_NT)
#define i32vec_store_u8_nt(base, src) _mm512_extstore_epi32(base, src, _MM_DOWNCONV_EPI32_UINT8, _MM_HINT_NT)
#define i32vec_store_i8_nt(base, src) _mm512_extstore_epi32(base, src, _MM_DOWNCONV_EPI32_SINT8, _MM_HINT_NT)

    // Masked variant
#define i32vec_mask_store(base, src, mask) _mm512_mask_extstore_epi32(base, mask, src, _MM_DOWNCONV_EPI32_NONE, _MM_HINT_NONE)
#define i32vec_mask_store_u16(base, src, mask) _mm512_mask_extstore_epi32(base, mask, src, _MM_DOWNCONV_EPI32_UINT16, _MM_HINT_NONE)
#define i32vec_mask_store_i16(base, src, mask) _mm512_mask_extstore_epi32(base, mask, src, _MM_DOWNCONV_EPI32_SINT16, _MM_HINT_NONE)
#define i32vec_mask_store_u8(base, src, mask) _mm512_mask_extstore_epi32(base, mask, src, _MM_DOWNCONV_EPI32_UINT8, _MM_HINT_NONE)
#define i32vec_mask_store_i8(base, src, mask) _mm512_mask_extstore_epi32(base, mask, src, _MM_DOWNCONV_EPI32_SINT8, _MM_HINT_NONE)
    // Masked, non-temporal variant
#define i32vec_mask_store_nt(base, src, mask) _mm512_mask_extstore_epi32(base, mask, src, _MM_DOWNCONV_EPI32_NONE, _MM_HINT_NT)
#define i32vec_mask_store_u16_nt(base, src, mask) _mm512_mask_extstore_epi32(base, mask, src, _MM_DOWNCONV_EPI32_UINT16, _MM_HINT_NT)
#define i32vec_mask_store_i16_nt(base, src, mask) _mm512_mask_extstore_epi32(base, mask, src, _MM_DOWNCONV_EPI32_SINT16, _MM_HINT_NT)
#define i32vec_mask_store_u8_nt(base, src, mask) _mm512_mask_extstore_epi32(base, mask, src, _MM_DOWNCONV_EPI32_UINT8, _MM_HINT_NT)
#define i32vec_mask_store_i8_nt(base, src, mask) _mm512_mask_extstore_epi32(base, mask, src, _MM_DOWNCONV_EPI32_SINT8, _MM_HINT_NT)

#endif /* __MIC__ */
#endif /* _LIBVEC_HH_ */
