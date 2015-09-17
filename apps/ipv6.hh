#ifndef _IPV6_HH_
#define _IPV6_HH_
#include "../types.hh"

void app_ipv6(struct worker *arg);




#define __jhash_mix(a, b, c) \
{ \
  a -= b; a -= c; a ^= (c>>13); \
  b -= c; b -= a; b ^= (a<<8); \
  c -= a; c -= b; c ^= (b>>13); \
  a -= b; a -= c; a ^= (c>>12);  \
  b -= c; b -= a; b ^= (a<<16); \
  c -= a; c -= b; c ^= (b>>5); \
  a -= b; a -= c; a ^= (c>>3);  \
  b -= c; b -= a; b ^= (a<<10); \
  c -= a; c -= b; c ^= (b>>15); \
}

/* The golden ration: an arbitrary value */
#define JHASH_GOLDEN_RATIO  0x9e3779b9


static void print128(uint128_t a)
{
    for (int i = 0; i < 64; i++) {
        printf("%ld", (a.u64[1] >> (63 - i) & 0x1));
    }
    for (int i = 0; i < 64; i++) {
        printf("%ld", (a.u64[0] >> (63 - i) & 0x1));
    }
}

//#define HASH(x, y) (jhash2((u32*)&x, 4, 0) % y)
#define HASH(x, y) (gpu_jhash2_optimized(x) % y)

typedef uint32_t u32;
typedef uint8_t u8;

/* The most generic version, hashes an arbitrary sequence
 * of bytes.  No alignment or length assumptions are made about
 * the input key.
 */
static inline u32 jhash(const void *key, u32 length, u32 initval)
{
    u32 a, b, c, len;
    const u8 *k = (const u8 *)key;

    len = length;
    a = b = JHASH_GOLDEN_RATIO;
    c = initval;

    while (len >= 12) {
        a += (k[0] +((u32)k[1]<<8) +((u32)k[2]<<16) +((u32)k[3]<<24));
        b += (k[4] +((u32)k[5]<<8) +((u32)k[6]<<16) +((u32)k[7]<<24));
        c += (k[8] +((u32)k[9]<<8) +((u32)k[10]<<16)+((u32)k[11]<<24));

        __jhash_mix(a,b,c);

        k += 12;
        len -= 12;
    }
    

    c += length;
    switch (len) {
    case 11: c += ((u32)k[10]<<24);
    case 10: c += ((u32)k[9]<<16);
    case 9 : c += ((u32)k[8]<<8);
    case 8 : b += ((u32)k[7]<<24);
    case 7 : b += ((u32)k[6]<<16);
    case 6 : b += ((u32)k[5]<<8);
    case 5 : b += k[4];
    case 4 : a += ((u32)k[3]<<24);
    case 3 : a += ((u32)k[2]<<16);
    case 2 : a += ((u32)k[1]<<8);
    case 1 : a += k[0];
    };

    __jhash_mix(a,b,c);

    return c;
}

/* A special optimized version that handles 1 or more of u32s.
 * The length parameter here is the number of u32s in the key.
 */
static inline u32 jhash2(const u32 *k, u32 length, u32 initval)
{
    u32 a, b, c, len;

    a = b = JHASH_GOLDEN_RATIO;
    c = initval;
    len = length;

    while (len >= 3) {
        a += k[0];
        b += k[1];
        c += k[2];
        __jhash_mix(a, b, c);
        k += 3; len -= 3;
    }

    c += length * 4;

    switch (len) {
    case 2 : b += k[1];
    case 1 : a += k[0];
    };

    __jhash_mix(a,b,c);

    return c;
}


/* A special ultra-optimized versions that knows they are hashing exactly
 * 3, 2 or 1 word(s).
 *
 * NOTE: In partilar the "c += length; __jhash_mix(a,b,c);" normally
 *       done at the end is not done here.
 */
static inline u32 jhash_3words(u32 a, u32 b, u32 c, u32 initval)
{
    a += JHASH_GOLDEN_RATIO;
    b += JHASH_GOLDEN_RATIO;
    c += initval;

    __jhash_mix(a, b, c);

    return c;
}

static inline u32 jhash_2words(u32 a, u32 b, u32 initval)
{
    return jhash_3words(a, b, 0, initval);
}

static inline u32 jhash_1word(u32 a, u32 initval)
{
    return jhash_3words(a, 0, 0, initval);
}


static inline u32 gpu_jhash2_optimized(const uint128_t &k)
{
    u32 a, b, c;

    a = b = JHASH_GOLDEN_RATIO;
    c = 0;

    a += k.u32[0];
    b += k.u32[1];
    c += k.u32[2];
    __jhash_mix(a, b, c);

    c += 4 * 4;
    a += k.u32[3];
    __jhash_mix(a, b, c);

    return c;
}

#endif
