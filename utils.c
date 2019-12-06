#include "utils.h"

int constant_time_memcmp(const void *s1, const void *s2, size_t n) {
const uint8_t * a = (const uint8_t*)s1;
const uint8_t * b = (const uint8_t*)s2;
    int ret = 0;
    size_t i;

    for (i = 0; i < n; ++i) {
        ret |= *a++ ^ *b++;
    }

    return ret;
}

void conditional_constant_time_memcpy(void *  dst, const void *  src, size_t n, uint8_t flag) {
uint8_t * d = (uint8_t*)dst;
const uint8_t * s = (const uint8_t*)src;
    flag = (unsigned char) (-(flag | -flag) >> 7); // Force flag into 0x00 or 0xff
    size_t i;

    for (i = 0; i < n; ++i) {
        d[i] = (uint8_t) (d[i] ^ (flag & (d[i] ^ s[i])));
    }
}

uint32_t ceil_log2(uint32_t x) {
    uint32_t bits = 0;
    uint32_t ones = 0;

    while (x >>= 1) {
        ones += x & 0x1;
        ++bits;
    }
    if (ones > 1) { /* ceil */
        ++bits;
    }

    return bits;
}
