#ifndef UTILS_H
#define UTILS_H

#include "types.h"

/**
 * Macro to calculate _ceil(a/b)_.
 *
 * Note: only for _a_ and _b > 0_!
 *
 * @param[in] a, b the values of _a_ and _b_
 * @return _ceil(a/b)_
 */
#define CEIL_DIV(a,b) ((a+b-1)/b)

/**
 * Macro to converts a number of bits into a number of bytes.
 *
 * @param[in] b the number of bits to convert to number of bytes
 * @return _ceil(b/8)_
 */
#define BITS_TO_BYTES(b) (CEIL_DIV(b,8))

    /**
     * Constant time memory comparison function. Use to replace `memcmp()` when
     * comparing security critical data.
     *
     * @param s1 the byte string to compare to
     * @param s2 the byte string to compare
     * @param n the number of bytes to compare
     * @return 0 if all size bytes are equal, non-zero otherwise
     */
    int constant_time_memcmp(const void *s1, const void *s2, size_t n);

    /**
     * Conditionally copies the data from the source to the destination in
     * constant time.
     *
     * @param dst the destination of the copy
     * @param src the source of the copy
     * @param n the number of bytes to copy
     * @param flag indicating whether or not the copy should be performed
     */
    void conditional_constant_time_memcpy(void *  dst, const void *  src, size_t n, uint8_t flag);

    void copy_u8(uint8_t* out, const uint8_t* in, size_t len);
    void copy_u16(uint16_t* out, const uint16_t* in, size_t len);

void zero_u8(uint8_t* out, size_t len);
void zero_u16(uint16_t* out, size_t len);

void crash_immediately();

#endif
