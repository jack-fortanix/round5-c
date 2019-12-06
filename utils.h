#ifndef UTILS_H
#define UTILS_H

#include <stdlib.h>
#include <stdint.h>

/**
 * Macro to round a floating point value to an integer value.
 *
 * @param[in] x the value to round
 * @return _round(x)_
 */
#define ROUND(x) ((int)(x + 0.5))

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
     * Computes the log2 of a number, rounding up if it's not exact.
     *
     * @param[in] x  the value to compute the log2 for
     * @return ceil(log2(x))
     */
    uint32_t ceil_log2(uint32_t x);

/**
 * Macro to switch the byte order of a 64-bit integer to/from little-endian.
 *
 * @param x the 64-bit integer
 */
#define LITTLE_ENDIAN64(x) (x)
#define LITTLE_ENDIAN32(x) (x)
#define LITTLE_ENDIAN16(x) (x)

    /*
     * Note that on a little-endian machine, the compiler actually optimises
     * below functions to to a memory copy already so we don't have to
     * optimise the code ourselves.
     */

    /**
     * Creates an 8 bit value from an array of 1 byte.
     *
     * @param[in] x array of 1 byte (little-endian) that make up the 8 bit
     *              unsigned integer
     * @return the 8 bit value represented by the byte
     */
    inline uint8_t u8_from_le(const unsigned char *x) {
        return (uint8_t) x[0];
    }

    /**
     * Creates an array of 1 byte from an 8 bit unsigned integer.
     *
     * @param[out] x array of 1 bytes
     * @param[in]  u the 8 bit unsigned integer
     */
    inline void u8_to_le(unsigned char *x, const uint8_t u) {
        x[0] = u;
    }

    /**
     * Creates a 16 bit value from an array of 2 bytes (little-endian).
     *
     * @param[in] x array of 2 bytes (little-endian) that make up the 16 bit
     *              unsigned integer
     * @return the 16 bit value represented by the 2 bytes
     */
    inline uint16_t u16_from_le(const unsigned char *x) {
        return (uint16_t) (x[0]
                | (uint16_t) (x[1]) << 8);
    }

    /**
     * Creates an array of 2 bytes (little-endian) from a 16 bit unsigned
     * integer.
     *
     * @param[out] x array of 2 bytes
     * @param[in]  u the 16 bit unsigned integer
     */
    inline void u16_to_le(unsigned char *x, const uint16_t u) {
        x[0] = (unsigned char) u;
        x[1] = (unsigned char) (u >> 8);
    }

    /**
     * Creates a 32 bit value from an array of 4 bytes (little-endian).
     *
     * @param[in] x array of 4 bytes (little-endian) that make up the 32 bit
     *              unsigned integer
     * @return the 32 bit value represented by the 4 bytes
     */
    inline uint32_t u32_from_le(const unsigned char *x) {
        return (uint32_t) (x[0])
                | (((uint32_t) (x[1])) << 8)
                | (((uint32_t) (x[2])) << 16)
                | (((uint32_t) (x[3])) << 24);
    }

    /**
     * Creates an array of 4 bytes (little-endian) from a 32 bit unsigned
     * integer.
     *
     * @param[out] x array of 4 bytes
     * @param[in]  u the 32 bit unsigned integer
     */
    inline void u32_to_le(unsigned char *x, const uint32_t u) {
        x[0] = (unsigned char) u;
        x[1] = (unsigned char) (u >> 8);
        x[2] = (unsigned char) (u >> 16);
        x[3] = (unsigned char) (u >> 24);
    }

    /**
     * Creates a 64 bit value from an array of 8 bytes (little-endian).
     *
     * @param[in] x array of 8 bytes (little-endian) that make up the 64 bit
     *              unsigned integer
     * @return the 64 bit value represented by the 8 bytes
     */
    inline uint64_t u64_from_le(const unsigned char *x) {
        return (uint64_t) (x[0])
                | (((uint64_t) (x[1])) << 8)
                | (((uint64_t) (x[2])) << 16)
                | (((uint64_t) (x[3])) << 24)
                | (((uint64_t) (x[4])) << 32)
                | (((uint64_t) (x[5])) << 40)
                | (((uint64_t) (x[6])) << 48)
                | (((uint64_t) (x[7])) << 56);
    }

    /**
     * Creates an array of 8 bytes (little-endian) from a 64 bit unsigned
     * integer.
     *
     * @param[out] x array of 8 bytes
     * @param[in]  u the 64 bit unsigned integer
     */
    inline void u64_to_le(unsigned char *x, const uint64_t u) {
        x[0] = (unsigned char) u;
        x[1] = (unsigned char) (u >> 8);
        x[2] = (unsigned char) (u >> 16);
        x[3] = (unsigned char) (u >> 24);
        x[4] = (unsigned char) (u >> 32);
        x[5] = (unsigned char) (u >> 40);
        x[6] = (unsigned char) (u >> 48);
        x[7] = (unsigned char) (u >> 56);
    }

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

#endif