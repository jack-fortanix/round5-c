#ifndef UTILS_H
#define UTILS_H

#include "types.h"

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
