#include "checksum.h"

/* ⚠ The one loop. Both entry points go through it, so there is one place where
 * this arithmetic is written (`CLAUDE.md` §3).
 *
 * `cleared_at` is the offset of a two-octet field to count as zero, or
 * NOTHING_CLEARED. */
#define NOTHING_CLEARED ((size_t)-1)

static uint16_t sum_and_complement(const uint8_t *octets, size_t count, size_t cleared_at)
{
    /* ⚠ 32 bits so the carries have somewhere to go before they are folded
     * back in. ⚠ Adding 16-bit words into a 16-bit accumulator would lose
     * every carry, and the result would still look like a checksum. */
    uint32_t total = 0;

    size_t pairs = count / 2;
    for (size_t i = 0; i < pairs; i++) {
        size_t at = i * 2;
        /* ⚠ Adding zero, which is what "the checksum field itself is cleared"
         * amounts to, without writing into the caller's octets. */
        if (at == cleared_at) {
            continue;
        }
        total += ((uint32_t)octets[at] << 8) | octets[at + 1];
    }

    /* ⚠ "[A,B] +' [C,D] +' ... +' [Z,0]" — RFC 1071, read 2026-08-27. The final
     * octet is paired with a zero, which makes it the high half of the word. */
    if (count % 2 != 0) {
        total += (uint32_t)octets[count - 1] << 8;
    }

    /* ⚠ Folded until nothing is left above 16 bits. One fold is not always
     * enough: the fold can itself carry. */
    while (total >> 16) {
        total = (total & 0xffffu) + (total >> 16);
    }

    return (uint16_t)(~total & 0xffffu);
}

uint16_t internet_checksum(const uint8_t *octets, size_t count)
{
    return sum_and_complement(octets, count, NOTHING_CLEARED);
}

uint16_t internet_checksum_with_field_cleared(const uint8_t *octets, size_t count,
                                              size_t field_offset)
{
    return sum_and_complement(octets, count, field_offset);
}
