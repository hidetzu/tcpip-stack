#include "checksum.h"

/* ⚠ No field to clear. ⚠ An offset at or past a block's length clears nothing,
 * which is what checksum.h promises a caller placing a checksum. */
#define NOTHING_CLEARED ((size_t)-1)

/* ⚠ The one loop. All three entry points go through it, so there is one place
 * where this arithmetic is written (`CLAUDE.md` §3).
 *
 * ⚠ The pad for an odd length belongs at the very end and nowhere else, which is
 * why only the last block may be odd (see checksum.h). */
static uint32_t add_block(uint32_t total, const uint8_t *octets, size_t count,
                          size_t cleared_at)
{
    /* ⚠ Nothing to add, and ⚠ `octets` may be NULL here — a caller with no
     * prefix says so by passing none. */
    if (count == 0) {
        return total;
    }

    /* ⚠ 32 bits so the carries have somewhere to go before they are folded
     * back in. ⚠ Adding 16-bit words into a 16-bit accumulator would lose
     * every carry, and the result would still look like a checksum. */
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
    return total;
}

uint16_t internet_checksum_of_two(const uint8_t *prefix, size_t prefix_count,
                                  const uint8_t *octets, size_t count,
                                  size_t field_offset)
{
    /* ⚠ The prefix carries no field to clear: the caller's offset applies to the
     * block that was really sent. */
    uint32_t total = add_block(0, prefix, prefix_count, NOTHING_CLEARED);
    total = add_block(total, octets, count, field_offset);

    /* ⚠ Folded until nothing is left above 16 bits. One fold is not always
     * enough: the fold can itself carry. */
    while (total >> 16) {
        total = (total & 0xffffu) + (total >> 16);
    }

    return (uint16_t)(~total & 0xffffu);
}

uint16_t internet_checksum(const uint8_t *octets, size_t count)
{
    return internet_checksum_of_two(NULL, 0, octets, count, NOTHING_CLEARED);
}

uint16_t internet_checksum_with_field_cleared(const uint8_t *octets, size_t count,
                                              size_t field_offset)
{
    return internet_checksum_of_two(NULL, 0, octets, count, field_offset);
}
