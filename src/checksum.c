#include "checksum.h"

uint16_t internet_checksum(const uint8_t *octets, size_t count)
{
    /* ⚠ 32 bits so the carries have somewhere to go before they are folded
     * back in. ⚠ Adding 16-bit words into a 16-bit accumulator would lose
     * every carry, and the result would still look like a checksum. */
    uint32_t total = 0;

    size_t pairs = count / 2;
    for (size_t i = 0; i < pairs; i++) {
        total += ((uint32_t)octets[i * 2] << 8) | octets[i * 2 + 1];
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
