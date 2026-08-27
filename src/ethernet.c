#include "ethernet.h"

#include <string.h>

/* Where the length/type field sits: after both addresses. ⚠ Written as the
 * layout rather than as 12, so it cannot drift from ETHERNET_ADDRESS_BYTES. */
#define LENGTH_TYPE_OFFSET (ETHERNET_ADDRESS_BYTES * 2)

enum ethernet_parse ethernet_parse_header(const uint8_t *frame, size_t frame_bytes,
                                          struct ethernet_header *header)
{
    /* ⚠ Checked against what was actually read, before a single octet is
     * touched. A zero-length read lands here and `frame` is never dereferenced. */
    if (frame_bytes < ETHERNET_HEADER_BYTES) {
        return ETHERNET_PARSE_SHORTER_THAN_THE_HEADER;
    }

    memcpy(header->destination, frame, ETHERNET_ADDRESS_BYTES);
    memcpy(header->source, frame + ETHERNET_ADDRESS_BYTES, ETHERNET_ADDRESS_BYTES);

    /* ⚠ Network byte order, read one octet at a time. ⚠ Never a struct overlaid
     * on the buffer and never a 16-bit load at an offset nothing aligned — the
     * caller chose where this buffer starts (`.claude/rules/c.md`). */
    header->length_type = (uint16_t)(((uint16_t)frame[LENGTH_TYPE_OFFSET] << 8) |
                                     frame[LENGTH_TYPE_OFFSET + 1]);

    if (header->length_type >= ETHERNET_TYPE_MIN) {
        return ETHERNET_PARSE_OK;
    }
    if (header->length_type <= ETHERNET_LENGTH_MAX) {
        return ETHERNET_PARSE_LENGTH_NOT_A_TYPE;
    }
    return ETHERNET_PARSE_LENGTH_TYPE_UNDEFINED;
}

bool ethernet_build_header(const uint8_t *destination, const uint8_t *source,
                           uint16_t length_type, uint8_t *frame, size_t frame_bytes)
{
    if (frame_bytes < ETHERNET_HEADER_BYTES) {
        return false;
    }
    memcpy(frame, destination, ETHERNET_ADDRESS_BYTES);
    memcpy(frame + ETHERNET_ADDRESS_BYTES, source, ETHERNET_ADDRESS_BYTES);
    /* ⚠ Network byte order, one octet at a time (`.claude/rules/c.md`). */
    frame[2 * ETHERNET_ADDRESS_BYTES] = (uint8_t)(length_type >> 8);
    frame[2 * ETHERNET_ADDRESS_BYTES + 1] = (uint8_t)(length_type & 0xffu);
    return true;
}
