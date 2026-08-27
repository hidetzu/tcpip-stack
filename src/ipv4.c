#include "ipv4.h"

#include <string.h>

#include "checksum.h"

/* Where each field sits, written as the layout so nothing drifts. */
#define VERSION_AND_LENGTH_OFFSET 0
#define TYPE_OF_SERVICE_OFFSET 1
#define TOTAL_LENGTH_OFFSET 2
#define IDENTIFICATION_OFFSET 4
#define FLAGS_AND_OFFSET_OFFSET 6
#define TIME_TO_LIVE_OFFSET 8
#define PROTOCOL_OFFSET 9
#define HEADER_CHECKSUM_OFFSET 10
#define SOURCE_ADDRESS_OFFSET 12
#define DESTINATION_ADDRESS_OFFSET 16

/* The header without any Options. ⚠ Derived from the minimum the document
 * states, never written as 20. */
#define FIXED_HEADER_BYTES (IPV4_HEADER_LENGTH_MINIMUM * IPV4_HEADER_LENGTH_UNIT)

/* ⚠ Network byte order, one octet at a time. ⚠ Never a struct overlaid on the
 * buffer (`.claude/rules/c.md`). */
static uint16_t read_16(const uint8_t *at)
{
    return (uint16_t)(((uint16_t)at[0] << 8) | at[1]);
}

enum ipv4_parse ipv4_parse_header(const uint8_t *datagram, size_t datagram_bytes,
                                  struct ipv4_header *header)
{
    memset(header, 0, sizeof *header);

    /* ⚠ Checked against what was actually read, before an octet is touched. */
    if (datagram_bytes < FIXED_HEADER_BYTES) {
        return IPV4_PARSE_MALFORMED;
    }

    uint8_t version_and_length = datagram[VERSION_AND_LENGTH_OFFSET];
    header->version = (uint8_t)(version_and_length >> 4);
    header->internet_header_length = (uint8_t)(version_and_length & 0x0f);
    header->type_of_service = datagram[TYPE_OF_SERVICE_OFFSET];
    header->total_length = read_16(datagram + TOTAL_LENGTH_OFFSET);
    header->identification = read_16(datagram + IDENTIFICATION_OFFSET);

    uint16_t flags_and_offset = read_16(datagram + FLAGS_AND_OFFSET_OFFSET);
    header->flags = (uint8_t)(flags_and_offset >> 13);
    header->fragment_offset = (uint16_t)(flags_and_offset & 0x1fffu);

    header->time_to_live = datagram[TIME_TO_LIVE_OFFSET];
    header->protocol = datagram[PROTOCOL_OFFSET];
    header->header_checksum = read_16(datagram + HEADER_CHECKSUM_OFFSET);
    memcpy(header->source_address, datagram + SOURCE_ADDRESS_OFFSET, IPV4_ADDRESS_BYTES);
    memcpy(header->destination_address, datagram + DESTINATION_ADDRESS_OFFSET,
           IPV4_ADDRESS_BYTES);

    /* ⚠ RFC 791: "Note that the minimum value for a correct header is 5."
     * ⚠ Below it the document says the header is not correct, so the sender is
     * wrong — malformed, not unsupported. */
    if (header->internet_header_length < IPV4_HEADER_LENGTH_MINIMUM) {
        return IPV4_PARSE_MALFORMED;
    }

    /* ⚠ The header's own length and the datagram's own length are assertions by
     * whoever sent them. ⚠ Both are checked against what arrived before either
     * is used, and ⚠ truncation is decided before support: a datagram that does
     * not contain what it says it contains is malformed whether or not we would
     * have handled it (the order ADR 0005 set). */
    size_t header_bytes = (size_t)header->internet_header_length * IPV4_HEADER_LENGTH_UNIT;
    if (datagram_bytes < header_bytes || datagram_bytes < header->total_length) {
        return IPV4_PARSE_MALFORMED;
    }

    /* ⚠ RFC 791: "Bit 0: reserved, must be zero". ⚠ Set means the sender broke
     * what the document states (Owner Decision 2). ⚠ What its lower-case "must"
     * carries is not defined by anything that was read — ⚠ the decision is the
     * owner's, not the document's (ADR 0010). */
    if (header->flags & IPV4_FLAG_RESERVED) {
        return IPV4_PARSE_MALFORMED;
    }

    /* ⚠ RFC 791: "A checksum on the header only." ⚠ Over the header's own
     * length, not the datagram's. */
    /* ⚠ RFC 1071, verbatim: "the checksum field itself is cleared, the 16-bit
     * 1's complement sum is computed over the octets concerned, and the 1's
     * complement of this sum is placed in the checksum field." ⚠ So the check is
     * the generation, done again, compared with what arrived — ⚠ not a second
     * way of asking the same question (`CLAUDE.md` §3). */
    uint8_t cleared[IPV4_HEADER_LENGTH_MAXIMUM * IPV4_HEADER_LENGTH_UNIT];
    memcpy(cleared, datagram, header_bytes);
    cleared[HEADER_CHECKSUM_OFFSET] = 0;
    cleared[HEADER_CHECKSUM_OFFSET + 1] = 0;
    if (internet_checksum(cleared, header_bytes) != header->header_checksum) {
        return IPV4_PARSE_CHECKSUM_DISAGREES;
    }

    if (header->version != IPV4_VERSION ||
        header->internet_header_length > IPV4_HEADER_LENGTH_MINIMUM) {
        return IPV4_PARSE_NOT_HANDLED;
    }

    /* ⚠ RFC 791: "Bit 2: (MF) ... 1 = More Fragments", and the offset "is
     * measured in units of 8 octets". ⚠ Either one means this is a piece of
     * something, and reassembly is not written (Owner Decision 1). */
    if ((header->flags & IPV4_FLAG_MORE_FRAGMENTS) != 0 || header->fragment_offset != 0) {
        return IPV4_PARSE_FRAGMENT;
    }

    return IPV4_PARSE_OK;
}
