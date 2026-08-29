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

/* ⚠ The header without any Options. Named in ipv4.h now that a caller has to
 * reserve room for one (hidetzu/tcpip-stack#35); this is the short spelling
 * used inside this file. */
#define FIXED_HEADER_BYTES IPV4_FIXED_HEADER_BYTES

/* ⚠ Network byte order, one octet at a time. ⚠ Never a struct overlaid on the
 * buffer (`.claude/rules/c.md`). */
static uint16_t read_16(const uint8_t *at)
{
    return (uint16_t)(((uint16_t)at[0] << 8) | at[1]);
}

bool ipv4_address_is_broadcast_or_multicast(const uint8_t *address)
{
    /* ⚠ The limited broadcast, all thirty-two bits set. */
    if (address[0] == 255u && address[1] == 255u &&
        address[2] == 255u && address[3] == 255u) {
        return true;
    }
    /* ⚠ RFC 791 §3.2 on class D: "the first four bits being 1110". ⚠ Read as a
     * mask rather than a range, so ⚠ **the boundary is the document's and not
     * arithmetic of ours.** */
    return (address[0] & 0xf0u) == 0xe0u;
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

    /* ⚠ RFC 791 counts Total Length as "the length of the datagram, measured in
     * octets, including internet header and data", so ⚠ a Total Length below
     * the header's own length is a header contradicting itself — the sender is
     * wrong (hidetzu/tcpip-stack#35 Owner Decision 4).
     *
     * ⚠ Left undecided by hidetzu/tcpip-stack#33 on purpose: its approved order
     * had no row for it and that change did not invent one. ⚠ It is decided here
     * because this is where a payload length is first computed as
     * `Total Length - header`, and that subtraction is unsigned. */
    if (header->total_length < header_bytes) {
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
     * way of asking the same question (`CLAUDE.md` §3).
     *
     * ⚠ This copied the header into a 60-octet scratch and zeroed the field
     * there until hidetzu/tcpip-stack#34 gave `checksum.h` an entry point that
     * counts the field as zero in place. ⚠ Two ways of clearing one field is the
     * same defect as two ways of summing it, so the copy is gone. */
    if (internet_checksum_with_field_cleared(datagram, header_bytes,
                                             HEADER_CHECKSUM_OFFSET) !=
        header->header_checksum) {
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

static void write_16(uint8_t *at, uint16_t value)
{
    at[0] = (uint8_t)(value >> 8);
    at[1] = (uint8_t)(value & 0xffu);
}

enum ipv4_build ipv4_build_datagram(const uint8_t *source_address,
                                    const uint8_t *destination_address,
                                    uint8_t protocol, uint8_t time_to_live,
                                    const uint8_t *payload, size_t payload_bytes,
                                    uint8_t *datagram, size_t datagram_bytes,
                                    size_t *built_bytes)
{
    size_t needed = FIXED_HEADER_BYTES + payload_bytes;

    /* ⚠ Decided before a single octet is written, so a refused build leaves the
     * caller's buffer exactly as it was. */
    if (datagram_bytes < needed) {
        return IPV4_BUILD_BUFFER_TOO_SMALL;
    }

    /* ⚠ Total Length is 16 bits. ⚠ A payload that would not fit in the field is
     * refused rather than written as a number that means something else. */
    if (needed > 0xffffu) {
        return IPV4_BUILD_BUFFER_TOO_SMALL;
    }

    /* ⚠ The payload first, and with memmove: it is allowed to point into this
     * same buffer, which is what answering in place looks like. */
    if (payload_bytes > 0) {
        memmove(datagram + FIXED_HEADER_BYTES, payload, payload_bytes);
    }

    datagram[VERSION_AND_LENGTH_OFFSET] =
        (uint8_t)((IPV4_VERSION << 4) | IPV4_HEADER_LENGTH_MINIMUM);
    datagram[TYPE_OF_SERVICE_OFFSET] = 0;
    write_16(datagram + TOTAL_LENGTH_OFFSET, (uint16_t)needed);
    write_16(datagram + IDENTIFICATION_OFFSET, IPV4_IDENTIFICATION_WE_SEND);
    /* ⚠ All three flag bits clear and Fragment Offset 0, in the one field they
     * share. ⚠ Don't Fragment clear is Owner Decision 2, not a reading. */
    write_16(datagram + FLAGS_AND_OFFSET_OFFSET, 0);
    datagram[TIME_TO_LIVE_OFFSET] = time_to_live;
    datagram[PROTOCOL_OFFSET] = protocol;
    memcpy(datagram + SOURCE_ADDRESS_OFFSET, source_address, IPV4_ADDRESS_BYTES);
    memcpy(datagram + DESTINATION_ADDRESS_OFFSET, destination_address, IPV4_ADDRESS_BYTES);

    /* ⚠ "the checksum field itself is cleared" — RFC 1071 — and ⚠ "A checksum on
     * the header only" — RFC 791. */
    write_16(datagram + HEADER_CHECKSUM_OFFSET, 0);
    write_16(datagram + HEADER_CHECKSUM_OFFSET,
             internet_checksum(datagram, FIXED_HEADER_BYTES));

    *built_bytes = needed;
    return IPV4_BUILD_OK;
}
