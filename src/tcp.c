#include "tcp.h"

#include <string.h>

/* Where each field sits, written as the layout so nothing drifts. */
#define SOURCE_PORT_OFFSET 0
#define DESTINATION_PORT_OFFSET 2
#define SEQUENCE_NUMBER_OFFSET 4
#define ACKNOWLEDGMENT_NUMBER_OFFSET 8
#define OFFSET_AND_RESERVED_OFFSET 12
#define CONTROL_BITS_OFFSET 13
#define WINDOW_OFFSET 14
#define CHECKSUM_OFFSET 16
#define URGENT_POINTER_OFFSET 18

/* ⚠ Network byte order, one octet at a time. ⚠ Never a struct overlaid on the
 * buffer (`.claude/rules/c.md`). */
static uint16_t read_16(const uint8_t *at)
{
    return (uint16_t)(((uint16_t)at[0] << 8) | at[1]);
}

static uint32_t read_32(const uint8_t *at)
{
    return ((uint32_t)at[0] << 24) | ((uint32_t)at[1] << 16) |
           ((uint32_t)at[2] << 8) | (uint32_t)at[3];
}

/* Walk the option list far enough to know it is well formed.
 *
 * ⚠ Nothing is interpreted. ⚠ RFC 793, quoted:
 *
 *   "There are two cases for the format of an option:
 *      Case 1: A single octet of option-kind.
 *      Case 2: An octet of option-kind, an octet of option-length, and the
 *              actual option-data octets."
 *   "The option-length counts the two octets of option-kind and option-length
 *    as well as the option-data octets."
 *   "Note that the list of options may be shorter than the data offset field
 *    might imply."
 *
 * ⚠ That last sentence is why End of Option List stops the walk and the rest is
 * left alone: what follows it is padding, not options.
 *
 * `options` is the octets between the fixed fields and where the data begins.
 * Returns false when the list does not walk. */
static bool options_walk(const uint8_t *options, size_t options_bytes)
{
    size_t at = 0;
    while (at < options_bytes) {
        uint8_t kind = options[at];

        if (kind == TCP_OPTION_END_OF_OPTION_LIST) {
            /* ⚠ "This is used at the end of all options, not the end of each
             * option". ⚠ Whatever follows is padding and is not walked. */
            return true;
        }
        if (kind == TCP_OPTION_NO_OPERATION) {
            /* Case 1: a single octet. */
            at++;
            continue;
        }

        /* Case 2. ⚠ The length octet has to be there before it can be read. */
        if (at + 1 >= options_bytes) {
            return false;
        }
        uint8_t length = options[at + 1];

        /* ⚠ The length counts its own two octets, so anything below 2 is not a
         * length. ⚠ A length of 0 in particular would leave `at` where it is and
         * this loop would never end — ⚠ which is a hang, not a wrong answer, and
         * it is reachable by anyone who can send us a segment
         * (`.claude/rules/c.md`: everything here is untrusted input). */
        if (length < 2) {
            return false;
        }
        /* ⚠ And it must not run past the options. */
        if (length > options_bytes - at) {
            return false;
        }
        at += length;
    }
    return true;
}

enum tcp_parse tcp_parse_header(const uint8_t *segment, size_t segment_bytes,
                                struct tcp_header *header)
{
    memset(header, 0, sizeof *header);

    /* ⚠ Checked against what was actually read, before an octet is touched. */
    if (segment_bytes < TCP_FIXED_HEADER_BYTES) {
        return TCP_PARSE_MALFORMED;
    }

    header->source_port = read_16(segment + SOURCE_PORT_OFFSET);
    header->destination_port = read_16(segment + DESTINATION_PORT_OFFSET);
    header->sequence_number = read_32(segment + SEQUENCE_NUMBER_OFFSET);
    header->acknowledgment_number = read_32(segment + ACKNOWLEDGMENT_NUMBER_OFFSET);

    uint8_t offset_and_reserved = segment[OFFSET_AND_RESERVED_OFFSET];
    header->data_offset = (uint8_t)(offset_and_reserved >> 4);
    /* ⚠ Reserved is six bits and they do not all live in one octet: four of them
     * are the low half of this one and two are the top of the next, above the
     * six Control Bits. */
    header->reserved = (uint8_t)(((offset_and_reserved & 0x0fu) << 2) |
                                 (segment[CONTROL_BITS_OFFSET] >> 6));
    header->control_bits = (uint8_t)(segment[CONTROL_BITS_OFFSET] & 0x3fu);

    header->window = read_16(segment + WINDOW_OFFSET);
    header->checksum = read_16(segment + CHECKSUM_OFFSET);
    header->urgent_pointer = read_16(segment + URGENT_POINTER_OFFSET);

    /* ⚠ A header shorter than its own fixed fields is contradicting itself.
     * ⚠ RFC 793 states no minimum here — unlike RFC 791 for `IHL` — so ⚠ this is
     * our reading and it is recorded as ours (ADR 0013). */
    if (header->data_offset < TCP_HEADER_LENGTH_MINIMUM) {
        return TCP_PARSE_MALFORMED;
    }

    /* ⚠ The header's own length is an assertion by whoever sent it, and it is
     * checked against what arrived before it is used (`.claude/rules/c.md`).
     *
     * ⚠ The order above is load-bearing, not tidiness: `header_bytes` is used
     * below as `header_bytes - TCP_FIXED_HEADER_BYTES`, and ⚠ that subtraction
     * is unsigned. ⚠ Without the minimum having been settled first, a Data
     * Offset of 0 makes it enormous and the walk reads whatever is there. */
    size_t header_bytes = (size_t)header->data_offset * TCP_HEADER_LENGTH_UNIT;
    if (segment_bytes < header_bytes) {
        return TCP_PARSE_MALFORMED;
    }

    /* ⚠ RFC 793: "Reserved: 6 bits - Reserved for future use.  Must be zero."
     * ⚠ Set means the sender broke what the document states. ⚠ The document does
     * not tell a receiver to reject such a segment — that conclusion is ours,
     * and it is the third time this repository has drawn it from the same shape
     * of sentence (ADR 0010, ADR 0011, ADR 0013). */
    if (header->reserved != 0) {
        return TCP_PARSE_MALFORMED;
    }

    if (!options_walk(segment + TCP_FIXED_HEADER_BYTES,
                      header_bytes - TCP_FIXED_HEADER_BYTES)) {
        return TCP_PARSE_MALFORMED;
    }

    header->data_begins_at = header_bytes;
    return TCP_PARSE_OK;
}
