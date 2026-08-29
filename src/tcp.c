#include "tcp.h"

#include <string.h>

#include "checksum.h"

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
static bool options_walk(const uint8_t *options, size_t options_bytes,
                         struct tcp_options *meaning)
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

        /* ⚠ The one option this file gives a meaning to. ⚠ RFC 9293 §3.2:
         * "Kind: 2, Length: 4" — ⚠ **the length is checked against the
         * document's, not assumed from the kind** (`.claude/rules/c.md`: a
         * length in a packet is an assertion by whoever sent it).
         *
         * ⚠ **A wrong length is not malformed.** ⚠ The walk goes on by what the
         * sender said, and ⚠ **the option is simply not read** — the same answer
         * every other kind gets. ⚠ Refusing the segment would make an option we
         * do not have to act on into a reason to drop it
         * (`.claude/rules/layers.md`: malformed and unsupported are different
         * answers). */
        if (kind == TCP_OPTION_MAXIMUM_SEGMENT_SIZE &&
            length == TCP_OPTION_MAXIMUM_SEGMENT_SIZE_BYTES) {
            /* ⚠ Read one octet at a time. ⚠ **Nothing here assumes the option
             * begins on a word boundary** — RFC 9293 `MUST-64`, and ⚠ this is
             * the line that makes it true rather than incidental. */
            meaning->has_maximum_segment_size = true;
            meaning->maximum_segment_size =
                (uint16_t)(((uint16_t)options[at + 2] << 8) | options[at + 3]);
        }

        at += length;
    }
    return true;
}

/* The pseudo-header RFC 793 puts in front of the segment, quoted:
 *
 *   +--------+--------+--------+--------+
 *   |           Source Address          |
 *   +--------+--------+--------+--------+
 *   |         Destination Address       |
 *   +--------+--------+--------+--------+
 *   |  zero  |  PTCL  |    TCP Length   |
 *   +--------+--------+--------+--------+
 *
 * ⚠ "The TCP Length is the TCP header length plus the data length in octets
 * (this is not an explicitly transmitted quantity, but is computed), and it does
 * not count the 12 octets of the pseudo header."
 *
 * ⚠ Twelve octets, and ⚠ **even** — which is what lets it be summed as a prefix
 * at all (`src/checksum.h`: only the last block may be odd).
 *
 * ⚠ Measured, and worth knowing before trusting this too far: ⚠ **swapping the
 * Source and Destination Addresses here does not change the sum.** They are two
 * four-octet blocks aligned the same way, so the set of 16-bit words is
 * identical and the sum is commutative — ⚠ **no check can catch that order
 * through the checksum, and none pretends to** (2026-08-28, ADR 0014).
 * ⚠ RFC 793 says the pseudo-header "gives the TCP protection against misrouted
 * segments"; ⚠ this is one thing it does not give. */
#define PSEUDO_HEADER_BYTES 12

static void build_the_pseudo_header(uint8_t *into, const uint8_t *source_address,
                                    const uint8_t *destination_address,
                                    size_t tcp_length)
{
    memcpy(into, source_address, TCP_ADDRESS_BYTES);
    memcpy(into + TCP_ADDRESS_BYTES, destination_address, TCP_ADDRESS_BYTES);
    into[8] = 0;
    into[9] = (uint8_t)TCP_PROTOCOL_NUMBER;
    into[10] = (uint8_t)(tcp_length >> 8);
    into[11] = (uint8_t)(tcp_length & 0xffu);
}

enum tcp_parse tcp_parse_header(const uint8_t *segment, size_t segment_bytes,
                                const uint8_t *source_address,
                                const uint8_t *destination_address,
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
    /* ⚠ Four bits of `Reserved` and eight Control Bits, ⚠ **not six and six.**
     * ⚠ RFC 9293 §3.1 assigns the top two to `CWR` and `ECE` (`src/tcp.h`). */
    header->reserved = (uint8_t)(offset_and_reserved & 0x0fu);
    header->control_bits = segment[CONTROL_BITS_OFFSET];

    header->window = read_16(segment + WINDOW_OFFSET);
    header->checksum = read_16(segment + CHECKSUM_OFFSET);
    header->urgent_pointer = read_16(segment + URGENT_POINTER_OFFSET);

    /* ⚠ RFC 793: "While computing the checksum, the checksum field itself is
     * replaced with zeros." ⚠ So the check is the generation done again,
     * compared with what arrived — ⚠ not a second way of asking the same
     * question (`CLAUDE.md` §3).
     *
     * ⚠ Decided before any field's content, the order ADR 0010 and ADR 0011
     * already set: judging a Data Offset or a Reserved first would blame the
     * sender for octets that were changed in flight, and ⚠ malformed means the
     * sender is wrong.
     *
     * ⚠ The whole segment, and ⚠ `segment_bytes` is the TCP Length: the
     * document computes it as "the TCP header length plus the data length in
     * octets", which is exactly the extent this function was handed (see
     * tcp.h — it must not be what arrived). */
    uint8_t pseudo_header[PSEUDO_HEADER_BYTES];
    build_the_pseudo_header(pseudo_header, source_address, destination_address,
                            segment_bytes);
    if (internet_checksum_of_two(pseudo_header, sizeof pseudo_header, segment,
                                 segment_bytes, CHECKSUM_OFFSET) != header->checksum) {
        return TCP_PARSE_CHECKSUM_DISAGREES;
    }

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

    /* ⚠ **Nothing is decided from `Reserved`**, and ⚠ **the grounds are two
     * things, not one** (hidetzu/tcpip-stack#92 corrected this comment).
     *
     * ⚠ **The layout is the document's, and is not a keyword matter at all**:
     * RFC 9293 §3.1 defines `Reserved` as four bits and lists eight control
     * bits. ⚠ **This build was reading the header wrong**, and a definition is
     * not a `MUST`.
     *
     * ⚠ **Ignoring a set bit is prose, not a requirement.** RFC 9293 §3.1
     * verbatim: "Must be zero in generated segments and must be ignored in
     * received segments if the corresponding future features are not
     * implemented by the sending or receiving host." ⚠ **Both are lowercase**,
     * ⚠ **there is no labelled keyword in that passage**, and §2 binds the
     * keywords "when, and only when, they appear in all capitals". ⚠ This
     * comment first called it "the document's rule and not ours" — ⚠ **the same
     * overstatement `CLAUDE.md` §9 has a row for.**
     *
     * ⚠ **So the grounds for ignoring it are measured, not textual** (below).
     *
     * ⚠ Until hidetzu/tcpip-stack#86 a set bit made the segment malformed, from
     * RFC 793's "Must be zero" — ⚠ **a conclusion recorded as ours** (ADR 0013).
     *
     * ⚠ **Measured 2026-08-29**: with the refusal in place and
     * `net.ipv4.tcp_ecn=1`, the Linux kernel's first SYN carries `CWR|ECE|SYN`
     * and was thrown away; ⚠ **the connection opened only because Linux fell
     * back to a plain SYN.** */

    if (!options_walk(segment + TCP_FIXED_HEADER_BYTES,
                      header_bytes - TCP_FIXED_HEADER_BYTES, &header->options)) {
        return TCP_PARSE_MALFORMED;
    }

    header->data_begins_at = header_bytes;
    /* ⚠ Safe because `segment_bytes < header_bytes` was refused above. */
    header->data_bytes = segment_bytes - header_bytes;
    return TCP_PARSE_OK;
}

static void write_16(uint8_t *at, uint16_t value)
{
    at[0] = (uint8_t)(value >> 8);
    at[1] = (uint8_t)(value & 0xffu);
}

static void write_32(uint8_t *at, uint32_t value)
{
    at[0] = (uint8_t)(value >> 24);
    at[1] = (uint8_t)((value >> 16) & 0xffu);
    at[2] = (uint8_t)((value >> 8) & 0xffu);
    at[3] = (uint8_t)(value & 0xffu);
}

enum tcp_build tcp_build_segment(const struct tcp_header *fields,
                                 const uint8_t *source_address,
                                 const uint8_t *destination_address,
                                 uint8_t *segment, size_t segment_bytes,
                                 size_t *built_bytes)
{
    /* ⚠ How long the header will be, decided before anything is written.
     * ⚠ The MSS Option is four octets — exactly one 32-bit word — ⚠ **so no
     * padding and no End of Option List are needed**, and `Data Offset` goes
     * from 5 to 6 (RFC 9293 §3.2: "Kind: 2, Length: 4"). */
    size_t option_bytes = fields->options.has_maximum_segment_size
                              ? TCP_OPTION_MAXIMUM_SEGMENT_SIZE_BYTES : 0u;
    size_t header_bytes = TCP_FIXED_HEADER_BYTES + option_bytes;
    uint8_t words = (uint8_t)(header_bytes / 4u);

    /* ⚠ Decided before a single octet is written, so a refused build leaves the
     * caller's buffer exactly as it was. */
    if (segment_bytes < header_bytes) {
        return TCP_BUILD_BUFFER_TOO_SMALL;
    }

    write_16(segment + SOURCE_PORT_OFFSET, fields->source_port);
    write_16(segment + DESTINATION_PORT_OFFSET, fields->destination_port);
    write_32(segment + SEQUENCE_NUMBER_OFFSET, fields->sequence_number);
    write_32(segment + ACKNOWLEDGMENT_NUMBER_OFFSET, fields->acknowledgment_number);

    /* ⚠ `Reserved` is zero, which is what this file calls malformed on the way
     * in. ⚠ `Data Offset` follows the options rather than being five always
     * (hidetzu/tcpip-stack#123). */
    segment[OFFSET_AND_RESERVED_OFFSET] = (uint8_t)(words << 4);
    segment[CONTROL_BITS_OFFSET] = (uint8_t)(fields->control_bits & 0x3fu);

    write_16(segment + WINDOW_OFFSET, fields->window);
    /* ⚠ Zero, and it means it: `URG` is not among the Control Bits we set, so
     * RFC 793's "Urgent Pointer field significant" does not apply. */
    write_16(segment + URGENT_POINTER_OFFSET, 0);

    /* ⚠ Written after the fixed fields and before the checksum, ⚠ **because the
     * checksum covers it.** ⚠ One octet at a time, in the order the wire wants:
     * kind, length, then the value most significant octet first. */
    if (fields->options.has_maximum_segment_size) {
        uint8_t *option = segment + TCP_FIXED_HEADER_BYTES;
        option[0] = TCP_OPTION_MAXIMUM_SEGMENT_SIZE;
        option[1] = TCP_OPTION_MAXIMUM_SEGMENT_SIZE_BYTES;
        write_16(option + 2, fields->options.maximum_segment_size);
    }

    /* ⚠ RFC 793: "While computing the checksum, the checksum field itself is
     * replaced with zeros." ⚠ The same one loop the Parse side uses, over the
     * same pseudo-header (`CLAUDE.md` §3).
     *
     * ⚠ **The length is the header's, not the fixed header's.** ⚠ A pseudo-header
     * naming twenty octets over a twenty-four octet segment is a checksum the
     * peer computes differently, ⚠ **and the only thing that would come back is
     * "it does not agree".** */
    write_16(segment + CHECKSUM_OFFSET, 0);
    uint8_t pseudo_header[PSEUDO_HEADER_BYTES];
    build_the_pseudo_header(pseudo_header, source_address, destination_address,
                            header_bytes);
    write_16(segment + CHECKSUM_OFFSET,
             internet_checksum_of_two(pseudo_header, sizeof pseudo_header, segment,
                                      header_bytes, CHECKSUM_OFFSET));

    *built_bytes = header_bytes;
    return TCP_BUILD_OK;
}
