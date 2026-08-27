/* Parse — the header of a TCP segment, checked and in host terms.
 *
 * ⚠ Nothing here writes a word a human reads, nothing here decides anything,
 * and nothing here remembers anything between calls
 * (`.claude/rules/layers.md`). A segment that is not accepted comes back as a
 * reason; `report.c` is the only place that becomes a sentence.
 *
 * ⚠ The names below are RFC 793's own, read on 2026-08-28 from rfc-editor.org
 * and cross-checked against the copy at datatracker.ietf.org. ⚠ Both agreed,
 * and this is what they say (ADR 0013):
 *
 *     Source Port: 16 bits.  The source port number.
 *     Destination Port: 16 bits.  The destination port number.
 *     Sequence Number: 32 bits.
 *     Acknowledgment Number: 32 bits.
 *     Data Offset: 4 bits - The number of 32 bit words in the TCP Header.
 *     Reserved: 6 bits - Reserved for future use.  Must be zero.
 *     Control Bits: 6 bits (from left to right):
 *       URG: Urgent Pointer field significant
 *       ACK: Acknowledgment field significant
 *       PSH: Push Function
 *       RST: Reset the connection
 *       SYN: Synchronize sequence numbers
 *       FIN: No more data from sender
 *     Window: 16 bits.
 *     Checksum: 16 bits.
 *     Urgent Pointer: 16 bits.
 *
 * ⚠ It is "Acknowledgment", with no "e" in the middle. ⚠ The document spells it
 * that way and so does this file (`.claude/rules/c.md`: borrow the RFC's names,
 * exactly).
 *
 * ⚠ RFC 793 does not use the RFC 2119 keywords in capitals. ⚠ So nothing here
 * or in any wording built on it may say the RFC requires something
 * (`CLAUDE.md` §1) — the same standing RFC 826, 791 and 792 are in here.
 *
 * ⚠ Nothing here checks the checksum. ⚠ It is computed over a pseudo-header
 * that is not in the segment (hidetzu/tcpip-stack#41). */
#ifndef TCP_H
#define TCP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* ⚠ RFC 793: "Data Offset: 4 bits - The number of 32 bit words in the TCP
 * Header." ⚠ So a header is Data Offset of these. */
#define TCP_HEADER_LENGTH_UNIT 4

/* The header before any Options, in units of the above.
 *
 * ⚠ Grounds, and they are NOT the document: ⚠ **RFC 793 states no minimum for
 * Data Offset.** RFC 791 does for `IHL` — "Note that the minimum value for a
 * correct header is 5" — and ⚠ there is no sentence like it here.
 *
 * ⚠ This is counted off the diagram: the fields above Options occupy five
 * 32-bit words. ⚠ A Data Offset below it is a header saying it is shorter than
 * its own fixed fields, which is a contradiction — ⚠ our reading, recorded as
 * ours (ADR 0013). */
#define TCP_HEADER_LENGTH_MINIMUM 5

/* ⚠ Data Offset is four bits wide, so it cannot exceed this. */
#define TCP_HEADER_LENGTH_MAXIMUM 15

/* The fixed part, in octets. ⚠ Derived, never written as 20. */
#define TCP_FIXED_HEADER_BYTES (TCP_HEADER_LENGTH_MINIMUM * TCP_HEADER_LENGTH_UNIT)

/* ⚠ RFC 793's six Control Bits, in the order the document lists them,
 * left to right. */
#define TCP_CONTROL_URG 0x20u
#define TCP_CONTROL_ACK 0x10u
#define TCP_CONTROL_PSH 0x08u
#define TCP_CONTROL_RST 0x04u
#define TCP_CONTROL_SYN 0x02u
#define TCP_CONTROL_FIN 0x01u

/* ⚠ RFC 793's option-kinds, quoted: "End of option list", "No-Operation",
 * "Maximum Segment Size". ⚠ Only the first two are named here, because ⚠ they
 * are the two the walk has to know about — they are Case 1, "a single octet of
 * option-kind", and every other kind is Case 2.
 *
 * ⚠ Maximum Segment Size is deliberately not named: nothing here interprets an
 * option, and a constant for one would be the beginning of doing so. */
#define TCP_OPTION_END_OF_OPTION_LIST 0u
#define TCP_OPTION_NO_OPERATION 1u

/* Why a segment was not accepted. ⚠ An enum never reaches a human
 * (`CLAUDE.md` §4). */
enum tcp_parse {
    TCP_PARSE_OK = 0,

    /* ⚠ Malformed: the octets do not hold what the header says they hold, or
     * the header breaks what RFC 793 states. ⚠ Whoever sent it is wrong.
     * ⚠ Four inputs land here — fewer octets than the fixed fields need; a Data
     * Offset below or beyond what a header can be; a Reserved that is not zero;
     * and ⚠ an option list that does not walk (ADR 0013).
     *
     * ⚠ There is no "well-formed but unsupported" answer in this file, and that
     * is not an oversight: ⚠ reading a header declines nothing. ⚠ Options are
     * walked past rather than refused, because ⚠ the Linux kernel's own SYN
     * carries twenty octets of them (tests/fixtures/tcp-syn-74.hex) and a
     * parser that refused them would refuse every real SYN there is. */
    TCP_PARSE_MALFORMED
};

struct tcp_header {
    uint16_t source_port;
    uint16_t destination_port;
    uint32_t sequence_number;
    uint32_t acknowledgment_number;
    uint8_t data_offset;   /* in 32-bit words, as the document counts */
    uint8_t reserved;      /* ⚠ six bits, and the document says they are zero */
    uint8_t control_bits;  /* the six above */
    uint16_t window;
    uint16_t checksum;     /* ⚠ carried, never verified here */
    uint16_t urgent_pointer;

    /* ⚠ Where the data begins, counted from the start of the segment.
     * ⚠ This is what walking the options buys, and ⚠ it is the only thing the
     * options are read for. ⚠ It is `data_offset` in octets, and it is
     * meaningful only when OK is returned. */
    size_t data_begins_at;
};

/* Read the header of one TCP segment.
 *
 * `segment` is what followed the internet header, and `segment_bytes` is ⚠ what
 * was actually read, never what anything claims about itself
 * (`.claude/rules/c.md`). `header` must not be NULL.
 *
 * ⚠ *header is zeroed first, and filled as far as the octets allowed — so a
 * caller can say which port was asked for without reading them itself, even for
 * a segment it declines. ⚠ Meaningful only when the answer is not malformed.
 *
 * ⚠ The options are walked and ⚠ not one of them is interpreted. RFC 793 says
 * "A TCP must implement all options"; ⚠ **this file implements none of them**,
 * and that gap is named in `docs/SPEC.md` §2 rather than left silent. */
enum tcp_parse tcp_parse_header(const uint8_t *segment, size_t segment_bytes,
                                struct tcp_header *header);

#endif /* TCP_H */
