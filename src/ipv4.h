/* Parse — the internet header, checked and in host terms.
 *
 * ⚠ Nothing here writes a word a human reads, and nothing here decides what to
 * do next (`.claude/rules/layers.md`). A datagram that is not accepted comes
 * back as a reason; `report.c` is the only place that becomes a sentence.
 *
 * ⚠ The names below are RFC 791's own, read from rfc-editor.org on 2026-08-28
 * and ⚠ cross-checked against the copy at datatracker.ietf.org. ⚠ Both agreed
 * verbatim, and this is the list they give:
 *
 *   Version, IHL, Type of Service, Total Length, Identification, Flags,
 *   Fragment Offset, Time to Live, Protocol, Header Checksum, Source Address,
 *   Destination Address, Options, Padding
 *
 * ⚠ It is `time_to_live`, not `ttl`. The document does not abbreviate it.
 *
 * ⚠ Nothing here interprets anything above the header
 * (hidetzu/tcpip-stack#33). */
#ifndef IPV4_H
#define IPV4_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* ⚠ RFC 791: "Internet Header Length is the length of the internet header in
 * 32 bit words". ⚠ So a header is IHL of these. */
#define IPV4_HEADER_LENGTH_UNIT 4

/* ⚠ RFC 791: "Note that the minimum value for a correct header is 5." ⚠ Below
 * this the document calls the header not correct, which is why a smaller value
 * is malformed rather than unsupported (hidetzu/tcpip-stack#33). */
#define IPV4_HEADER_LENGTH_MINIMUM 5

/* ⚠ IHL is four bits wide, so it cannot exceed this. ⚠ Grounds: the layout in
 * RFC 791 §3.1, not an assumption about what senders do. */
#define IPV4_HEADER_LENGTH_MAXIMUM 15

#define IPV4_ADDRESS_BYTES 4
#define IPV4_VERSION 4

/* ⚠ RFC 791's own flag bits, quoted:
 *   "Bit 0: reserved, must be zero"
 *   "Bit 1: (DF) 0 = May Fragment, 1 = Don't Fragment."
 *   "Bit 2: (MF) 0 = Last Fragment, 1 = More Fragments."
 * ⚠ Bit 0 is the most significant of the three. */
#define IPV4_FLAG_RESERVED 0x4u
#define IPV4_FLAG_DONT_FRAGMENT 0x2u
#define IPV4_FLAG_MORE_FRAGMENTS 0x1u

/* Why a datagram was not accepted. ⚠ An enum never reaches a human. */
enum ipv4_parse {
    IPV4_PARSE_OK = 0,

    /* ⚠ Malformed: the octets do not hold what the header says they hold, or
     * the header breaks what RFC 791 states. ⚠ Whoever sent it is wrong.
     * ⚠ Three inputs land here: fewer octets than a header needs; an IHL or a
     * Total Length larger than what arrived; ⚠ an IHL below 5, which the
     * document calls not correct; and ⚠ the reserved flag bit set, which it
     * says must be zero (hidetzu/tcpip-stack#33 Owner Decision 2). */
    IPV4_PARSE_MALFORMED,

    /* ⚠ Well-formed and unsupported: a version that is not 4, or a header long
     * enough to carry Options. ⚠ The sender is fine; we do not handle it. */
    IPV4_PARSE_NOT_HANDLED,

    /* ⚠ Its own answer. ⚠ A datagram whose header checksum does not agree is
     * not a datagram we may act on, and it is not the sender being wrong about
     * the format — ⚠ something changed it, or it was never right. ⚠ Counting it
     * with either of the others would hide it. */
    IPV4_PARSE_CHECKSUM_DISAGREES,

    /* ⚠ Its own answer (Owner Decision 1). ⚠ A fragment is perfectly well
     * formed; reassembly is simply not written. ⚠ Folding it in with a wrong
     * version would mix two counts that mean different things, and ⚠ when
     * reassembly is considered, how many arrived will already be known. */
    IPV4_PARSE_FRAGMENT
};

struct ipv4_header {
    uint8_t version;
    uint8_t internet_header_length;   /* in 32-bit words, as the document counts */
    uint8_t type_of_service;
    uint16_t total_length;
    uint16_t identification;
    uint8_t flags;                    /* the three bits above */
    uint16_t fragment_offset;         /* ⚠ "in units of 8 octets (64 bits)" */
    uint8_t time_to_live;
    uint8_t protocol;
    uint16_t header_checksum;
    uint8_t source_address[IPV4_ADDRESS_BYTES];
    uint8_t destination_address[IPV4_ADDRESS_BYTES];
};

/* Read the internet header of one datagram.
 *
 * `datagram` is what followed the ethernet header and `datagram_bytes` is ⚠ what
 * was actually read, never what anything claims about itself
 * (`.claude/rules/c.md`). `header` must not be NULL.
 *
 * ⚠ *header is zeroed first, and filled as far as the octets allowed — so a
 * caller can say which address was asked for without guessing, even for a
 * datagram it declines. ⚠ Meaningful only when the answer is not malformed. */
enum ipv4_parse ipv4_parse_header(const uint8_t *datagram, size_t datagram_bytes,
                                  struct ipv4_header *header);

#endif /* IPV4_H */
