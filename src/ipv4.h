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

/* The value the `Protocol` field carries for ICMP.
 *
 * ⚠ Grounds, and they are not RFC 791: ⚠ **this was not taken from the
 * document.** RFC 791 names the field and says the values are in "Assigned
 * Numbers"; ⚠ that was not read. ⚠ This is octet 9 of the internet header in
 * tests/fixtures/icmp-echo-request-98.hex and of icmp-echo-reply-98.hex, both
 * put on a TAP device by the Linux kernel while carrying ICMP. ⚠ An
 * observation, and it is recorded as one — the same standing ADR 0005 gave
 * ARP's numbers. */
#define IPV4_PROTOCOL_ICMP 1u

/* And the one for TCP. ⚠ Same grounds as above and the same standing: ⚠ **not
 * read in RFC 791**, which names the field without giving values. ⚠ It is
 * octet 9 of the internet header in tests/fixtures/tcp-syn-74.hex, put there by
 * the Linux kernel while carrying TCP. ⚠ An observation. */
#define IPV4_PROTOCOL_TCP 6u

/* The header with no `Options`, in octets. ⚠ Derived from the minimum RFC 791
 * states, never written as 20. */
#define IPV4_FIXED_HEADER_BYTES (IPV4_HEADER_LENGTH_MINIMUM * IPV4_HEADER_LENGTH_UNIT)

/* The ethernet length/type an IPv4 datagram rides under.
 *
 * ⚠ Grounds: this was NOT taken from RFC 791 — it was not looked for there and
 * is not attributed to it. ⚠ It is octets 12 and 13 of
 * tests/fixtures/icmp-echo-request-98.hex and of icmp-echo-reply-98.hex, both
 * put on a TAP device by the Linux kernel. ⚠ An observation, the same standing
 * `ARP_ETHERNET_LENGTH_TYPE` has (ADR 0005).
 *
 * ⚠ `report.c` still never turns this value into a name (ADR 0003). ⚠ Using it
 * to decide what to build is not the same as printing it as a claim. */
#define IPV4_ETHERNET_LENGTH_TYPE 0x0800u

/* What goes in a header we build. ⚠ Owner decisions, not readings of RFC 791
 * (hidetzu/tcpip-stack#35 Owner Decision 2, ADR 0012).
 *
 * ⚠ Time to Live 64 and Don't Fragment clear are what the Linux kernel does:
 * measured 5 runs of 5, all five `ttl=64` and `flags=0x0`, on this machine on
 * 2026-08-28. ⚠ An observation about the kernel, ⚠ not a claim that RFC 791
 * asks for either.
 *
 * ⚠ Identification is 0 and does not vary. ⚠ Nothing here fragments, so there
 * is nothing for a receiver to match pieces by. ⚠ The kernel puts a different
 * value in every reply — ⚠ that was measured too, and ⚠ no grounds for copying
 * the behaviour were read, so it is not copied. */
/* ⚠ **The default, not the value.** ⚠ Since hidetzu/tcpip-stack#103 a caller
 * says what to send, and this is what `--ttl` starts at. */
#define IPV4_TIME_TO_LIVE_WE_SEND 64u
#define IPV4_IDENTIFICATION_WE_SEND 0u

/* ⚠ Is this address one a connection must never be made to?
 *
 * ⚠ RFC 9293 `MUST-57`: "A TCP implementation MUST silently discard an incoming
 * SYN segment that is addressed to a broadcast or multicast address." ⚠ The
 * document gives the reason beside it: "This prevents connection state and
 * replies from being erroneously generated."
 *
 * ⚠ **Two of the three kinds, and the third is named rather than pretended
 * away** (hidetzu/tcpip-stack#99 Owner Decision):
 *
 *     255.255.255.255     ⚠ the limited broadcast — recognisable from the
 *                         address alone
 *     224.0.0.0/4         ⚠ multicast — RFC 791 §3.2: "the first four bits
 *                         being 1110"
 *     10.0.0.255 etc.     ⚠ **a directed broadcast, and this returns false for
 *                         it** — ⚠ **it cannot be told from a host address
 *                         without a netmask, and nothing here has one.**
 *
 * ⚠ **So `MUST-57` is met in part**, and `docs/conformance.md` says which part.
 * ⚠ Claiming it met on the strength of the two that are easy would be the
 * shape `CLAUDE.md` §1 forbids. */
bool ipv4_address_is_broadcast_or_multicast(const uint8_t *address);

/* ⚠ Could this address have sent anything at all?
 *
 * ⚠ **A different question from the one above, with a different citation.**
 * That one asks whether a connection may be made TO an address; ⚠ this asks
 * whether an address may have been the SOURCE of what just arrived.
 * ⚠ **One function answering both would be two decisions in one place**
 * (`CLAUDE.md` §3), so there are two (hidetzu/tcpip-stack#112 Owner Decision 3).
 *
 * ⚠ RFC 9293 `MUST-63`, §3.9.2.3: "An incoming SYN with an invalid source
 * address MUST be ignored either by TCP or by the IP layer ... (see
 * Section 3.2.1.3)." ⚠ **The section it sends the reader to is RFC 1122's**, and
 * that is where every form below comes from.
 *
 * ⚠ **Returns false for the forms RFC 1122 §3.2.1.3 says MUST NOT be a source
 * and that are recognisable from the address alone**, quoted:
 *
 *     0.0.0.0/8         (a) and (b): "MUST NOT be sent, except as a source
 *                       address as part of an initialization procedure by which
 *                       the host learns its own IP address."
 *                       ⚠ **A `SYN` is not that procedure.**
 *     127.0.0.0/8       (g): "Addresses of this form MUST NOT appear outside a
 *                       host."
 *     255.255.255.255   (c): "It MUST NOT be used as a source address."
 *
 * ⚠ **And one more, whose grounds are NOT §3.2.1.3:**
 *
 *     224.0.0.0/4       ⚠ **The multicast address model, not the section
 *                       RFC 9293 cites.** ⚠ A Class D address names a group of
 *                       receivers; ⚠ **it is never one host that could have
 *                       sent a segment.** ⚠ **Recorded as reaching outside the
 *                       citation rather than quoted to it**
 *                       (hidetzu/tcpip-stack#112 Owner Decision 1).
 *
 * ⚠ **What this returns TRUE for and should not**, and it is named rather than
 * pretended away — ⚠ the same gap `ipv4_address_is_broadcast_or_multicast` has,
 * ⚠ **for the same reason**:
 *
 *     10.0.0.255 etc.   ⚠ **a directed broadcast** — §3.2.1.3 (d), (e) and (f),
 *                       each "MUST NOT be used as a source address".
 *                       ⚠ **It cannot be told from a host address without a
 *                       netmask, and nothing here has one.**
 *
 * ⚠ **So `MUST-63` is met in part**, and `docs/conformance.md` says which part.
 * ⚠ **Never met** (hidetzu/tcpip-stack#112 Owner Decision 2). */
bool ipv4_address_can_be_a_source(const uint8_t *address);

/* Why a datagram was not built. ⚠ An enum never reaches a human. */
enum ipv4_build {
    IPV4_BUILD_OK = 0,

    /* ⚠ The caller's buffer cannot hold the whole datagram. ⚠ Refused, never
     * truncated: a header whose Total Length names octets that are not there is
     * the malformed datagram this file rejects on the way in, and ⚠ a caller
     * told it succeeded would count one that was never whole. */
    IPV4_BUILD_BUFFER_TOO_SMALL
};

/* Build an internet header with `payload` behind it, into a caller's buffer.
 *
 * `datagram_bytes` is what the buffer actually holds, and ⚠ not one octet is
 * written unless the whole datagram fits. On OK, *built_bytes is how much was
 * written.
 *
 * ⚠ The header carries no `Options`: `IHL` is 5, which is the same header this
 * file accepts on the way in. ⚠ Version 4, `Type of Service` 0, `Fragment
 * Offset` 0, and the three constants above.
 *
 * ⚠ `Header Checksum` is computed as RFC 1071 describes, over the header only —
 * "A checksum on the header only", RFC 791.
 *
 * ⚠ `payload` may overlap the buffer being written; the copy allows it. */
/* ⚠ `time_to_live` is the caller's, and ⚠ **it is a parameter rather than the
 * constant it used to be** (hidetzu/tcpip-stack#103).
 *
 * ⚠ RFC 9293 `MUST-49`: "The TTL value used to send TCP segments MUST be
 * configurable." ⚠ **It was written here once and nothing could change it**;
 * `docs/SPEC.md` §1 recorded the value and not that it was fixed.
 *
 * ⚠ `IPV4_TIME_TO_LIVE_WE_SEND` is still what a caller passes when nothing said
 * otherwise, and ⚠ **it is still an observation about the Linux kernel** rather
 * than a reading of RFC 791. */
enum ipv4_build ipv4_build_datagram(const uint8_t *source_address,
                                    const uint8_t *destination_address,
                                    uint8_t protocol, uint8_t time_to_live,
                                    const uint8_t *payload, size_t payload_bytes,
                                    uint8_t *datagram, size_t datagram_bytes,
                                    size_t *built_bytes);

#endif /* IPV4_H */
