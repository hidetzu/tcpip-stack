/* Parse — the fixed part of an ARP packet, checked and in host terms.
 *
 * ⚠ Nothing here writes a word a human reads, and nothing here decides what to
 * do next (`.claude/rules/layers.md`). A packet that is not accepted comes back
 * as a reason; `report.c` is the only place that becomes a sentence.
 *
 * ⚠ The names below are RFC 826's own, read from the document on 2026-08-26 and
 * cross-checked against a second copy of it — ⚠ not recalled
 * (ADR 0005, hidetzu/tcpip-stack#16 Owner Decision 2):
 *
 *     16.bit: (ar$hrd) Hardware address space
 *     16.bit: (ar$pro) Protocol address space
 *      8.bit: (ar$hln) byte length of each hardware address
 *      8.bit: (ar$pln) byte length of each protocol address
 *     16.bit: (ar$op)  opcode (ares_op$REQUEST | ares_op$REPLY)
 *     nbytes: (ar$sha) Hardware address of sender of this packet
 *     mbytes: (ar$spa) Protocol address of sender of this packet
 *     nbytes: (ar$tha) Hardware address of target of this packet (if known)
 *     mbytes: (ar$tpa) Protocol address of target
 *
 * ⚠ It is "opcode", not "operation", and "address space", not "type". A name
 * that differed from the RFC's would be a claim (`.claude/rules/layers.md`).
 *
 * ⚠ RFC 826 uses no RFC 2119 keywords. ⚠ So nothing here or in any wording
 * built on it may say the RFC requires something (`CLAUDE.md` §1). */
#ifndef ARP_H
#define ARP_H

#include <stddef.h>
#include <stdint.h>

/* ar$hrd through ar$op, before the four addresses begin. */
#define ARP_FIXED_BYTES 8

/* The address spaces and lengths this parser can place.
 *
 * ⚠ Grounds, and they are not the same for the names and the numbers. The names
 * above were read in RFC 826. ⚠ These numeric values were NOT taken from it —
 * they are what the Linux kernel put on an ethernet TAP device while asking for
 * an IPv4 address, in tests/fixtures/arp-request-42.hex. ⚠ An observation, and
 * it is recorded as one (ADR 0005). */
#define ARP_HARDWARE_ADDRESS_SPACE_ETHERNET 0x0001u
#define ARP_PROTOCOL_ADDRESS_SPACE_IPV4 0x0800u
#define ARP_HARDWARE_ADDRESS_BYTES 6
#define ARP_PROTOCOL_ADDRESS_BYTES 4

/* ⚠ RFC 826's own values, read from the document: "ares_op$REQUEST (= 1, high
 * byte transmitted first) and ares_op$REPLY (= 2)". */
#define ARP_OPCODE_REQUEST 1u
#define ARP_OPCODE_REPLY 2u

/* Why a packet was not accepted. ⚠ An enum never reaches a human (`CLAUDE.md` §4). */
enum arp_parse {
    ARP_PARSE_OK = 0,

    /* ⚠ Malformed: the octets that arrived do not hold what the packet says it
     * holds — either fewer than the fixed fields need, or fewer than ar$hln and
     * ar$pln declare. ⚠ Whoever sent it is wrong. */
    ARP_PARSE_MALFORMED,

    /* ⚠ Well-formed and unsupported: an ar$hrd, ar$pro, ar$hln or ar$pln this
     * parser cannot place. ⚠ The sender is fine; we do not handle it, and that
     * is a different answer from malformed (`.claude/rules/layers.md`). */
    ARP_PARSE_ADDRESS_SPACES_NOT_HANDLED,

    /* ⚠ Its own outcome, neither of the two above
     * (hidetzu/tcpip-stack#16 Owner Decision 1). The packet is well formed and
     * its address spaces are ones we place; ⚠ the opcode is one we do not act
     * on. ⚠ Folding it into either of the others would make a count of one
     * indistinguishable from a count of the other (`.claude/rules/c.md`). */
    ARP_PARSE_OPCODE_NOT_HANDLED
};

struct arp_packet {
    uint16_t hardware_address_space;               /* ar$hrd */
    uint16_t protocol_address_space;               /* ar$pro */
    uint8_t hardware_address_length;               /* ar$hln */
    uint8_t protocol_address_length;               /* ar$pln */
    uint16_t opcode;                               /* ar$op  */
    uint8_t sender_hardware_address[ARP_HARDWARE_ADDRESS_BYTES]; /* ar$sha */
    uint8_t sender_protocol_address[ARP_PROTOCOL_ADDRESS_BYTES]; /* ar$spa */
    uint8_t target_hardware_address[ARP_HARDWARE_ADDRESS_BYTES]; /* ar$tha */
    uint8_t target_protocol_address[ARP_PROTOCOL_ADDRESS_BYTES]; /* ar$tpa */
};

/* Read the fixed part of one ARP packet.
 *
 * `payload` is what followed the ethernet header, and `payload_bytes` is ⚠ what
 * was actually read, never what anything claims about itself
 * (`.claude/rules/c.md`). `packet` must not be NULL.
 *
 * ⚠ *packet is zeroed first, and the five fixed fields are filled whenever the
 * 8 octets were there — including for the two answers that decline the packet,
 * because those were read perfectly well.
 *
 * ⚠ The four addresses are filled only when OK is returned. Until the lengths
 * are ones this parser can place there is nowhere to put them, and
 * ⚠ ar$tha is "(if known)" even in a packet we accept, so all-zero there is a
 * value the sender chose and not an unfilled field. */
enum arp_parse arp_parse_packet(const uint8_t *payload, size_t payload_bytes,
                                struct arp_packet *packet);

#endif /* ARP_H */
