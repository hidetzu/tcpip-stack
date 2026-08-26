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

#include "ethernet.h"

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

/* The ethernet length/type an ARP packet rides under.
 *
 * ⚠ Grounds: this was NOT taken from RFC 826 — it was not looked for there and
 * is not attributed to it (ADR 0005). It is octets 12 and 13 of
 * tests/fixtures/arp-request-42.hex and of tests/fixtures/arp-reply-42.hex,
 * both put on a TAP device by the Linux kernel. ⚠ An observation. */
#define ARP_ETHERNET_LENGTH_TYPE 0x0806u

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

/* An ARP reply on ethernet, header and packet together.
 *
 * ⚠ Measured, not assumed: the reply the Linux kernel built for us is exactly
 * this long — tests/fixtures/arp-reply-42.hex, 42 octets. ⚠ There is no padding
 * to 60 and no FCS. */
#define ARP_REPLY_FRAME_BYTES \
    (ETHERNET_HEADER_BYTES + ARP_FIXED_BYTES + \
     2 * (ARP_HARDWARE_ADDRESS_BYTES + ARP_PROTOCOL_ADDRESS_BYTES))

/* Why a reply was not built. ⚠ An enum never reaches a human (`CLAUDE.md` §4). */
enum arp_build {
    ARP_BUILD_OK = 0,

    /* ⚠ The caller's buffer cannot hold the whole reply. ⚠ Refused, never
     * truncated: half a frame on the wire is worse than none, and a caller told
     * it succeeded would count a frame that was never whole
     * (`.claude/rules/c.md`). */
    ARP_BUILD_BUFFER_TOO_SMALL
};

/* Build the reply to `request`, into a caller-supplied buffer.
 *
 * `frame_bytes` is what the buffer actually holds, and ⚠ nothing is written
 * unless the whole reply fits. On OK, *reply_bytes is how much was written.
 *
 * ⚠ Where each field comes from, and none of it is guessed:
 *
 *     ethernet destination   the request's ar$sha — the host that asked
 *     ethernet source        our_hardware_address
 *     ar$sha, ar$spa         ours, both passed in
 *     ar$tha, ar$tpa         the request's ar$sha and ar$spa
 *
 * ⚠ The addresses we answer with are handed in and never reached for. The TAP
 * device's own hardware address is the kernel's end of the wire, not ours, and
 * it is a different value on every run (hidetzu/tcpip-stack#19 Owner Decision 1).
 *
 * ⚠ This decides nothing. Whether a request deserves an answer at all belongs
 * to whoever calls this (hidetzu/tcpip-stack#19). */
enum arp_build arp_build_reply(const struct arp_packet *request,
                               const uint8_t *our_hardware_address,
                               const uint8_t *our_protocol_address,
                               uint8_t *frame, size_t frame_bytes,
                               size_t *reply_bytes);

#endif /* ARP_H */
