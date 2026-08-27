/* State — what an arriving IPv4 datagram means for us, and what we did about it.
 *
 * ⚠ No fd, no clock, no prose (`.claude/rules/layers.md`). It is handed octets
 * and the addresses we answer with, and it says what it decided and why.
 * ⚠ `report.c` is the only place any of it becomes a sentence.
 *
 * ⚠ The decision and the reason are two things, never one — the shape
 * hidetzu/tcpip-stack#19 Owner Decision 2 set for ARP. ⚠ And every reason is
 * counted on its own: one "declined" counter would make a datagram we could not
 * read look exactly like one that was simply not addressed to us
 * (`.claude/rules/c.md`, hidetzu/tcpip-stack#35 AC 4). */
#ifndef ECHO_RESPONDER_H
#define ECHO_RESPONDER_H

#include <stddef.h>
#include <stdint.h>

#include "ethernet.h"
#include "icmp.h"
#include "ipv4.h"

enum echo_decision {
    ECHO_ANSWER = 0,
    ECHO_NO_ANSWER
};

/* ⚠ Nine reasons and they are never folded together. ⚠ Six of them are the
 * outcomes `src/ipv4.c` and `src/icmp.c` already keep apart, surviving the trip
 * upward — which is the only thing that made keeping them apart worth doing
 * (the point ADR 0005 and ADR 0008 made for ARP).
 *
 * ⚠ The tenth is ours and not the sender's, and it says so in `report.c`. */
enum echo_reason {
    ECHO_REASON_NONE = 0, /* it was answered */

    /* From the internet header (ADR 0010). */
    ECHO_REASON_INTERNET_HEADER_MALFORMED,
    ECHO_REASON_INTERNET_HEADER_NOT_HANDLED,
    ECHO_REASON_INTERNET_HEADER_CHECKSUM_DISAGREES,
    ECHO_REASON_FRAGMENT,

    /* From what the accepted header said. */
    ECHO_REASON_NOT_FOR_US,
    ECHO_REASON_PROTOCOL_NOT_HANDLED,

    /* From the ICMP message (ADR 0011). */
    ECHO_REASON_ICMP_MALFORMED,
    ECHO_REASON_ICMP_TYPE_NOT_HANDLED,
    ECHO_REASON_ICMP_CHECKSUM_DISAGREES,

    /* ⚠ Ours, not the sender's. The datagram was one we would have answered and
     * ⚠ the buffer we were given could not hold the reply. ⚠ Counted rather than
     * dropped in silence, because an uncounted drop is invisible and an
     * invisible drop looks exactly like a datagram that never arrived
     * (`.claude/rules/c.md`).
     *
     * ⚠ A caller that supplies a buffer at least as long as the frame that
     * arrived cannot reach this: an echo reply is exactly as long as the echo
     * request it answers. */
    ECHO_REASON_WE_COULD_NOT_BUILD_THE_REPLY
};

struct echo_counts {
    unsigned long answered;
    unsigned long internet_header_malformed;
    unsigned long internet_header_not_handled;
    unsigned long internet_header_checksum_disagrees;
    unsigned long fragment;
    unsigned long not_for_us;
    unsigned long protocol_not_handled;
    unsigned long icmp_malformed;
    unsigned long icmp_type_not_handled;
    unsigned long icmp_checksum_disagrees;
    unsigned long we_could_not_build_the_reply;
};

struct echo_outcome {
    enum echo_decision decision;
    enum echo_reason reason;

    /* ⚠ Filled as far as the datagram parsed, so a caller can say which address
     * was asked for without reading the octets itself. ⚠ The header is
     * meaningful only when the reason is not `INTERNET_HEADER_MALFORMED`; the
     * message only once the internet header was accepted. */
    struct ipv4_header header;
    struct icmp_echo request;

    /* ⚠ How many octets of the caller's reply buffer were written. ⚠ 0 unless
     * the decision is ECHO_ANSWER, and ⚠ a caller must not send what was not
     * built. */
    size_t reply_bytes;
};

/* Decide what to do with one arriving frame, and count it.
 *
 * `datagram` is what followed the ethernet header and `datagram_bytes` is
 * ⚠ what was actually read. `requester_hardware_address` is that frame's
 * ethernet source — ⚠ where a reply would have to go, taken from the frame and
 * never from a table this stack does not keep.
 *
 * `reply` is the caller's buffer for a whole frame, ⚠ ethernet header included,
 * and `reply_bytes` is what it holds. ⚠ It may be the very buffer `datagram`
 * points into: answering in place is allowed and is what a caller holding one
 * frame will do.
 *
 * ⚠ `counts` gains exactly one, under the reason decided. ⚠ It does NOT gain an
 * `answered`: nothing here sends, and a reply that was built is not a reply that
 * left. ⚠ The caller counts that once the wire has taken it (`CLAUDE.md` §1, in
 * the sending direction) — the same division `arp_respond` uses.
 *
 * ⚠ Nothing is sent here and nothing is printed here. */
void echo_respond(const uint8_t *datagram, size_t datagram_bytes,
                  const uint8_t *requester_hardware_address,
                  const uint8_t *our_hardware_address,
                  const uint8_t *our_protocol_address,
                  uint8_t *reply, size_t reply_bytes,
                  struct echo_outcome *outcome, struct echo_counts *counts);

#endif /* ECHO_RESPONDER_H */
