/* State — what an arriving ARP packet means for us, and what we did about it.
 *
 * ⚠ No fd, no clock, no prose (`.claude/rules/layers.md`). It is handed octets
 * and the two addresses we answer for, and it says what it decided and why.
 * ⚠ `report.c` is the only place any of it becomes a sentence.
 *
 * ⚠ The decision and the reason are two things, never one
 * (hidetzu/tcpip-stack#19 Owner Decision 2). ⚠ And the four reasons are counted
 * one by one: a single "declined" counter would make a packet we could not read
 * look exactly like one that was simply not addressed to us
 * (`.claude/rules/c.md`). */
#ifndef ARP_RESPONDER_H
#define ARP_RESPONDER_H

#include <stddef.h>
#include <stdint.h>

#include "arp.h"

enum arp_decision {
    ARP_ANSWER = 0,
    ARP_NO_ANSWER
};

/* ⚠ Owner Decision 2 names these four and they are never folded together, nor
 * into `not-for-us` (Owner Decision 4). ⚠ Three of them are the outcomes
 * ADR 0005 kept apart inside the parser, surviving the trip upward — which is
 * the only thing that made keeping them apart worth doing. */
enum arp_reason {
    ARP_REASON_NONE = 0, /* it was answered */
    ARP_REASON_NOT_FOR_US,
    ARP_REASON_MALFORMED,
    ARP_REASON_UNSUPPORTED_ADDRESS_SPACE,
    ARP_REASON_UNHANDLED_OPCODE
};

struct arp_counts {
    unsigned long answered;
    unsigned long not_for_us;
    unsigned long malformed;
    unsigned long unsupported_address_space;
    unsigned long unhandled_opcode;
};

struct arp_outcome {
    enum arp_decision decision;
    enum arp_reason reason;

    /* ⚠ Filled as far as the packet parsed, so a caller can say which address
     * was asked for without guessing. ⚠ Meaningful only when the reason is not
     * malformed. */
    struct arp_packet request;

    /* ⚠ Written only when the decision is ARP_ANSWER. `reply_bytes` is 0
     * otherwise, and ⚠ a caller must not send what was not built. */
    uint8_t reply[ARP_REPLY_FRAME_BYTES];
    size_t reply_bytes;
};

/* Decide what to do with one ARP payload, and count it.
 *
 * `payload` is what followed the ethernet header; `payload_bytes` is ⚠ what was
 * actually read.
 *
 * ⚠ `counts` gains exactly one for a decision of no-answer, under the reason
 * decided. ⚠ It does NOT gain an `answered`: nothing here sends, and a reply
 * that was built is not a reply that left. ⚠ The caller counts what it actually
 * handed over (`CLAUDE.md` §1, in the sending direction).
 *
 * ⚠ Nothing is sent here and nothing is printed here. */
void arp_respond(const uint8_t *payload, size_t payload_bytes,
                 const uint8_t *our_hardware_address,
                 const uint8_t *our_protocol_address,
                 struct arp_outcome *outcome, struct arp_counts *counts);

#endif /* ARP_RESPONDER_H */
