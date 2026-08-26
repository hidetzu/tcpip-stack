#include "arp_responder.h"

#include <string.h>

static void decided(struct arp_outcome *outcome, enum arp_decision decision,
                    enum arp_reason reason)
{
    outcome->decision = decision;
    outcome->reason = reason;
}

void arp_respond(const uint8_t *payload, size_t payload_bytes,
                 const uint8_t *our_hardware_address,
                 const uint8_t *our_protocol_address,
                 struct arp_outcome *outcome, struct arp_counts *counts)
{
    memset(outcome, 0, sizeof *outcome);

    enum arp_parse parsed = arp_parse_packet(payload, payload_bytes, &outcome->request);

    /* ⚠ The parser's three answers arrive here as three answers. ⚠ Folding any
     * of them into another, or into not-for-us, would make a count of one
     * indistinguishable from a count of the other (Owner Decision 4). */
    switch (parsed) {
    case ARP_PARSE_MALFORMED:
        counts->malformed++;
        decided(outcome, ARP_NO_ANSWER, ARP_REASON_MALFORMED);
        return;
    case ARP_PARSE_ADDRESS_SPACES_NOT_HANDLED:
        counts->unsupported_address_space++;
        decided(outcome, ARP_NO_ANSWER, ARP_REASON_UNSUPPORTED_ADDRESS_SPACE);
        return;
    case ARP_PARSE_OPCODE_NOT_HANDLED:
        counts->unhandled_opcode++;
        decided(outcome, ARP_NO_ANSWER, ARP_REASON_UNHANDLED_OPCODE);
        return;
    case ARP_PARSE_OK:
        break;
    }

    /* ⚠ A reply is well formed and placeable, and we do not act on one — so it
     * is an opcode we do not act on, which is what that reason says. ⚠ It is
     * not "not for us": that answer is about whose address was asked for, and
     * this is about what was asked. */
    if (outcome->request.opcode != ARP_OPCODE_REQUEST) {
        counts->unhandled_opcode++;
        decided(outcome, ARP_NO_ANSWER, ARP_REASON_UNHANDLED_OPCODE);
        return;
    }

    if (memcmp(outcome->request.target_protocol_address, our_protocol_address,
               ARP_PROTOCOL_ADDRESS_BYTES) != 0) {
        counts->not_for_us++;
        decided(outcome, ARP_NO_ANSWER, ARP_REASON_NOT_FOR_US);
        return;
    }

    if (arp_build_reply(&outcome->request, our_hardware_address, our_protocol_address,
                        outcome->reply, sizeof outcome->reply,
                        &outcome->reply_bytes) != ARP_BUILD_OK) {
        /* ⚠ Cannot happen with a buffer of exactly the reply's size, and it is
         * still handled: an unbuilt reply must never be counted as answered. */
        outcome->reply_bytes = 0;
        counts->malformed++;
        decided(outcome, ARP_NO_ANSWER, ARP_REASON_MALFORMED);
        return;
    }

    /* ⚠ Deliberately not counted here. The reply exists; it has not left.
     * ⚠ The caller counts it once the wire has taken it. */
    decided(outcome, ARP_ANSWER, ARP_REASON_NONE);
}
