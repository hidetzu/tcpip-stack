#include "echo_responder.h"

#include <string.h>

static void decided(struct echo_outcome *outcome, enum echo_reason reason,
                    unsigned long *count)
{
    outcome->decision = ECHO_NO_ANSWER;
    outcome->reason = reason;
    outcome->reply_bytes = 0;
    /* ⚠ The reason and the counter it moves are passed together, so a reason
     * cannot be reported under one name and counted under another. */
    (*count)++;
}

void echo_respond(const uint8_t *datagram, size_t datagram_bytes,
                  uint8_t time_to_live,
                  const uint8_t *requester_hardware_address,
                  const uint8_t *our_hardware_address,
                  const uint8_t *our_protocol_address,
                  uint8_t *reply, size_t reply_bytes,
                  struct echo_outcome *outcome, struct echo_counts *counts)
{
    memset(outcome, 0, sizeof *outcome);

    /* ⚠ The parser's four answers arrive here as four answers. ⚠ Folding any of
     * them into another would make a count of one indistinguishable from a
     * count of the other (hidetzu/tcpip-stack#35 AC 4). */
    switch (ipv4_parse_header(datagram, datagram_bytes, &outcome->header)) {
    case IPV4_PARSE_MALFORMED:
        decided(outcome, ECHO_REASON_INTERNET_HEADER_MALFORMED,
                &counts->internet_header_malformed);
        return;
    case IPV4_PARSE_NOT_HANDLED:
        decided(outcome, ECHO_REASON_INTERNET_HEADER_NOT_HANDLED,
                &counts->internet_header_not_handled);
        return;
    case IPV4_PARSE_CHECKSUM_DISAGREES:
        decided(outcome, ECHO_REASON_INTERNET_HEADER_CHECKSUM_DISAGREES,
                &counts->internet_header_checksum_disagrees);
        return;
    case IPV4_PARSE_FRAGMENT:
        decided(outcome, ECHO_REASON_FRAGMENT, &counts->fragment);
        return;
    case IPV4_PARSE_OK:
        break;
    }

    /* ⚠ Whose address was asked for, before what was asked. ⚠ This is the other
     * way round from `arp_respond`, and on purpose: there, "not for us" is about
     * `ar$tpa`, which only means anything once the opcode says it is a request.
     * ⚠ Here the destination address means the same thing in every datagram, so
     * ⚠ a datagram addressed to somebody else is not ours to have an opinion
     * about the protocol of. */
    if (memcmp(outcome->header.destination_address, our_protocol_address,
               IPV4_ADDRESS_BYTES) != 0) {
        decided(outcome, ECHO_REASON_NOT_FOR_US, &counts->not_for_us);
        return;
    }

    if (outcome->header.protocol != IPV4_PROTOCOL_ICMP) {
        decided(outcome, ECHO_REASON_PROTOCOL_NOT_HANDLED,
                &counts->protocol_not_handled);
        return;
    }

    /* ⚠ How far the message runs comes from Total Length, not from how many
     * octets arrived: a short frame is padded up to 60 on the wire, and ⚠ that
     * padding is not part of the message the checksum covers.
     *
     * ⚠ Neither subtraction can wrap. `ipv4_parse_header` accepted this header,
     * which means `Total Length` is at least the header's own length
     * (hidetzu/tcpip-stack#35 Owner Decision 4) and no larger than what
     * arrived. */
    size_t header_bytes =
        (size_t)outcome->header.internet_header_length * IPV4_HEADER_LENGTH_UNIT;
    size_t message_bytes = (size_t)outcome->header.total_length - header_bytes;

    switch (icmp_parse_echo(datagram + header_bytes, message_bytes, &outcome->request)) {
    case ICMP_PARSE_MALFORMED:
        decided(outcome, ECHO_REASON_ICMP_MALFORMED, &counts->icmp_malformed);
        return;
    case ICMP_PARSE_TYPE_NOT_HANDLED:
        decided(outcome, ECHO_REASON_ICMP_TYPE_NOT_HANDLED,
                &counts->icmp_type_not_handled);
        return;
    case ICMP_PARSE_CHECKSUM_DISAGREES:
        /* ⚠ This is the branch that stops `ping` succeeding from being the only
         * proof. ⚠ A stack that never looked would answer this one
         * (`CLAUDE.md` §1, hidetzu/tcpip-stack#35 AC 2). */
        decided(outcome, ECHO_REASON_ICMP_CHECKSUM_DISAGREES,
                &counts->icmp_checksum_disagrees);
        return;
    case ICMP_PARSE_OK:
        break;
    }

    /* Built from the inside out, so each layer's payload is already in place.
     * ⚠ `reply` is allowed to be the buffer `datagram` points into, and every
     * builder below copies in a way that allows the overlap. */
    size_t message_reply_bytes = 0;
    if (reply_bytes < ETHERNET_HEADER_BYTES ||
        icmp_build_echo_reply(&outcome->request, reply + ETHERNET_HEADER_BYTES +
                                                     IPV4_FIXED_HEADER_BYTES,
                              reply_bytes - ETHERNET_HEADER_BYTES -
                                  IPV4_FIXED_HEADER_BYTES,
                              &message_reply_bytes) != ICMP_BUILD_OK) {
        decided(outcome, ECHO_REASON_WE_COULD_NOT_BUILD_THE_REPLY,
                &counts->we_could_not_build_the_reply);
        return;
    }

    size_t datagram_reply_bytes = 0;
    if (ipv4_build_datagram(our_protocol_address, outcome->header.source_address,
                            IPV4_PROTOCOL_ICMP, time_to_live,
                            reply + ETHERNET_HEADER_BYTES + IPV4_FIXED_HEADER_BYTES,
                            message_reply_bytes, reply + ETHERNET_HEADER_BYTES,
                            reply_bytes - ETHERNET_HEADER_BYTES,
                            &datagram_reply_bytes) != IPV4_BUILD_OK) {
        decided(outcome, ECHO_REASON_WE_COULD_NOT_BUILD_THE_REPLY,
                &counts->we_could_not_build_the_reply);
        return;
    }

    /* ⚠ Where the reply goes comes from the frame that arrived, never from a
     * table: this stack keeps no neighbour cache (`docs/SPEC.md` §2). */
    if (!ethernet_build_header(requester_hardware_address, our_hardware_address,
                               IPV4_ETHERNET_LENGTH_TYPE, reply, reply_bytes)) {
        decided(outcome, ECHO_REASON_WE_COULD_NOT_BUILD_THE_REPLY,
                &counts->we_could_not_build_the_reply);
        return;
    }

    /* ⚠ Deliberately not counted here. The reply exists; it has not left.
     * ⚠ The caller counts it once the wire has taken it. */
    outcome->decision = ECHO_ANSWER;
    outcome->reason = ECHO_REASON_NONE;
    outcome->reply_bytes = ETHERNET_HEADER_BYTES + datagram_reply_bytes;
}
