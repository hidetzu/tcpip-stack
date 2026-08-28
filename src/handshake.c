#include "handshake.h"

#include <string.h>

/* ⚠ Two files name the same protocol number, because ⚠ `src/tcp.c` deliberately
 * includes nothing from the layer below it and ⚠ `src/ipv4.c` deliberately
 * knows nothing about what it carries. ⚠ This is the mechanical cross-check
 * that stops them diverging (`CLAUDE.md` §3, the same shape `src/tap.c` uses for
 * `IFNAMSIZ`).
 *
 * ⚠ They must be the same number or every checksum we compute is over a
 * pseudo-header that does not match the datagram it rides in — ⚠ and the only
 * thing that would come back is "it does not agree". */
_Static_assert(TCP_PROTOCOL_NUMBER == IPV4_PROTOCOL_TCP,
               "the pseudo-header's Protocol must be the one the internet header carries");

/* ⚠ `a` is at or before `b` on a sequence space that wraps at 2^32.
 *
 * ⚠ Written with unsigned arithmetic on purpose. ⚠ The usual
 * `(int32_t)(a - b) <= 0` is signed overflow, which is undefined behaviour and
 * so is not a comparison at all (`.claude/rules/c.md`: a program with undefined
 * behaviour has no defined output to be right about). ⚠ Unsigned subtraction is
 * defined to wrap, and the difference landing in the lower half of the space is
 * what "at or before" means.
 *
 * ⚠ A plain `a <= b` is the defect this exists to avoid: it is correct for
 * years and then wrong once, at the wrap. */
static bool at_or_before(uint32_t a, uint32_t b)
{
    return (uint32_t)(b - a) < 0x80000000u;
}

static void stayed(struct handshake_outcome *outcome, enum handshake_reason reason,
                   unsigned long *count)
{
    outcome->decision = HANDSHAKE_STAYED;
    outcome->reason = reason;
    /* ⚠ The reason and the counter it moves are passed together, so a reason
     * cannot be reported under one name and counted under another. */
    (*count)++;
}

static void moved(struct handshake_outcome *outcome, enum connection_state state,
                  unsigned long *count)
{
    outcome->decision = HANDSHAKE_MOVED;
    outcome->reason = HANDSHAKE_REASON_NONE;
    outcome->state = state;
    (*count)++;
}

/* Build the answer RFC 793 describes, into the caller's frame buffer.
 *
 *   "ISS should be selected and a SYN segment sent of the form:
 *      <SEQ=ISS><ACK=RCV.NXT><CTL=SYN,ACK>"
 *
 * ⚠ Built from the inside out, so each layer's payload is already in place.
 * Returns 0 when it would not fit. */
static size_t build_the_answer(const struct transmission_control_block *block,
                               const struct connection_id *id,
                               const uint8_t *requester_hardware_address,
                               const uint8_t *our_hardware_address,
                               uint8_t *reply, size_t reply_bytes)
{
    if (reply_bytes < ETHERNET_HEADER_BYTES + IPV4_FIXED_HEADER_BYTES) {
        return 0;
    }

    struct tcp_header fields;
    memset(&fields, 0, sizeof fields);
    fields.source_port = id->local.port;
    fields.destination_port = id->remote.port;
    fields.sequence_number = block->iss;
    fields.acknowledgment_number = block->rcv_nxt;
    fields.control_bits = TCP_CONTROL_SYN | TCP_CONTROL_ACK;
    /* ⚠ Zero, and it is the truth: nothing here accepts a single octet of data
     * (hidetzu/tcpip-stack#44 Owner Decision 3). */
    fields.window = 0;

    uint8_t *segment = reply + ETHERNET_HEADER_BYTES + IPV4_FIXED_HEADER_BYTES;
    size_t segment_bytes = 0;
    if (tcp_build_segment(&fields, id->local.address, id->remote.address, segment,
                          reply_bytes - ETHERNET_HEADER_BYTES - IPV4_FIXED_HEADER_BYTES,
                          &segment_bytes) != TCP_BUILD_OK) {
        return 0;
    }

    size_t datagram_bytes = 0;
    if (ipv4_build_datagram(id->local.address, id->remote.address, IPV4_PROTOCOL_TCP,
                            segment, segment_bytes, reply + ETHERNET_HEADER_BYTES,
                            reply_bytes - ETHERNET_HEADER_BYTES,
                            &datagram_bytes) != IPV4_BUILD_OK) {
        return 0;
    }

    if (!ethernet_build_header(requester_hardware_address, our_hardware_address,
                               IPV4_ETHERNET_LENGTH_TYPE, reply, reply_bytes)) {
        return 0;
    }
    return ETHERNET_HEADER_BYTES + datagram_bytes;
}

void handshake_receive(const struct tcp_header *header, const struct connection_id *id,
                       uint16_t listening_port,
                       const uint8_t *requester_hardware_address,
                       const uint8_t *our_hardware_address,
                       struct connections *connections,
                       uint8_t *reply, size_t reply_bytes,
                       struct handshake_counts *counts,
                       struct handshake_outcome *outcome)
{
    memset(outcome, 0, sizeof *outcome);
    outcome->id = *id;
    outcome->state = CONNECTION_LISTEN;

    bool carries_syn = (header->control_bits & TCP_CONTROL_SYN) != 0;
    bool carries_ack = (header->control_bits & TCP_CONTROL_ACK) != 0;

    struct transmission_control_block *held = connections_find(connections, id);

    if (held != NULL) {
        outcome->state = held->state;

        /* ⚠ RFC 793, on a SYN reaching a connection past LISTEN: "If the SYN is
         * in the window it is an error, send a reset ... If the SYN is not in
         * the window this step would not be reached and an ack would have been
         * sent in the first step (sequence number check)."
         *
         * ⚠ Our reading, and it is recorded as ours: ⚠ **a retransmitted SYN
         * carries the sequence number their first one did**, which is `irs` —
         * ⚠ **below `rcv_nxt`, so it is not in the window**, so it is not the
         * error that step describes. ⚠ Nothing moves and ⚠ **nothing is
         * re-chosen**: a peer that did get our first answer must not be told a
         * different number (ADR 0016). */
        if (carries_syn && !carries_ack && header->sequence_number == held->irs) {
            stayed(outcome, HANDSHAKE_REASON_ASKED_AGAIN, &counts->asked_again);
            return;
        }

        if (held->state == CONNECTION_SYN_RECEIVED && carries_ack) {
            outcome->acknowledgment_we_had = header->acknowledgment_number;
            outcome->acknowledgment_we_expected = held->snd_nxt;

            /* ⚠ RFC 793, verbatim: "If SND.UNA =< SEG.ACK =< SND.NXT then enter
             * ESTABLISHED state and continue processing."
             *
             * ⚠ It is a window and not one number. ⚠ `SND.UNA` is the `iss` we
             * chose and `SND.NXT` is `iss + 1`, so ⚠ **both are acceptable** —
             * writing `== iss + 1` would be stricter than the document and
             * would reject something it accepts. */
            if (at_or_before(held->snd_una, header->acknowledgment_number) &&
                at_or_before(header->acknowledgment_number, held->snd_nxt)) {
                held->state = CONNECTION_ESTABLISHED;
                moved(outcome, CONNECTION_ESTABLISHED, &counts->established);
                return;
            }

            /* ⚠ "If the segment acknowledgment is not acceptable, form a reset
             * segment". ⚠ Nothing is sent here, and `docs/SPEC.md` §2 names that
             * gap rather than leaving it silent. */
            stayed(outcome, HANDSHAKE_REASON_ACKNOWLEDGMENT_WE_ARE_NOT_WAITING_FOR,
                   &counts->acknowledgment_we_are_not_waiting_for);
            return;
        }

        stayed(outcome, HANDSHAKE_REASON_NOT_EXPECTED_IN_THIS_STATE,
               &counts->not_expected_in_this_state);
        return;
    }

    /* Nothing is held for this connection.
     *
     * ⚠ RFC 793 for the LISTEN state: "Any acknowledgment is bad if it arrives
     * on a connection still in the LISTEN state. An acceptable reset segment
     * should be formed for any arriving ACK-bearing segment."
     *
     * ⚠ So a bare SYN is the only thing that opens one. ⚠ Nothing is sent for
     * the rest, and that gap is named in `docs/SPEC.md` §2. */
    if (!carries_syn || carries_ack || id->local.port != listening_port) {
        stayed(outcome, HANDSHAKE_REASON_NO_CONNECTION_HELD, &counts->no_connection_held);
        return;
    }

    struct transmission_control_block *taken = NULL;
    if (connections_take(connections, id, &counts->room, &taken) != CONNECTION_TAKEN) {
        /* ⚠ The one reason that does not go through `stayed()`, and it is not a
         * style choice: ⚠ **`connections_take` has already counted it**
         * (hidetzu/tcpip-stack#42). ⚠ Counting it again here would make one
         * refusal look like two — ⚠ which is the same defect as not counting it
         * at all, in the other direction, and ⚠ a number nobody can trust is
         * worse than no number (`CLAUDE.md` §6).
         *
         * ⚠ Found by `each_reason_moves_only_its_own_count`, which read 2. */
        outcome->decision = HANDSHAKE_STAYED;
        outcome->reason = HANDSHAKE_REASON_NO_ROOM;
        return;
    }

    /* ⚠ RFC 793, verbatim: "Set RCV.NXT to SEG.SEQ+1, IRS is set to SEG.SEQ ...
     * ISS should be selected and a SYN segment sent of the form:
     * <SEQ=ISS><ACK=RCV.NXT><CTL=SYN,ACK>. SND.NXT is set to ISS+1 and SND.UNA
     * to ISS. The connection state should be changed to SYN-RECEIVED."
     *
     * ⚠ Every number below is one of those. ⚠ The segment the document says to
     * send is hidetzu/tcpip-stack#44's; this decides what would go in it. */
    taken->irs = header->sequence_number;
    taken->rcv_nxt = header->sequence_number + 1u;
    taken->iss = HANDSHAKE_INITIAL_SEND_SEQUENCE;
    taken->snd_una = taken->iss;
    taken->snd_nxt = taken->iss + 1u;
    taken->state = CONNECTION_SYN_RECEIVED;

    outcome->reply_bytes = build_the_answer(taken, id, requester_hardware_address,
                                            our_hardware_address, reply, reply_bytes);
    if (outcome->reply_bytes == 0) {
        /* ⚠ The connection was opened and we cannot answer it. ⚠ Ours, not the
         * sender's, and ⚠ the block is given back so the next SYN is not refused
         * for want of room by a connection nothing will ever answer. */
        connections_release(connections, taken);
        stayed(outcome, HANDSHAKE_REASON_WE_COULD_NOT_BUILD_THE_REPLY,
               &counts->we_could_not_build_the_reply);
        outcome->state = CONNECTION_LISTEN;
        return;
    }

    moved(outcome, CONNECTION_SYN_RECEIVED, &counts->opened);
}
