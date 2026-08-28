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

/* ⚠ The window goes into a sixteen-bit field and into `outcome->octets_taken`,
 * which is sixteen bits too. ⚠ A larger promise would be truncated on the way
 * out, and ⚠ **the number a peer read would not be the number we chose.** */
_Static_assert(HANDSHAKE_WINDOW <= 0xffffu,
               "the window must fit the field RFC 793 gives it");

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
    /* ⚠ A promise of exactly this many octets, and ⚠ `take_the_data` is what
     * backs it (hidetzu/tcpip-stack#64 Owner Decision 1). */
    fields.window = HANDSHAKE_WINDOW;

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

/* Take delivery of as much of the segment's data as the window promised, and
 * ⚠ **discard it** (hidetzu/tcpip-stack#64 Owner Decision 2). ⚠ How many were
 * taken goes into `outcome->octets_taken`, and is 0 when none were.
 *
 * ⚠ RFC 793's sequence number check, quoted: "Segments are processed in
 * sequence ... segments with higher beginning sequence numbers may be held for
 * later processing." ⚠ **Nothing here holds anything**, so a segment beginning
 * beyond `RCV.NXT` is refused rather than kept, and `docs/SPEC.md` §2 names it.
 *
 * ⚠ The document also says of a partly-acceptable segment: "if the segment
 * contains data that begins outside the window, that data is trimmed." ⚠ That is
 * what the arithmetic below does — ⚠ **it takes the octets from `RCV.NXT`
 * onward, not the octets the segment starts with.**
 *
 * ⚠ Every comparison is unsigned subtraction on a space that wraps at 2^32, for
 * the reason `at_or_before` above gives. ⚠ `behind_us >= header->data_bytes`
 * catches both a segment entirely already taken and one entirely in the future:
 * ⚠ **for the future one the subtraction wraps to something enormous**, which is
 * the comparison working, not it failing.
 *
 * ⚠ `RCV.NXT` advances by what was taken, so ⚠ **the same octet is never taken
 * twice** — a retransmission of it is then entirely behind us. ⚠ Nothing tells
 * the sender: sending is not this layer's, and ⚠ **the window is a promise kept
 * in taking and not yet in telling** (`docs/SPEC.md` §2, closed by
 * hidetzu/tcpip-stack#66). */
static void take_the_data(struct transmission_control_block *block,
                          const struct tcp_header *header,
                          struct handshake_outcome *outcome,
                          struct handshake_counts *counts)
{
    outcome->octets_taken = 0;
    if (header->data_bytes == 0) {
        return;
    }

    uint32_t behind_us = block->rcv_nxt - header->sequence_number;
    if (behind_us >= header->data_bytes) {
        return;
    }

    size_t still_to_come = header->data_bytes - behind_us;
    size_t take = still_to_come < HANDSHAKE_WINDOW ? still_to_come : HANDSHAKE_WINDOW;

    block->rcv_nxt += (uint32_t)take;
    /* ⚠ The number reported and the number counted are set from one place, so
     * they cannot diverge — the same pairing `stayed()` enforces for a reason
     * and its counter. */
    outcome->octets_taken = (uint16_t)take;
    counts->octets_taken_and_discarded += (unsigned long)take;
}

void handshake_receive(const struct tcp_header *header, const struct connection_id *id,
                       uint16_t listening_port, struct moment now,
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
                /* ⚠ The acknowledgment that opens a connection may carry data —
                 * ⚠ **the window we advertised is what invites it.** ⚠ Taken
                 * before the transition is reported, because ⚠ a payload nobody
                 * counted is indistinguishable from one that never arrived
                 * (`.claude/rules/c.md`). ⚠ The reason stays the transition:
                 * ⚠ `counts` still gains exactly one reason per segment, and the
                 * octets are their own number. */
                take_the_data(held, header, outcome, counts);
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

        /* ⚠ Data on an open connection is not a segment the state did not
         * expect — ⚠ **it is exactly what advertising a window invites**, and
         * the two are counted apart. ⚠ A segment carrying no data still falls
         * through to the line below, which is what keeps a FIN outside this
         * change (hidetzu/tcpip-stack#65 reads one).
         *
         * ⚠ A segment carrying BOTH data and a FIN is reported for its data and
         * ⚠ **says nothing about the FIN.** ⚠ That is not new — before this it
         * said nothing about either — and ⚠ **it is named rather than left to be
         * found**: hidetzu/tcpip-stack#65 is what reads the bit. */
        if (held->state == CONNECTION_ESTABLISHED && header->data_bytes != 0) {
            take_the_data(held, header, outcome, counts);
            if (outcome->octets_taken != 0) {
                /* ⚠ The one other reason that does not go through `stayed()`,
                 * and for the same cause `NO_ROOM` gives below:
                 * ⚠ **`take_the_data` has already counted it**, in octets.
                 * ⚠ Counting again here would make one octet look like two. */
                outcome->decision = HANDSHAKE_STAYED;
                outcome->reason = HANDSHAKE_REASON_THE_DATA_WAS_TAKEN_AND_DISCARDED;
            } else {
                stayed(outcome, HANDSHAKE_REASON_DATA_OUTSIDE_THE_WINDOW,
                       &counts->data_outside_the_window);
            }
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
    /* ⚠ RFC 793: the retransmission timer is reinitialised on each send, so it
     * starts here and not when the connection was found. ⚠ The give-up moment
     * is from now and is never moved again. */
    memcpy(taken->requester_hardware_address, requester_hardware_address,
           CONNECTION_HARDWARE_ADDRESS_BYTES);
    taken->answer_due = moment_after(now, HANDSHAKE_ANSWER_AGAIN_AFTER_MILLISECONDS);
    taken->give_up_at = moment_after(now, HANDSHAKE_GIVE_UP_AFTER_MILLISECONDS);

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

/* The one connection that is waiting for something, or NULL.
 *
 * ⚠ Only `SYN-RECEIVED` waits: a connection that reached `ESTABLISHED` is
 * waiting for nothing, and one that is not in use is not a connection. */
static struct transmission_control_block *the_one_waiting(struct connections *connections)
{
    for (size_t i = 0; i < CONNECTIONS_AT_ONCE; i++) {
        struct transmission_control_block *block = &connections->block[i];
        if (block->in_use && block->state == CONNECTION_SYN_RECEIVED) {
            return block;
        }
    }
    return NULL;
}

enum handshake_due handshake_what_is_due(struct connections *connections,
                                         struct moment now,
                                         const uint8_t *our_hardware_address,
                                         uint8_t *reply, size_t reply_bytes,
                                         struct handshake_counts *counts,
                                         struct handshake_outcome *outcome)
{
    memset(outcome, 0, sizeof *outcome);
    outcome->state = CONNECTION_LISTEN;

    struct transmission_control_block *waiting = the_one_waiting(connections);
    if (waiting == NULL) {
        outcome->decision = HANDSHAKE_STAYED;
        outcome->reason = HANDSHAKE_REASON_NONE;
        return HANDSHAKE_NOTHING_DUE;
    }

    outcome->id = waiting->id;
    outcome->state = waiting->state;

    /* ⚠ Giving up is decided first, so ⚠ **at the moment both are due the
     * connection is given up on rather than answered a third time.** ⚠ The other
     * order would send an answer nobody is waiting for any more. */
    if (moment_is_at_or_after(now, waiting->give_up_at)) {
        /* ⚠ RFC 793's USER TIMEOUT: "delete the TCB, enter the CLOSED state and
         * return." ⚠ Released, so the next SYN can open one — there is room for
         * exactly one (ADR 0015). */
        connections_release(connections, waiting);
        outcome->decision = HANDSHAKE_STAYED;
        outcome->reason = HANDSHAKE_REASON_NOBODY_CONFIRMED_IT;
        outcome->state = CONNECTION_LISTEN;
        counts->given_up_on++;
        return HANDSHAKE_GIVE_UP;
    }

    if (moment_is_at_or_after(now, waiting->answer_due)) {
        /* ⚠ "send the segment at the front of the retransmission queue again,
         * reinitialize the retransmission timer" — ⚠ one step, so the timer moves
         * here. ⚠ From `now` and not from the moment it was due, so ⚠ a caller
         * that woke late does not immediately owe another. */
        waiting->answer_due =
            moment_after(now, HANDSHAKE_ANSWER_AGAIN_AFTER_MILLISECONDS);

        /* ⚠ Addressed from what the connection remembers: ⚠ **there is no
         * arriving frame to read it from** (hidetzu/tcpip-stack#59). */
        outcome->reply_bytes =
            build_the_answer(waiting, &waiting->id, waiting->requester_hardware_address,
                             our_hardware_address, reply, reply_bytes);
        if (outcome->reply_bytes == 0) {
            /* ⚠ Ours, not the sender's. ⚠ The attempt is spent either way — the
             * timer has already moved — and ⚠ the give-up timer still runs. */
            outcome->decision = HANDSHAKE_STAYED;
            outcome->reason = HANDSHAKE_REASON_WE_COULD_NOT_BUILD_THE_REPLY;
            counts->we_could_not_build_the_reply++;
            return HANDSHAKE_NOTHING_DUE;
        }

        outcome->decision = HANDSHAKE_STAYED;
        /* ⚠ Its own reason. ⚠ Until hidetzu/tcpip-stack#59 this said the sender
         * had asked again, ⚠ **which was false: our timer fired.** */
        outcome->reason = HANDSHAKE_REASON_THE_ANSWER_WENT_OUT_AGAIN;
        return HANDSHAKE_ANSWER_AGAIN;
    }

    outcome->decision = HANDSHAKE_STAYED;
    outcome->reason = HANDSHAKE_REASON_NONE;
    return HANDSHAKE_NOTHING_DUE;
}

bool handshake_next_moment(const struct connections *connections, struct moment *due)
{
    for (size_t i = 0; i < CONNECTIONS_AT_ONCE; i++) {
        const struct transmission_control_block *block = &connections->block[i];
        if (!block->in_use || block->state != CONNECTION_SYN_RECEIVED) {
            continue;
        }
        /* ⚠ The earlier of the two, ⚠ compared the way moments must be so it
         * works across the wrap (`src/moment.h`). */
        *due = moment_is_at_or_after(block->give_up_at, block->answer_due)
                   ? block->answer_due
                   : block->give_up_at;
        return true;
    }
    return false;
}
