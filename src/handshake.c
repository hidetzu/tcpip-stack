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
                               enum handshake_reply what, uint8_t time_to_live,
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
    fields.acknowledgment_number = block->rcv_nxt;
    /* ⚠ Which segment this is, said by the caller.
     *
     * ⚠ Until hidetzu/tcpip-stack#80 it followed from the state, ⚠ **and it
     * could not any more**: one state now produces two shapes — an
     * acknowledgment for data we took, and one for a segment we would not.
     * ⚠ **Inferring it would put the rule in two layers and let them drift**
     * (`CLAUDE.md` §3).
     *
     * ⚠ In LAST-ACK the sequence number of our FIN is the one it occupies —
     * `SND.NXT` was advanced over it when it was first built, so the FIN sits
     * one below. ⚠ RFC 793: "All segments preceding and including FIN will be
     * retransmitted until acknowledged", and ⚠ **a retransmission carrying a
     * different number is a different segment.** */
    switch (what) {
    case HANDSHAKE_REPLY_OUR_FIN:
        fields.sequence_number = block->snd_nxt - 1u;
        fields.control_bits = TCP_CONTROL_FIN | TCP_CONTROL_ACK;
        break;
    case HANDSHAKE_REPLY_THE_DATA_IS_ACKNOWLEDGED:
    case HANDSHAKE_REPLY_WHERE_WE_ARE:
        /* ⚠ RFC 793: "<SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>", for both — ⚠ **the
         * document gives the same form in its seventh step and in its first.**
         * ⚠ `SND.NXT` is not moved: an ACK is "A control bit (acknowledge)
         * occupying no sequence space", so ⚠ **nothing is consumed and there is
         * nothing to retransmit.** */
        fields.sequence_number = block->snd_nxt;
        fields.control_bits = TCP_CONTROL_ACK;
        break;
    case HANDSHAKE_REPLY_THE_ANSWER:
    case HANDSHAKE_REPLY_NONE:
        fields.sequence_number = block->iss;
        fields.control_bits = TCP_CONTROL_SYN | TCP_CONTROL_ACK;
        break;
    }
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
    if (ipv4_build_datagram(id->local.address, id->remote.address, IPV4_PROTOCOL_TCP, time_to_live,
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

/* Where a segment sat, relative to what we are waiting for.
 *
 * ⚠ It exists so that ⚠ **the two ways a segment can be unacceptable are one
 * answer each**, rather than one answer and a sentence saying "either, or"
 * (hidetzu/tcpip-stack#76).
 *
 * ⚠ An enum never reaches a human (`CLAUDE.md` §4). */
enum where_it_sat {
    /* ⚠ At least one octet of it was inside the window, or the FIN sat exactly
     * where we were waiting. */
    IT_WAS_ACCEPTED = 0,

    /* ⚠ All of it is behind `RCV.NXT`. ⚠ We have had it. */
    WE_HAVE_HAD_IT_ALREADY,

    /* ⚠ It begins past `RCV.NXT`. ⚠ There is something before it we have not
     * seen, and ⚠ **nothing here holds a segment to wait for it.** */
    IT_BEGINS_TOO_FAR_AHEAD
};

/* Which of the two a refused sequence number is.
 *
 * ⚠ `RCV.NXT` minus where the segment ends (for data) or sits (for a FIN),
 * unsigned: ⚠ **the lower half of the space means we are past it, the upper half
 * means it is past us.** ⚠ That is the same reading `at_or_before` uses, and it
 * holds where the space wraps for the same reason.
 *
 * ⚠ Zero cannot reach here: a segment ending exactly at `RCV.NXT` with data in
 * it was accepted, and a FIN sitting exactly there was read. */
static enum where_it_sat which_side(uint32_t rcv_nxt, uint32_t theirs)
{
    return (uint32_t)(rcv_nxt - theirs) < 0x80000000u ? WE_HAVE_HAD_IT_ALREADY
                                                     : IT_BEGINS_TOO_FAR_AHEAD;
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
 * twice** — a retransmission of it is then entirely behind us. ⚠ **Nothing is
 * sent from here**; the caller's branch builds the acknowledgment RFC 793 asks
 * for once this has said how much was taken (hidetzu/tcpip-stack#74). */
static enum where_it_sat take_the_data(struct transmission_control_block *block,
                                       const struct tcp_header *header,
                                       struct handshake_outcome *outcome,
                                       struct handshake_counts *counts)
{
    outcome->octets_taken = 0;
    if (header->data_bytes == 0) {
        return IT_WAS_ACCEPTED;
    }

    uint32_t behind_us = block->rcv_nxt - header->sequence_number;
    if (behind_us >= header->data_bytes) {
        /* ⚠ Which of the two it is, judged from where the segment ENDS: ⚠ a
         * segment that begins behind us but reaches past `RCV.NXT` was
         * accepted above, so ⚠ **reaching here means the whole of it is on one
         * side or the other.** */
        return which_side(block->rcv_nxt,
                          header->sequence_number + (uint32_t)header->data_bytes);
    }

    size_t still_to_come = header->data_bytes - behind_us;
    size_t take = still_to_come < HANDSHAKE_WINDOW ? still_to_come : HANDSHAKE_WINDOW;

    block->rcv_nxt += (uint32_t)take;
    /* ⚠ Every move of `RCV.NXT` and the number reported for it are written
     * together, so ⚠ **what a reader is told and what the connection holds
     * cannot drift apart** — the pairing `stayed()` enforces for a reason and
     * its counter. */
    outcome->we_would_acknowledge = block->rcv_nxt;
    outcome->octets_taken = (uint16_t)take;
    counts->octets_taken_and_discarded += (unsigned long)take;
    return IT_WAS_ACCEPTED;
}

/* Read the FIN if the segment carries one the window covers, and ⚠ **move the
 * connection to CLOSE-WAIT.**
 *
 * ⚠ RFC 793, the eighth step of SEGMENT ARRIVES, verbatim: "If the FIN bit is
 * set, signal the user 'connection closing' and return any pending RECEIVEs
 * with same message, advance RCV.NXT over the FIN, and send an acknowledgment
 * for the FIN." ⚠ For SYN-RECEIVED and ESTABLISHED it then says: "Enter the
 * CLOSE-WAIT state."
 *
 * ⚠ **Two of those four things are not done here, and neither is silent.**
 * ⚠ There is no user to signal and no RECEIVE to return (ADR 0022), and
 * ⚠ **nothing is sent** — hidetzu/tcpip-stack#66 owns the acknowledgment, and
 * `docs/SPEC.md` §2 names the gap.
 *
 * ⚠ **`RCV.NXT` advances by exactly one**, because the document's glossary says
 * a FIN is "A control bit (finis) occupying one sequence number", and because
 * ⚠ **the FIN sits after any data**: "the FIN is considered to occur after the
 * last actual data octet in a segment in which it occurs". ⚠ So this runs after
 * `take_the_data`, never before — ⚠ **off by one here is the error that still
 * looks like it works.**
 *
 * ⚠ **The FIN is read only when it sits exactly at `RCV.NXT`** — that is, when
 * everything before it has been taken. ⚠ RFC 793 says to "advance RCV.NXT over
 * the FIN", and ⚠ **you can only advance over it from where it is.**
 *
 * ⚠ **This is stricter than the window test the data uses, and it has to be.**
 * ⚠ A FIN riding more octets than the window covers sits past the octets we
 * trimmed away; ⚠ **reading it would advance `RCV.NXT` over data we never
 * took**, and the acknowledgment that went out would claim octets we discarded
 * without looking at.
 *
 * ⚠ Until hidetzu/tcpip-stack#75 this was written as the document's window test
 * — "RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND" — which ⚠ **is the same thing when
 * the window is 1** and ⚠ **is wrong for any larger window.** ⚠ Raising the
 * window to 1460 is what exposed it, and `a_fin_sits_after_the_data_it_rides_with`
 * is what caught it.
 *
 * ⚠ Equality needs no wrap-safe comparison: ⚠ **two sequence numbers are equal
 * or they are not**, wherever the space happens to be.
 *
 * Returns false when the segment carries no FIN or carries one outside the
 * window; ⚠ **`outcome->the_fin_was_read` says which of those it was not.** */
static enum where_it_sat read_the_fin(struct transmission_control_block *block,
                                      const struct tcp_header *header,
                                      struct moment now,
                                      struct handshake_outcome *outcome,
                                      struct handshake_counts *counts)
{
    if ((header->control_bits & TCP_CONTROL_FIN) == 0) {
        return IT_WAS_ACCEPTED;
    }

    /* ⚠ The FIN's own sequence number is the one after the data it rides with,
     * and `rcv_nxt` has already moved over whatever data was taken. */
    uint32_t where_the_fin_sits = header->sequence_number + (uint32_t)header->data_bytes;
    if (where_the_fin_sits != block->rcv_nxt) {
        return which_side(block->rcv_nxt, where_the_fin_sits);
    }

    block->rcv_nxt = where_the_fin_sits + 1u;
    block->state = CONNECTION_CLOSE_WAIT;
    /* ⚠ And it does not rest there. ⚠ ADR 0022 decided that the arrival of a
     * FIN is the CLOSE the absent user would have made, so ⚠ **the CLOSE
     * happens now**, and RFC 793's CLOSE Call for CLOSE-WAIT is "send a FIN
     * segment, enter LAST-ACK state" — ⚠ `LAST-ACK` and not `CLOSING`, which is
     * RFC 1122 §4.2.2.20 (a) correcting a known error in RFC 793 and RFC 9293
     * §3.10.4 carrying that correction (ADR 0022).
     *
     * ⚠ Our FIN occupies one sequence number, the same rule theirs did.
     * ⚠ Both timers start now: the send is what RFC 793 reinitialises them on,
     * and ⚠ **the ones from the handshake may already have passed.** */
    block->snd_nxt += 1u;
    block->state = CONNECTION_LAST_ACK;
    block->answer_due = moment_after(now, HANDSHAKE_ANSWER_AGAIN_AFTER_MILLISECONDS);
    block->give_up_at = moment_after(now, HANDSHAKE_GIVE_UP_AFTER_MILLISECONDS);
    /* ⚠ Reported and counted from one place, so the two cannot diverge. */
    outcome->we_would_acknowledge = block->rcv_nxt;
    outcome->the_fin_was_read = true;
    counts->the_other_side_closed++;
    return IT_WAS_ACCEPTED;
}

/* Build whatever `block->state` says is due into the caller's buffer, and say
 * which segment it was.
 *
 * ⚠ The kind and the octets are set together, so ⚠ **a caller told it holds our
 * FIN cannot be counting the answer** (the pairing `stayed()` enforces for a
 * reason and its counter). ⚠ On failure the buffer is reported as empty, and
 * ⚠ a caller must not send what was not built. */
static bool build_what_is_due(const struct transmission_control_block *block,
                              enum handshake_reply what, uint8_t time_to_live,
                              const struct connection_id *id,
                              const uint8_t *requester_hardware_address,
                              const uint8_t *our_hardware_address,
                              uint8_t *reply, size_t reply_bytes,
                              struct handshake_outcome *outcome)
{
    outcome->reply_bytes = build_the_answer(block, what, time_to_live, id, requester_hardware_address,
                                            our_hardware_address, reply, reply_bytes);
    if (outcome->reply_bytes == 0) {
        outcome->reply = HANDSHAKE_REPLY_NONE;
        return false;
    }
    outcome->reply = what;
    return true;
}

/* Send the acknowledgment the document describes for a segment that was not
 * acceptable.
 *
 * ⚠ Verbatim, RFC 9293 §3.10.7.4 (and RFC 793's first step of SEGMENT ARRIVES
 * in the same words): "If an incoming segment is not acceptable, an
 * acknowledgment should be sent in reply (unless the RST bit is set, if so drop
 * the segment and return): <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>. After sending
 * the acknowledgment, drop the unacceptable segment and return."
 *
 * ⚠ **"should" there is lowercase, and RFC 9293 §2 says the keywords bind
 * "when, and only when, they appear in all capitals".** ⚠ So this is ⚠ **the
 * document describing behaviour, not requiring it** — ⚠ and calling it
 * something the document "asks for" would collapse `MUST`, `SHOULD` and prose
 * into one thing (`CLAUDE.md` §1).
 *
 * ⚠ **The grounds for doing it are measured, not textual**: with our
 * acknowledgment for data dropped on purpose, the peer's `Send-Q` sticks at 5,
 * and ⚠ **this is what lets it reach 0 once the loss stops**
 * (hidetzu/tcpip-stack#80, `tests/foreign.sh`
 * `a_peer_whose_acknowledgment_was_lost_recovers`).
 *
 * ⚠ **It accepts nothing.** ⚠ The segment was dropped; this says where we are,
 * so ⚠ **a peer whose acknowledgment was lost learns it instead of resending
 * until it gives up** (hidetzu/tcpip-stack#80).
 *
 * ⚠ **The reason and its count are already set by the caller and are not
 * touched here.** ⚠ Failing to build it does not un-refuse the segment: the
 * refusal stands and is reported, and ⚠ **a caller must not send what was not
 * built.**
 *
 * ⚠ Nothing is counted for the send here — ⚠ **a segment that was built is not
 * a segment that left**, and the caller counts what the wire took. */
static void say_where_we_are(const struct transmission_control_block *block,
                             uint8_t time_to_live, const struct connection_id *id,
                             const uint8_t *requester_hardware_address,
                             const uint8_t *our_hardware_address,
                             uint8_t *reply, size_t reply_bytes,
                             struct handshake_outcome *outcome)
{
    (void)build_what_is_due(block, HANDSHAKE_REPLY_WHERE_WE_ARE, time_to_live, id,
                            requester_hardware_address, our_hardware_address,
                            reply, reply_bytes, outcome);
}

/* What the state of a connection that is waiting says should go out again.
 *
 * ⚠ Only these two states wait, and ⚠ **each waits for one thing**, so there is
 * nothing to choose between here (see `the_one_waiting`). */
static enum handshake_reply what_is_owed(const struct transmission_control_block *block)
{
    return block->state == CONNECTION_LAST_ACK ? HANDSHAKE_REPLY_OUR_FIN
                                               : HANDSHAKE_REPLY_THE_ANSWER;
}

void handshake_receive(const struct tcp_header *header, const struct connection_id *id,
                       uint16_t listening_port, struct moment now,
                       uint8_t time_to_live,
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

    /* ⚠ Before anything is looked up or taken. ⚠ RFC 9293 `MUST-57`'s reason is
     * "This prevents connection state and replies from being erroneously
     * created", so ⚠ **this has to come before either could happen.** */
    if (ipv4_address_is_broadcast_or_multicast(id->local.address)) {
        stayed(outcome, HANDSHAKE_REASON_ADDRESSED_TO_EVERYONE,
               &counts->addressed_to_everyone);
        return;
    }

    bool carries_syn = (header->control_bits & TCP_CONTROL_SYN) != 0;
    bool carries_ack = (header->control_bits & TCP_CONTROL_ACK) != 0;

    struct transmission_control_block *held = connections_find(connections, id);

    if (held != NULL) {
        outcome->state = held->state;
        outcome->we_would_acknowledge = held->rcv_nxt;

        /* ⚠ RFC 9293 §3.10.7.4's second step, before the rest. ⚠ A `RST` that
         * the sequence check accepts ends the connection: "Enter the CLOSED
         * state, delete the TCB, and return."
         *
         * ⚠ The acceptability test is the document's first step, for a segment
         * of length 0 against a window above zero:
         * "RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND". ⚠ Written unsigned so it holds
         * where the space wraps, for the reason `at_or_before` gives.
         *
         * ⚠ **A `RST` outside the window is dropped and nothing is sent** — the
         * first step says so in as many words: an acknowledgment is sent for an
         * unacceptable segment ⚠ **"(unless the RST bit is set, if so drop the
         * segment and return)"**. */
        if ((header->control_bits & TCP_CONTROL_RST) != 0) {
            uint32_t past_the_window = held->rcv_nxt + HANDSHAKE_WINDOW;
            bool inside = at_or_before(held->rcv_nxt, header->sequence_number) &&
                          !at_or_before(past_the_window, header->sequence_number);
            if (inside) {
                connections_release(connections, held);
                stayed(outcome, HANDSHAKE_REASON_THE_OTHER_SIDE_RESET_IT,
                       &counts->reset_by_the_other_side);
                outcome->state = CONNECTION_CLOSED;
            } else {
                stayed(outcome, HANDSHAKE_REASON_A_RESET_OUTSIDE_THE_WINDOW,
                       &counts->reset_outside_the_window);
            }
            return;
        }

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
                /* ⚠ RFC 793: "enter ESTABLISHED state and continue processing"
                 * — ⚠ **the same segment goes on to the FIN check.** ⚠ So the
                 * state reported is the one it ended in, which may be
                 * CLOSE-WAIT, and ⚠ **both counters move**: one connection did
                 * reach open, and one side did close (ADR 0022). */
                read_the_fin(held, header, now, outcome, counts);
                moved(outcome, held->state, &counts->established);
                if (held->state == CONNECTION_LAST_ACK &&
                    !build_what_is_due(held, HANDSHAKE_REPLY_OUR_FIN, time_to_live, id,
                                       requester_hardware_address, our_hardware_address,
                                       reply, reply_bytes, outcome)) {
                    held->state = CONNECTION_CLOSE_WAIT;
                    held->snd_nxt -= 1u;
                    outcome->state = CONNECTION_CLOSE_WAIT;
                }
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
        /* ⚠ RFC 793: "if the ACK bit is off drop the segment and return",
         * before the FIN is ever looked at. ⚠ So a bare FIN reaches nothing
         * here, and ⚠ **that is the document's rule and not ours.**
         *
         * ⚠ CLOSE-WAIT is included because the document says a FIN arriving
         * there means "Remain in the CLOSE-WAIT state" — ⚠ but `RCV.NXT` has
         * already moved over the first one, so ⚠ **every retransmission is
         * outside the window and is counted as that.** */
        if ((held->state == CONNECTION_ESTABLISHED ||
             held->state == CONNECTION_CLOSE_WAIT ||
             held->state == CONNECTION_LAST_ACK) &&
            carries_ack && (header->control_bits & TCP_CONTROL_FIN) != 0) {
            take_the_data(held, header, outcome, counts);
            enum where_it_sat the_fin = read_the_fin(held, header, now, outcome, counts);
            if (the_fin == IT_WAS_ACCEPTED) {
                /* ⚠ It moved, and ⚠ **no counter moves here**: `read_the_fin`
                 * has already counted it, the same way `take_the_data` and
                 * `connections_take` count their own. ⚠ `established` must not
                 * move — this connection reached open earlier, and counting it
                 * again would say two did. */
                outcome->decision = HANDSHAKE_MOVED;
                outcome->reason = HANDSHAKE_REASON_NONE;
                outcome->state = held->state;
                if (!build_what_is_due(held, HANDSHAKE_REPLY_OUR_FIN, time_to_live, id,
                                       requester_hardware_address, our_hardware_address,
                                       reply, reply_bytes, outcome)) {
                    /* ⚠ Ours, not the sender's. ⚠ The connection is left in
                     * CLOSE-WAIT rather than claiming to have closed, and
                     * ⚠ **the block is NOT given back**: their FIN was read and
                     * `RCV.NXT` moved, so ⚠ forgetting it would make the next
                     * copy of that FIN look like a new connection. */
                    held->state = CONNECTION_CLOSE_WAIT;
                    held->snd_nxt -= 1u;
                    stayed(outcome, HANDSHAKE_REASON_WE_COULD_NOT_BUILD_THE_REPLY,
                           &counts->we_could_not_build_the_reply);
                    outcome->state = CONNECTION_CLOSE_WAIT;
                }
                return;
            }
            /* ⚠ Two answers, not one with an "either, or" in it
             * (hidetzu/tcpip-stack#76). */
            if (the_fin == WE_HAVE_HAD_IT_ALREADY) {
                stayed(outcome, HANDSHAKE_REASON_A_FIN_WE_HAVE_READ_ALREADY,
                       &counts->fin_we_have_read_already);
            } else {
                stayed(outcome, HANDSHAKE_REASON_A_FIN_THAT_BEGINS_TOO_FAR_AHEAD,
                       &counts->fin_that_begins_too_far_ahead);
            }
            say_where_we_are(held, time_to_live, id, requester_hardware_address, our_hardware_address,
                             reply, reply_bytes, outcome);
            return;
        }

        /* ⚠ RFC 793 for LAST-ACK: "The only thing that can arrive in this state
         * is an acknowledgment of our FIN.  If our FIN is now acknowledged,
         * delete the TCB, enter the CLOSED state, and return."
         *
         * ⚠ `SND.NXT` was advanced over our FIN, so an acknowledgment at or past
         * it is one that covers the FIN. ⚠ Unsigned, for the wrap. */
        if (held->state == CONNECTION_LAST_ACK && carries_ack) {
            outcome->acknowledgment_we_had = header->acknowledgment_number;
            outcome->acknowledgment_we_expected = held->snd_nxt;
            if (at_or_before(held->snd_nxt, header->acknowledgment_number)) {
                connections_release(connections, held);
                moved(outcome, CONNECTION_CLOSED, &counts->closed);
                return;
            }
            stayed(outcome, HANDSHAKE_REASON_ACKNOWLEDGMENT_WE_ARE_NOT_WAITING_FOR,
                   &counts->acknowledgment_we_are_not_waiting_for);
            return;
        }

        if (held->state == CONNECTION_ESTABLISHED && header->data_bytes != 0) {
            enum where_it_sat the_data = take_the_data(held, header, outcome, counts);
            if (the_data == IT_WAS_ACCEPTED) {
                /* ⚠ The one other reason that does not go through `stayed()`,
                 * and for the same cause `NO_ROOM` gives below:
                 * ⚠ **`take_the_data` has already counted it**, in octets.
                 * ⚠ Counting again here would make one octet look like two. */
                outcome->decision = HANDSHAKE_STAYED;
                outcome->reason = HANDSHAKE_REASON_THE_DATA_WAS_TAKEN_AND_DISCARDED;
                /* ⚠ RFC 793: "it must also acknowledge the receipt of the
                 * data." ⚠ Built here and not counted here — ⚠ **a segment that
                 * was built is not a segment that left**, and the caller counts
                 * what the wire took (`CLAUDE.md` §1).
                 *
                 * ⚠ When it will not fit, the octets were still taken and
                 * `RCV.NXT` still moved: ⚠ **giving them back is not possible**,
                 * so the failure is reported as ours and the taking stands. */
                if (!build_what_is_due(held, HANDSHAKE_REPLY_THE_DATA_IS_ACKNOWLEDGED, time_to_live,
                                       id, requester_hardware_address,
                                       our_hardware_address, reply, reply_bytes,
                                       outcome)) {
                    stayed(outcome, HANDSHAKE_REASON_WE_COULD_NOT_BUILD_THE_REPLY,
                           &counts->we_could_not_build_the_reply);
                }
            } else {
                if (the_data == WE_HAVE_HAD_IT_ALREADY) {
                    stayed(outcome, HANDSHAKE_REASON_DATA_WE_HAVE_TAKEN_ALREADY,
                           &counts->data_we_have_taken_already);
                } else {
                    stayed(outcome, HANDSHAKE_REASON_DATA_THAT_BEGINS_TOO_FAR_AHEAD,
                           &counts->data_that_begins_too_far_ahead);
                }
                say_where_we_are(held, time_to_live, id, requester_hardware_address,
                                 our_hardware_address, reply, reply_bytes, outcome);
            }
            return;
        }

        /* ⚠ RFC 9293 asks that a segment carrying `URG` have its pointer
         * processed and the user signalled. ⚠ **There is no user** (ADR 0022),
         * so ⚠ **it is counted and said** rather than passing as ordinary.
         * ⚠ Reached only when nothing else was: ⚠ **a segment carrying `URG`
         * AND data is acted on for its data**, above. */
        if ((header->control_bits & TCP_CONTROL_URG) != 0) {
            stayed(outcome, HANDSHAKE_REASON_URGENT_AND_NOBODY_TO_TELL,
                   &counts->urgent_and_nobody_to_tell);
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
    if ((header->control_bits & TCP_CONTROL_FIN) != 0) {
        /* ⚠ RFC 793: "Do not process the FIN if the state is CLOSED, LISTEN or
         * SYN-SENT since the SEG.SEQ cannot be validated". ⚠ Holding nothing is
         * our LISTEN, and ⚠ **the document gives this its own reason** — so it
         * is counted as its own and not as any other stray segment. */
        stayed(outcome, HANDSHAKE_REASON_A_FIN_WE_CANNOT_PLACE,
               &counts->fin_we_could_not_place);
        return;
    }

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
    outcome->we_would_acknowledge = taken->rcv_nxt;
    /* ⚠ RFC 793: the retransmission timer is reinitialised on each send, so it
     * starts here and not when the connection was found. ⚠ The give-up moment
     * is from now and is never moved again. */
    memcpy(taken->requester_hardware_address, requester_hardware_address,
           CONNECTION_HARDWARE_ADDRESS_BYTES);
    taken->answer_due = moment_after(now, HANDSHAKE_ANSWER_AGAIN_AFTER_MILLISECONDS);
    taken->give_up_at = moment_after(now, HANDSHAKE_GIVE_UP_AFTER_MILLISECONDS);

    if (!build_what_is_due(taken, HANDSHAKE_REPLY_THE_ANSWER, time_to_live, id,
                           requester_hardware_address, our_hardware_address,
                           reply, reply_bytes, outcome)) {
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
 * ⚠ Two states wait, and ⚠ **for two different things**: `SYN-RECEIVED` for a
 * connection to be confirmed, and `LAST-ACK` for our own FIN to be acknowledged.
 * ⚠ RFC 793: "All segments preceding and including FIN will be retransmitted
 * until acknowledged."
 *
 * ⚠ A connection that reached `ESTABLISHED` is waiting for nothing, ⚠ **and one
 * left in `CLOSE-WAIT` is waiting for nothing either** — nothing rests there,
 * and a connection only stays when the answer could not be built, which
 * `build_what_is_due` has already counted as ours. ⚠ One that is not in use is
 * not a connection. */
static struct transmission_control_block *the_one_waiting(struct connections *connections)
{
    for (size_t i = 0; i < CONNECTIONS_AT_ONCE; i++) {
        struct transmission_control_block *block = &connections->block[i];
        if (block->in_use && (block->state == CONNECTION_SYN_RECEIVED ||
                              block->state == CONNECTION_LAST_ACK)) {
            return block;
        }
    }
    return NULL;
}

enum handshake_due handshake_what_is_due(struct connections *connections,
                                         struct moment now, uint8_t time_to_live,
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
        /* ⚠ Two different events, counted and said apart: ⚠ **a connection that
         * never opened, and one that would not finish closing.** ⚠ Folding them
         * into one reason is the defect hidetzu/tcpip-stack#59 had to undo. */
        bool was_closing = waiting->state == CONNECTION_LAST_ACK;
        connections_release(connections, waiting);
        outcome->decision = HANDSHAKE_STAYED;
        outcome->reason = was_closing ? HANDSHAKE_REASON_NOBODY_ACKNOWLEDGED_OUR_FIN
                                      : HANDSHAKE_REASON_NOBODY_CONFIRMED_IT;
        outcome->state = CONNECTION_LISTEN;
        if (was_closing) {
            counts->never_acknowledged_our_fin++;
        } else {
            counts->given_up_on++;
        }
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
        if (!build_what_is_due(waiting, what_is_owed(waiting), time_to_live, &waiting->id,
                               waiting->requester_hardware_address,
                               our_hardware_address, reply, reply_bytes, outcome)) {
            /* ⚠ Ours, not the sender's. ⚠ The attempt is spent either way — the
             * timer has already moved — and ⚠ the give-up timer still runs. */
            outcome->decision = HANDSHAKE_STAYED;
            outcome->reason = HANDSHAKE_REASON_WE_COULD_NOT_BUILD_THE_REPLY;
            counts->we_could_not_build_the_reply++;
            return HANDSHAKE_NOTHING_DUE;
        }

        outcome->decision = HANDSHAKE_STAYED;
        /* ⚠ Its own reason. ⚠ Until hidetzu/tcpip-stack#59 this said the sender
         * had asked again, ⚠ **which was false: our timer fired.** ⚠ And our
         * FIN going out again is not the answer going out again — ⚠ **two
         * sends, two names** (hidetzu/tcpip-stack#66). */
        outcome->reason = outcome->reply == HANDSHAKE_REPLY_OUR_FIN
                              ? HANDSHAKE_REASON_OUR_FIN_WENT_OUT_AGAIN
                              : HANDSHAKE_REASON_THE_ANSWER_WENT_OUT_AGAIN;
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
