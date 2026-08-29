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
 * out, and ⚠ **the number a peer read would not be the number we chose.**
 *
 * ⚠ Until hidetzu/tcpip-stack#119 a `_Static_assert` held this, ⚠ **and it could,
 * because the window was a constant.** ⚠ **It is a device's answer now**, so the
 * same job is done where the answer arrives — `handshake_window_for_mtu`. */
enum handshake_window handshake_window_for_mtu(unsigned int mtu, uint16_t *window)
{
    if (mtu <= HANDSHAKE_HEADERS_BEFORE_DATA) {
        return HANDSHAKE_WINDOW_THE_MTU_LEAVES_NOTHING;
    }
    unsigned int room = mtu - HANDSHAKE_HEADERS_BEFORE_DATA;
    if (room > 0xffffu) {
        return HANDSHAKE_WINDOW_WOULD_NOT_FIT_THE_FIELD;
    }
    *window = (uint16_t)room;
    return HANDSHAKE_WINDOW_OK;
}

/* ⚠ The same arithmetic as the window, and ⚠ **written once**: two functions
 * performing it separately would be two copies of one decision, and they would
 * diverge the first time either moved (`CLAUDE.md` §3). */
enum handshake_window handshake_maximum_segment_size_for_mtu(unsigned int mtu,
                                                             uint16_t *mss)
{
    return handshake_window_for_mtu(mtu, mss);
}

enum handshake_window handshake_effective_send_mss(uint16_t send_mss,
                                                   unsigned int mtu,
                                                   uint16_t *effective)
{
    uint16_t ours = 0;
    enum handshake_window what = handshake_window_for_mtu(mtu, &ours);
    if (what != HANDSHAKE_WINDOW_OK) {
        return what;
    }
    /* ⚠ RFC 9293 §3.7.1: "MUST be the smaller (MUST-16) of the send MSS ... and
     * the largest transmission size permitted by the sender". ⚠ **The smaller,
     * and nothing else** — no floor and no rounding of ours. */
    *effective = send_mss < ours ? send_mss : ours;
    return HANDSHAKE_WINDOW_OK;
}

/* ⚠ Chosen so that ⚠ **no two octets within 251 of each other are the same**:
 * a segment boundary put in the wrong place shows up as a break in the run, not
 * as a coincidence. ⚠ 251 is prime, so the pattern does not line up with any
 * power-of-two segment size. */
uint8_t handshake_octet_at(uint32_t offset)
{
    return (uint8_t)(offset % 251u);
}

/* ⚠ RFC 6298 §2.2 and §2.3 end the same way: "RTO <- SRTT + max (G, K*RTTVAR)",
 * ⚠ **then §2.4's floor and §2.5's ceiling, in that order.** ⚠ Written once so
 * the two callers cannot disagree (`CLAUDE.md` §3). */
static void set_the_timeout(struct handshake_round_trip *estimate)
{
    uint64_t variance = (uint64_t)HANDSHAKE_RTO_K * estimate->variation_nanoseconds;
    if (variance < HANDSHAKE_CLOCK_GRANULARITY_NANOSECONDS) {
        /* ⚠ §4: "if the K*RTTVAR term in the RTO calculation equals zero, the
         * variance term MUST be rounded to G seconds". ⚠ The `max(G, ...)` in
         * §2.2 and §2.3 says the same thing for every value below G. */
        variance = HANDSHAKE_CLOCK_GRANULARITY_NANOSECONDS;
    }
    uint64_t timeout = estimate->smoothed_nanoseconds + variance;

    if (timeout < HANDSHAKE_RTO_LEAST_NANOSECONDS) {
        timeout = HANDSHAKE_RTO_LEAST_NANOSECONDS;
    }
    if (timeout > HANDSHAKE_RTO_MOST_NANOSECONDS) {
        timeout = HANDSHAKE_RTO_MOST_NANOSECONDS;
    }
    estimate->timeout_nanoseconds = timeout;
}

void handshake_round_trip_begin(struct handshake_round_trip *estimate)
{
    estimate->have_a_sample = false;
    estimate->smoothed_nanoseconds = 0;
    estimate->variation_nanoseconds = 0;
    /* ⚠ §2.1, and ⚠ **not through `set_the_timeout`**: the document gives this
     * value directly and ⚠ **computing it from two zeroes would reach it by
     * accident of the floor rather than by the sentence that gives it.** */
    estimate->timeout_nanoseconds = HANDSHAKE_RTO_BEFORE_ANY_SAMPLE_NANOSECONDS;
}

void handshake_round_trip_sample(struct handshake_round_trip *estimate,
                                 uint64_t r_nanoseconds)
{
    if (!estimate->have_a_sample) {
        /* ⚠ §2.2: "SRTT <- R, RTTVAR <- R/2". */
        estimate->smoothed_nanoseconds = r_nanoseconds;
        estimate->variation_nanoseconds = r_nanoseconds / 2u;
        estimate->have_a_sample = true;
        set_the_timeout(estimate);
        return;
    }

    /* ⚠ §2.3: "RTTVAR <- (1 - beta) * RTTVAR + beta * |SRTT - R'|" and
     * "SRTT <- (1 - alpha) * SRTT + alpha * R'".
     *
     * ⚠ **"The value of SRTT used in the update to RTTVAR is its value BEFORE
     * updating SRTT itself ... updating RTTVAR and SRTT MUST be computed in the
     * above order."** ⚠ A `MUST` about an order, ⚠ **and both orders produce a
     * number** — which is why a check asserts it. */
    uint64_t smoothed = estimate->smoothed_nanoseconds;
    uint64_t difference = smoothed > r_nanoseconds ? smoothed - r_nanoseconds
                                                   : r_nanoseconds - smoothed;
    estimate->variation_nanoseconds =
        estimate->variation_nanoseconds -
        (estimate->variation_nanoseconds >> HANDSHAKE_RTO_BETA_SHIFT) +
        (difference >> HANDSHAKE_RTO_BETA_SHIFT);
    estimate->smoothed_nanoseconds =
        smoothed - (smoothed >> HANDSHAKE_RTO_ALPHA_SHIFT) +
        (r_nanoseconds >> HANDSHAKE_RTO_ALPHA_SHIFT);
    set_the_timeout(estimate);
}

/* ⚠ RFC 6298 §5.5: "The host MUST set RTO <- RTO * 2 (\"back off the timer\").
 * The maximum value discussed in (2.5) above may be used to provide an upper
 * bound to this doubling operation."
 *
 * ⚠ **The backed-off value stands until a clean sample replaces it.** ⚠ RFC 9293
 * §3.8.2: backoff includes "keeping the backed-off value until a subsequent
 * segment with new data has been sent and acknowledged without retransmission."
 * ⚠ **Karn\'s algorithm is what makes that true here**: a sample covering
 * anything sent twice is refused, ⚠ **so nothing recomputes the RTO until one
 * clean round trip is measured** — and RFC 6298 §5 says that is the moment it
 * may "collapse" back down. */
static void back_off(struct transmission_control_block *block)
{
    uint64_t doubled = block->round_trip.timeout_nanoseconds * 2u;
    if (doubled > HANDSHAKE_RTO_MOST_NANOSECONDS ||
        doubled < block->round_trip.timeout_nanoseconds) {
        doubled = HANDSHAKE_RTO_MOST_NANOSECONDS;
    }
    block->round_trip.timeout_nanoseconds = doubled;
}

/* ⚠ RFC 9293 §3.8.3 (b): "When the number of transmissions of the same segment
 * reaches or exceeds threshold R1, pass negative advice ... to the IP layer, to
 * trigger dead-gateway diagnosis."
 *
 * ⚠ **There is no IP layer here to advise** — nothing routes and there is no
 * gateway to diagnose (`docs/SPEC.md` §2). ⚠ **So the threshold is crossed and
 * SAID, and `MUST-20` (b) stays not met**: ⚠ **a line on a terminal is not
 * negative advice to a routing layer**, and calling it one would be the shape
 * `CLAUDE.md` §1 forbids.
 *
 * ⚠ **Said once**, because R1 is a threshold crossed once. */
static bool crossed_r1(struct transmission_control_block *block)
{
    if (block->retransmissions < HANDSHAKE_R1_RETRANSMISSIONS ||
        block->told_them_about_r1) {
        return false;
    }
    block->told_them_about_r1 = true;
    return true;
}

uint32_t handshake_initial_congestion_window(uint16_t smss)
{
    unsigned int segments = 4u;
    if (smss > HANDSHAKE_IW_SMSS_LARGE) {
        segments = 2u;
    } else if (smss > HANDSHAKE_IW_SMSS_MEDIUM) {
        segments = 3u;
    }
    return (uint32_t)segments * (uint32_t)smss;
}

/* ⚠ RFC 5681 §3.1, on an acknowledgment covering new data.
 *
 * ⚠ "The slow start algorithm is used when cwnd < ssthresh, while the congestion
 * avoidance algorithm is used when cwnd > ssthresh. When cwnd and ssthresh are
 * equal, the sender may use either." ⚠ **Equal is congestion avoidance here, and
 * the document allows either** — ⚠ said rather than left to be read off the
 * comparison.
 *
 * ⚠ Slow start uses equation (2), `cwnd += min (N, SMSS)`, which the document
 * ⚠ **RECOMMENDs** and which satisfies the `MUST` above it ("increments cwnd by
 * at most SMSS bytes for each ACK").
 *
 * ⚠ Congestion avoidance uses equation (3), `cwnd += SMSS*SMSS/cwnd`, which the
 * document says ⚠ **a TCP MAY use.** ⚠ **It cannot truncate to zero in this
 * stack\'s range**: `cwnd` is bounded by `rwnd`, sixteen bits, and the smallest
 * `SMSS` a tap can give is 28 — ⚠ 28*28/65535 IS zero, ⚠ **so the guard below is
 * not decoration.** */
static void grew_by(struct transmission_control_block *block, uint32_t acknowledged,
                    uint16_t smss)
{
    if (block->cwnd < block->ssthresh) {
        uint32_t by = acknowledged < smss ? acknowledged : smss;
        block->cwnd += by;
        return;
    }
    uint32_t by = ((uint32_t)smss * (uint32_t)smss) / block->cwnd;
    /* ⚠ **Never nothing.** ⚠ Integer division truncates, and a window that
     * stopped growing for ever would be a stall this document does not ask for.
     * ⚠ **One octet is the smallest step that is still growth**, and it is
     * ⚠ **far below "one full-sized segment per RTT", which is the ceiling the
     * MUST puts on it.** */
    block->cwnd += by == 0u ? 1u : by;
}

uint32_t handshake_initial_send_sequence(struct moment now)
{
    /* ⚠ Truncated to 32 bits on purpose: ⚠ **the document's clock IS a 32-bit
     * counter that wraps**, and the sequence space wraps with it. ⚠ Unsigned,
     * so the narrowing is defined (`.claude/rules/c.md`). */
    return (uint32_t)(now.nanoseconds / HANDSHAKE_INITIAL_SEQUENCE_STEP_NANOSECONDS);
}

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
                               const uint8_t *data, size_t data_bytes,
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
    case HANDSHAKE_REPLY_THE_DATA_WE_WERE_ASKED_FOR:
        /* ⚠ It occupies sequence space, so it starts where `SND.NXT` is now and
         * ⚠ **the caller moves `SND.NXT` past it after this returns.**
         * ⚠ `ACK` is set because RFC 9293 §3.1 requires it on every segment
         * after the handshake. */
        fields.sequence_number = block->snd_nxt;
        fields.control_bits = TCP_CONTROL_ACK;
        break;
    }
    /* ⚠ A promise of exactly this many octets, and ⚠ `take_the_data` is what
     * backs it (hidetzu/tcpip-stack#64 Owner Decision 1). */
    fields.window = block->rcv_wnd;

    /* ⚠ RFC 9293 `MUST-65`: the MSS Option ⚠ **"is only used in the initial
     * connection request"** — so it rides the `SYN,ACK` and nothing else.
     * ⚠ `what` is what decides, and ⚠ **the two shapes that carry `SYN` are the
     * two above.**
     *
     * ⚠ `MAY-3` — "send it always" — ⚠ **is not taken**, and `SHLD-5` is met by
     * the same line: the document asks for it "when its receive MSS differs from
     * the default 536", ⚠ **and it always does here** unless the device carries
     * frames of exactly 576. */
    fields.options.has_maximum_segment_size =
        (what == HANDSHAKE_REPLY_THE_ANSWER || what == HANDSHAKE_REPLY_NONE);
    fields.options.maximum_segment_size = block->mss_we_advertise;

    uint8_t *segment = reply + ETHERNET_HEADER_BYTES + IPV4_FIXED_HEADER_BYTES;
    size_t segment_bytes = 0;
    if (tcp_build_segment(&fields, id->local.address, id->remote.address,
                          data, data_bytes, segment,
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
    size_t take = still_to_come < block->rcv_wnd ? still_to_come : block->rcv_wnd;

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
    /* ⚠ The same mechanism a `SYN` gets — RFC 9293 `MUST-22`, "Same mechanism
     * for SYNs" — ⚠ **so it is the computed RTO here too** and not a constant
     * of its own (hidetzu/tcpip-stack#131). */
    block->answer_due =
        moment_after_nanoseconds(now, block->round_trip.timeout_nanoseconds);
    block->give_up_at = moment_after(now, HANDSHAKE_R2_FOR_DATA_MILLISECONDS);
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
                                            our_hardware_address, NULL, 0,
                                            reply, reply_bytes);
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
 * (hidetzu/tcpip-stack#80, `tests/interop.sh`
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
                       uint16_t listening_port, uint16_t window,
                       uint16_t maximum_segment_size, uint32_t octets_to_send,
                       struct moment now,
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

    /* ⚠ And before anything is looked up or taken, for the same reason: RFC 9293
     * `MUST-63` says such a `SYN` "MUST be ignored", and ⚠ **a connection taken
     * and then dropped would not have been ignored.**
     *
     * ⚠ `id->remote` is the sender. ⚠ **The refusal above reads `id->local` and
     * this one reads `id->remote`** — ⚠ they are opposite questions and the two
     * lines are the only place that could confuse them. */
    if (!ipv4_address_can_be_a_source(id->remote.address)) {
        stayed(outcome, HANDSHAKE_REASON_FROM_AN_IMPOSSIBLE_SOURCE,
               &counts->from_an_impossible_source);
        return;
    }

    bool carries_syn = (header->control_bits & TCP_CONTROL_SYN) != 0;
    bool carries_ack = (header->control_bits & TCP_CONTROL_ACK) != 0;

    struct transmission_control_block *held = connections_find(connections, id);

    if (held != NULL) {
        outcome->state = held->state;
        outcome->we_would_acknowledge = held->rcv_nxt;

        /* ⚠ RFC 9293 §3.3.1's `SND.WND`: what they say they will accept.
         * ⚠ **Read from every segment they send**, because it is theirs to
         * change and ⚠ **the last thing they said is the only thing we may
         * rely on.**
         *
         * ⚠ Taken before anything is decided, ⚠ **including for a segment that
         * is then refused**: they told us, and refusing their segment does not
         * unsay it. */
        held->snd_wnd = header->window;

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
            uint32_t past_the_window = held->rcv_nxt + held->rcv_wnd;
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

                /* ⚠ RFC 9293 §3.3.1: `SND.UNA` is "send unacknowledged".
                 * ⚠ **They acknowledged our `SYN`, so it is no longer
                 * unacknowledged.**
                 *
                 * ⚠ **Found by a check, not by reading** (hidetzu/tcpip-stack#126):
                 * ⚠ nothing read `SND.UNA` until data of ours needed a window to
                 * fit into, and ⚠ **a case asserting a window of 100 got 99** —
                 * the `SYN` was still counted against the peer's window forever.
                 * ⚠ **It was wrong before and it did not matter; it matters
                 * now.** */
                held->snd_una = header->acknowledgment_number;
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

        /* ⚠ RFC 9293 §3.3.1's `SND.UNA`, advanced by an acknowledgment that
         * covers data of ours.
         *
         * ⚠ **Inside `(SND.UNA, SND.NXT]` and nowhere else**: one below is a
         * duplicate and says nothing new, ⚠ **one above acknowledges something
         * we never sent** and is not ours to believe
         * (`.claude/rules/c.md`: everything here is untrusted input).
         *
         * ⚠ RFC 6298 §5.2: "When all outstanding data has been acknowledged,
         * turn off the retransmission timer." ⚠ §5.3: "When an ACK is received
         * that acknowledges new data, restart the retransmission timer." */
        if (carries_ack && held->snd_una != header->acknowledgment_number &&
            at_or_before(held->snd_una, header->acknowledgment_number) &&
            at_or_before(header->acknowledgment_number, held->snd_nxt)) {
            uint32_t newly = header->acknowledgment_number - held->snd_una;
            held->snd_una = header->acknowledgment_number;

            /* ⚠ RFC 5681 §3.1, on an acknowledgment covering new data.
             * ⚠ **Only when a window exists**: before the first send there is no
             * `cwnd` and `IW` has not been applied.
             *
             * ⚠ `held->send_mss` stands in for `SMSS`. ⚠ **The receive path is
             * not handed the device's MTU**, so the effective send MSS cannot be
             * computed here; ⚠ **`send_mss` is the other half of `MUST-16`'s
             * minimum and is never smaller than the effective one**, so
             * ⚠ **the growth can only be at or below what the document allows**
             * — ⚠ which is the direction the `MUST` bounds. */
            if (held->cwnd_is_set && newly != 0u) {
                grew_by(held, newly, held->send_mss);
            }

            /* ⚠ RFC 6298 §2 and §3, in that order: ⚠ **the sample is taken
             * before the timer is restarted**, so the timer gets the RTO this
             * acknowledgment just produced rather than the one before it.
             *
             * ⚠ **Refused when it is spoilt** — Karn's. ⚠ Either way the sample
             * ends, because ⚠ **holding a spoilt one open would make the next
             * acknowledgment ambiguous too.** */
            if (held->sampling &&
                at_or_before(held->sample_covers, header->acknowledgment_number)) {
                if (!held->sample_is_spoilt) {
                    handshake_round_trip_sample(
                        &held->round_trip,
                        now.nanoseconds - held->sample_sent_at.nanoseconds);
                    counts->round_trips_we_measured++;
                } else {
                    counts->round_trips_we_would_not_use++;
                }
                held->sampling = false;
                held->sample_is_spoilt = false;
            }

            /* ⚠ The count is of THE SAME segment being sent again, so ⚠ **it
             * goes back to zero when something new is acknowledged** and not
             * when anything at all is sent (RFC 9293 §3.8.3 (a)). */
            {
                held->retransmissions = 0;
                held->told_them_about_r1 = false;
            }

            if (held->snd_una == held->snd_nxt) {
                held->waiting_for_an_ack = false;
            } else {
                held->send_again_at =
                    moment_after_nanoseconds(now, held->round_trip.timeout_nanoseconds);
            }
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

    /* ⚠ RFC 9293 §3.3.1 puts `RCV.WND` in the TCB, so it is written here, where
     * the block becomes this connection's. ⚠ **Every block in this build is
     * given the same number** — it is the device's, not the connection's — and
     * ⚠ **the document's shape is followed anyway** (`.claude/rules/layers.md`).
     *
     * ⚠ Written on every arrival and not only on the first, because
     * ⚠ **`connections_take` hands back the block that already holds this id**
     * when the peer retransmits its `SYN`, and ⚠ the value is the same either
     * way. */
    taken->snd_wnd = header->window;
    taken->still_to_send = octets_to_send;
    /* ⚠ RFC 6298 §2.1: the value before anything has been measured. */
    handshake_round_trip_begin(&taken->round_trip);
    taken->rcv_wnd = window;
    taken->mss_we_advertise = maximum_segment_size;

    /* ⚠ RFC 9293 `MUST-15`: "If an MSS Option is not received at connection
     * setup, TCP implementations MUST assume a default send MSS of 536 (576 -
     * 40) for IPv4". ⚠ **Absent and zero are different answers**, and the Parse
     * layer keeps them apart, so ⚠ **the default is applied here rather than
     * guessed from a value.**
     *
     * ⚠ Written on every arrival, not only the first: a retransmitted `SYN`
     * carries the option again and ⚠ **the answer is the same either way.** */
    if (carries_syn) {
        if (header->options.has_maximum_segment_size) {
            taken->send_mss = header->options.maximum_segment_size;
            taken->send_mss_was_told_to_us = true;
            counts->they_told_us_their_segment_size++;
        } else {
            taken->send_mss = CONNECTION_DEFAULT_SEND_MSS;
            taken->send_mss_was_told_to_us = false;
            counts->they_told_us_nothing_so_we_assumed++;
        }
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
    taken->iss = handshake_initial_send_sequence(now);
    taken->snd_una = taken->iss;
    taken->snd_nxt = taken->iss + 1u;
    taken->state = CONNECTION_SYN_RECEIVED;
    outcome->we_would_acknowledge = taken->rcv_nxt;
    /* ⚠ RFC 793: the retransmission timer is reinitialised on each send, so it
     * starts here and not when the connection was found. ⚠ The give-up moment
     * is from now and is never moved again. */
    memcpy(taken->requester_hardware_address, requester_hardware_address,
           CONNECTION_HARDWARE_ADDRESS_BYTES);
    /* ⚠ `MUST-23`: R2 for a `SYN` is at least three minutes. ⚠ **This is the
     * one the document puts a floor under**, and it is the connection's while
     * it is still opening. */
    taken->answer_due =
        moment_after_nanoseconds(now, taken->round_trip.timeout_nanoseconds);
    taken->give_up_at = moment_after(now, HANDSHAKE_R2_FOR_A_SYN_MILLISECONDS);

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
        /* ⚠ Backed off first, so the new deadline is the doubled one — ⚠ RFC
         * 6298 §5.5 then §5.6, in that order. ⚠ `MUST-22`: the same mechanism a
         * data segment gets. */
        waiting->retransmissions++;
        back_off(waiting);
        if (crossed_r1(waiting)) {
            counts->reached_r1++;
        }
        waiting->answer_due =
            moment_after_nanoseconds(now, waiting->round_trip.timeout_nanoseconds);

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

bool handshake_send_what_is_next(struct connections *connections,
                                 unsigned int mtu, struct moment now,
                                 uint8_t time_to_live,
                                 const uint8_t *our_hardware_address,
                                 uint8_t *reply, size_t reply_bytes,
                                 struct handshake_counts *counts,
                                 struct handshake_outcome *outcome)
{
    memset(outcome, 0, sizeof *outcome);

    for (size_t i = 0; i < CONNECTIONS_AT_ONCE; i++) {
        struct transmission_control_block *block = &connections->block[i];
        /* ⚠ A block with nothing left to send is NOT skipped here: ⚠ **it may
         * still be waiting for an acknowledgment of what already went**, and
         * that is exactly the case retransmission exists for. ⚠ The skip is
         * below, after the deadline has been read. */
        if (!block->in_use || block->state != CONNECTION_ESTABLISHED ||
            (block->still_to_send == 0u && !block->waiting_for_an_ack)) {
            continue;
        }

        outcome->id = block->id;
        outcome->state = block->state;

        /* ⚠ RFC 9293 `MUST-16`, per connection: ⚠ **the smaller of what THEY
         * told us and what one of OUR frames carries.** ⚠ `send_mss` is theirs
         * or `MUST-15`'s default of 536; the MTU gives the other half. */
        uint16_t effective_send_mss = 0;
        if (handshake_effective_send_mss(block->send_mss, mtu,
                                         &effective_send_mss) != HANDSHAKE_WINDOW_OK ||
            effective_send_mss == 0u) {
            return false;
        }

        /* ⚠ RFC 6298 §5.4: "Retransmit the earliest segment that has not been
         * acknowledged by the TCP receiver."
         *
         * ⚠ **Winding `SND.NXT` back to `SND.UNA` IS that**, because the octets
         * are a pattern: everything from `SND.UNA` onward is reproduced exactly
         * (ADR 0030). ⚠ **A stack with a real send buffer would have to hold the
         * segments; this one recomputes them**, and `docs/SPEC.md` §2 says so.
         *
         * ⚠ **It sends the earliest again and everything after it** — ⚠ that is
         * more than §5.4 asks for and ⚠ **it is said rather than claimed as the
         * document's**: with no `SND.WND` change and no fast retransmit, the
         * rest would follow anyway. */
        if (block->waiting_for_an_ack && moment_is_at_or_after(now, block->send_again_at)) {
            uint32_t unacknowledged = block->snd_nxt - block->snd_una;
            if (unacknowledged != 0u) {
                block->snd_nxt = block->snd_una;
                block->still_to_send += unacknowledged;
                counts->data_segments_we_sent_again++;
                counts->data_octets_we_sent_again += unacknowledged;
                /* ⚠ RFC 6298 §3, Karn's algorithm: ⚠ **a sample covering
                 * anything that has just been sent again is ambiguous**, and
                 * ⚠ **an ambiguity is not a measurement** (`CLAUDE.md` §1). */
                block->sample_is_spoilt = true;

                /* ⚠ RFC 9293 §3.8.3 (a): the count is of "the same segment"
                 * being sent again. ⚠ §5.5 doubles the timeout with it. */
                /* ⚠ RFC 5681 §3.1, on loss detected by the retransmission
                 * timer: "the value of ssthresh MUST be set to no more than the
                 * value given in equation (4): ssthresh = max (FlightSize / 2,
                 * 2*SMSS)". ⚠ **`FlightSize`, not `cwnd`** — the document calls
                 * that "an easy mistake to make".
                 *
                 * ⚠ "when a TCP sender detects segment loss using the
                 * retransmission timer and the given segment has already been
                 * retransmitted ... the value of ssthresh is held constant."
                 * ⚠ **So only the first expiry for the same thing moves it.**
                 *
                 * ⚠ "upon a timeout ... cwnd MUST be set to no more than the
                 * loss window, LW, which equals 1 full-sized segment." */
                if (block->cwnd_is_set) {
                    if (block->retransmissions == 0u) {
                        uint32_t half = unacknowledged / 2u;
                        uint32_t two = 2u * (uint32_t)effective_send_mss;
                        block->ssthresh = half > two ? half : two;
                    }
                    block->cwnd = (uint32_t)HANDSHAKE_LW_SEGMENTS *
                                  (uint32_t)effective_send_mss;
                    counts->congestion_windows_we_cut++;
                }
                block->retransmissions++;
                back_off(block);
                if (crossed_r1(block)) {
                    counts->reached_r1++;
                }
            }
            /* ⚠ Cleared so one expiry winds back once. ⚠ It is set again below
             * when the first segment goes out (§5.1). */
            block->waiting_for_an_ack = false;
        }

        if (block->still_to_send == 0u) {
            continue;
        }


        /* ⚠ What the peer said it will take, from `SND.UNA`. ⚠ Octets past
         * `SND.UNA + SND.WND` are octets they told us they cannot hold. */
        uint32_t outstanding = block->snd_nxt - block->snd_una;
        /* ⚠ RFC 5681 §3.1: `IW` is "the size of the sender's congestion window
         * after the three-way handshake is completed". ⚠ **Applied at the first
         * send, because `SMSS` needs the device's MTU and the receive path is
         * not handed one.** */
        if (!block->cwnd_is_set) {
            block->cwnd = handshake_initial_congestion_window(effective_send_mss);
            block->ssthresh = HANDSHAKE_SSTHRESH_AT_THE_START;
            block->cwnd_is_set = true;
        }

        /* ⚠ RFC 5681 §2: "a TCP MUST NOT send data with a sequence number higher
         * than the sum of the highest acknowledged sequence number and **the
         * minimum of cwnd and rwnd**." ⚠ `rwnd` is theirs, `cwnd` is ours, and
         * ⚠ **the smaller governs.** */
        uint32_t governs = block->cwnd < (uint32_t)block->snd_wnd
                               ? block->cwnd : (uint32_t)block->snd_wnd;
        if (outstanding >= governs) {
            stayed(outcome, HANDSHAKE_REASON_THEIR_WINDOW_HAD_NO_ROOM,
                   &counts->their_window_had_no_room);
            return false;
        }
        uint32_t room = governs - outstanding;

        /* ⚠ RFC 9293 `MUST-16`: no segment carries more than the effective send
         * MSS. ⚠ **Three limits and the smallest wins** — what is left, what
         * they will take, and what one segment may carry. */
        uint32_t take = block->still_to_send;
        if (take > room) {
            take = room;
        }
        if (take > effective_send_mss) {
            take = effective_send_mss;
        }
        if (take == 0u) {
            return false;
        }

        /* ⚠ Built from the sequence offset, ⚠ **so no buffer is held between
         * calls** (ADR 0030). */
        uint8_t data[TCP_SEGMENT_DATA_MOST];
        if (take > sizeof data) {
            take = (uint32_t)sizeof data;
        }
        uint32_t already = block->snd_nxt - (block->iss + 1u);
        for (uint32_t at = 0; at < take; at++) {
            data[at] = handshake_octet_at(already + at);
        }

        outcome->reply_bytes =
            build_the_answer(block, HANDSHAKE_REPLY_THE_DATA_WE_WERE_ASKED_FOR,
                             time_to_live, &block->id, block->requester_hardware_address,
                             our_hardware_address, data, take, reply, reply_bytes);
        if (outcome->reply_bytes == 0) {
            counts->we_could_not_build_the_reply++;
            return false;
        }

        block->snd_nxt += take;
        block->still_to_send -= take;
        counts->data_segments_we_sent++;
        counts->data_octets_we_sent += take;

        /* ⚠ RFC 6298 §5.1: "Every time a packet containing data is sent
         * (including a retransmission), if the timer is not running, start it
         * running." ⚠ **Not restarted when it already is** — that would push the
         * deadline out on every segment of a burst and ⚠ **the earliest
         * unacknowledged one would never come due.** */
        if (!block->waiting_for_an_ack) {
            block->waiting_for_an_ack = true;
            block->send_again_at =
                moment_after_nanoseconds(now, block->round_trip.timeout_nanoseconds);
        }

        /* ⚠ RFC 6298 §3: "A TCP implementation MUST take at least one RTT
         * measurement per RTT." ⚠ One is started when none is running.
         *
         * ⚠ **`sample_is_spoilt` is not cleared here.** ⚠ It is cleared only
         * when a fresh sample starts on a segment that has not been sent
         * before — which is the branch above, and ⚠ **a wind-back sets it
         * again before reaching here.** */
        if (!block->sampling) {
            block->sampling = true;
            block->sample_sent_at = now;
            block->sample_covers = block->snd_nxt;
        }
        outcome->reply = HANDSHAKE_REPLY_THE_DATA_WE_WERE_ASKED_FOR;
        outcome->decision = HANDSHAKE_STAYED;
        outcome->reason = HANDSHAKE_REASON_WE_SENT_WHAT_WE_WERE_ASKED_TO;
        outcome->octets_taken = (uint16_t)take;
        return true;
    }
    return false;
}

void handshake_receive_error(struct connections *connections,
                             const struct connection_id *id,
                             enum icmp_error_class what,
                             struct handshake_counts *counts,
                             struct handshake_outcome *outcome)
{
    memset(outcome, 0, sizeof *outcome);
    outcome->id = *id;
    outcome->state = CONNECTION_LISTEN;

    struct transmission_control_block *held = connections_find(connections, id);
    if (held == NULL) {
        /* ⚠ Not ours and not the sender's: ⚠ **it may name a connection that has
         * since closed**, which is the ordinary case and not a fault. */
        stayed(outcome, HANDSHAKE_REASON_AN_ERROR_FOR_NO_CONNECTION_WE_HOLD,
               &counts->errors_for_no_connection_we_hold);
        return;
    }
    outcome->state = held->state;

    switch (what) {
    case ICMP_ERROR_SOURCE_QUENCH:
        /* ⚠ `MUST-55`: "TCP implementations MUST silently discard any received
         * ICMP Source Quench messages." ⚠ **"Silently" forbids a segment on the
         * wire, not a line telling the human who is watching** — the same
         * reading `MUST-57` took at hidetzu/tcpip-stack#99.
         *
         * ⚠ **It was met before this existed, and by accident**: nothing acted
         * on any ICMP error at all (hidetzu/tcpip-stack#97). ⚠ **It is met by a
         * decision now** — ⚠ the message reaches this function and is dropped
         * here. */
        stayed(outcome, HANDSHAKE_REASON_A_SOURCE_QUENCH_WE_DISCARDED,
               &counts->source_quenches_we_discarded);
        return;
    case ICMP_ERROR_SOFT:
        /* ⚠ `MUST-56`: "Since these Unreachable messages indicate soft error
         * conditions, a TCP implementation MUST NOT abort the connection."
         * ⚠ **Met by a decision now, not by never seeing one.**
         *
         * ⚠ `SHLD-25` — "SHOULD make the information available to the
         * application" — ⚠ **does not arise: there is none** (ADR 0022). */
        stayed(outcome, HANDSHAKE_REASON_A_SOFT_ERROR_THAT_CHANGES_NOTHING,
               &counts->soft_errors_that_changed_nothing);
        return;
    case ICMP_ERROR_HARD:
        /* ⚠ `SHLD-26`: "These are hard error conditions, so TCP implementations
         * SHOULD abort the connection."
         *
         * ⚠ **A `SHOULD` and the document says so in the same breath**: "[35]
         * notes that some implementations do not abort connections when an ICMP
         * hard error is received for a connection that is in any of the
         * synchronized states." ⚠ **Taken anyway, and that is a decision**
         * (ADR 0035). */
        connections_release(connections, held);
        outcome->decision = HANDSHAKE_MOVED;
        outcome->state = CONNECTION_LISTEN;
        outcome->reason = HANDSHAKE_REASON_A_HARD_ERROR_THAT_ENDS_IT;
        counts->hard_errors_that_ended_a_connection++;
        return;
    case ICMP_ERROR_NOT_CLASSIFIED:
        /* ⚠ **The document classifies some codes and not others**, and
         * ⚠ **silence in an RFC is not permission** (`CLAUDE.md` §1).
         * ⚠ **The connection is left alone** — ⚠ the safe direction, ⚠ **said as
         * a choice of ours and not as a reading.** */
        stayed(outcome, HANDSHAKE_REASON_AN_ERROR_THE_DOCUMENT_DOES_NOT_CLASSIFY,
               &counts->errors_the_document_does_not_classify);
        return;
    }
}

bool handshake_next_moment(const struct connections *connections, struct moment *due)
{
    for (size_t i = 0; i < CONNECTIONS_AT_ONCE; i++) {
        const struct transmission_control_block *block = &connections->block[i];
        if (!block->in_use) {
            continue;
        }
        if (block->state == CONNECTION_SYN_RECEIVED) {
            /* ⚠ The earlier of the two, ⚠ compared the way moments must be so it
             * works across the wrap (`src/moment.h`). */
            *due = moment_is_at_or_after(block->give_up_at, block->answer_due)
                       ? block->answer_due
                       : block->give_up_at;
            return true;
        }
        /* ⚠ Data of ours nobody has acknowledged (hidetzu/tcpip-stack#129).
         * ⚠ **Without this the caller would wait without a limit and the
         * deadline would pass unnoticed** — ⚠ a timer nothing wakes for is not a
         * timer. */
        if (block->waiting_for_an_ack) {
            *due = block->send_again_at;
            return true;
        }
    }
    return false;
}
