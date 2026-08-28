/* State — what an arriving TCP segment means for a connection we are listening
 * for, and what moved as a result.
 *
 * ⚠ No fd, no clock, no prose, and ⚠ **nothing is sent**
 * (`.claude/rules/layers.md`, hidetzu/tcpip-stack#43 Out of Scope). This layer
 * is handed a header that was already read and checked, and it says what it
 * decided and why. ⚠ `report.c` is the only place any of it becomes a sentence,
 * and hidetzu/tcpip-stack#44 is what puts something on the wire.
 *
 * ⚠ The decision and the reason are two things, never one — the shape
 * hidetzu/tcpip-stack#19 Owner Decision 2 set for ARP and #35 followed. ⚠ Every
 * reason is counted on its own.
 *
 * ⚠ The rules are RFC 793's §3.9, read on 2026-08-28 from the document itself
 * rather than through a summary, and quoted where they are applied
 * (ADR 0016). */
#ifndef HANDSHAKE_H
#define HANDSHAKE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "connection.h"
#include "ethernet.h"
#include "ipv4.h"
#include "tcp.h"

/* The initial send sequence number this build chooses.
 *
 * ⚠ RFC 793's own method is not available here, and that is a decision rather
 * than an oversight:
 *
 *   "The generator is bound to a (possibly fictitious) 32 bit clock whose low
 *    order bit is incremented roughly every 4 microseconds."
 *
 * ⚠ **There is no clock** — hidetzu/tcpip-stack#42 Owner Decision 2 recorded
 * that as a deliberate gap for the handshake (ADR 0015).
 *
 * ⚠ And the reason the document gives for the method does not arise here:
 *
 *   "To avoid confusion we must prevent segments from one incarnation of a
 *    connection from being used while the same sequence numbers may still be
 *    present in the network from an earlier incarnation."
 *
 * ⚠ **There is room for one connection and nothing frees it**, so ⚠ a run has
 * one incarnation and there is no earlier one to be confused with (ADR 0015).
 * ⚠ The device itself is gone when the fd closes (`docs/SPEC.md` §1).
 *
 * ⚠ **None of that makes a fixed number generally safe.** ⚠ A predictable
 * initial sequence number is a known weakness, and ⚠ `docs/SPEC.md` §2 says
 * plainly that this holds only inside a private namespace whose other end is
 * the kernel — ⚠ **and names this as the first thing to revisit when a clock
 * arrives.** ⚠ Nothing here claims RFC 793 asks for it.
 *
 * ⚠ Why not zero: ⚠ **a block nobody filled in is all zeroes**, so a check
 * asserting "the ISS is 0" would pass for one. ⚠ This value cannot be there by
 * accident (hidetzu/tcpip-stack#43 Owner Decision 1). */
#define HANDSHAKE_INITIAL_SEND_SEQUENCE 0xdeadbeefu

/* How long until the answer goes out again, and how long until we stop.
 *
 * ⚠ RFC 793 read verbatim on 2026-08-28: ⚠ **"the retransmission timeout must
 * be dynamically determined"**, and the procedure it gives needs a Round Trip
 * Time. ⚠ **Nothing here measures a round trip**, so ⚠ **this stack does not do
 * what the document asks**, and `docs/SPEC.md` §2 names that gap.
 *
 * ⚠ 1000 is the document's own example lower bound — "LBOUND is a lower bound on
 * the timeout (e.g., 1 second)". ⚠ **Going below it would mean going under the
 * only floor the document offers, and the reason would have been that a check is
 * cheaper that way** (hidetzu/tcpip-stack#57 Owner Decision 1).
 *
 * ⚠ 3000 is ours and has no grounds in the document. ⚠ Its example upper bound is
 * a minute; ⚠ **a check that waits a minute would change what the real tier
 * costs by an order of magnitude** (`docs/SPEC.md` §3 holds what it costs).
 * ⚠ **Chosen for what a check can afford, and recorded as that** (ADR 0019).
 *
 * ⚠ So the answer goes out again twice — after a second and after two — and
 * ⚠ **the connection is given up on at three.** */
#define HANDSHAKE_ANSWER_AGAIN_AFTER_MILLISECONDS 1000u
#define HANDSHAKE_GIVE_UP_AFTER_MILLISECONDS 3000u

/* How many octets the answer's Window promises, and ⚠ **it is a promise.**
 *
 * ⚠ RFC 793: "Window: 16 bits - The number of data octets beginning with the
 * one indicated in the acknowledgment field which the sender of this segment is
 * willing to accept."
 *
 * ⚠ 1, and 1 is a measurement rather than a taste. Same conditions as
 * `docs/SPEC.md` §3, 2026-08-29 — a `connect()`, a wait, a `close()`, watched on
 * the wire:
 *
 *     window 0   SYN ACK ACK ACK ACK ACK            ⚠ no FIN, ever
 *     window 1   SYN ACK ACK|FIN ACK|FIN ...        ⚠ the FIN arrives
 *     window 2   SYN ACK ACK|FIN ACK|FIN ...        the same
 *
 * ⚠ **A window of 0 makes closing impossible**, and ⚠ **1 is the smallest that
 * lets a FIN through** (hidetzu/tcpip-stack#64 Owner Decision 1).
 *
 * ⚠ Until hidetzu/tcpip-stack#64 this was 0, and 0 was equally the truth then:
 * ⚠ **nothing accepted a single octet, so promising one would have been a claim
 * this stack could not back** (hidetzu/tcpip-stack#44 Owner Decision 3). ⚠ The
 * number moved because ⚠ **what backs it moved** — `take_the_data` below —
 * ⚠ not because a check was easier that way. */
#define HANDSHAKE_WINDOW 1u

enum handshake_decision {
    /* ⚠ The connection moved to a state it was not in. `outcome->state` says
     * which. */
    HANDSHAKE_MOVED = 0,

    /* ⚠ Nothing moved, and `outcome->reason` says why. ⚠ That includes the
     * ordinary case of a retransmitted SYN, which is not an error. */
    HANDSHAKE_STAYED
};

/* Which segment was built into the caller's reply buffer, if any.
 *
 * ⚠ Its own field so that ⚠ **the caller never has to work out from a state
 * which counter to move** — that rule would then live in two layers, and one of
 * them would go stale (`CLAUDE.md` §3). ⚠ An enum never reaches a human. */
enum handshake_reply {
    HANDSHAKE_REPLY_NONE = 0,

    /* The `<SEQ=ISS><ACK=RCV.NXT><CTL=SYN,ACK>` that answers a SYN. */
    HANDSHAKE_REPLY_THE_ANSWER,

    /* ⚠ Our own FIN, ⚠ **carrying the acknowledgment of theirs in the same
     * segment.** ⚠ Measured 2026-08-29, in a namespace on `lo`: when its
     * application closes the moment the peer's FIN arrives, ⚠ **the Linux
     * kernel sends one segment carrying `FIN,ACK`** — and two segments when the
     * close comes later. ⚠ ADR 0022 puts this stack in the first situation
     * always, because the FIN's arrival IS the close here (ADR 0023). */
    HANDSHAKE_REPLY_OUR_FIN
};

enum handshake_reason {
    HANDSHAKE_REASON_NONE = 0, /* it moved */

    /* ⚠ Not an error, and ⚠ not folded in with anything that is. ⚠ The Linux
     * kernel retransmits its SYN — 7 times in one measured `connect()`,
     * 2026-08-28 — so ⚠ **this is the ordinary case, not a rare one.**
     * ⚠ Nothing is re-chosen: the same `iss` stands, so a peer that did get our
     * first answer is not told a different number (ADR 0016). */
    HANDSHAKE_REASON_ASKED_AGAIN,

    /* ⚠ RFC 793: "If SND.UNA =< SEG.ACK =< SND.NXT then enter ESTABLISHED
     * state". ⚠ This is what happens when it is not. ⚠ The document says a reset
     * should be formed; ⚠ **nothing is sent here**, and `docs/SPEC.md` §2 names
     * that gap rather than leaving it silent. */
    HANDSHAKE_REASON_ACKNOWLEDGMENT_WE_ARE_NOT_WAITING_FOR,

    /* ⚠ A segment for a connection we hold, carrying something this state has
     * no rule for here. ⚠ Counted apart from a wrong acknowledgment: one is the
     * sender being early, the other is the sender being wrong. */
    HANDSHAKE_REASON_NOT_EXPECTED_IN_THIS_STATE,

    /* ⚠ Nothing is listening for it and it is not a request to open one.
     * ⚠ RFC 793: "Any acknowledgment is bad if it arrives on a connection still
     * in the LISTEN state." ⚠ The document says a reset should be formed;
     * nothing is sent here. */
    HANDSHAKE_REASON_NO_CONNECTION_HELD,

    /* ⚠ Ours, not the sender's: every block is in use
     * (hidetzu/tcpip-stack#42 Owner Decision 1). */
    HANDSHAKE_REASON_NO_ROOM,

    /* ⚠ Nobody has confirmed it yet, and the answer went out again. ⚠ **Not the
     * same event as a retransmitted SYN arriving**, and ⚠ not counted with it:
     * one is how many times they asked, the other how many times we answered
     * (hidetzu/tcpip-stack#59 Owner Decision 1).
     *
     * ⚠ Until #59 these shared `ASKED_AGAIN`, and ⚠ **the sentence printed for
     * our own timer said the sender had asked again, which was false.** */
    HANDSHAKE_REASON_THE_ANSWER_WENT_OUT_AGAIN,

    /* ⚠ Nobody acknowledged our FIN, and we stopped waiting. ⚠ Counted apart
     * from a handshake nobody confirmed: ⚠ **one is a connection that never
     * opened, the other one that would not finish closing** — the same division
     * hidetzu/tcpip-stack#59 had to make when one reason was doing two jobs.
     *
     * ⚠ RFC 793 for LAST-ACK: "The only thing that can arrive in this state is
     * an acknowledgment of our FIN." ⚠ The document gives no timeout for it
     * beyond the user timeout, and ⚠ **the interval used is ours** (ADR 0019). */
    HANDSHAKE_REASON_NOBODY_ACKNOWLEDGED_OUR_FIN,

    /* ⚠ Our FIN went out again because nobody had acknowledged it. ⚠ Counted
     * apart from the answer going out again, for the same reason as above.
     *
     * ⚠ RFC 793: "All segments preceding and including FIN will be
     * retransmitted until acknowledged." */
    HANDSHAKE_REASON_OUR_FIN_WENT_OUT_AGAIN,

    /* ⚠ Nobody confirmed it, and we stopped waiting. ⚠ Not the sender being
     * wrong about anything — ⚠ **the sentence a human reads says so**
     * (`CLAUDE.md` §4-1). ⚠ RFC 793's USER TIMEOUT is what this follows:
     * "delete the TCB, enter the CLOSED state and return." */
    HANDSHAKE_REASON_NOBODY_CONFIRMED_IT,

    /* ⚠ A FIN arrived that ⚠ **the window we promised does not cover** — its
     * sequence number is not the next one we are waiting for.
     *
     * ⚠ RFC 793's acceptability test for a segment of length 1 against a window
     * above zero, quoted: "RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND". ⚠ A FIN
     * occupies one sequence number — "A control bit (finis) occupying one
     * sequence number" — so ⚠ **a FIN is a segment of length 1 even carrying no
     * data.**
     *
     * ⚠ **This is the measured case, not a rare one**: `RCV.NXT` advances over
     * a FIN we read, so ⚠ **every retransmission of it lands here.** ⚠ The Linux
     * kernel sent five in one `close()` — measured 2026-08-29.
     *
     * ⚠ Which of the two it was is not told apart, the same as
     * `DATA_OUTSIDE_THE_WINDOW`: this build asks one question. */
    HANDSHAKE_REASON_A_FIN_OUTSIDE_THE_WINDOW,

    /* ⚠ A FIN arrived and ⚠ **nothing is held for the connection it names.**
     *
     * ⚠ RFC 793, verbatim: "Do not process the FIN if the state is CLOSED,
     * LISTEN or SYN-SENT since the SEG.SEQ cannot be validated; drop the
     * segment and return." ⚠ **Holding nothing is our LISTEN.**
     *
     * ⚠ Counted apart from any other segment arriving for no connection we
     * hold: ⚠ **the document gives this one its own sentence and its own
     * reason**, and folding it in would lose why it was dropped. */
    HANDSHAKE_REASON_A_FIN_WE_CANNOT_PLACE,

    /* ⚠ Data arrived on an open connection, ⚠ **we took delivery of it, and we
     * had nobody to give it to** (hidetzu/tcpip-stack#64 Owner Decision 2).
     *
     * ⚠ Counted apart from a segment the state did not expect: ⚠ **this one was
     * expected** — it is exactly what advertising a window invites — and the two
     * are not the same event.
     *
     * ⚠ `RCV.NXT` advanced, so ⚠ **the same octet is not taken twice.**
     * ⚠ **Nothing tells the sender**, because nothing is sent from this layer at
     * all: ⚠ **the window is a promise kept in taking and not yet in telling**,
     * and `docs/SPEC.md` §2 names hidetzu/tcpip-stack#66 as what closes it.
     * ⚠ The peer retransmits meanwhile, and that is the measured consequence,
     * not a surprise. */
    HANDSHAKE_REASON_THE_DATA_WAS_TAKEN_AND_DISCARDED,

    /* ⚠ Data arrived that ⚠ **none of the window we promised covers** — every
     * octet of it is behind `RCV.NXT`, or every octet is beyond what was
     * promised.
     *
     * ⚠ RFC 793's sequence number check, verbatim: "segments with higher
     * beginning sequence numbers may be held for later processing." ⚠ Nothing
     * here holds anything, and ⚠ `docs/SPEC.md` §2 names that gap rather than
     * leaving it silent.
     *
     * ⚠ Counted apart from data that was taken: ⚠ **one is octets that reached
     * us, the other is a segment that reached us and had nothing in it we had
     * room for.** */
    HANDSHAKE_REASON_DATA_OUTSIDE_THE_WINDOW,

    /* ⚠ Ours, not the sender's. ⚠ The connection moved and ⚠ the answer could
     * not be built into the buffer we were given. ⚠ Counted rather than dropped
     * in silence (`.claude/rules/c.md`), and ⚠ the sentence a human reads says
     * whose it is (`CLAUDE.md` §4-1). */
    HANDSHAKE_REASON_WE_COULD_NOT_BUILD_THE_REPLY
};

struct handshake_counts {
    unsigned long opened;
    unsigned long established;
    unsigned long asked_again;
    unsigned long acknowledgment_we_are_not_waiting_for;
    unsigned long not_expected_in_this_state;
    unsigned long no_connection_held;
    unsigned long we_could_not_build_the_reply;
    unsigned long given_up_on;
    unsigned long answered_again;

    /* ⚠ **Octets, not segments** — the denominator is stated because the
     * counters around it are all segments (`CLAUDE.md` §6). ⚠ It is what we
     * took delivery of and discarded, so ⚠ **one 5-octet segment taken one
     * octet at a time over five arrivals moves this by 5, not by 1 and not by
     * 25**: `RCV.NXT` advanced each time, so no octet is counted twice. */
    unsigned long octets_taken_and_discarded;

    /* ⚠ **Segments** — a segment none of whose octets the window covered. */
    unsigned long data_outside_the_window;

    /* ⚠ **Segments.** ⚠ The other side closed and we read its FIN. ⚠ Counted
     * apart from `established`, ⚠ **and both can move for one segment**: RFC 793
     * takes the acknowledgment that opens a connection through to the FIN check
     * in the same pass. */
    unsigned long the_other_side_closed;

    /* ⚠ **Segments** — a FIN the window did not cover, and a FIN naming a
     * connection we hold nothing for. ⚠ Kept apart from each other and from
     * everything else (hidetzu/tcpip-stack#65). */
    unsigned long fin_outside_the_window;
    unsigned long fin_we_could_not_place;

    /* ⚠ **Segments.** ⚠ Our own FIN, counted only once the wire took the whole
     * of it — ⚠ **a segment that was built is not a segment that left**, the
     * division everything here uses. ⚠ The caller moves these two, not this
     * file. */
    unsigned long our_fin_left;
    unsigned long our_fin_went_out_again;

    /* ⚠ **Connections.** ⚠ They acknowledged our FIN and the connection was
     * released, so ⚠ **the next SYN can open one** (ADR 0015: there is room for
     * one). */
    unsigned long closed;

    /* ⚠ **Connections.** ⚠ Nobody acknowledged our FIN and we stopped waiting.
     * ⚠ Apart from `given_up_on`, which is a handshake that never finished. */
    unsigned long never_acknowledged_our_fin;

    /* ⚠ Counted only once the wire took the whole answer. ⚠ A reply that was
     * built is not a reply that left — the same division `arp_respond` and
     * `echo_respond` use (`CLAUDE.md` §1, in the sending direction). ⚠ The
     * caller moves this one, not this file. */
    unsigned long answered;

    /* ⚠ The refusal `src/connection.c` already counts, carried here so a caller
     * has one place to look (hidetzu/tcpip-stack#42). */
    struct connection_counts room;
};

struct handshake_outcome {
    enum handshake_decision decision;
    enum handshake_reason reason;

    /* ⚠ The state after. ⚠ Meaningful whenever a connection was held or taken;
     * `CONNECTION_LISTEN` when none was. */
    enum connection_state state;

    /* ⚠ Which connection this was about, filled whatever was decided, so a
     * caller can say so without reading the octets itself. */
    struct connection_id id;

    /* ⚠ For the sentence a human reads when an acknowledgment was not the one
     * we wait for. ⚠ Meaningful only for that reason. */
    uint32_t acknowledgment_we_had;
    uint32_t acknowledgment_we_expected;

    /* ⚠ How many octets of data we took delivery of and discarded. ⚠ 0 unless
     * the segment carried data the window covered, and ⚠ **it can be non-zero
     * alongside a connection reaching ESTABLISHED**: the acknowledgment that
     * opens a connection may carry data, and ⚠ **a payload nobody counted is
     * indistinguishable from one that never arrived** (`.claude/rules/c.md`).
     * ⚠ That is why this is a field and not a reason — ⚠ `counts` still gains
     * exactly one reason per segment. */
    uint16_t octets_taken;

    /* ⚠ True when this segment's FIN was read and `RCV.NXT` moved over it.
     * ⚠ Its own field rather than a reason, ⚠ **because a segment can both
     * open a connection and close it** — RFC 793 goes on to the FIN check after
     * entering ESTABLISHED, in the same pass — and ⚠ a reason cannot say two
     * things (hidetzu/tcpip-stack#65). */
    bool the_fin_was_read;

    /* ⚠ What we would acknowledge for this connection now, ⚠ **as a number.**
     * ⚠ Meaningful whenever a connection was held or taken. ⚠ It is `RCV.NXT`
     * after everything this segment moved, so ⚠ **a FIN that was read has
     * already been counted into it** — RFC 793: "advance RCV.NXT over the FIN".
     * ⚠ Nothing sends it; hidetzu/tcpip-stack#66 does. */
    uint32_t we_would_acknowledge;

    /* ⚠ Which segment was built, so ⚠ **a caller counts what left under the
     * right name without deciding which it was.** ⚠ `HANDSHAKE_REPLY_NONE`
     * whenever `reply_bytes` is 0. */
    enum handshake_reply reply;

    /* ⚠ How many octets of the caller's reply buffer were written. ⚠ 0 unless a
     * SYN opened a connection, and ⚠ a caller must not send what was not
     * built. */
    size_t reply_bytes;
};

/* Take one already-read segment through whatever transition it causes.
 *
 * `header` must have come back `TCP_PARSE_OK` from `tcp_parse_header` — ⚠ this
 * layer never re-checks what the Parse layer already decided, and ⚠ it must not
 * be handed a segment whose checksum was not judged (`CLAUDE.md` §1, the whole
 * reason hidetzu/tcpip-stack#41 made that an outcome).
 *
 * `id` is the connection the segment belongs to, ⚠ built by the caller from the
 * internet header and the ports — ⚠ this layer reads no address.
 *
 * `listening_port` is the port this stack answers for. ⚠ A segment for any other
 * local port is not ours to open.
 *
 * ⚠ `counts` gains exactly one, under the reason decided — ⚠ **with one
 * exception the document forces**: a segment that both opens a connection and
 * closes it moves `established` and `the_other_side_closed` together, because
 * ⚠ **RFC 793 goes on to the FIN check after entering ESTABLISHED, in the same
 * pass**, and ⚠ a single reason cannot say two things (ADR 0022). ⚠ The octets
 * taken are their own number for the same cause.
 * ⚠ Nothing is sent here and nothing is printed here. */
/* `requester_hardware_address` is the arriving frame's ethernet source — ⚠ where
 * an answer would have to go, taken from that frame and ⚠ never from a table
 * this stack does not keep.
 *
 * `reply` is the caller's buffer for a whole frame, ⚠ ethernet header included.
 *
 * ⚠ What goes in the answer, and none of it is guessed:
 *
 *     Control Bits     SYN and ACK — RFC 793: "<SEQ=ISS><ACK=RCV.NXT>
 *                      <CTL=SYN,ACK>"
 *     Sequence Number  ISS
 *     Acknowledgment   RCV.NXT
 *     Window           ⚠ `HANDSHAKE_WINDOW`, and ⚠ **it is a promise this
 *                      stack keeps in taking**: `take_the_data` accepts that
 *                      many octets and discards them
 *                      (hidetzu/tcpip-stack#64 Owner Decisions 1 and 2)
 *     Options          ⚠ none (Owner Decision 2)
 *
 * ⚠ Since hidetzu/tcpip-stack#66 the same buffer also carries our own FIN:
 *
 *     Control Bits     FIN and ACK — ⚠ **one segment, not two**, measured
 *     Sequence Number  `SND.NXT` before the FIN, ⚠ which is the sequence
 *                      number the FIN occupies and ⚠ **the one every
 *                      retransmission of it repeats**
 *     Acknowledgment   RCV.NXT, ⚠ already advanced over their FIN
 *
 * ⚠ An answer is built only when a SYN opened a connection. ⚠ The three places
 * RFC 793 §3.9 asks for a reset or an ack produce a counted reason and nothing
 * on the wire; `docs/SPEC.md` §2 names them. */
void handshake_receive(const struct tcp_header *header, const struct connection_id *id,
                       uint16_t listening_port, struct moment now,
                       const uint8_t *requester_hardware_address,
                       const uint8_t *our_hardware_address,
                       struct connections *connections,
                       uint8_t *reply, size_t reply_bytes,
                       struct handshake_counts *counts,
                       struct handshake_outcome *outcome);

/* What a timer says should happen now. ⚠ An enum never reaches a human. */
enum handshake_due {
    /* ⚠ Nothing is waiting, or what is waiting is not due yet. */
    HANDSHAKE_NOTHING_DUE = 0,

    /* ⚠ The answer should go out again. ⚠ The timer is already reinitialised
     * when this is returned — RFC 793 makes sending again and reinitialising one
     * step, and ⚠ **a caller that then fails to send has spent the attempt.**
     * ⚠ It cannot spin: the give-up timer still runs. */
    HANDSHAKE_ANSWER_AGAIN,

    /* ⚠ Nobody confirmed it and we have stopped waiting. ⚠ The connection is
     * already released when this is returned, so ⚠ **the next SYN can open
     * one** — there is room for exactly one (ADR 0015). */
    HANDSHAKE_GIVE_UP
};

/* Say what `now` makes due, and move the state accordingly.
 *
 * ⚠ `now` is handed in and never read here (ADR 0018), which is why ⚠ **every
 * check of this runs with no clock and no waiting.**
 *
 * ⚠ Giving up is decided before answering again, so ⚠ **at the moment both are
 * due the connection is given up on rather than answered a third time.**
 *
 * ⚠ `counts` gains exactly one when a connection is given up on. ⚠ Answering
 * again is NOT counted here — ⚠ **a reply that was built is not a reply that
 * left**, and the caller counts what the wire took (`CLAUDE.md` §1).
 *
 * ⚠ Nothing is sent here and nothing is printed here. */
/* ⚠ `reply` is the caller's buffer for a whole frame, ⚠ ethernet header
 * included, exactly as `handshake_receive` takes one. ⚠ On
 * `HANDSHAKE_ANSWER_AGAIN` the answer is built into it and `outcome->reply_bytes`
 * says how much; ⚠ **0 for everything else, and a caller must not send what was
 * not built.**
 *
 * `our_hardware_address` is ours; ⚠ **the requester's is remembered in the
 * connection**, because a retransmission has no arriving frame to read it from. */
enum handshake_due handshake_what_is_due(struct connections *connections,
                                         struct moment now,
                                         const uint8_t *our_hardware_address,
                                         uint8_t *reply, size_t reply_bytes,
                                         struct handshake_counts *counts,
                                         struct handshake_outcome *outcome);

/* The next moment anything is waiting for, if anything is.
 *
 * ⚠ Returns false when nothing is waiting. ⚠ For a caller about to decide how
 * long to wait (hidetzu/tcpip-stack#58). */
bool handshake_next_moment(const struct connections *connections,
                           struct moment *due);

#endif /* HANDSHAKE_H */
