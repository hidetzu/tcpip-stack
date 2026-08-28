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

enum handshake_decision {
    /* ⚠ The connection moved to a state it was not in. `outcome->state` says
     * which. */
    HANDSHAKE_MOVED = 0,

    /* ⚠ Nothing moved, and `outcome->reason` says why. ⚠ That includes the
     * ordinary case of a retransmitted SYN, which is not an error. */
    HANDSHAKE_STAYED
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
 * ⚠ `counts` gains exactly one, under the reason decided.
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
 *     Window           ⚠ 0, because this stack accepts no data at all and
 *                      ⚠ anything else would be a claim it cannot back
 *                      (hidetzu/tcpip-stack#44 Owner Decision 3)
 *     Options          ⚠ none (Owner Decision 2)
 *
 * ⚠ An answer is built only when a SYN opened a connection. ⚠ The three places
 * RFC 793 §3.9 asks for a reset or an ack produce a counted reason and nothing
 * on the wire; `docs/SPEC.md` §2 names them. */
void handshake_receive(const struct tcp_header *header, const struct connection_id *id,
                       uint16_t listening_port,
                       const uint8_t *requester_hardware_address,
                       const uint8_t *our_hardware_address,
                       struct connections *connections,
                       uint8_t *reply, size_t reply_bytes,
                       struct handshake_counts *counts,
                       struct handshake_outcome *outcome);

#endif /* HANDSHAKE_H */
