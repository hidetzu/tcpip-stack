/* State — where what we know about a connection lives, and who owns it.
 *
 * ⚠ No fd, no clock, no prose (`.claude/rules/layers.md`). ⚠ Nothing here reads
 * an octet of a segment and nothing here decides anything: it holds numbers and
 * hands them back (hidetzu/tcpip-stack#42).
 *
 * ⚠ This is the first thing in this repository that lives between frames.
 * Everything before it — the ARP responder, the echo responder — is a pure
 * function of one frame, and ⚠ `docs/SPEC.md` §2 records "no ARP cache" as a
 * decision rather than an omission. ⚠ ADR 0015 says why this one had to exist.
 *
 * ⚠ The names are RFC 793's own, read on 2026-08-28 from rfc-editor.org and
 * cross-checked against the copy at datatracker.ietf.org. ⚠ Both agreed:
 *
 *     "To store this information we imagine that there is a data structure
 *      called a Transmission Control Block (TCB)."
 *     "To provide for unique addresses within each TCP, we concatenate an
 *      internet address identifying the TCP with a port identifier to create a
 *      socket which will be unique throughout all networks connected together."
 *     "A connection is fully specified by the pair of sockets at the ends."
 *
 * ⚠ So a connection is identified by two sockets and never by where it sits in
 * an array (`.claude/skills/change-review/SKILL.md` §4: matching by position or
 * by arrival order is the defect). */
#ifndef CONNECTION_H
#define CONNECTION_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "moment.h"

/* ⚠ This file includes nothing from the layers around it. An address is four
 * octets here and that is all it needs to know (the same shape `src/tcp.h`
 * takes for the pseudo-header). */
#define CONNECTION_ADDRESS_BYTES 4
#define CONNECTION_HARDWARE_ADDRESS_BYTES 6

/* One of RFC 793's sockets: "an internet address identifying the TCP with a
 * port identifier". */
struct socket {
    uint8_t address[CONNECTION_ADDRESS_BYTES];
    uint16_t port;
};

/* ⚠ "A connection is fully specified by the pair of sockets at the ends."
 *
 * ⚠ `local` is the end this stack answers for. ⚠ Both are compared, always: a
 * connection that differs only in the remote port is a different connection,
 * and ⚠ "A local socket may participate in many connections to different
 * foreign sockets." */
struct connection_id {
    struct socket local;
    struct socket remote;
};

/* What we know about one connection.
 *
 * ⚠ It holds its identity and nothing else yet. ⚠ The state RFC 793 names and
 * the sequence numbers arrive with hidetzu/tcpip-stack#43 — ⚠ this issue
 * decides where they will live and does not decide what they are.
 *
 * ⚠ Owner: `struct connections`. ⚠ Nothing here is allocated and nothing is
 * freed; a caller hands in the storage and it lives exactly as long as that
 * does (`.claude/rules/c.md`: prefer a caller-supplied buffer). */
/* RFC 793's own state names, read on 2026-08-28 and quoted:
 *
 *   "LISTEN - represents waiting for a connection request from any remote TCP
 *    and port."
 *   "SYN-RECEIVED - represents waiting for a confirming connection request
 *    acknowledgment after having both received and sent a connection request."
 *   "ESTABLISHED - represents an open connection, data received can be
 *    delivered to the user."
 *   "CLOSE-WAIT - represents waiting for a connection termination request
 *    from the local user."
 *
 *   "LAST-ACK - represents waiting for an acknowledgment of the connection
 *    termination request previously sent to the remote TCP (which includes an
 *    acknowledgment of its connection termination request)."
 *   "CLOSED - represents no connection state at all."
 *
 * ⚠ Named exactly as the document names them (`.claude/rules/layers.md`).
 * ⚠ The states this milestone does not reach are not here: ⚠ **a state with no
 * transition into it would be a claim that we implement it.** ⚠ So
 * `TIME-WAIT`, `FIN-WAIT-1`, `FIN-WAIT-2` and `CLOSING` are absent:
 * ⚠ **every one of them belongs to the side that closed first, and this stack
 * never does** (RFC 793 Figures 6 and 13; ADR 0022). */
enum connection_state {
    CONNECTION_LISTEN = 0,
    CONNECTION_SYN_RECEIVED,
    CONNECTION_ESTABLISHED,

    /* ⚠ The other side has closed and ⚠ **we have not.** ⚠ The document's own
     * definition names a local user, and ⚠ **there is none here** — what this
     * stack does instead is ADR 0022's decision, not the document's.
     *
     * ⚠ **No connection rests here.** ⚠ Since hidetzu/tcpip-stack#66 the FIN's
     * arrival is the CLOSE, so the same pass goes on to `LAST-ACK` — ⚠ this is
     * where a connection is left only when the answer could not be built. */
    CONNECTION_CLOSE_WAIT,

    /* ⚠ Our own FIN has gone out and ⚠ **nobody has acknowledged it yet.**
     *
     * ⚠ RFC 793's CLOSE Call section says `CLOSE-WAIT` enters `CLOSING`;
     * ⚠ **that is a known error.** ⚠ RFC 1122 §4.2.2.20 (a): "CLOSE Call,
     * CLOSE-WAIT state, p. 61: enter LAST-ACK state, not CLOSING." ⚠ RFC 9293
     * §3.10.4 carries the correction into the current specification (ADR 0022).
     */
    CONNECTION_LAST_ACK,

    /* ⚠ **Nothing is ever in this state**, and that is the document's own
     * framing: RFC 793 calls `CLOSED` "fictional" and defines it as "no
     * connection state at all". ⚠ It is what an outcome says when the block was
     * released — ⚠ **so that a connection finishing has a name a reader can
     * see**, rather than simply vanishing (hidetzu/tcpip-stack#66). */
    CONNECTION_CLOSED
};

struct transmission_control_block {
    bool in_use;
    struct connection_id id;

    enum connection_state state;

    /* RFC 793's own send-sequence names, from the LISTEN state's rules:
     *
     *   "ISS should be selected and a SYN segment sent of the form:
     *      <SEQ=ISS><ACK=RCV.NXT><CTL=SYN,ACK>
     *    SND.NXT is set to ISS+1 and SND.UNA to ISS."
     *
     * ⚠ `iss` is what we chose; `snd_una` and `snd_nxt` are the window an
     * acknowledgment has to fall inside (hidetzu/tcpip-stack#43, ADR 0016). */
    uint32_t iss;
    uint32_t snd_una;
    uint32_t snd_nxt;

    /* ⚠ RFC 9293 §3.3.1 names this among the TCB's send-sequence variables:
     * "SND.WND - send window". ⚠ **Borrowed exactly**
     * (`.claude/rules/layers.md`).
     *
     * ⚠ **What the peer said it will accept**, read off their `Window` field.
     * ⚠ Until hidetzu/tcpip-stack#126 nothing read it at all — ⚠ **there was
     * nothing to send, so there was nothing to send INTO.**
     *
     * ⚠ **Nothing may be put on the wire past `SND.UNA + SND.WND`.** ⚠ That is
     * not a nicety: octets past it are octets the peer told us it cannot take. */
    uint16_t snd_wnd;

    /* How much of what we were asked to send is still to go, and where it
     * starts.
     *
     * ⚠ **There is no buffer, and that is on purpose.** ⚠ The octets are a
     * pattern computed from the sequence offset (`handshake_octet_at`), so
     * ⚠ **nothing is allocated and nothing has to be freed** (ADR 0015:
     * connection state lives in one block and nothing frees on its own).
     *
     * ⚠ **What this cannot do is retransmit** — ⚠ an octet handed over is gone
     * from `still_to_send` and nothing remembers it was unacknowledged.
     * ⚠ **hidetzu/tcpip-stack#126 Owner Decision: that is out of scope and the
     * limitation is recorded** (`docs/SPEC.md` §2), ⚠ **not discovered later.** */
    uint32_t still_to_send;

    /* When the earliest unacknowledged octet should go out again, and whether
     * anything is waiting for it at all.
     *
     * ⚠ RFC 6298 §5.1: "Every time a packet containing data is sent (including
     * a retransmission), if the timer is not running, start it running."
     * ⚠ §5.2: "When all outstanding data has been acknowledged, turn off the
     * retransmission timer." ⚠ **Those two are what `waiting_for_an_ack` is.**
     *
     * ⚠ **The interval is NOT an RTO** (hidetzu/tcpip-stack#129 Owner Decision):
     * ⚠ see `HANDSHAKE_SEND_DATA_AGAIN_AFTER_MILLISECONDS`. */
    bool waiting_for_an_ack;
    struct moment send_again_at;

    /* RFC 793's own receive-sequence names, same rules:
     *
     *   "Set RCV.NXT to SEG.SEQ+1, IRS is set to SEG.SEQ"
     *
     * ⚠ `irs` is the sequence number their SYN carried; `rcv_nxt` is the next
     * one we expect from them. */
    uint32_t irs;
    uint32_t rcv_nxt;

    /* ⚠ RFC 9293 §3.3.1 names this among the TCB's receive-sequence variables:
     * "RCV.WND - receive window". ⚠ **Borrowed exactly**
     * (`.claude/rules/layers.md`).
     *
     * ⚠ **It lives here because the document puts it here**, not because it
     * varies per connection — ⚠ every block in this build is given the same
     * number, derived once from the device's MTU
     * (hidetzu/tcpip-stack#119, ADR 0028).
     *
     * ⚠ **It never shrinks**, and that is provable rather than convenient: every
     * octet is discarded as it is taken, so ⚠ **the window is always this many
     * from `rcv_nxt`**, and `rcv_nxt` only advances. RFC 793: "The total of
     * RCV.NXT and RCV.WND should not be reduced." */
    uint16_t rcv_wnd;

    /* What we advertised to them, and what they told us.
     *
     * ⚠ RFC 9293 §3.7.1 names the second "send MSS" — ⚠ **"the send MSS (that
     * reflects the available reassembly buffer size at the remote host)"** —
     * and the first is what our own MSS Option carried.
     *
     * ⚠ **`send_mss_was_told_to_us` is separate from the value on purpose.**
     * ⚠ `MUST-15` says an absent option means a default of 536, ⚠ **so "they
     * said 536" and "they said nothing" are different facts** and a reader that
     * could not tell them apart would be guessing (`CLAUDE.md` §1).
     *
     * ⚠ **NOTHING READS `send_mss` YET.** ⚠ This stack originates no data, so
     * ⚠ **there is no segment whose size it could constrain** — and
     * ⚠ **hidetzu/tcpip-stack#123's Owner Decision is that storing it is NOT
     * `MUST-14` met.** ⚠ It is met when a consumer exists that uses it as the
     * effective send MSS (`MUST-16`), and ⚠ **`docs/conformance.md` says so.** */
    uint16_t mss_we_advertise;
    uint16_t send_mss;
    bool send_mss_was_told_to_us;

    /* When the answer should go out again, and when we stop waiting for one.
     *
     * ⚠ Both are handed in rather than read (ADR 0018), and ⚠ **both mean
     * something only while the state is `SYN-RECEIVED`** — a connection that
     * reached `ESTABLISHED` is waiting for nothing.
     *
     * ⚠ RFC 793 says the retransmission timer is reinitialised on each send,
     * ⚠ **not measured from when the connection opened** (ADR 0019). */
    struct moment answer_due;
    struct moment give_up_at;

    /* Where an answer has to go on the wire.
     *
     * ⚠ Read out of the frame that asked, and ⚠ **kept because a retransmission
     * has no frame to read it from** (hidetzu/tcpip-stack#59), ⚠ **and because
     * data of ours goes out unprompted** (hidetzu/tcpip-stack#126).
     *
     * ⚠ hidetzu/tcpip-stack#126 added a SECOND field for the second reason
     * before noticing this one. ⚠ **Two fields holding the same address is two
     * copies of one decision** (`CLAUDE.md` §3), ⚠ **and they would have
     * diverged the first time either was written from a different place.**
     *
     * ⚠ This is not a neighbour cache, and `docs/SPEC.md` §2 says which:
     * ⚠ **it is one field of one connection, it cannot be looked up by address,
     * no other connection can see it, and it goes when the connection does.** */
    uint8_t requester_hardware_address[CONNECTION_HARDWARE_ADDRESS_BYTES];
};

/* Room for the connections this build can hold at once.
 *
 * ⚠ One, and that is an owner decision with a measurement behind it
 * (hidetzu/tcpip-stack#42 Owner Decision 1, ADR 0015). ⚠ Nothing here frees a
 * block on its own — there is no clock and no `FIN` handling — so ⚠ **a block
 * that is taken stays taken**, and a larger number would only postpone the same
 * wall while looking like a table. */
#define CONNECTIONS_AT_ONCE 1

/* ⚠ Owner: the caller. ⚠ Zeroed by `connections_forget_everything` before use;
 * nothing in this file allocates. */
struct connections {
    struct transmission_control_block block[CONNECTIONS_AT_ONCE];
};

/* ⚠ Counted, never dropped in silence: an uncounted refusal is invisible, and
 * an invisible refusal looks exactly like a segment that never arrived
 * (`.claude/rules/c.md`). ⚠ Owner: the caller, the same way `struct arp_counts`
 * and `struct echo_counts` are. */
struct connection_counts {
    unsigned long refused_for_want_of_room;
};

/* Put a set of connections back to holding nothing.
 *
 * ⚠ Must be called before anything else. ⚠ Reading a block that was never given
 * a value is the bug this exists to make impossible. */
void connections_forget_everything(struct connections *connections);

/* Find the block for `id`, or NULL when there is none.
 *
 * ⚠ Matched on both sockets, ⚠ never on position and never on arrival order. */
struct transmission_control_block *connections_find(struct connections *connections,
                                                    const struct connection_id *id);

/* Why a block was not taken. ⚠ An enum never reaches a human (`CLAUDE.md` §4). */
enum connection_take {
    CONNECTION_TAKEN = 0,

    /* ⚠ Ours, and not the sender's. ⚠ Every block is in use and this build has
     * room for one. ⚠ The sentence a human reads says so rather than pointing at
     * whoever asked (hidetzu/tcpip-stack#42 Owner Decision 1, `CLAUDE.md` §4-1).
     *
     * ⚠ There is no wording for it in `src/report.c` yet, on purpose: nothing
     * calls this from the program until hidetzu/tcpip-stack#44, and ⚠ a line
     * with no caller is a line no check exercises. ⚠ ADR 0015 carries the
     * approved wording until then. */
    CONNECTION_NO_ROOM
};

/* RFC 9293 §3.7.1, quoted: "If an MSS Option is not received at connection
 * setup, TCP implementations MUST assume a default send MSS of 536 (576 - 40)
 * for IPv4 or 1220 (1280 - 60) for IPv6 (MUST-15)."
 *
 * ⚠ **IPv4 only, because nothing here reads or writes IPv6** — and the document
 * gives its arithmetic, so ⚠ **the number is quoted rather than computed here.** */
#define CONNECTION_DEFAULT_SEND_MSS 536u

/* Take a block for `id`.
 *
 * On `CONNECTION_TAKEN`, *taken points at it. ⚠ On `CONNECTION_NO_ROOM`, *taken
 * is NULL and `counts->refused_for_want_of_room` has gained exactly one.
 *
 * ⚠ Taking an id that is already held hands back the block that holds it rather
 * than a second one: ⚠ the kernel retransmits a SYN — 7 times in one measured
 * `connect()`, 2026-08-28 — and ⚠ a retransmission is the same connection, not
 * a new one. */
enum connection_take connections_take(struct connections *connections,
                                      const struct connection_id *id,
                                      struct connection_counts *counts,
                                      struct transmission_control_block **taken);

/* Give a block back.
 *
 * ⚠ Everything in it is cleared, so ⚠ the next connection to take it cannot read
 * what the last one left (`.claude/skills/change-review/SKILL.md` §4: state
 * overwritten by a stale result reads, from outside, as something observed).
 * ⚠ A NULL block is ignored. */
void connections_release(struct connections *connections,
                         struct transmission_control_block *block);

#endif /* CONNECTION_H */
