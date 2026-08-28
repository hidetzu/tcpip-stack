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

/* ⚠ This file includes nothing from the layers around it. An address is four
 * octets here and that is all it needs to know (the same shape `src/tcp.h`
 * takes for the pseudo-header). */
#define CONNECTION_ADDRESS_BYTES 4

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
 *
 * ⚠ Named exactly as the document names them (`.claude/rules/layers.md`).
 * ⚠ The states this milestone does not reach are not here: ⚠ **a state with no
 * transition into it would be a claim that we implement it.** */
enum connection_state {
    CONNECTION_LISTEN = 0,
    CONNECTION_SYN_RECEIVED,
    CONNECTION_ESTABLISHED
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

    /* RFC 793's own receive-sequence names, same rules:
     *
     *   "Set RCV.NXT to SEG.SEQ+1, IRS is set to SEG.SEQ"
     *
     * ⚠ `irs` is the sequence number their SYN carried; `rcv_nxt` is the next
     * one we expect from them. */
    uint32_t irs;
    uint32_t rcv_nxt;
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
