# ADR 0023 — Our close rides the acknowledgment of theirs, in one segment

Date: 2026-08-29
Status: accepted
Issue: hidetzu/tcpip-stack#66

## Context

⚠ **hidetzu/tcpip-stack#65 read the FIN and stopped there.** ⚠ Measured 2026-08-29, same
conditions as `docs/SPEC.md` §3: ⚠ **the Linux kernel sent its FIN five times** in one `close()`,
because nothing acknowledged it, and ⚠ **the connection was never closed.**

⚠ **RFC 793's eighth step asks for an acknowledgment** — "send an acknowledgment for the FIN" —
and ⚠ **its CLOSE Call for `CLOSE-WAIT` asks for a FIN of our own.**

⚠ **ADR 0022 decided that the arrival of a FIN is the CLOSE this stack has no user to make.**
⚠ **So both are due at the same instant**, which is not the situation the document's Figure 13
draws (there, a user closes some time later).

## Decision

### ⚠ One segment carrying `FIN,ACK`, not two

⚠ **Measured before deciding** (`CLAUDE.md` §7), in a namespace on `lo` with `AF_PACKET`,
2026-08-29 — ⚠ **what the Linux kernel itself does**, with nothing of ours involved:

```text
its application closes 0.6 s after the FIN arrives
        peer -> kernel   ACK|FIN
        kernel -> peer   ACK              ⚠ the acknowledgment on its own
        kernel -> peer   ACK|FIN          ⚠ then its own FIN — two segments

its application closes the moment the FIN arrives
        peer -> kernel   ACK|FIN
        kernel -> peer   ACK|FIN          ⚠ one segment
```

⚠ **ADR 0022 puts this stack in the second situation always.** ⚠ One segment is what the other end
of the conversation does there, and ⚠ **nothing in RFC 793 asks for one segment per event.**

⚠ **This is our decision and it is recorded as ours.** ⚠ The measurement is evidence about what a
peer does, ⚠ **not the document telling us to do the same.**

### ⚠ `CLOSE-WAIT` → `LAST-ACK`, on the grounds hidetzu/tcpip-stack#70 settled

⚠ RFC 793's CLOSE Call section says `CLOSING`. ⚠ **That is a known error**, corrected by
RFC 1122 §4.2.2.20 (a) — "CLOSE Call, CLOSE-WAIT state, p. 61: enter LAST-ACK state, not CLOSING"
— and carried into RFC 9293 §3.10.4. ⚠ **ADR 0022 holds the reading; this ADR only implements it.**

⚠ **Nothing else is taken from RFC 1122 or RFC 9293.** ⚠ Which document this repository holds itself
to is still open, and ⚠ **it matters because those two use the RFC 2119 keywords in capitals and
RFC 793 does not** (ADR 0013). ⚠ Named in ADR 0022 and on hidetzu/tcpip-stack#66.

### ⚠ Our FIN is retransmitted, on the schedule the handshake already had

⚠ RFC 793: "All segments preceding and including FIN will be retransmitted until acknowledged."

⚠ **`LAST-ACK` joins `SYN-RECEIVED` as a state that waits**, and ⚠ **both timers are restarted when
our close is built** — the ones left over from the handshake may already have passed.

⚠ **The intervals are ADR 0019's and are still ours**: RFC 793's retransmission timeout "must be
dynamically determined" from a round trip, and ⚠ **nothing here measures one.** ⚠ `docs/SPEC.md` §2
already names that gap and it is unchanged.

⚠ **Two endings, counted and worded apart**: a handshake nobody confirmed, and a close nobody
acknowledged. ⚠ **Folding them into one reason is the defect hidetzu/tcpip-stack#59 had to undo**,
and the same applies to a send going out again.

### ⚠ `CLOSED` is a name an outcome carries, never a state a block sits in

⚠ RFC 793 calls `CLOSED` "fictional" and defines it as "no connection state at all". ⚠ The block is
released. ⚠ **The name exists so that a connection finishing is something a reader can see**, rather
than a line that simply stops appearing (`CLAUDE.md` §1: an uncounted thing is invisible).

## ⚠ What happens when our close cannot be built

⚠ The connection is left in `CLOSE-WAIT`, ⚠ **`SND.NXT` is put back**, and ⚠ **the block is not
given back.** ⚠ Their FIN was read and `RCV.NXT` moved over it, so ⚠ **forgetting the connection
would make the next copy of that FIN look like a new one.** ⚠ Counted as ours, not the sender's.

## ⚠ Re-read against RFC 9293 on 2026-08-29

⚠ hidetzu/tcpip-stack#87. ⚠ **Still ours, and the sentence that leaves it ours is
the one already quoted here**: RFC 9293 §3.10.4 says `CLOSE-WAIT` "send a FIN
segment, enter LAST-ACK state" ⚠ **and says nothing about how many segments the
acknowledgment and the FIN occupy.** ⚠ One segment rather than two is a decision,
⚠ **evidenced by what the Linux kernel does and not required by the document.**

## Consequences

⚠ **Measured after building it, 2026-08-29, same conditions:**

```text
before   the kernel sent its FIN 5 times; the connection was never closed
after    the kernel sent its FIN once and stopped; ss reported TIME-WAIT
```

⚠ **`TIME-WAIT` is the kernel's own state after it has had our FIN and acknowledged it** — ⚠ which
is the other side's verdict that we answered properly, and ⚠ **not our word for it.**

- ⚠ **The connection is released when it finishes**, so the next SYN can open one — there is room
  for exactly one (ADR 0015).
- ⚠ **`ss` shows `TIME-WAIT` and not "gone"**, because the peer holds it for 2 MSL of its own
  accord. ⚠ **That is the peer's business and nothing here can shorten it**;
  hidetzu/tcpip-stack#67 is where what `ss` should show is decided.
