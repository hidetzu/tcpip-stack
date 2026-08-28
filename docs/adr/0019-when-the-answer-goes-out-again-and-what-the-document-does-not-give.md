# 0019 — When the answer goes out again, and what the document does not give

Date: 2026-08-28
Status: accepted
Issue: hidetzu/tcpip-stack#57

## Context

⚠ **RFC 793 §3.7 and §3.9 were read from the document itself**, not through a
summary. ⚠ **Three of the findings changed the shape of the decision.**

### What was read, quoted

```
Because of the variability of the networks that compose an internetwork system
and the wide range of uses of TCP connections the retransmission timeout must be
dynamically determined.  One procedure for determining a retransmission time out
is given here as an illustration.

  ... Measure the elapsed time between sending a data octet with a particular
  sequence number and receiving an acknowledgment that covers that sequence
  number ...  This measured elapsed time is the Round Trip Time (RTT). ...
  RTO = min[UBOUND,max[LBOUND,(BETA*SRTT)]]
  where UBOUND is an upper bound on the timeout (e.g., 1 minute), LBOUND is a
  lower bound on the timeout (e.g., 1 second) ...

RETRANSMISSION TIMEOUT
  For any state if the retransmission timeout expires on a segment in the
  retransmission queue, send the segment at the front of the retransmission
  queue again, reinitialize the retransmission timer, and return.

USER TIMEOUT
  For any state if the user timeout expires, flush all queues, signal the user
  "error:  connection aborted due to user timeout" in general and for any
  outstanding calls, delete the TCB, enter the CLOSED state and return.
```

### ⚠ The three findings

1. ⚠ **The document says the timeout must be dynamically determined**, and the
   procedure it gives needs a Round Trip Time. ⚠ **Nothing here measures a round
   trip.** ⚠ **So this stack does not do what the document asks**, and
   `docs/SPEC.md` §2 names that as a gap rather than leaving it silent.
   ⚠ **RFC 793 uses no RFC 2119 keywords in capitals** (ADR 0013), so ⚠ nothing
   here says the document requires it.
2. ⚠ **The retransmission timer is reinitialised on each send**, ⚠ **not measured
   from when the connection opened.** ⚠ The document answers that directly, and
   `the_answer_is_due_a_second_after_each_send` asserts it.
3. ⚠ **Giving up is not a count of attempts.** ⚠ It is a separate timer — the
   user timeout — and it ⚠ **"delete[s] the TCB"**. ⚠ **The issue was written
   asking "how many attempts", and that is not the shape the document has.**

## Decision

### ⚠ Owner Decision 1 — a second between answers, three seconds before giving up

⚠ **1000 ms is the document's own example lower bound** — "LBOUND is a lower
bound on the timeout (e.g., 1 second)". ⚠ **Going below it would mean going under
the only floor the document offers, and the reason would have been that a check
is cheaper that way.** ⚠ That reason was refused.

⚠ **3000 ms is ours and has no grounds in the document.** ⚠ Its example upper
bound is a minute; ⚠ **a check waiting a minute would change what the real tier
costs by an order of magnitude** (`docs/SPEC.md` §3 owns that number).
⚠ **Chosen for what a check can afford, and recorded as exactly that** —
⚠ **not dressed up as a reading.**

⚠ So the answer goes out again after a second and after two, and ⚠ **the
connection is given up on at three.**

### ⚠ Owner Decision 2 — giving up releases the connection

⚠ **The document's "delete the TCB", read.** ⚠ There is room for one connection
(ADR 0015), so ⚠ **releasing it means the next SYN can open one** rather than
being refused for want of room by a connection nobody will ever confirm.

⚠ The wording is in `src/report.c` and asserted:

```
  10.0.0.1:50568 never confirmed it; the connection was given up on
1 connection was given up on after nobody confirmed it
```

⚠ **Nobody confirmed it.** ⚠ **Not "they did not answer", and nothing about them
being wrong** — ⚠ we stopped waiting (`CLAUDE.md` §4-1).

### ⚠ Giving up is decided before answering again

⚠ **At the moment both are due, the connection is given up on.** ⚠ The other
order sends an answer nobody is waiting for any more. ⚠ Asserted at exactly three
seconds.

### ⚠ The clock may not move, and that is the document's word

⚠ `man 2 clock_gettime`: "successive calls may—depending on the
architecture—return identical (not-increased) time values" (ADR 0018).

⚠ **So being due must not depend on the clock having moved.** ⚠ The timer is
moved forward when the answer becomes due, so ⚠ **asking again at the same moment
says nothing is due** — ⚠ a caller in a loop cannot send for ever without the
clock moving. ⚠ `a_clock_that_does_not_move_neither_spins_nor_stops` asserts both
halves: not due again at the same moment, ⚠ **and due again once it moves.**

### ⚠ Answering again is one step with reinitialising

⚠ The document makes them one — "send ... again, reinitialize the retransmission
timer". ⚠ **So the timer moves when `handshake_what_is_due` says an answer is
due, and a caller that then fails to send has spent the attempt.** ⚠ It cannot
spin, because the give-up timer still runs. ⚠ **Said in the header rather than
left to be discovered.**

## Consequences

- ⚠ **Nothing sends anything.** hidetzu/tcpip-stack#58 makes the wait end when a
  timer is due and #59 puts the answer on the wire. ⚠ **Until then nothing calls
  `handshake_what_is_due` from the program.**
- ⚠ **Answering again is not counted here.** ⚠ A reply that was built is not a
  reply that left, and the caller counts what the wire took — the division ARP,
  ICMP and the handshake already use.
- ⚠ **Every check of this runs with no clock and no waiting**, ⚠ **which is what
  ADR 0018 bought.** ⚠ The moment is made up in the case and handed in.
- ⚠ **The TCB does not remember the requester's hardware address yet**, so
  ⚠ **an answer cannot actually be addressed on a retransmission.**
  ⚠ hidetzu/tcpip-stack#59 has to deal with that, and ⚠ **it changes what
  `docs/SPEC.md` §2 says about keeping no neighbour cache** — ⚠ named here so it
  is not discovered there.
