# 0020 — The answer really goes out again, and a false sentence corrected

Date: 2026-08-29
Status: accepted
Issue: hidetzu/tcpip-stack#59

## Context

Where hidetzu/tcpip-stack#56, #57 and #58 meet: ⚠ **the answer to an unconfirmed
SYN really goes out again on the wire**, twice, and ⚠ **then the connection is
given up on.**

### ⚠ Watched from outside our own output

⚠ **Our own summary says we answered again. That is our word for it.**
⚠ `.claude/rules/layers.md` question 3 is why that is not enough: ⚠ a stack that
only agrees with its own tests has proved nothing.

⚠ **So the frames are counted with an `AF_PACKET` socket on `tap0`**, which
neither holds the tun fd nor asks any parser of ours what it is looking at
(ADR 0009).

⚠ **It must be opened with `ETH_P_ALL`.** ⚠ Measured 2026-08-29: ⚠ **a packet
socket opened with protocol 0 receives nothing** — the first attempt at this
watched and saw no frames at all, ⚠ **and that was the instrument, not the
system.** ⚠ Recorded because the same mistake reads exactly like "the route does
not exist".

## Decision

### ⚠ Owner Decision 1 — them asking again is not us answering again

⚠ **hidetzu/tcpip-stack#57 gave both events the same reason**, and ⚠ **the
sentence printed for one of them was false:**

```
10.0.0.99:40000 asked again; nothing changed     ⚠ nobody asked. Our timer fired
```

⚠ **It was live on `main`, and #57's completion report did not mention it — it
was missed.** ⚠ Found while measuring for #59.

⚠ Two reasons now, two sentences, two counts:

```
they retransmitted a SYN:
  10.0.0.1:50568 asked again; nothing changed

our timer fired:
  10.0.0.1:50568 has not confirmed it; the answer went out again

1 answer went out again because nobody had confirmed it
```

⚠ **One number for both would make "how many times they asked" and "how many
times we answered" the same number**, and they are different questions
(`.claude/rules/c.md`).

### ⚠ Owner Decision 2 — the connection remembers where to answer

⚠ **A retransmission has no arriving frame to read a hardware address from**, so
the connection keeps the requester's.

⚠ **`docs/SPEC.md` §2's row is narrowed rather than dropped.** ⚠ It said a reply
goes to addresses "read out of that frame and never out of a table this stack
does not keep". ⚠ **That stops being exactly true**, and the honest narrowing is:

⚠ **one field of one connection, not reachable by address, invisible to any other
connection, and gone when the connection is.** ⚠ **Saying "this stack keeps a
neighbour cache" would be a wider claim than what is there.**

### ⚠ Nothing is re-chosen between attempts

⚠ **The same answer, octet for octet.** ⚠ A peer that did get the first must not
be told a different number — ⚠ the same reasoning ADR 0016 used in the other
direction for a retransmitted SYN.

### Counted once the wire took it

⚠ **An answer that was built is not an answer that left** (`CLAUDE.md` §1). ⚠ The
caller moves `answered_again` after `tap_write_frame` took the whole frame — the
division everything else here uses.

## Consequences

- ⚠ **The milestone is met**: `SYN|ACK from us x3` on the wire — the first answer
  and two more — ⚠ **counted by something that is not ours**, and ⚠ **no fourth**,
  because the watch outlasts the schedule by a second.
- ⚠ **An answer that cannot be built into the caller's buffer is counted as ours**
  and the attempt is still spent — the timer has already moved. ⚠ The give-up
  timer still runs, so it cannot spin.
- ⚠ **The real tier grew again.** ⚠ `docs/SPEC.md` §3 carries what it costs; ⚠ the
  new case waits about four seconds, which is ⚠ **the price of watching a
  schedule run out on a real device.**
- ⚠ **`docs/SPEC.md` §2 still says nothing is sent after a connection is open.**
  ⚠ Answering an unconfirmed SYN again is not that.
