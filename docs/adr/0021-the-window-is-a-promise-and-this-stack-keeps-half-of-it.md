# ADR 0021 — The window is a promise, and this stack keeps half of it

Date: 2026-08-29
Status: accepted
Issue: hidetzu/tcpip-stack#64

## Context

⚠ **The answer this stack sends carries a `Window`, and RFC 793 says what that field means:**

> "Window: 16 bits - The number of data octets beginning with the one indicated in the
> acknowledgment field which the sender of this segment is willing to accept."

⚠ **It is a promise, not a formality.**

ADR 0017 chose 0, and ⚠ **0 was the truth then**: nothing in this stack accepted a single octet, so
promising one would have been a claim it could not back.

⚠ **What 0 also does was measured rather than assumed.** Same conditions as `docs/SPEC.md` §3,
Arch Linux `7.0.2-arch1-1`, `unshare -Urn` as uid 1000, no `sudo`, 2026-08-29. A `connect()`,
a wait, a `close()`, watched on the wire:

```text
window 0     SYN  ACK  ACK  ACK  ACK  ACK              ⚠ no FIN, ever
window 1     SYN  ACK  ACK|FIN  ACK|FIN  ...           ⚠ the FIN arrives
window 2     SYN  ACK  ACK|FIN  ACK|FIN  ...           the same
```

⚠ **So a window of 0 makes closing impossible.** ⚠ **The whole "close the connection" milestone
sits behind this one number.**

⚠ **`docs/SPEC.md` §2 had recorded the repeated bare `ACK`s as looking like probes provoked by our
window of 0, and had marked that an inference.** ⚠ **The table above is the measurement that settles
it** — the row is no longer an inference.

## Decision

⚠ **Two questions were put to the owner, and neither was decided here** (`CLAUDE.md` §7-1).

### 1. The window promises one octet

⚠ **1 is the smallest promise that lets a `FIN` through**, measured above. ⚠ Larger would promise
more than anything here can back the difference of.

### 2. Data that arrives is taken delivery of and discarded, and it is said out loud

⚠ **We accepted it and had nobody to give it to.** ⚠ There is no user of this stack to hand an octet
to, and ⚠ **inventing one was not in scope.**

⚠ The alternative — advertising a window and refusing what arrives — ⚠ **would make the number a
promise nothing ever intended to keep.**

## ⚠ What this deliberately does not finish

⚠ **Taking delivery is half of keeping the promise. Telling the sender is the other half.**
⚠ **Sending is not this layer's**, and hidetzu/tcpip-stack#66 owns it.

⚠ **So `RCV.NXT` advances and the sender is never told.** ⚠ **Measured 2026-08-29**: the peer
retransmits the same segment, and each arrival hands over the next octet — one octet of a five-octet
segment at a time, five arrivals to consume it, and the sixth is entirely behind us.

⚠ **This was said before the decision was taken, not discovered afterwards**
(hidetzu/tcpip-stack#64, in the comment recording the two answers). ⚠ **`docs/SPEC.md` §2 carries it
as our gap, with #66 named as what closes it.**

## ⚠ What was read, and what was not

⚠ **RFC 793 §3.9, read from the document itself** (the standing ADR 0016 set).

Used:

- the definition of `Window`, quoted above
- "if the segment contains data that begins outside the window, that data is trimmed" —
  ⚠ **which is why five octets against a promise of one advance `RCV.NXT` by one, rather than
  being refused whole**

⚠ **Read and deliberately not implemented:**

- "segments with higher beginning sequence numbers may be held for later processing."
  ⚠ **Nothing here holds anything.** ⚠ Such a segment is refused and counted. ⚠ `docs/SPEC.md` §2
  names that as our gap.

⚠ **Not read and not relied on:** anything the document says about the window changing over time,
about window updates, or about zero-window probing. ⚠ **The window here is a constant**, and
⚠ calling it a window management scheme would be a wider claim than what is there.

## Consequences

- ⚠ **A `FIN` now reaches this stack**, and is counted as arriving where the connection's state did
  not expect it. ⚠ Reading one is hidetzu/tcpip-stack#65.
- ⚠ **Octets taken are counted in octets**, beside counters that are in segments. ⚠ **The summary
  line says which is which** (`CLAUDE.md` §6).
- ⚠ **`tests/foreign.sh` `a_fin_reaches_us_once_the_window_is_open` is what holds this.** ⚠ It is a
  foreign-tier case and not a real-tier one, ⚠ **because the `FIN` is produced by the Linux kernel's
  own `close()`** and who the other end is is what separates the tiers
  (`.claude/skills/verify/SKILL.md` §1). ⚠ The issue had named `real`; ⚠ **a real-tier check would
  have had to craft the `FIN` itself, which asserts nothing about the window.**
