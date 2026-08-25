# Layers

⚠ **`MUST` = required, `SHOULD` = default, `MAY` = optional.**

## The questions this project answers

Before adding anything, ⚠ **say which of these it answers.**

1. Does what arrived on the wire mean what we think it means?
2. Does our state machine do what the RFC says it must?
3. Can we show that, against something other than ourselves?

- MUST NOT: ⚠ **Add something that answers none of them because it looked useful.**

⚠ **Question 3 is the one that gets skipped.** ⚠ **A stack that only agrees with its own tests
has proved nothing.** ⚠ The other side of the conversation has to be something we did not write —
the Linux kernel stack, `ping`, `tcpdump`, a captured trace.

## The four layers

```text
Wire  →  Parse  →  State  →  Report
```

⚠ **Never mix them.**

### Wire (the octets that actually arrived)
Bytes read from the tap/tun fd, or handed to it. Lengths, offsets, network byte order.

- MUST: ⚠ **Never let the raw byte layout escape upward.** No `struct` overlaid on a packet
  buffer travelling into protocol code.
- MUST NOT: ⚠ **Never assume alignment**, and ⚠ **never assume the buffer is as long as the header
  claims.** ⚠ The length field is an assertion by the sender, not a fact.
- MUST: ⚠ **Everything here is untrusted input.** It arrives from outside.

### Parse (validated, in host terms)
Header fields checked and converted. ⚠ **This is where "malformed" is decided.**

- MUST: ⚠ **Separate "malformed" from "well-formed but unsupported".**
  ⚠ They are different answers and they call for different behaviour on the wire.
- MUST: ⚠ **Record why something was rejected**, at least well enough to count it.
  ⚠ A silent drop is indistinguishable from a packet that never arrived (`CLAUDE.md` §1).

### State (what the protocol means)
The TCB, the ARP cache, the routing decision, counters, timers.

- MUST: ⚠ **Numbers and state only.** ⚠ **No wording lives here.**
- MUST: ⚠ **Distinguish what was observed from what was inferred**
  (owner: `CLAUDE.md` §1). A retransmission counter is observed; an RTT estimate is inferred.
- MUST: ⚠ **Name states after the RFC's names**, exactly.

### Report (what a human reads)
Log lines, CLI output, error messages, statistics.

- MUST: ⚠ **All prose is written here, and only here.**
- MUST: ⚠ **Never print an internal enum at a human** (`CLAUDE.md` §4).

## Before adding anything

1. Which of the three questions does it answer?
2. Required, or an aid?
3. Wire / Parse / State / Report — which one?
4. ⚠ **What does it do when the data is absent, truncated, or hostile?**
5. Does the structure survive a second protocol being added beside it?

- MUST NOT: ⚠ **Never abstract because a second case might appear someday.**
- SHOULD: ⚠ **Generalise once the second case actually exists.**
