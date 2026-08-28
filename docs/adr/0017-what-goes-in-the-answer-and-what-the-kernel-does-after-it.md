# 0017 — What goes in the answer, and what the kernel does after it

Date: 2026-08-28
Status: accepted
Issue: hidetzu/tcpip-stack#44

## Context

Where hidetzu/tcpip-stack#40 to #43 meet: ⚠ **the kernel's own `connect()`
succeeds and `ss` reports the connection established.**

⚠ **The verdict is the kernel's, not ours** (`.claude/rules/layers.md`, question
3): it checks the TCP checksum over a pseudo-header and the acknowledgment
number before it completes a connection.

⚠ **And that alone proves nothing about what we validated** — ⚠ a stack that
never looked at an incoming checksum would complete this handshake too
(`CLAUDE.md` §1). ⚠ **The second check is not optional and it is not a nicety.**

## Decision

### ⚠ Owner Decision 1 — `--tcp-port`

⚠ hidetzu/tcpip-stack#35 Owner Decision 3 refused `--ttl` as an option nobody
needed. ⚠ **This is a different kind of thing:** ⚠ **a TTL is how we answer, a
port is what we answer for** — the same kind as `--ipv4`. ⚠ Hard-coding it would
leave this as the one piece of "what we answer for" that is not on the command
line.

⚠ **A port with no identity is refused rather than accepted and ignored**, the
shape hidetzu/tcpip-stack#19 Owner Decision 6 set for half an identity.

### ⚠ Owner Decision 2 — no options in the answer

⚠ hidetzu/tcpip-stack#40 decided options are walked and never interpreted.
⚠ **Sending something we cannot read would be a claim we cannot back.**

⚠ **The kernel's own SYN carries five** — Maximum Segment Size, SACK permitted,
Timestamps, No-Operation, Window Scale (measured, `tests/fixtures/tcp-syn-74.hex`).
⚠ **What its answer to none of them would be was measured after this was built,
not assumed before it:** ⚠ `connect()` succeeds, 3 runs of 3.

### ⚠ Owner Decision 3 — the window we advertise is 0

RFC 793: `"Window: 16 bits. The number of data octets ... which the sender of
this segment is willing to accept."`

⚠ **This stack accepts no data at all.** ⚠ **So 0 is the truth**, and anything
else would be a claim it cannot back (`CLAUDE.md` §1).

⚠ **Measured after building it, not assumed before:** the handshake completes.

### ⚠ Owner Decision 4 — counted once the wire took it

⚠ **A reply that was built is not a reply that left**, the same division
`arp_respond` and `echo_respond` use. ⚠ `handshake_counts.answered` is moved by
the caller, after `tap_write_frame` took the whole frame.

## ⚠ What the kernel does after ESTABLISHED — observed

⚠ **AC 6.** Same conditions, 2026-08-28, ⚠ **3 runs, all three identical.** A
`connect()`, a wait, then `close()`:

```
        len  flags  window   seq          ack          payload
        74   SYN    64240    69170264     0            0
        54   ACK    64240    69170265     3735928560   0
        54   ACK    64240    69170264     3735928560   0     <- and five more
```

⚠ **Observation:** after the connection is open the kernel sends bare `ACK`s,
repeatedly, ⚠ **carrying no payload and a sequence number one below the one it
already sent.** ⚠ **No `FIN` and no `RST` arrived** in the window observed.

⚠ **Inference, kept separate** (`CLAUDE.md` §7): those look like probes provoked
by the window of 0, and ⚠ nothing here answers them, so the peer never learns the
window opened and ⚠ **the connection is never closed.** ⚠ **Not measured, and not
claimed as measured.**

⚠ **Each of them is counted** as arriving where the connection's state did not
expect it. ⚠ `docs/SPEC.md` §2 records that nothing after `ESTABLISHED` is
implemented.

## ⚠ How AC 2 was met, and the route that did not work

⚠ **First attempt:** write a captured SYN with one octet flipped straight onto
the device. ⚠ **It cannot work — two processes cannot hold one TAP device**,
which `tests/real.sh` `a_second_attach_to_the_same_device_is_refused` already
asserts. ⚠ The harness change for it was reverted rather than left as a feature
with no caller.

⚠ **What works:** build the segment and hand it to the kernel on a raw socket, so
⚠ **the kernel routes it out `tap0`** and our stack reads it exactly as it reads
anything else.

⚠ **Both halves in one run**: the same segment with the right checksum and with a
wrong one. ⚠ Without the first, the case would pass for a stack that answered
nothing at all.

## Consequences

- ⚠ **A datagram that is for us and carries TCP is diverted before
  `echo_respond`.** ⚠ One that is malformed, a fragment, or addressed elsewhere
  still reaches it and is counted there, so ⚠ **those numbers keep meaning what
  they meant.** ⚠ What changes is the population of "carried a protocol we do not
  act on": TCP for us is no longer in it, ⚠ **because it is now one we act on.**
- ⚠ **`ipv4_parse_header` runs twice for such a frame.** ⚠ The same function
  called twice, not a second implementation of the question (`CLAUDE.md` §3), and
  it keeps every IPv4-level reason counted in one place.
- ⚠ **Two files name TCP's protocol number** — `src/tcp.h` for the pseudo-header
  and `src/ipv4.h` for the internet header — because each deliberately knows
  nothing of the other. ⚠ **`_Static_assert` in `src/handshake.c` is the
  mechanical cross-check** (the shape `src/tap.c` uses for `IFNAMSIZ`). ⚠ They
  must agree or every checksum is over a pseudo-header that does not match the
  datagram, and ⚠ the only thing that would come back is "it does not agree".
- ⚠ **A connection we opened and cannot answer is given back**, so the next SYN
  is not refused for want of room by one nothing will ever answer.
- ⚠ **One mutation cannot be caught, and ADR 0014 already recorded why:**
  building the pseudo-header with the two addresses swapped ⚠ **does not change
  the sum** — two four-octet blocks aligned the same way, and the sum is
  commutative. ⚠ **No check catches it and none pretends to.**
