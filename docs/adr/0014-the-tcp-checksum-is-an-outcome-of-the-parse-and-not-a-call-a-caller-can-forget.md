# 0014 — The TCP checksum is an outcome of the parse, not a call a caller can forget

Date: 2026-08-28
Status: accepted
Issue: hidetzu/tcpip-stack#41

## Context

A TCP checksum covers a pseudo-header that ⚠ **is not in the segment**. RFC 793,
read verbatim on 2026-08-28 from `rfc-editor.org` and cross-checked against
`datatracker.ietf.org` — ⚠ **the two agreed**:

```
The checksum field is the 16 bit one's complement of the one's complement sum of
all 16 bit words in the header and text.  If a segment contains an odd number of
header and text octets to be checksummed, the last octet is padded on the right
with zeros to form a 16 bit word for checksum purposes.  The pad is not
transmitted as part of the segment.  While computing the checksum, the checksum
field itself is replaced with zeros.

The checksum also covers a 96 bit pseudo header conceptually prefixed to the TCP
header.  This pseudo header contains the Source Address, the Destination
Address, the Protocol, and TCP length.  This gives the TCP protection against
misrouted segments.

  +--------+--------+--------+--------+
  |           Source Address          |
  +--------+--------+--------+--------+
  |         Destination Address       |
  +--------+--------+--------+--------+
  |  zero  |  PTCL  |    TCP Length   |
  +--------+--------+--------+--------+

The TCP Length is the TCP header length plus the data length in octets (this is
not an explicitly transmitted quantity, but is computed), and it does not count
the 12 octets of the pseudo header.
```

⚠ **What was NOT read:** the value the `Protocol` field carries. ⚠ RFC 793 names
the field and does not give the number. ⚠ **`TCP_PROTOCOL_NUMBER` is an
observation** — octet 9 of the internet header in `tests/fixtures/tcp-syn-74.hex`,
put there by the Linux kernel — ⚠ **the same standing ADR 0005 gave ARP's numbers
and ADR 0012 gave ICMP's.**

## Decision

### ⚠ Owner Decision 1 — the checksum is an outcome of `tcp_parse_header`

⚠ **`TCP_PARSE_CHECKSUM_DISAGREES`**, and the function takes the two addresses.

⚠ **The grounds are not consistency with ADR 0010 and ADR 0011.** ⚠ **They are
that a separate call can be forgotten.**

> ⚠ **A stack that answers a ping while computing the checksum wrong still
> answers the ping.** — `CLAUDE.md` §1

⚠ With a separate `tcp_checksum_agrees()`, a caller that never called it would
compile, its own checks would stay green, and ⚠ **the handshake would complete**
— the same sentence in TCP's clothes. ⚠ **As an outcome, a parsed header whose
checksum nobody judged cannot exist.**

⚠ **It also puts the order beyond a caller's reach**: the checksum is decided
before any field's content, so ⚠ a segment changed in flight is never reported as
the sender's mistake.

⚠ **Re-read against RFC 9293 on 2026-08-29** (ADR 0024, hidetzu/tcpip-stack#87).
⚠ **Still ours.** ⚠ RFC 9293 §3.1 requires the check — "The TCP checksum is never
optional.  The sender MUST generate it (MUST-2) and the receiver MUST check it
(MUST-3)" — ⚠ **and says nothing about when it is checked relative to reading a
field.** ⚠ The order is ours, and it stays recorded as ours.

### ⚠ Three things trimmed off the plain version

1. ⚠ **The protocol number is not a parameter.** A pseudo-header for a TCP
   segment always carries TCP's own number; a parameter would only be a value a
   caller could get wrong.
2. ⚠ **The addresses arrive as four octets each, not as a `struct ipv4_header`.**
   ⚠ **`src/tcp.c` includes nothing from the layer below it.** The dependency is
   RFC 793's; the direction Wire → Parse → State stays clean.
3. ⚠ **`segment_bytes` must be the segment as `Total Length` bounds it**, never
   as many octets as arrived. ⚠ The `TCP Length` is computed from it, so
   ⚠ **a frame padded up to the wire's minimum makes the checksum disagree and
   nothing points at the padding.** ⚠ Stated in `src/tcp.h` and asserted by
   `the_tcp_length_comes_from_the_extent_it_was_handed`.

### ⚠ Owner Decision 2 — `checksum.h` gains one call taking two blocks

⚠ **`internet_checksum_of_two`**, and ⚠ **all three entry points now run one
loop**: the two older ones are this one with no prefix.

⚠ **Two shapes were measured and dropped.** ⚠ Composing two partial sums is the
folding arithmetic again (`CLAUDE.md` §3). ⚠ Copying everything into one
contiguous scratch needs a length limit a segment does not have — ⚠ **the reason
ADR 0011 already refused it for an ICMP message.**

⚠ **An accumulator was dropped for a measured reason, not a preference.** RFC 793
pads "the last octet" — ⚠ **once, at the very end**. An accumulator lets a caller
add an odd-length block in the middle:

```
one contiguous block  a+b : 0x6699
added block by block  a,b : 0x7788   ⚠ different
odd block last            : the two agree
```

⚠ Every pseudo-header here is 12 octets, so ⚠ **nothing in this repository can
reach it** — ⚠ **but the API would permit it, and a call taking two blocks knows
which one is last.** ⚠ `checksum.h` states the requirement rather than relying on
it going unmet.

⚠ **Decision 1 is what made this the easy choice**: with the checksum inside the
parse, ⚠ **only `src/tcp.c` ever composes blocks**, so no public accumulator is
needed at all.

### ⚠ What this reorders, said out loud

⚠ **hidetzu/tcpip-stack#40's decision order changes**, and `docs/SPEC.md` §1's row
for it is rewritten:

```
fewer octets than the fixed fields  ->  the checksum  ->  Data Offset
  ->  Reserved  ->  the option list
```

⚠ **#40's order was only defensible because it had no checksum.** ⚠ This is a
correction, not an extension.

## Consequences

- ⚠ **Every check in `tests/test_tcp.c` now hands over the two addresses and
  repairs the checksum after breaking a field.** ⚠ Without the repair each would
  come back as the checksum answer and would assert nothing about the field it
  was named for.
- ⚠ **`no_option_is_interpreted` had to change what it claims.** It required every
  reported field to be identical for two different option lists; ⚠ **the checksum
  legitimately differs, because the options are inside the sum.** ⚠ It now
  requires every other field to match ⚠ **and the checksum to differ** — which is
  a stronger statement than it made before.
- ⚠ **Nothing else asserted the order, and that was found by mutation.** Every
  other case repairs the checksum, so ⚠ **all of them passed with the Reserved
  check moved in front of it.** ⚠ `the_order_the_answers_are_decided_in` is the
  only thing holding it.
- ⚠ **Measured limitation, recorded rather than papered over: swapping the Source
  and Destination Addresses in the pseudo-header does not change the sum.** They
  are two four-octet blocks aligned the same way, so the set of 16-bit words is
  identical and the sum is commutative. ⚠ **No check can catch that order through
  the checksum and none pretends to.** ⚠ RFC 793 says the pseudo-header "gives
  the TCP protection against misrouted segments"; ⚠ **this is one thing it does
  not give.**
- ⚠ **`src/tcp.c` still has no caller in the program** (hidetzu/tcpip-stack#44).
