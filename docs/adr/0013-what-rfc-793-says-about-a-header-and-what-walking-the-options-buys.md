# 0013 — What RFC 793 says about a header, and what walking the options buys

Date: 2026-08-28
Status: accepted; ⚠ **the `Reserved` conclusion is superseded by ADR 0024 and hidetzu/tcpip-stack#86**
Issue: hidetzu/tcpip-stack#40

## Context

⚠ **RFC 793 had never been read in this repository.** It was read verbatim on
2026-08-28 from `rfc-editor.org` and cross-checked against the copy at
`datatracker.ietf.org`. ⚠ **The two agreed.**

### What was read, quoted

```
Source Port:  16 bits.  The source port number.
Destination Port:  16 bits.  The destination port number.
Sequence Number:  32 bits.
Acknowledgment Number:  32 bits.
Data Offset:  4 bits - The number of 32 bit words in the TCP Header.
Reserved:  6 bits - Reserved for future use.  Must be zero.
Control Bits:  6 bits (from left to right):
  URG, ACK, PSH, RST, SYN, FIN
Window:  16 bits.
Checksum:  16 bits.
Urgent Pointer:  16 bits.

Options may occupy space at the end of the TCP header and are a multiple of
8 bits in length.
There are two cases for the format of an option:
  Case 1:  A single octet of option-kind.
  Case 2:  An octet of option-kind, an octet of option-length, and the actual
           option-data octets.
The option-length counts the two octets of option-kind and option-length as
well as the option-data octets.
Note that the list of options may be shorter than the data offset field might
imply.
A TCP must implement all options.
```

⚠ **It is "Acknowledgment", with no "e" in the middle**, and `src/tcp.h` spells
it the document's way (`.claude/rules/c.md`: borrow the RFC's names, exactly).

### ⚠ What was NOT read, and is therefore not claimed

- ⚠ **RFC 793 does not use the RFC 2119 keywords in capitals.** ⚠ Its lower-case
  "Must be zero" is not `MUST` — ⚠ the same standing RFC 826, 791 and 792 are in
  here (`CLAUDE.md` §1).
- ⚠ **RFC 793 states no minimum for `Data Offset`.** ⚠ **RFC 791 does state one
  for `IHL`** — "Note that the minimum value for a correct header is 5" — and
  ⚠ **there is no sentence like it here.** ⚠ That difference is the whole reason
  the next section exists.
- ⚠ Nothing was read about the checksum's pseudo-header
  (hidetzu/tcpip-stack#41), about any state, or about any transition.
- ⚠ **Nothing was read about what any option means.** Maximum Segment Size is
  named in the document's list and ⚠ **its meaning was not looked up.**
- ⚠ **RFC 793 has been updated by later documents.** ⚠ **Everything above was
  read in RFC 793 itself**, and ⚠ nothing here is attributed to a successor.

⚠ **This one moved the other way on 2026-08-29.** ⚠ RFC 9293 §3.1 states the
minimum where RFC 793 did not: "Options: [TCP Option]; size(Options) ==
(DOffset-5)*32; ⚠ **present only when DOffset > 5**". ⚠ **The claim stops being
ours and becomes the document's**, and ⚠ **nothing about the code changes.**

## Decision

### Two answers, and there is deliberately no third

```
fewer octets than the fixed fields        -> malformed
Data Offset below the fixed header        -> malformed
Data Offset beyond what arrived           -> malformed
Reserved is not zero                      -> malformed
the option list does not walk             -> malformed
otherwise                                 -> accepted, with where the data begins
```

⚠ **There is no "well-formed but unsupported" answer in `src/tcp.c`, and that is
not an oversight:** ⚠ **reading a header declines nothing.** Every other parser
here has one because it reaches a value it will not act on; this one stops at
the header.

### ⚠ Options are walked, never refused — and that is measured

⚠ **For IPv4 we decided `Options` → unsupported** (ADR 0010). ⚠ **That was only
safe because the kernel never sends them.**

⚠ **The Linux kernel's own SYN carries a 40-octet TCP header**, 20 octets of
which are options — `tests/fixtures/tcp-syn-74.hex`, captured 2026-08-28:

```
02 04 05 b4  04 02  08 0a fa 89 72 5f 00 00 00 00  01  03 03 0a
kind 2 len 4  kind 4 len 2  kind 8 len 10           kind 1  kind 3 len 3
```

⚠ **A parser that refused a header carrying options would refuse every real SYN
there is.** ⚠ So the list is walked far enough to know it is well formed, and
⚠ **not one option is interpreted.** ⚠ `struct tcp_header` has nowhere to put an
option's meaning, on purpose.

### ⚠ The gap this leaves, named rather than left silent

⚠ **RFC 793 says "A TCP must implement all options."** ⚠ **This implements
none.** ⚠ It is written into `docs/SPEC.md` §2 as a gap, ⚠ **not a decision** —
because nothing here has decided that options should never be implemented
(`CLAUDE.md` §4-1: what we have not written is ours, and it is said in our own
terms).

### ⚠ Two rules that are ours, and are recorded as ours

⚠ **`Data Offset` below 5 is malformed.** ⚠ **RFC 791's sentence has no
counterpart here**, so this is not a reading: it is that a header claiming to be
shorter than its own fixed fields is contradicting itself. ⚠ **The same shape as
hidetzu/tcpip-stack#35 Owner Decision 4** for a `Total Length` below its header.

⚠ **A `Reserved` that is not zero is malformed.** ⚠ Grounds are the document's
"Must be zero"; ⚠ **the conclusion drawn from it is ours.** ⚠ **This is the third
time this repository has drawn it from the same shape of sentence** — ADR 0010
for IPv4's reserved flag bit, ADR 0011 for ICMP's `Code`, and here. ⚠ **RFC 793
does not tell a receiver to reject such a segment**, and this is not presented as
if it did.

⚠ **Superseded on 2026-08-29** (ADR 0024, hidetzu/tcpip-stack#86). ⚠ **The
conclusion was ours because RFC 793 is silent, and it said so.** ⚠ RFC 9293 §3.1
is not silent: "Reserved (Rsrvd): 4 bits ... Must be zero in generated segments
and **must be ignored in received segments** if the corresponding future
features are not implemented" — ⚠ **four bits, and a receiver must ignore them.**

⚠ **A set `Reserved` no longer makes a segment malformed.** ⚠ Measured before
the change, with `net.ipv4.tcp_ecn=1`: the Linux kernel's first SYN carries
`CWR|ECE|SYN` and was thrown away, ⚠ **and the connection opened only because
Linux fell back to a plain SYN.**

⚠ **The reasoning above is not withdrawn** — it is what RFC 793 says and what
was concluded from it. ⚠ **ADR 0010 and ADR 0011 drew the same shape for IPv4
and ICMP and are untouched**: they are held to RFC 791 and RFC 792, which
ADR 0024 did not move.

### ⚠ An option-length of 0 is a hang, not a wrong answer

⚠ **The option-length counts its own two octets, so anything below 2 is not a
length.** ⚠ A length of 0 leaves the walk where it is and it never ends.

⚠ **This is reachable by anyone who can send us a segment**
(`.claude/rules/c.md`: everything here is untrusted input), and ⚠ **it is a hang
rather than a wrong answer**, which is why the check for it is written as a case
whose completing at all is the assertion. ⚠ Measured 2026-08-28: with the guard
removed, `an_option_list_that_does_not_walk_is_malformed` ⚠ **did not finish in
25 seconds.**

### ⚠ The order of the checks is load-bearing

⚠ **The minimum has to be settled before `header_bytes - TCP_FIXED_HEADER_BYTES`
is computed**, because that subtraction is unsigned. ⚠ Measured: with the minimum
check removed, a `Data Offset` of 0 makes it enormous and the walk reads whatever
is behind the segment. ⚠ There is a comment at the subtraction saying so.

## Consequences

- ⚠ **Nothing here checks the checksum, decides anything, or remembers anything.**
  hidetzu/tcpip-stack#41, #42, #43 and #44 own those.
- ⚠ **`src/tcp.c` has no caller in the program yet**, and the `Makefile` says so
  where the sources are listed.
- ⚠ **`Reserved` and the `Control Bits` share an octet**, and the six Reserved
  bits are split four-and-two across two. ⚠ A check that only ever set Reserved
  to zero would not notice a parser that read the Control Bits unmasked — ⚠ that
  hole existed and was found by mutation, so the case now feeds a segment it
  declines and requires the fields to have been read correctly anyway.
