# 0025 — An address that may never be a source, and the one we cannot see

Date: 2026-08-29
Status: accepted
Issue: hidetzu/tcpip-stack#112

## Context

⚠ **The Appendix B audit (hidetzu/tcpip-stack#96) found `MUST-63` not met, and measured it.**

RFC 9293 §3.9.2.3, "Source Address Validation", quoted:

```
|  An incoming SYN with an invalid source address MUST be ignored
|  either by TCP or by the IP layer [(MUST-63)] (see
|  Section 3.2.1.3).
```

⚠ **The `MUST` is in capitals and carries its label**, so it binds — ⚠ `CLAUDE.md` §9's third
row is about not making the opposite mistake, and it was checked here before anything was called
a requirement.

⚠ **Measured 2026-08-29** — Arch Linux, kernel 7.0.2-arch1-1, `unshare -Urn`, tap0, MTU 1500:
⚠ **a `SYN` whose source was `255.255.255.255` opened a connection and was answered.**

⚠ **The document does not say what "invalid" means.** ⚠ **It sends the reader to RFC 1122
§3.2.1.3**, which names seven forms, each with a `MUST NOT`. ⚠ **So the question this ADR answers
is not "should we refuse" — it is "which of the seven can we even see".**

### ⚠ What §3.2.1.3 names, and what an address alone can tell us

```text
(a) { 0, 0 }                    0.0.0.0           ⚠ visible
(b) { 0, <host> }               0.x.x.x           ⚠ visible
(c) { -1, -1 }                  255.255.255.255   ⚠ visible
(g) { 127, <any> }              127.x.x.x         ⚠ visible
(d) { <net>, -1 }               10.0.0.255?       ⚠ NEEDS A NETMASK
(e) { <net>, <subnet>, -1 }             "         ⚠ NEEDS A NETMASK
(f) { <net>, -1, -1 }                   "         ⚠ NEEDS A NETMASK
```

⚠ **Four of the seven are recognisable from the address alone. Three are not**, and
⚠ **this is the same wall `MUST-57` hit at hidetzu/tcpip-stack#99, for the same reason:
`10.0.0.255` is a directed broadcast on a /24 and an ordinary host on a /16**, and
⚠ **nothing in this stack has a netmask.**

## Decision

### ⚠ Owner Decision 1 — the four §3.2.1.3 forms, plus multicast

⚠ **Refused as a source**: `0.0.0.0/8`, `127.0.0.0/8`, `255.255.255.255`, `224.0.0.0/4`.

⚠ **The first three quote §3.2.1.3 directly.** ⚠ **The fourth does not, and that is written down
rather than glossed**: RFC 9293 cites §3.2.1.3, and §3.2.1.3 does not name class D as a forbidden
source. ⚠ **The grounds for refusing it are the multicast address model** — a class D address names
a group of receivers, ⚠ **so it is never one host that could have sent a segment.**

⚠ **Why reach past the citation at all**: the destination side already refuses `224.0.0.0/4`
(hidetzu/tcpip-stack#99), and ⚠ **a stack that will not answer a multicast destination while
happily answering a multicast source is asymmetric with no reason behind the asymmetry.**
⚠ **The alternative was considered and rejected on that ground alone** — ⚠ **not on any reading of
§3.2.1.3, which would not support it.**

### ⚠ Owner Decision 2 — `met in part`, and never `met`

⚠ **A directed broadcast source is not refused, and `docs/conformance.md` says so.**

⚠ **`MUST-63` does not become `met`.** ⚠ Claiming it on the strength of the four that are easy is
the shape `CLAUDE.md` §1 forbids, and ⚠ **`MUST-57` already has this exact row.**

⚠ **The check asserts the gap**: `a_syn_from_an_impossible_source_is_refused` requires that a `SYN`
sourced from `10.0.0.255` **IS still answered**, ⚠ **so the gap cannot close in silence** — closing
it would fail the case, and the change would have to say what it did.

### ⚠ Owner Decision 3 — two predicates, not one widened

⚠ `ipv4_address_is_broadcast_or_multicast` answers **"may a connection be made TO this address"**
(`MUST-57`). ⚠ `ipv4_address_can_be_a_source` answers **"may this address have sent anything"**
(`MUST-63`).

⚠ **They overlap on two forms and differ on three, and they cite different documents.**
⚠ **One function answering both would be two decisions in one place** (`CLAUDE.md` §3), and
⚠ **the next change to either would silently move the other.**

⚠ **What is shared is the class D mask, `(address[0] & 0xf0u) == 0xe0u`, read from RFC 791 §3.2
in both** — ⚠ **so the two cannot disagree about where class D begins.**

## Consequences

- ⚠ **`MUST-63` moves from not met to met in part.** ⚠ `docs/SPEC.md` §2 **keeps** a row, narrowed
  to the directed broadcast — ⚠ **the row does not disappear because the easy part was done.**
- ⚠ **The refusal is counted apart from the destination's.** ⚠ **One is where a segment was going,
  the other is where it claims to have come from**, and a merged count could not tell a misdirected
  segment from a forged one (`.claude/rules/c.md`: an uncounted drop is invisible).
- ⚠ **The refusal happens before a lookup and before a TCB is taken.** ⚠ `MUST-63` says "ignored",
  and ⚠ **a connection taken and then dropped would not have been ignored.**
- ⚠ **It applies to every segment and not only a `SYN`.** ⚠ §3.9.2.3 says "implementers **should**
  note that this guidance is applicable to all incoming segments" ⚠ **in lowercase, so it is not a
  requirement** — ⚠ **refusing the rest as well is ours, and is the narrower behaviour.** The same
  shape hidetzu/tcpip-stack#99 took.
- ⚠ **The foreign-tier check drives the `SYN` by hand over `AF_PACKET`**, ⚠ **because no kernel
  will send one from an address RFC 1122 forbids as a source** — ⚠ that is the point of the
  requirement. ⚠ **The kernel is still the other end for the half that must keep working.**
