# 0010 — The internet header is read as five outcomes, and two of them are ours

Date: 2026-08-28
Status: accepted
Issue: hidetzu/tcpip-stack#33

## Context

The Parse layer had to read the fixed part of an IPv4 header. ⚠ **The question was
never "how do you parse twenty octets".** It was: ⚠ **which answers does a reader
get, and which of them come from RFC 791 and which are ours.**

⚠ **RFC 791 was read verbatim on 2026-08-28**, from `rfc-editor.org` and
cross-checked against the copy at `datatracker.ietf.org`. ⚠ **The two agreed.**

### What was read, quoted

The field names, in the order the document lists them:

```
Version, IHL, Type of Service, Total Length, Identification, Flags,
Fragment Offset, Time to Live, Protocol, Header Checksum, Source Address,
Destination Address, Options, Padding
```

⚠ **It is `Time to Live`, not `TTL`.** ⚠ **The document does not abbreviate it**, so
neither does `src/ipv4.h` (`.claude/rules/c.md`: borrow the RFC's names, exactly).

```
"Internet Header Length is the length of the internet header in 32 bit words"
"Note that the minimum value for a correct header is 5."
"Bit 0: reserved, must be zero"
"Bit 1: (DF) 0 = May Fragment, 1 = Don't Fragment."
"Bit 2: (MF) 0 = Last Fragment, 1 = More Fragments."
"fragment offset is measured in units of 8 octets (64 bits)"
"A checksum on the header only."
```

### ⚠ What was NOT read, and is therefore not claimed

- ⚠ **RFC 791 uses no RFC 2119 keywords.** ⚠ **Its lower-case "must be zero" is not
  `MUST`**, and this repository does not translate one into the other
  (`CLAUDE.md` §1: silence in an RFC is not permission, and the four levels are
  not collapsed). ⚠ **What a receiver should DO about a violated "must be zero"
  is not stated in what was read.**
- ⚠ Nothing was read about what a receiver does with Options, with a
  Type of Service value, or with a Total Length shorter than the header it
  claims. ⚠ **The last of those is left undecided here** — see Consequences.
- ⚠ Reassembly is described in the document and ⚠ **was not read for this change.**

## Decision

⚠ **Five outcomes**, decided in this order:

```
fewer octets arrived than a fixed header needs   -> malformed
IHL below 5                                      -> malformed
IHL or Total Length larger than what arrived     -> malformed
the reserved flag bit is set                     -> malformed
the header checksum does not agree               -> its own outcome
version is not 4, or IHL is above 5 (Options)    -> well-formed but unsupported
More Fragments set, or a non-zero Fragment Offset -> its own outcome
otherwise                                        -> accepted
```

### ⚠ Two of these are the owner's decisions, not the document's

⚠ **Owner Decision 1 — a fragment is its own outcome.** ⚠ Not folded into
"unsupported". ⚠ **A fragment is perfectly well formed and the sender did nothing
wrong**; reassembly is simply not written here. Counting it with an unsupported
version would ⚠ **merge two numbers that mean different things**, and when
reassembly is considered, ⚠ **how many arrived will already have been counted**
(`.claude/rules/c.md`: an uncounted drop is invisible).

⚠ **Owner Decision 2 — the reserved flag bit set is malformed.** ⚠ **The grounds
are the document's sentence, and the conclusion drawn from it is ours.** RFC 791
says the bit must be zero; ⚠ **the sender broke what the document states, which is
what malformed means here and is not what unsupported means** (`.claude/rules/layers.md`:
malformed = the sender is wrong; unsupported = the sender is fine and we decline).
⚠ **RFC 791 does not say to reject such a datagram**, and this row is not
presented as if it did.

⚠ **IHL below 5 is malformed on the document's own words** — "the minimum value
for a **correct** header is 5" — ⚠ **and that is a reading of the text, not a
decision.**

### ⚠ Truncation is decided before support

⚠ **Same order ADR 0005 set for ARP.** A datagram that does not contain what it
says it contains is malformed ⚠ **whether or not we would have handled it**. The
alternative reports the sender's version as our reason for declining, when the
octets never allowed us to look.

### ⚠ The checksum is verified by generating it again

⚠ **RFC 1071's own description, applied a second time**: clear the field, sum,
complement, compare with what arrived. ⚠ **Not a second way of asking the same
question** (`CLAUDE.md` §3), and ⚠ **`internet_checksum` is the same function the
builder will use.** What holds that function honest is `tests/test_checksum.c`,
against two numbers ⚠ **the Linux kernel computed** (ADR 0009's principle).

## Consequences

- ⚠ **`src/ipv4.c` reads the header and nothing above it.** ⚠ The Protocol field is
  handed back as the number it is and ⚠ **is never turned into a name here** — the
  same rule ADR 0003 set for the ethernet length/type.
- ⚠ **Left undecided, deliberately: a Total Length SHORTER than the header it
  claims.** ⚠ **It is accepted today**, because ⚠ **the approved decision order has
  no row for it** and this change does not invent one. ⚠ **It matters for
  hidetzu/tcpip-stack#34**, which will want `Total Length - header` as a payload
  length — ⚠ **that subtraction is where the decision has to be taken, and it is
  the owner's.** ⚠ **Nothing here pretends the question is settled.**
- ⚠ Options are declined rather than skipped. ⚠ When something needs them,
  generalise then — ⚠ never now (`.claude/rules/layers.md`).
- ⚠ The addresses are filled in even for a datagram that is declined, so a caller
  can say which address was asked for ⚠ **without reading the octets itself**.
  The same shape ARP already has.
