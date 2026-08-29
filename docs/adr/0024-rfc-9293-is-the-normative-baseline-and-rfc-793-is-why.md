# ADR 0024 — RFC 9293 is the normative baseline, and RFC 793 is why

Date: 2026-08-29
Status: accepted
Issue: hidetzu/tcpip-stack#70

## Context

⚠ **Every TCP decision in this repository so far cites RFC 793.** ADR 0013, ADR 0014, ADR 0016,
ADR 0017, ADR 0019, ADR 0021, ADR 0022 and ADR 0023 all do.

⚠ **RFC 793 is obsolete.** ⚠ Its replacement's header says so:

```text
STD: 7
Obsoletes: 793, 879, 2873, 6093, 6429, 6528, 6691
Category: Standards Track
```

⚠ **This came up while implementing hidetzu/tcpip-stack#66**, where RFC 793's CLOSE Call section
turned out to contain a known error — `CLOSE-WAIT` entering `CLOSING` rather than `LAST-ACK` — that
RFC 1122 §4.2.2.20 (a) corrected in 1989 and RFC 9293 §3.10.4 carries. ⚠ **Only that one correction
was taken**, and hidetzu/tcpip-stack#70 recorded the wider question rather than deciding it in
passing.

### ⚠ Why it is not a matter of taste

⚠ **RFC 793 uses no RFC 2119 keywords in capitals — measured, 0 occurrences.** ⚠ RFC 9293 uses them,
⚠ **203 `MUST` and 38 `SHOULD`**, and §2 says: "Each use of RFC 2119 keywords in the document is
individually labeled."

⚠ **Several decisions here rest on the shape "the document states X and does not tell a receiver
what to do about it", with the conclusion recorded as ours** (ADR 0010, ADR 0011, ADR 0013 all say
so in as many words). ⚠ **Under a document with 203 `MUST`s, some of those sentences are no longer
silent** — ⚠ and `CLAUDE.md` §1 forbids collapsing `MUST`, `SHOULD` and silence into one thing.

### ⚠ The first thing it catches, measured before this was written

⚠ RFC 9293 §3.1, verbatim:

> "Reserved (Rsrvd): 4 bits
>
> A set of control bits reserved for future use.  Must be zero in generated segments and must be
> ignored in received segments if the corresponding future features are not implemented by the
> sending or receiving host."

⚠ **This build reads six bits as Reserved and refuses a segment with any of them set.** ⚠ RFC 9293
says four, with the other two assigned to `CWR` and `ECE`, ⚠ **and says a receiver must IGNORE
them.**

⚠ **Measured 2026-08-29**, same conditions as `docs/SPEC.md` §3, with `net.ipv4.tcp_ecn=1`:

```text
the kernel's first SYN     flags 0xc2 = CWR|ECE|SYN   ⚠ refused as malformed
the kernel's second SYN    flags 0x02 = SYN            connection opened
```

⚠ **An ECN-capable peer's first SYN is thrown away, and the connection only opens because Linux
falls back.** ⚠ **It replied, and not for the right reason** (`CLAUDE.md` §1) — ⚠ **and no check
here had ever met it**, because nothing turned ECN on.

## Decision

⚠ **The owner's, taken 2026-08-29.**

1. ⚠ **RFC 9293 (STD 7) is the normative baseline for TCP.**
2. ⚠ **RFC 793 is an informative source**, for historical explanation and design intent.
3. ⚠ **What RFC 9293 leaves to other RFCs is added to the baseline one function at a time, when
   that function is implemented** — ⚠ never wholesale.

## Consequences

### ⚠ Nothing already written is withdrawn, and nothing is silently re-attributed

⚠ **Every sentence quoted so far was read from RFC 793 and is what RFC 793 says.** ⚠ Those quotes
stay, and ⚠ **the ADRs that carry them stay as the record of why the code is what it is.**

⚠ **What changes is which document a NEW claim is held to**, and ⚠ **which document settles a
disagreement.**

### ⚠ Clause 3 is the one that stops this becoming a rewrite

⚠ RFC 9293 defers to other documents for congestion control, for ECN, for window scaling, for
timestamps. ⚠ **None of those is implemented here**, and ⚠ **pulling them into the baseline because
the baseline mentions them would be claiming a scope this stack does not have.**

⚠ **The same shape hidetzu/tcpip-stack#66 already used**: RFC 1122's correction was taken and
⚠ **nothing else from RFC 1122 was.**

### ⚠ What this leaves to be done, and it is not documentation

⚠ **The claims recorded as "ours" have to be re-read against the new baseline, one at a time.**
⚠ A conclusion that was ours because RFC 793 was silent ⚠ **may be the document's now, or may be
contradicted by it** — the Reserved bits are the second kind.

⚠ **That is work with a verdict per claim, not a sweep**, and ⚠ **it is issues, not this ADR.**
⚠ Nothing here changes behaviour.
