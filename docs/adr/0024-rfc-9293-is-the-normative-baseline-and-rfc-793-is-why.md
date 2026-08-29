# ADR 0024 — RFC 9293 is the normative baseline, and RFC 793 is why

Date: 2026-08-29
Status: accepted
Raised in: hidetzu/tcpip-stack#70 (a pull request, not an issue — ⚠ **the question
never had one, and this ADR is where it is settled**)

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

⚠ **hidetzu/tcpip-stack#70 is a pull request.** ⚠ **The question never had an issue of its own**, and
it was carried in that PR's text, in a comment on hidetzu/tcpip-stack#66, and in several completion
reports that called it "still open". ⚠ **Referring to it as an issue was wrong**, and ⚠ **this ADR
is where it is settled** — not a `Closes` line on anything.

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

### ⚠ Amendment, 2026-08-29 — clause 3 admits two documents, with their scope named

⚠ **The owner's, taken the same day**, on hidetzu/tcpip-stack#130 and hidetzu/tcpip-stack#132:

> ADR 0024 を改訂し、RFC 6298 を RTT/RTO/retransmission/backoff の正本、RFC 5681 を
> slow start/congestion avoidance の正本として、**適用範囲を限定して**追加してください。

4. ⚠ **RFC 6298 is normative for the round-trip measurement, the retransmission timeout, the
   retransmission timer's management, and the backing off of that timeout.** ⚠ RFC 9293 §3.8.1
   sends us there in capitals: "The RTO **MUST** be computed according to the algorithm in [10],
   including Karn's algorithm for taking RTT samples (`MUST-18`)."
5. ⚠ **RFC 5681 is normative for slow start and congestion avoidance.** ⚠ RFC 9293 §3.8.2 sends us
   there for `MUST-19`: "A TCP endpoint **MUST** implement the basic congestion control algorithms
   slow start, congestion avoidance, and exponential backoff of RTO".

### ⚠ What the amendment does NOT admit, and this is the limit the owner asked for

⚠ **Clause 3 is not repealed.** ⚠ **These two documents enter for the functions named above and for
nothing else**, and ⚠ **a sentence of theirs about anything else is not binding here:**

| ⚠ In | ⚠ Out, and it stays out |
|---|---|
| RFC 6298 §2 (SRTT, RTTVAR, RTO), §3 (Karn's), §4 (clock granularity), §5 (managing the timer, backoff) | ⚠ **The TCP Timestamps Option**, which §3 names as the one safe way to sample a retransmitted segment. ⚠ **RFC 7323 is not admitted** |
| RFC 5681 §3.1 (slow start, congestion avoidance) and the `cwnd`/`ssthresh`/`FlightSize` definitions §3.1 rests on | ⚠ **§3.2 fast retransmit and fast recovery.** ⚠ **`MUST-19` names three algorithms and these are not among them**, and §3.2 rests on counting duplicate ACKs, which this stack does not do |
| | ⚠ **§4.1 restarting idle connections, §4.2 generating acknowledgments, §4.3 loss recovery** |
| | ⚠ **RFC 3042 limited transmit, RFC 3390's IW rationale as a requirement, RFC 2018 SACK, RFC 3168 ECN** |

⚠ **A requirement from an unadmitted section is recorded in `docs/conformance.md` the way any other
unmet thing is** — ⚠ **not implemented quietly because a neighbouring paragraph was.**

### ⚠ Both documents carry their own BCP 14 clause, and it is not RFC 9293's

⚠ **RFC 6298 §1 and RFC 5681 both say their keywords are to be read as RFC 2119 describes.**
⚠ **So they have no labelled `MUST-n`**, and ⚠ **a capital keyword in them binds on its own** —
there is no label to look for and ⚠ **its absence is not evidence of anything**
(`CLAUDE.md` §9's third row is about the opposite mistake, and this is where it could be made
backwards).

⚠ **A lowercase keyword in either is still not a requirement.** ⚠ Both documents contain them.

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

⚠ **The 2026-08-29 amendment is clause 3 being used, not bent.** ⚠ Two functions are being
implemented — the retransmission timeout and congestion control — ⚠ **so the two documents that
define them enter, for those functions.** ⚠ **The table above is what "limited" means**, and
⚠ **without it the amendment would be the wholesale admission clause 3 exists to refuse.**

### ⚠ What this leaves to be done, and it is not documentation

⚠ **The claims recorded as "ours" have to be re-read against the new baseline, one at a time.**
⚠ A conclusion that was ours because RFC 793 was silent ⚠ **may be the document's now, or may be
contradicted by it** — the Reserved bits are the second kind.

⚠ **That is work with a verdict per claim, not a sweep**, and ⚠ **it is issues, not this ADR.**
⚠ Nothing here changes behaviour.
