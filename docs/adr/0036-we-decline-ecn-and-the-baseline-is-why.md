# 0036 — We decline ECN, and the baseline is why

Date: 2026-08-29
Status: accepted
Issue: hidetzu/tcpip-stack#139

## Context

⚠ **The milestone item read "ECN behaviour required by the chosen baseline".** ⚠ **Reading the whole
of RFC 9293 for ECN, 2026-08-29, found three mentions and no more:**

1. **§3.1**, the header: "CWR: 1 bit — Congestion Window Reduced (see [6])." and "ECE: 1 bit —
   ECN-Echo (see [6])."
2. **§3.8.2**: "A TCP endpoint **SHOULD** implement ECN as described in RFC 3168 (`SHLD-8`)."
3. **The glossary**, on the TOS byte carrying "the 2-bit ECN codepoint [6]".

⚠ **`[6]` is RFC 3168 every time.** ⚠ **The baseline defines two bit positions and defers every
behaviour to a document outside itself.**

⚠ **And ADR 0024's scope table, as amended 2026-08-29, names RFC 3168 as out** — explicitly, by
name.

## Decision

### ⚠ Owner Decision — the baseline only, and `SHLD-8` is refused with a reason

⚠ **Verbatim, 2026-08-29**: A — the baseline only; assert the declining and record `SHLD-8` as a
`SHOULD` refused with its reason.

⚠ **A `SHOULD` refused is a decision.** ⚠ **A `SHOULD` ignored is neither**, and `docs/SPEC.md` §2
carries the difference. ⚠ The same shape `SHLD-1` already has: the ISN's secret was refused because
this repository has no cryptographic dependency and `CLAUDE.md` §3 forbids adding one without a
reason.

### ⚠ What this stack already does is correct, and nothing said so

⚠ **Measured 2026-08-29** (hidetzu/tcpip-stack#86): with `net.ipv4.tcp_ecn=1` the Linux kernel's
first `SYN` carries `CWR|ECE|SYN`. ⚠ **Before #86 this stack threw it away and the connection opened
only because Linux fell back** — ⚠ **it looked as if it worked, on somebody else's fallback.**

⚠ **Since #86 the ECN-capable `SYN` is the one that opens the connection**, and ⚠ **our `SYN,ACK`
carries neither bit.** ⚠ **That is exactly how a non-ECN endpoint answers an ECN-setup `SYN`**: both
ends then know the connection is not an ECN connection.

⚠ **And nothing asserted it.** ⚠ **A build that started setting `ECE` would have claimed a mechanism
it does not have, with every check green.**

⚠ **Measured on the wire now**: the kernel offered control bits 194 (`CWR|ECE|SYN`) and our answer
carried 18 (`SYN|ACK`). ⚠ Read off an `AF_PACKET` socket, ⚠ **not out of our own report**
(ADR 0009).

⚠ **The check requires that the kernel really offered ECN first** — ⚠ **a `SYN` with neither bit
would let any answer pass**, and the case would assert nothing.

### ⚠ What actually guarantees the declining, found by a mutation that changed nothing

⚠ **The first attempt at breaking this set `ECE` on the answer and every check stayed green.**
⚠ **That was not a gap in the checks** — ⚠ **it was a mutation with no effect**
(`.claude/rules/testing.md` asks which, and this is the second).

⚠ `tcp_build_segment` writes `fields->control_bits & 0x3fu`. ⚠ **The mask drops the top two bits,
so the builder CANNOT put `CWR` or `ECE` on the wire whatever a caller asks for.**

⚠ **So the declining is guaranteed by the mask and not by what the State layer passes.** ⚠ The
mutation that does break it is on the mask, ⚠ **and both checks then fail with the words they were
written for.**

⚠ **Worth knowing, because the mask is where a future ECN implementation has to start** — ⚠ and
⚠ **a reader who assumed the State layer decided it would look in the wrong place.**

## Consequences

- ⚠ **`SHLD-8` is `refused, with a reason` in `docs/conformance.md`** — ⚠ **not `not met`.** ⚠ The
  difference is whether a decision was taken, and one was.
- ⚠ **The refusal has an expiry written into it**: ⚠ **if RFC 3168 is ever admitted to the baseline,
  the reason goes and the verdict must be re-read.** ⚠ hidetzu/tcpip-stack#139 recorded what that
  work would be — the negotiation, the echoing, and the response to a congestion signal, ⚠ **three
  reasons and not one** — and ⚠ **hidetzu/tcpip-stack#132 made it possible where it was not**, since
  there is now a congestion window to reduce.
- ⚠ **Nothing in the code changed.** ⚠ **Two checks were added and two documents were corrected** —
  ⚠ **the behaviour was already right and unasserted**, which is the gap this closed.
