# 0032 — The timeout is computed from round trips this stack measured

Date: 2026-08-29
Status: accepted
Issue: hidetzu/tcpip-stack#130

⚠ **Supersedes ADR 0019 in the part about where the interval comes from.** ⚠ **ADR 0019 is not
edited** (`CLAUDE.md` §4). ⚠ **What it said was true when it was written**: 1000 ms was RFC 793's own
example lower bound, and its 2026-08-29 re-read already recorded that the grounds had gone when
RFC 9293 became the baseline.

## Context

⚠ RFC 9293 §3.8.1, read from the body: "The RTO **MUST** be computed according to the algorithm in
[10], including Karn's algorithm for taking RTT samples (`MUST-18`)." ⚠ **[10] is RFC 6298**, admitted
to the baseline the same day (ADR 0024 as amended).

⚠ **hidetzu/tcpip-stack#129 borrowed a fixed second** and the owner allowed it 「#130 までの
temporary interval としてのみ」. ⚠ **This is #130, so the loan is over.**

### ⚠ RFC 6298 has a 1 second twice and neither is an interval

```text
§2.1   the value used UNTIL a round trip has been measured
§2.4   a FLOOR: "if it is less than 1 second, then the RTO SHOULD be rounded up"
```

⚠ **The constant that was here was neither.**

## Decision

### ⚠ Nanoseconds, and that is what removes the rounding question

⚠ **The issue's Stop Condition said to stop and ask if integer arithmetic needed a rounding rule the
document does not give.** ⚠ **It did not need one.**

⚠ `struct moment` holds nanoseconds; ⚠ **the estimate is kept in nanoseconds too.** ⚠ Dividing by 8
and by 4 truncates below a nanosecond, ⚠ **which is under the granularity of the clock this stack
reads.** ⚠ **So no rule was invented and none had to be** — ⚠ truncation is what `>>` does, not a
rule chosen over another.

### ⚠ `G` is measured

⚠ Arch Linux 7.0.2-arch1-1, `CLOCK_MONOTONIC`, three runs of 200000 back-to-back reads:
⚠ **the smallest non-zero step observed was 10, 10 and 20 nanoseconds.** ⚠ **`clock_getres` claims
1 ns, which is a different question.**

⚠ **The largest of the three is carried.** ⚠ §4 uses `G` as a floor on the variance term, and ⚠ **a
floor too small does nothing while one too large would inflate every RTO.**

⚠ **It never decides anything here**, and it is carried anyway: ⚠ **a formula written without a term
it has is not that formula.**

### ⚠ Karn's algorithm is a field on the connection, not a rule in the estimator

⚠ `handshake_round_trip_sample` cannot know whether its argument came from a retransmission and
⚠ **does not check** — ⚠ the caller refuses the sample (`.claude/rules/c.md`: one function does
mainly one thing).

⚠ **`sample_is_spoilt` is set the moment anything is sent again**, and ⚠ **a spoilt sample is thrown
away rather than used.** ⚠ **An estimate built from an ambiguity is not a measurement**
(`CLAUDE.md` §1).

⚠ **Measured and refused samples are counted apart**: ⚠ **a refused sample is not a sample that never
happened**, and a stack whose samples were all refused would look identical to one that measured
nothing.

## Consequences

- ⚠ **On a tap, §2.4's floor decides every RTO there is.** ⚠ Round trips here are microseconds.
  ⚠ **So the number stays 1000 ms and its grounds change completely** — from a constant nobody could
  defend to a computation the document gives, floored by a sentence the document gives.
  ⚠ **A check that only ever saw a tap could not tell those apart**, so the checks feed round trips
  large enough to lift it off the floor.
- ⚠ **`tests/static.sh` `the_borrowed_interval_is_gone` stops the constant coming back**, and
  ⚠ **asserts what replaced it is there and is read** — a constant left unread would satisfy the
  first half and change nothing.
- ⚠ **`MUST-19`'s exponential backoff is not this requirement and is not met.**
  ⚠ hidetzu/tcpip-stack#131.

### ⚠ A mutation walked past everything, and the check was wrong

⚠ **Changing `K` from 4 to 1 left every check green.** ⚠ The arithmetic in the case named the
constant on both sides, ⚠ **so it moved with it.**

⚠ `.claude/rules/testing.md` says it: ⚠ **assert against the constant AND against the value it must
not be.** ⚠ **Only the first half had been done.** ⚠ The document's own numbers — `K = 4`,
`alpha = 1/8`, `beta = 1/4`, one second — are asserted as numbers now.
