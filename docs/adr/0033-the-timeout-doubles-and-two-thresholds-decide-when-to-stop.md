# 0033 — The timeout doubles, and two thresholds decide when to stop

Date: 2026-08-29
Status: accepted
Issue: hidetzu/tcpip-stack#131

## Context

⚠ RFC 6298 §5.5: "The host **MUST** set RTO <- RTO * 2 (\"back off the timer\")."
⚠ RFC 9293 §3.8.2 adds what backoff means beyond doubling: "including **keeping the backed-off
value until a subsequent segment with new data has been sent and acknowledged without
retransmission**."

⚠ **hidetzu/tcpip-stack#114 corrected a verdict this issue rests on.** ⚠ §3.8.3 (a): "R1 and R2
**might be measured in time units or as a count of retransmissions**." ⚠ **So the give-up being a
time was never the gap** — ⚠ **the gap was that there was no R1 at all.**

## Decision

### ⚠ Each threshold is expressed in the unit the sentence that gives its value uses

```text
R1   3 retransmissions   ⚠ SHLD-10: "at least 3 retransmissions, at the current RTO"
R2   100 seconds         ⚠ SHLD-11: "at least 100 seconds"          (data)
R2   180 seconds         ⚠ MUST-23: "at least 3 minutes"            (a SYN)
```

⚠ **§3.8.3 (a) offers both units**, so ⚠ **no conversion of ours stands between a threshold and the
sentence it comes from.**

### ⚠ Owner Decision — `MUST-23` is 180 seconds and no check waits three minutes

⚠ **Verbatim, 2026-08-29:** 「`MUST-23` は SYN R2 を 180 秒以上とします。ただし通常の verification
で実時間3分を毎回待つことは要求しません。production の時間モデルを使って境界を機械判定できる方法を
先に検討し、test 専用の seam が必要なら Owner へ戻してください。」

⚠ **Investigated first, as asked. No seam is needed and none was added.**

⚠ **ADR 0018 hands the State layer a moment rather than letting it read one**, and
⚠ **`handshake_what_is_due(connections, now, ...)` is the signature the program itself uses.**
⚠ So `at(180000)` and one millisecond either side judge the boundary exactly, in microseconds.

⚠ **What did cost real time was the device tier**, where three cases waited the old three seconds
out. ⚠ **Repointed, not deleted**: the boundary belongs where it can be judged exactly, and
⚠ **what a device is for is that the retransmissions really reach the wire.**

### ⚠ `MUST-22` means the handshake gets the same mechanism

⚠ "Same mechanism for SYNs" was already met. ⚠ **So the answer to an unconfirmed `SYN` uses the
computed RTO and backs off too** — ⚠ **it kept a constant of its own until this change**, and
keeping one would have made `MUST-22` false the moment data got a real one.

### ⚠ R1 is crossed, said once, and `MUST-20` (b) stays not met

⚠ §3.8.3 (b) asks for negative advice to the IP layer. ⚠ **There is none here to advise** — nothing
routes and there is no gateway to diagnose.

⚠ **So the threshold is crossed, counted and said, and the clause stays not met.** ⚠ **A line on a
terminal is not negative advice to a routing layer**, and ⚠ **`docs/conformance.md`'s legend says a
bare `MUST` is never *does not arise*.**

## Consequences

- ⚠ **Six static cases fired on this change and all six were right** — the schedule doubled and R2
  moved. ⚠ **Each was repointed and none was widened.** ⚠ `the_answer_is_due_a_second_after_each_send`
  now asserts one RTO, three and seven, ⚠ **so a build that doubled once and stopped fails it.**
- ⚠ **A device-tier case was intermittent and the fix was measured, not guessed.** ⚠ At 3500 ms the
  second answer had 0.5 s of margin: **2 then 3**. At 9000 ms asserting exactly three: **4, 4 then
  3** — ⚠ **because `--timeout` is the time with no frame arriving and a stray frame extends the
  run.** ⚠ **An exact count in a window the case does not control is not assertable there.**
  ⚠ **A lower bound of three is not weaker than an exact two**: ⚠ two would pass for a build that
  doubled once, ⚠ **and the third is what shows the doubling compounds.** ⚠ **The exact schedule is
  asserted exactly in the static tier, with no waiting.**
- ⚠ **`docs/SPEC.md` §3 re-measured, and the growth is explained by measurement**: the isolated tier
  roughly doubled, ⚠ **because a case watching answers go out again now waits 1 s, 3 s and 7 s where
  it waited 1 s, 2 s and 3 s.** ⚠ **The per-case interop breakdown was NOT re-measured and says so**
  rather than being carried forward as if it were this tree's.
- ⚠ **`MUST-19` is not met by this alone.** ⚠ Its exponential backoff is; ⚠ **slow start and
  congestion avoidance are hidetzu/tcpip-stack#132.**
