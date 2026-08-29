# 0029 — The MSS Option is sent and read, and nothing uses it yet

Date: 2026-08-29
Status: accepted
Issue: hidetzu/tcpip-stack#123

## Context

⚠ **The Appendix B audit found `MUST-4` and `MUST-14` not met** (hidetzu/tcpip-stack#96):
⚠ **no option was implemented at all.** ⚠ The dependency it named — an MSS cannot be honest without
an MTU — ⚠ **cleared at hidetzu/tcpip-stack#115 and #119.**

⚠ **This is the first segment this stack builds whose `Data Offset` is not 5.**

## Decision

### ⚠ Owner Decision 1 — storing the received value is not `MUST-14` met

⚠ **Verbatim, 2026-08-29:**

> 受信した MSS を parse して保存するだけでは `MUST-14` met とは呼びません。受信値が実際の
> SendMSS / effective send MSS に使われ、送信 segment の大きさを制約する consumer まで接続された
> 時点で再判定してください。hidetzu/tcpip-stack#96 と同じ基準を維持します。

⚠ **This is the standard #96 set for `MUST-20` R2**: ⚠ **an effect in a different shape is not the
requirement met.** ⚠ Here it is stricter still — ⚠ **there is not even an effect**, because nothing
originates data.

⚠ **So `MUST-14` stays `not met`**, and ⚠ **`docs/conformance.md` says what was proven and what was
not, in the same row.**

### ⚠ Owner Decision 2 — the advertised MSS is derived, never an owner constant

⚠ **Verbatim:** 「こちらが広告する MSS は、hidetzu/tcpip-stack#115/#119 で実測可能になった device
MTU を根拠に導出してください。定数を Owner 値として置かないでください。」

⚠ **`handshake_maximum_segment_size_for_mtu` calls `handshake_window_for_mtu` and returns what it
returns.** ⚠ **The same arithmetic, written once** — two functions performing it separately would be
two copies of one decision (`CLAUDE.md` §3).

⚠ **They are the same number and that is not a coincidence**: both answer ⚠ **"how much of their data
fits in one of their frames"** — the MSS says it per segment, the `Window` says how many we will
take.

### ⚠ Owner Decision 3 — the sending half first, and the receiving half reuses the walk

⚠ **Verbatim:** 「まず MSS Option を送れるようにすることで、Data Offset・checksum 範囲・20-octet
固定前提を解消してください。受信側は既存 `options_walk` を活かし、MSS の意味解釈だけ追加して
ください。」

⚠ **Three assumptions dissolved together, and they had to be**: ⚠ `Data Offset` follows the options,
⚠ **the pseudo-header's length is the header's**, and ⚠ **`built_bytes` is what resulted.** ⚠ A
pseudo-header naming twenty octets over a twenty-four octet segment is a checksum the peer computes
differently, ⚠ **and the only thing that would come back is "it does not agree".**

⚠ **The walk gained a meaning and nothing else.** ⚠ It already refused a length below 2 and one
running past the options; ⚠ **the MSS branch checks the document's length rather than assuming it
from the kind** — and ⚠ **a wrong length is not malformed**: the option is simply not read, the same
answer every other kind gets (`.claude/rules/layers.md`).

### ⚠ `MUST-64` stops being incidental

⚠ hidetzu/tcpip-stack#111 recorded that `MUST-64` — options need not begin on a word boundary — was
**met with nothing asserting it on purpose.** ⚠ **The MSS branch reads its two value octets one at a
time**, so ⚠ **the byte-wise walk now has a consumer that depends on it** rather than only a walk
that happens to be written that way.

## Consequences

- ⚠ **Every segment built before this change is byte for byte what it was.** ⚠ `Data Offset` stays 5
  when no option is asked for, and ⚠ **the acknowledgment for data and our close still carry none**
  (`MUST-65`).
- ⚠ **Four octets is exactly one 32-bit word**, ⚠ **so no padding and no End of Option List are
  needed.** ⚠ `MUST-69` stays met and stays vacuous, ⚠ **for a different reason than before.**
- ⚠ **`SHLD-5` and `MUST-67` and `MUST-68` move to met.** ⚠ **`MAY-3` does not**, and the row says
  why: ⚠ **the only `SYN` this stack builds is a `SYN,ACK`**, so "always" and "when it differs from
  536" have not been told apart by anything.
- ⚠ **`MUST-15` is met in the assuming and not in the using.** ⚠ `send_mss_was_told_to_us` keeps
  "they said 536" apart from "they said nothing", ⚠ **which is the distinction the requirement rests
  on** — and ⚠ **the assumed value constrains nothing.**
- ⚠ **`MUST-16` is the consumer all of this is waiting on.** ⚠ **Both halves of its input exist now**
  — the send MSS in the TCB and the device's MTU — ⚠ **and nothing takes the smaller of them because
  nothing needs one.** ⚠ **That is the structure, recorded apart from what was proven.**
- ⚠ **A check of this change first walked past a mutation.** ⚠ The `MUST-65` assertion sat inside a
  test for a reply that was never built, ⚠ **so putting the option on every segment left it green.**
  ⚠ **It demands a reply now**, and ⚠ **a check that can silently assert nothing is not a check**
  (`verify` §5).
- ⚠ **One mutation would not compile.** ⚠ Writing a constant `Data Offset` left `words` unused and
  ⚠ **`-Werror=unused-variable` refused the build** — ⚠ **which is a guard doing its job, and not a
  mutation that passed.** ⚠ It was rewritten so it compiled, and then it failed as intended.
