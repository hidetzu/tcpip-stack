# 0031 — Data nobody acknowledged goes out again

Date: 2026-08-29
Status: accepted
Issue: hidetzu/tcpip-stack#129

## Context

⚠ **Owner goal, 2026-08-29:** 「送信した data segment またはその ACK を1つ失っても、tcpip-stack が
再送によって Linux kernel へのデータ配送を完了できるようにしたい」

⚠ hidetzu/tcpip-stack#126 recorded that this could not happen: an octet handed to the device was
gone from `still_to_send` and ⚠ **nothing remembered it was unacknowledged.**

## Decision

### ⚠ Owner Decision — the fixed second is on loan, and it is not an RTO

⚠ **Verbatim:** 「固定1秒は #130 までの temporary interval としてのみ許可し、RFC 6298 準拠や RTO
とは呼ばないでください」

⚠ **So `HANDSHAKE_SEND_DATA_AGAIN_AFTER_MILLISECONDS` is used and not defended.** ⚠ Its comment says
what it is not, `docs/SPEC.md` §2 says `MUST-18` is not met, and ⚠ **hidetzu/tcpip-stack#130 replaces
the constant and the comment together.**

⚠ **RFC 6298 has a 1 second twice and neither is an interval**: §2.1 is the value used *until* a
round trip has been measured, §2.4 is a *floor*. ⚠ **This number is neither.**

⚠ **Its own name, not `ANSWER_AGAIN`'s.** ⚠ The two are equal today and ⚠ **they answer different
questions** — a handshake nobody confirmed, and data nobody acknowledged. ⚠ **Sharing the constant
would make hidetzu/tcpip-stack#130 move both** (`CLAUDE.md` §3).

### ⚠ Retransmission is winding `SND.NXT` back to `SND.UNA`

⚠ RFC 6298 §5.4: "Retransmit the earliest segment that has not been acknowledged by the TCP
receiver." ⚠ **The octets are a pattern (ADR 0030), so winding back reproduces exactly what was
sent** — ⚠ **no segment has to be held.**

⚠ **That is a simplification this stack has and a real one does not**, and `docs/SPEC.md` §2 says so:
⚠ **"retransmission works" here must not be read as "a send buffer exists".**

⚠ **It sends the earliest again and everything after it**, which is more than §5.4 asks for.
⚠ **Said rather than claimed as the document's**: with no window change and no fast retransmit, the
rest would follow anyway.

## Consequences

- ⚠ **`SND.UNA` advances on an acknowledgment inside `(SND.UNA, SND.NXT]` and nowhere else.**
  ⚠ One below is a duplicate and says nothing new; ⚠ **one above acknowledges something we never
  sent** and is not ours to believe.
- ⚠ **The timer is armed when data is sent and not restarted when it is already running**
  (RFC 6298 §5.1) — ⚠ **restarting on every segment of a burst would push the deadline out and the
  earliest unacknowledged one would never come due.** ⚠ It is turned off when everything is
  acknowledged (§5.2) and restarted when new data is (§5.3).

### ⚠ Two defects this found, and neither by reading

- ⚠ **A wait ended by our own timer was reported as a read timeout, and the program left.**
  ⚠ Measured: with one data segment dropped, ⚠ **the deadline woke the wait, nothing was due by the
  old reckoning, and 0 of 3000 octets were delivered.** ⚠ **That is `CLAUDE.md` §1's
  "not captured ≠ not sent", in the loop rather than in a report.**
- ⚠ **Not advancing `SND.UNA` on an acknowledgment covering data passed every tier.** ⚠ The stack
  would retransmit for ever ⚠ **and the kernel would still have the data**, so no interop check could
  see it. ⚠ `an_acknowledgment_for_data_stops_the_resending` sees it now.

### ⚠ What measuring said about losing an acknowledgment, and it changed the check

⚠ **The two halves of the goal are not the same assertion.**

```text
losing a data segment    ⚠ the kernel has a HOLE. ⚠ Nothing past it is delivered,
                         and ONLY a retransmission completes it
losing acknowledgments   ⚠ THE KERNEL ALREADY HAS THE DATA. ⚠ What was lost is
                         OUR knowing, not THEIR receiving — ⚠ and they are
                         CUMULATIVE, so a later one restores even that
```

⚠ **So the check asserts a retransmission for the first and refuses to for the second.**
⚠ **Asserting one for the ACK half would be asserting a defect**, and ⚠ **contriving a window where
it were needed would be testing the contrivance.**

⚠ **The check still requires that the drop happened** in both halves, ⚠ **or the ACK half would
assert nothing at all** (`verify` §5).
