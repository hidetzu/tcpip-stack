# 0030 — Data of ours leaves in segments the effective send MSS bounds

Date: 2026-08-29
Status: accepted
Issue: hidetzu/tcpip-stack#126

## Context

⚠ hidetzu/tcpip-stack#123 sent and read an MSS Option and ⚠ **left `MUST-14` not met on purpose**:
the received value reached no consumer.

⚠ **The criterion was set before any of this was built** (hidetzu/tcpip-stack#125), verbatim:

> 5 bytes を送れることではなく、MSS より大きいデータを渡したとき、effective send MSS を超えない
> 複数 segment として相手へ届くこと

⚠ **So a check that added the octets up would prove nothing**: 3000 in one segment and 3000 in three
are the same octet count and ⚠ **a different thing entirely.**

### ⚠ What was measured to be missing

⚠ **The peer's `Window` had no reader anywhere in `src/`** — ⚠ **so there was nothing to send into,
even if there were something to send.** ⚠ `SND.NXT` moved by one for a `SYN` and one for a `FIN`,
never by data. ⚠ There was no send buffer.

## Decision

### ⚠ Owner Decision 1 — `--send <n>`, not echo

⚠ **Something must hand this stack data before `MUST-16` can mean anything, and there is no
application** (ADR 0022).

⚠ **Echo was considered and refused, on one ground**: ⚠ `docs/SPEC.md` §1 proves the window never
shrinks **because every octet is discarded as it is taken** — ⚠ **echo would keep them, and the
proof would go.** ⚠ `CLAUDE.md` §9's window row stands on that proof too.

⚠ **`--send` leaves the receive side exactly as it was**, and ⚠ **the size is the harness's choice**,
which is what the criterion needs.

### ⚠ Owner Decision 2 — no retransmission, and the limitation is recorded

⚠ **An octet handed to the device is gone from `still_to_send`** and nothing remembers it was
unacknowledged. ⚠ **One segment lost and the connection stalls.**

⚠ **Nothing is lost on a tap**, which is ⚠ **why the check is deterministic and why it proves nothing
about loss.** ⚠ `docs/SPEC.md` §2 says so — ⚠ **recorded, not discovered later.**

### ⚠ A pattern, not a buffer

⚠ `handshake_octet_at(offset)` is `offset % 251`. ⚠ **Nothing is allocated and nothing has to be
freed** (ADR 0015). ⚠ **251 is prime, so the pattern lines up with no power-of-two segment size** —
⚠ a boundary in the wrong place shows as a break in the run, not as a coincidence.

⚠ **The check computes the same pattern independently**, so ⚠ **"3000 octets arrived" and "the right
3000 octets arrived" are different assertions and both are made.**

### ⚠ The effective send MSS is per connection

⚠ RFC 9293 `MUST-16`: **the smaller** of the send MSS and what our own frame carries. ⚠ **The first
half is theirs and arrives per connection**, so it is computed per block rather than handed in as one
number for all of them.

⚠ **The smaller, and nothing else** — ⚠ no floor, no rounding. ⚠ **A third rule of ours would be a
claim we cannot cite.**

### ⚠ The loop is in the caller

⚠ **Draining means writing to the device, and the State layer does not touch an fd**
(`.claude/rules/layers.md`). ⚠ `handshake_send_what_is_next` builds one segment; `src/tcpip_stack.c`
calls it until it refuses.

## Consequences

- ⚠ **`MUST-4`, `MUST-14`, `MUST-15` and `MUST-16` all move to met** — ⚠ **and `MUST-14` only because
  the consumer the owner named now exists.** ⚠ **Re-judged on the owner's own standard, not on it
  having become convenient.**
- ⚠ **`SND.UNA` was not advanced when the peer acknowledged our `SYN`, and it is now.** ⚠ **Found by a
  check and not by reading**: a case asserting a window of 100 got 99, ⚠ **because the `SYN` was
  counted against the peer's window for ever.** ⚠ **It was wrong before and it did not matter;
  nothing read `SND.UNA` until data of ours needed room.**
- ⚠ **`MUST-16`'s arithmetic had no check until a mutation walked past it.** ⚠ Turning the smaller
  into the larger left every check green. ⚠ **A pure function with no check is a decision nothing
  holds** — `the_effective_send_mss_is_the_smaller_of_the_two` holds it now.
- ⚠ **The first check written for this had a race of its own**: it read what the kernel had received
  ⚠ **before the kernel had received it**, and reported 0 while the stack was correct.
  ⚠ **That is `change-review` §4's stale result, in the check rather than the code**, and
  ⚠ **an empty read also passed the "were they the right octets" test** — both fixed.
- ⚠ **A segment carries at most 1460 octets of data**, which is ⚠ **a ceiling on the buffer and not a
  protocol number.** ⚠ On a device with a larger MTU the effective send MSS would allow more.
  ⚠ `docs/SPEC.md` §2 names it as a limit of ours.
