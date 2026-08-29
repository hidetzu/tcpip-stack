# 0028 — The window is what one frame carries on this device

Date: 2026-08-29
Status: accepted
Issue: hidetzu/tcpip-stack#119

⚠ **Supersedes ADR 0021 in the part about where the window's number comes from, and only that
part.** ⚠ **ADR 0021 is not edited** (`CLAUDE.md` §4: never rewrite in bulk). ⚠ **What it said was
true when it was written**: the window was `1460`, chosen because that is what one frame carries at
an MTU of 1500, ⚠ **and nothing performed the arithmetic.**

## Context

⚠ `docs/SPEC.md` §1 has said since hidetzu/tcpip-stack#75:

> ⚠ **1460 is what one frame carries at the MTU the checks use** — 1500 less an internet header and
> a TCP header

⚠ **That was a sentence beside a constant.** ⚠ `1460 = 1500 − 20 − 20` was arithmetic nobody
performed, and ⚠ **on a device with a different MTU the number was a claim about a frame size that
did not exist** — not wrong in what it promised, since every octet is discarded, ⚠ **but no longer
tied to the thing it was chosen for.**

⚠ **hidetzu/tcpip-stack#115 made the MTU available** (ADR 0027). ⚠ **Owner Decision 2026-08-29: the
window is derived from it.**

### ⚠ What was measured before anything was written

Arch Linux `7.0.2-arch1-1`, `unshare -Urn` as uid 1000, tap0. ⚠ **Three runs of each, identical:**

```text
smallest MTU a tap accepts   68      ⚠ 46 and below refused   → a window of 28
largest MTU a tap accepts    65521   ⚠ 65535 and above refused → a window of 65481
```

⚠ **So a derived window is bounded by 28 .. 65481 here and cannot overflow the sixteen-bit field.**
⚠ **This is a property of a tap on this kernel, not of TCP** — and it is why the two refusals below
are guards rather than paths.

## Decision

### ⚠ `RCV.WND` goes in the TCB, because that is where the document puts it

⚠ RFC 9293 §3.3.1 lists "RCV.WND - receive window" among the TCB's receive-sequence variables.
⚠ **Borrowed exactly** (`.claude/rules/layers.md`).

⚠ **It does not vary per connection here** — every block is given the same number, derived once from
the device — ⚠ **and the document's shape is followed anyway.** ⚠ **The alternative was threading a
parameter through six functions that already hold the block**, which would have been a second place
the same value lives.

### ⚠ The derivation is a pure function, and the two refusals are its outcomes

```c
enum handshake_window handshake_window_for_mtu(unsigned int mtu, uint16_t *window);
```

⚠ **No fd, no clock, no device** (`.claude/rules/c.md`), ⚠ **so the boundaries are asserted directly
rather than through a device that cannot reach them.**

- ⚠ **`THE_MTU_LEAVES_NOTHING`** — the MTU does not leave one octet after the two headers.
- ⚠ **`WOULD_NOT_FIT_THE_FIELD`** — what is left exceeds sixteen bits. ⚠ **Refused, never
  truncated**: the promise a peer reads must be the promise we made (`CLAUDE.md` §1).

⚠ **On a refusal the caller's number is untouched**, and the case asserts that: ⚠ a refusal that
writes a value is one a caller can use by accident.

⚠ **The `_Static_assert` that the window fits the field is gone**, and ⚠ **it could exist only while
the window was a constant.** ⚠ **The same job is done where the device's answer arrives.**

### ⚠ Both refusals stop the program

⚠ **Unlike a failed MTU read** (ADR 0027 Owner Decision 1: carry on and say so), ⚠ **a window that
cannot be derived is not an auxiliary thing missing.** ⚠ **It is the promise itself**, and there is
nothing to fall back to that would not be a lie on the wire.

## Consequences

- ⚠ **`docs/SPEC.md` §2's "A window derived from the device's MTU" row is gone.**
- ⚠ **`docs/SPEC.md` §1's window row now says the number is the device's**, with **1460 at the MTU
  the checks use and 1360 at 1400, measured on the wire.**
- ⚠ **"It never shrinks" survives, and it is still provable**: the value is fixed for the run, every
  octet is discarded as it is taken, so the window is always this many from `RCV.NXT`, and `RCV.NXT`
  only advances.
- ⚠ **`CLAUDE.md` §9's window row was repointed a second time**, and ⚠ **the row says so.**
  ⚠ Its wall asserted that lowering the window without re-measuring fails; ⚠ **"lowering the window"
  now means bringing the device up with a smaller MTU**, and the sibling case performs the same
  arithmetic the code performs, from `HANDSHAKE_HEADERS_BEFORE_DATA`.
  ⚠ **The subject moved twice and the assertion did not weaken either time**
  (`.claude/rules/testing.md`).
- ⚠ **`HANDSHAKE_HEADERS_BEFORE_DATA` is 40 because this stack sends neither kind of option**
  (ADR 0012, ADR 0013). ⚠ **The day it sends one — `MUST-14`, the MSS Option — this number is
  wrong**, and `the_window_is_what_one_frame_carries` is what will say so.
