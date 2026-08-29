# 0016 — The transitions to ESTABLISHED, and the numbers that were not recalled

Date: 2026-08-28
Status: accepted
Issue: hidetzu/tcpip-stack#43

## Context

⚠ **RFC 793 §3.9 was read from the document itself**, not through a summary.
⚠ **That mattered:** the first two attempts to read it came back truncated
before §3.9, and ⚠ **two of the rules below are ones this repository would have
got wrong from memory.**

### What was read, quoted

LISTEN, on a SYN:

```
Set RCV.NXT to SEG.SEQ+1, IRS is set to SEG.SEQ and any other control or text
should be queued for processing later.  ISS should be selected and a SYN
segment sent of the form:

  <SEQ=ISS><ACK=RCV.NXT><CTL=SYN,ACK>

SND.NXT is set to ISS+1 and SND.UNA to ISS.  The connection state should be
changed to SYN-RECEIVED.
```

LISTEN, on an ACK:

```
Any acknowledgment is bad if it arrives on a connection still in the LISTEN
state.  An acceptable reset segment should be formed for any arriving
ACK-bearing segment.
```

SYN-RECEIVED, on an ACK:

```
If SND.UNA =< SEG.ACK =< SND.NXT then enter ESTABLISHED state and continue
processing.
  If the segment acknowledgment is not acceptable, form a reset segment,
    <SEQ=SEG.ACK><CTL=RST>
  and send it.
```

SYN-RECEIVED, on a SYN:

```
If the SYN is in the window it is an error, send a reset ... enter the CLOSED
state, delete the TCB, and return.

If the SYN is not in the window this step would not be reached and an ack would
have been sent in the first step (sequence number check).
```

### ⚠ The two that would have been wrong from memory

⚠ **The acknowledgment test is a window, not one number.** `SND.UNA =< SEG.ACK
=< SND.NXT` is `ISS =< SEG.ACK =< ISS+1`, so ⚠ **both `ISS` and `ISS+1` are
acceptable.** ⚠ Writing `== ISS + 1` would be **stricter than the document** and
would reject something it accepts.

⚠ **A retransmitted SYN is not the error that "check the SYN bit" describes.**
That step is for a SYN **in the window**, and ⚠ the document says one that is not
"would not be reached". ⚠ **Our reading, recorded as ours:** a retransmitted SYN
carries the sequence number the first one did — `IRS`, which is below `RCV.NXT`
— ⚠ **so it is not in the window**, and it is not an error. ⚠ The document says
an ack would have been sent; ⚠ **nothing is sent here**, and `docs/SPEC.md` §2
names that gap.

⚠ **Re-read against RFC 9293 on 2026-08-29** (ADR 0024, hidetzu/tcpip-stack#87).
⚠ **The reading still holds and is still ours**: RFC 9293 §3.10.7.4's Table 6
gives the same acceptability test, and a bare `SYN` at `IRS` against
`RCV.NXT = IRS+1` fails it, ⚠ **so the fourth step is not reached.** ⚠ The
document does not say in as many words that a retransmission is not that error;
⚠ **the step is ours to place, and it is placed the same way.**

⚠ **The step it lands in changed, and it changed what we owe.** ⚠ RFC 793 said
"an ack would have been sent"; ⚠ **RFC 9293 §3.10.7.4 says it outright**: "If an
incoming segment is not acceptable, an acknowledgment should be sent in reply
(unless the RST bit is set, if so drop the segment and return):
`<SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>`."

⚠ **hidetzu/tcpip-stack#80 sends that acknowledgment for refused data and a
refused `FIN`, and NOT for a retransmitted SYN.** ⚠ **That is a contradiction,
not a gap that was named** — hidetzu/tcpip-stack#89 owns it.

⚠ **The other reading in this ADR is untouched**: `SND.UNA =< SEG.ACK =< SND.NXT`
is the document's own sentence in both, and accepting both ends is reading it,
not extending it.

## Decision

### ⚠ Owner Decision 1 — the initial send sequence number is `0xdeadbeef`

⚠ **RFC 793's own method is unavailable:** "The generator is bound to a (possibly
fictitious) 32 bit clock whose low order bit is incremented roughly every 4
microseconds." ⚠ **There is no clock**, and hidetzu/tcpip-stack#42 recorded that
as a deliberate gap for the handshake (ADR 0015).

⚠ **And the reason the document gives does not arise here:** "To avoid confusion
we must prevent segments from one incarnation of a connection from being used
while the same sequence numbers may still be present in the network from an
earlier incarnation." ⚠ **There is room for one connection and nothing frees
it**, so a run has one incarnation; the device is gone when the fd closes.

⚠ **None of that makes a fixed number generally safe, and it is not sold as
such.** ⚠ **A predictable initial sequence number is a known weakness.**
⚠ `docs/SPEC.md` §2 says plainly that this holds only inside a private namespace
whose other end is the kernel, and ⚠ **names it as the first thing to revisit
when a clock arrives.** ⚠ Nothing claims RFC 793 asks for it.

⚠ **Why not zero:** ⚠ **a block nobody filled in is all zeroes**, so a check
asserting "the ISS is 0" would pass for one — the concern
hidetzu/tcpip-stack#42's cleared blocks raised. ⚠ This value cannot be there by
accident.

### ⚠ Owner Decision 2 — the transitions are printed, not only the ends

⚠ Approved wording, in the two-line shape ARP, ICMP and #42 already use:

```
  10.0.0.1:50568 asked to open a connection; now waiting for it to
    confirm (SYN-RECEIVED)
  10.0.0.1:50568 confirmed it; the connection is open (ESTABLISHED)
  no answer: it acknowledged 3735928560, and we are waiting for 3735928560 + 1
  no answer: nothing here is expecting a segment from 10.0.0.1:50568

1 connection was opened. 1 acknowledged a number we are not waiting for,
1 arrived for no connection we hold
```

⚠ **The names in brackets are RFC 793's own state names**, not internal enums —
⚠ `CLAUDE.md` §4's `ERR_STATE_3` rule is about internal names leaking, and
⚠ **showing the document's vocabulary is the opposite of that.**

⚠ **Why the middle transition is printed at all:** ⚠ **there is no clock, so a
handshake that stops half way stops there forever.** ⚠ Printing nothing would
leave no trace of where it stopped.

⚠ **The wording is not in `src/report.c` yet**, the same as #42's: nothing calls
this from the program until hidetzu/tcpip-stack#44, and ⚠ **a line with no caller
is a line no check exercises.** ⚠ This ADR carries it.

### ⚠ The comparison is unsigned, and that is not a style choice

```c
static bool at_or_before(uint32_t a, uint32_t b)
{
    return (uint32_t)(b - a) < 0x80000000u;
}
```

⚠ **The usual `(int32_t)(a - b) <= 0` is signed overflow**, which is undefined
behaviour and ⚠ **so is not a comparison at all** (`.claude/rules/c.md`: a
program with undefined behaviour has no defined output to be right about).
⚠ Unsigned subtraction is defined to wrap.

⚠ **A plain `a <= b` is correct for years and then wrong once**, at the wrap.
⚠ Measured: with `a <= b`, an `ISS` of `0xffffffff` accepts neither its own
number nor `0`, and `the_window_still_works_where_the_sequence_space_wraps`
fails on both.

## Consequences

- ⚠ **A defect was found by a check, not by reading.** The refusal for want of
  room was ⚠ **counted twice** — once by `connections_take` and once by the
  handshake's own `stayed()`. ⚠ `each_reason_moves_only_its_own_count` read 2.
  ⚠ **That reason is now the one branch that does not go through `stayed()`**,
  with a comment saying why, because ⚠ **a number nobody can trust is worse than
  no number** (`CLAUDE.md` §6).
- ⚠ **ADR 0015's two unprovable lines are now provable — as a pair.** With both
  clearings removed, `a_block_taken_again_holds_none_of_the_last_connections_numbers`
  fails, reading back the previous connection's `iss` and `irs`. ⚠ **Removing
  either alone still changes nothing**, which is what ADR 0015's "either alone
  would do" meant. ⚠ Both comments in `src/connection.c` were rewritten; ⚠ they
  had become false and ⚠ **a stale comment misleads harder than stale code**
  (`CLAUDE.md` §5).
- ⚠ **Nothing is sent.** Three places where RFC 793 says a segment should be
  formed — a reset for an ACK in LISTEN, a reset for an unacceptable
  acknowledgment, an ack for a retransmitted SYN — ⚠ **produce a counted reason
  and no segment.** ⚠ `docs/SPEC.md` §2 names all three.
- ⚠ **The states this milestone does not reach are not in `enum
  connection_state`.** ⚠ A state with no transition into it would be a claim that
  we implement it.
- ⚠ `src/handshake.c` has no caller in the program (hidetzu/tcpip-stack#44).
