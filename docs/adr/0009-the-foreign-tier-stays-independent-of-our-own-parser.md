# 0009 — The foreign tier stays independent of our own parser

Decided 2026-08-27. Raised by hidetzu/tcpip-stack#11, and ⚠ **by a measurement that overturned part
of that issue.**

## The decision

⚠ **A check in `tests/foreign.sh` never asks `src/` what a frame is.** It decides for itself which
octets it is looking at.

⚠ **What it may share with `src/` is where a field sits, and only that.** The offsets are derived
from the constants `src/` uses, so ⚠ **the layout has one home and cannot drift** (`CLAUDE.md` §3).

⚠ **Breaking a parser must not break a foreign-tier case that is about wire fidelity.**
⚠ **That is not a gap. It is the property that makes the tier worth having.**

## What was measured, and what it overturned

hidetzu/tcpip-stack#11 originally required: *break the parser on purpose and watch this check fail;
if it passes with a broken parser, the tier is not honest.*

⚠ **It was tried on `main`, 2026-08-27**, by swapping `ar$spa` and `ar$tpa` in `src/arp.c`:

| | Result |
|---|---|
| `tests/foreign.sh` `an_arp_request_the_kernel_generated_is_read_intact` | ⚠ **passed** |
| `tests/static.sh` `arp_packet` | ⚠ **4 of 11 cases failed** |

⚠ **Passing was correct.** That case asserts the octets the kernel sent are the octets we read —
⚠ **Wire fidelity** — and a broken ARP parser does not change those octets. ⚠ **The parser's
correctness is the static tier's job, and the static tier caught it.**

⚠ **The original criterion conflated two questions**: whether a check runs through the parser, and
whether the foreign tier is honest. ⚠ **They are not the same.**

## Why

⚠ **`.claude/rules/layers.md` question 3 is "can we show that against something other than
ourselves?"** ⚠ **A check that used our parser to find the frame whose octets it then verifies would
be our parser agreeing with our parser** — and worse, ⚠ **a parser that mis-identified the frame
would make the check look at nothing and say nothing was wrong.**

⚠ **So the independence is load-bearing and it is now a requirement**, not something tolerated
because nobody got round to removing it.

⚠ **And `CLAUDE.md` §3 is still satisfied.** It forbids two implementations of the same *decision*.
⚠ **Where a field sits is one decision, and it now lives in one place.** ⚠ **How to read an octet is
not a decision that needs sharing** — it is arithmetic, and doing it twice is what independence
means here.

## What was decided against, and why

- **Letting the check use the program's own output to find the frame.** hidetzu/tcpip-stack#10 made
  the program print `length/type 0x0806`, so it could. ⚠ **It would hand the identification of the
  frame to the thing under test.**
- **Writing the offsets in the check a second time.** ⚠ **That is the drift `CLAUDE.md` §3 names**,
  and a mutation proves it is now impossible: moving `ARP_FIXED_BYTES` in `src/arp.h` makes the
  check fail rather than quietly look at the wrong octets.
- **Deleting the assertion to make the duplication go away.** ⚠ **A check removed is not a check
  paid off** (`CLAUDE.md` §9).

## The boundary this sets

- ⚠ **Every future foreign-tier check inherits this.** When ICMP arrives, its check decides for
  itself what it is looking at, and takes only offsets from `src/`.
- ⚠ **Two mutations, in opposite directions, are what proves it**: the check's own offsets made
  wrong must fail it, and ⚠ **a broken parser must not.**
- ⚠ **A foreign-tier case that starts failing when a parser breaks has lost its independence**, and
  that is a defect in the check rather than a sign of thoroughness.

## What this does not claim

⚠ **Not that the foreign tier proves the parser correct.** ⚠ **It proves the opposite kind of
thing**: that what the kernel put on the wire is what we read, and that what we sent the kernel
believed. ⚠ **The parser is asserted in the static tier and nowhere else.**
