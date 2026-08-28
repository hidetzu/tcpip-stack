# 0018 — The State layer is handed a moment, and never reads one

Date: 2026-08-28
Status: accepted
Issue: hidetzu/tcpip-stack#56
⚠ **Supersedes, in part: ADR 0015** — its clock section only. ⚠ Everything ADR
0015 says about where connection state lives still stands.

## Context

⚠ **ADR 0015 recorded having no clock as a deliberate gap, for the handshake
only**, and said where it stops holding:

> ⚠ **The moment data or closing is involved, what needs retransmitting is ours
> and the peer only waits.**

⚠ **That is the premise this milestone removes.** ⚠ ADR 0015 predicted it would
have to be removed and said so; ⚠ **this ADR is that removal, and it is written
rather than edited into the old one** (`CLAUDE.md` §5).

### ⚠ The decision was never "which clock function"

⚠ **Measured on `main`, 2026-08-28**, by counting call sites:

| | time needed | `src/` | `tests/` |
|---|---|---|---|
| `handshake_receive` | ⚠ **yes** — it is where a schedule will be decided | 1 | ⚠ **7** |
| `connections_take` / `find` / `release` | no — holds state, decides nothing | 7 | 30 |
| `arp_respond` / `echo_respond` | no — holds nothing | 4 | 10 |

```
handed in     ⚠ 8 call sites gain one argument. That is all
read inside   ⚠ no call site changes. ⚠ **In exchange, tests/test_handshake.c —
              744 lines that run with no waiting today — either waits in real
              time or installs a clock of its own**
```

⚠ **A clock of its own is a second implementation of what time is**
(`CLAUDE.md` §3), and ⚠ **injecting one through a function pointer is the same
thing with a different name.** ⚠ **A check that waits in real time is the least
reproducible thing in this repository** (`CLAUDE.md` §6).

## Decision

### ⚠ Owner Decision 1 — the State layer is handed a moment

⚠ **`src/moment.c` reads the clock and nothing else in `src/` does**, asserted by
`tests/static.sh` `the_clock_is_read_in_one_place`.

⚠ **What this buys is named, because it is the whole reason:** ⚠ the four
State-layer checks keep running with no clock and no waiting, ⚠ **and CI keeps
running them** (ADR 0004 — CI runs the static tier and only that).

### ⚠ Owner Decision 2 — `CLOCK_MONOTONIC`

⚠ **Read verbatim** from `man 2 clock_gettime` on 2026-08-28:

```
A nonsettable system-wide clock that represents monotonic time since—as
described by POSIX—"some unspecified point in the past". ... is not affected by
discontinuous jumps in the system time ..., but is affected by frequency
adjustments.  This clock does not count time that the system is suspended.  All
CLOCK_MONOTONIC variants guarantee that the time returned by consecutive calls
will not go backwards, but successive calls may—depending on the architecture—
return identical (not-increased) time values.
```

⚠ **Three things follow, and nothing else is claimed:**

1. ⚠ **It does not go backwards**, so ⚠ **nothing guards against that.** ⚠ A
   guard would be code nobody could say why they were reading — ⚠ and this
   repository does not carry code for a thing the document says will not happen.
2. ⚠ **Two calls can give the same value.** ⚠ **The document's word, not a
   worry**: anything deciding on elapsed time has to survive it, and
   hidetzu/tcpip-stack#57 must.
3. ⚠ **It does not count time the machine was suspended.** ⚠ **The only other end
   this stack has is on the same machine**, so it was suspended too. ⚠ **That is
   an observation about where this runs and not a claim about a distant peer.**

⚠ **`CLOCK_BOOTTIME` was not chosen, and the reason is recorded:** ⚠ **it claims
a wider guarantee, and a wider guarantee is one there are fewer places we could
say is true.**

### The type

⚠ **Nanoseconds since the origin the document names** — on Linux, since boot.
⚠ **It is not a date and nothing turns it into one.**

⚠ **The comparison is unsigned**, the same shape `src/handshake.c` uses for
sequence numbers. ⚠ **A plain `a >= b` is correct for centuries and then wrong
once**, and ⚠ the signed-difference trick is undefined behaviour, so it is not a
comparison at all (`.claude/rules/c.md`).

⚠ **`moment_milliseconds_until` never returns a negative number**, because
⚠ **`ppoll` reads a negative limit as "wait for ever"** (`src/tap.h`) — the
opposite of what a deadline already past means. ⚠ **And it rounds up**, so a
caller never wakes a moment early, finds nothing due, and waits again.

⚠ **A failed `clock_gettime` returns the last moment read.** ⚠ It cannot go
backwards and it cannot make something due early, ⚠ **and that is the whole
guarantee a caller gets** — ⚠ it is not a claim that the failure was handled.

## Consequences

- ⚠ **Nothing uses any of this yet.** ⚠ `src/moment.c` has no caller in the
  program, and the `Makefile` says so where the sources are listed.
- ⚠ **`docs/SPEC.md` §2 still says nothing times out, because nothing does.**
  ⚠ The rows were narrowed to say ⚠ **a clock exists and nothing reads it for a
  decision** — ⚠ **not that the gap is closed.** ⚠ Claiming otherwise would be
  claiming work that has not been done (`CLAUDE.md` §1).
- ⚠ **`the_clock_is_read_in_one_place` does not stop everything.** ⚠ Time read
  through `time(2)`, `gettimeofday(2)`, `/proc` or a timer fd goes past it, and
  so does a moment threaded so far down that a layer decides on time without
  saying so. ⚠ **Its own comment says both.**
- ⚠ **Its comment stripping changes nothing today, and says so.** ⚠ `src/moment.h`
  quotes the documentation but writes `man 2 clock_gettime` with no bracket, so
  ⚠ **removing the stripping breaks no check.** ⚠ It stays because that quote is
  one edit from naming the call — ⚠ **a reason to keep it, not a claim that it is
  asserted.**
