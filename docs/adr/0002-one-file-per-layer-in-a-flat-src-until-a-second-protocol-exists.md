# 0002 — One file per layer in a flat `src/`, until a second protocol exists

Decided 2026-08-26. Raised by hidetzu/tcpip-stack#2.
⚠ **This is the ADR `CLAUDE.md` §3 asks for before a layer split enters the code.**

## The decision

`.claude/rules/layers.md` fixes the layers: **Wire → Parse → State → Report**.
This decides how they appear on disk, ⚠ **for the layers that exist today and no others**.

```text
src/tap.c        Wire    the octets that arrived. No interpretation, no prose
src/report.c     Report  every sentence a human reads, and nothing else
src/tap_read.c   the program: options, the loop, the exit code
```

⚠ **A flat `src/`. One file per layer that has something in it.**
⚠ **A layer with nothing in it gets no file and no directory.**

## Why

`.claude/rules/layers.md` says to generalise once the second case actually exists, and not to
abstract because one might. ⚠ **`src/wire/` and `src/parse/` with one file each is that abstraction**:
it decides where ARP, IPv4 and ICMP will live before any of them exists.

There is a second reason, and it is the stronger one. ⚠ **A directory named `parse/` that is empty
reads as a claim that parsing is planned and placed.** `docs/SPEC.md` is where planned and
implemented are held apart, and an empty directory quietly says otherwise.

## What was decided against, and why

- **`src/wire/`, `src/parse/`, `src/state/`, `src/report/` from the start.** Two of the four would
  be empty. See above.
- **One file per protocol (`arp.c`, `ipv4.c`) crossing layers inside it.** ⚠ **That is the split
  `layers.md` forbids** — a file that both parses and decides is the thing the rules exist to stop.
- **A single `tap.c` holding the wording too.** Prose in the layer that touches the fd is exactly
  what `.claude/rules/c.md` rules out, and it is why `tap.c` returns a step and an errno while
  `report.c` owns every sentence.

## The boundary this sets

- ⚠ **No file mixes two layers.** A failure crosses the boundary as `struct tap_failure`
  — a step and an `errno`, never a sentence.
- ⚠ **Nothing under `src/` prints a word a human reads except `report.c`.**
- ⚠ **When Parse arrives it arrives as its own file**, because there will then be something to parse.
  ⚠ **Directories are revisited when a second protocol exists, not before.**

## What this does not decide

⚠ **Where Parse and State live.** They do not exist yet, and this ADR deliberately says nothing
about them beyond "their own file when they are real".
