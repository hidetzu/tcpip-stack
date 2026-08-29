# 0037 — v0.1 has no application and no routing layer, and that is a decision

Date: 2026-08-29
Status: accepted

## Context

⚠ **Owner, 2026-08-29, verbatim:**

> A user-space TCP/IP protocol core for Linux, interoperated against the Linux kernel and built as an
> experiment in AI-assisted systems engineering. v0.1 deliberately has no application-facing TCP API
> and no routing-layer consumer.

⚠ **Appendix B is read end to end — 119 of 119 — and nine requirements are not met.**
⚠ **Every one of them hangs from one of those two absences:**

```text
no application-facing TCP API
  MUST-30, MUST-31, MUST-32, MUST-33, MUST-62   the urgent mechanism
  MUST-43, MUST-47, MUST-48                     OPEN's local address, error
                                                reports, the Diffserv field

no routing-layer consumer
  MUST-20 (b)                                   negative advice to IP at R1
```

⚠ **Until this ADR they were nine absences.** ⚠ **They are one decision now.**

## Decision

### ⚠ The scope is stated, and no verdict moves

⚠ **This is the whole of the discipline here.**

⚠ `docs/conformance.md`'s legend: ⚠ **"A bare `MUST` is never *does not arise*. It is met or it is
not."** ⚠ **A scope decision does not make a requirement inapplicable.**

⚠ **So all nine stay `not met`.** ⚠ What changes is that ⚠ **the reason is recorded as a choice
rather than left to read as an oversight** — ⚠ **and the difference between those two is the whole
reason `docs/SPEC.md` §2 exists.**

⚠ **"Not applicable" is a claim** (hidetzu/tcpip-stack#97 said so before any of them was read), and
⚠ **it is not one this ADR makes.**

### ⚠ "protocol core", not "stack"

⚠ **A stack implies something above it.** ⚠ **There is nothing above this one and that is the
point** — ⚠ the name now says what the artefact is instead of what a reader might expect.

⚠ **"interoperated against the Linux kernel" is not decoration either.** ⚠ `.claude/rules/layers.md`
question 3 — "Can we show that, against something other than ourselves?" — ⚠ **is the one that gets
skipped**, and ⚠ **naming it in the first sentence is where it stops being skippable.**

## Consequences

- ⚠ **`README.md` and `CLAUDE.md` §0 carry the owner's sentence.** ⚠ `docs/SPEC.md` §2 carries the
  scope row, ⚠ **because that is the file that owns what may not be claimed.**
- ⚠ **The nine are grouped under one row rather than nine.** ⚠ A reader meeting them one at a time
  would read nine gaps; ⚠ **there are two.**
- ⚠ **This ADR has an expiry written into it.** ⚠ **If v0.2 gives this core a user, the nine come
  back one at a time and each is re-judged on its own** — ⚠ **not waved through because the scope
  changed.**

### ⚠ What this ADR does NOT cover, and it is worth being exact

⚠ **Not every unmet or partial thing is downstream of the two absences.** ⚠ `docs/SPEC.md` §2 holds
the rest, and ⚠ **they are not excused by this decision:**

- ⚠ **A directed broadcast is not recognised** — `MUST-57` and `MUST-63` are met **in part**, and
  ⚠ **it needs a netmask, which nothing here has.**
- ⚠ **RFC 5961's narrower acceptance test is not taken**, ⚠ **and this core takes segments from
  strangers.**
- ⚠ **The initial sequence number is guessable by anyone who can read a clock** — `SHLD-1` refused,
  with its reason.
- ⚠ **One connection at a time.** ⚠ **No IPv6, no fragment reassembly, no IP options, no UDP.**
- ⚠ **The failed MTU read's branch has no check**, and ⚠ **`MUST-64`'s byte-wise walk is not asserted
  on purpose.**

⚠ **These are what a reader of "v0.1" should be told, and `docs/SPEC.md` §2 tells them.**
