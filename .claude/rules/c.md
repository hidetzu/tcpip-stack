# C

⚠ **`MUST` = required, `SHOULD` = default, `MAY` = optional.**

⚠ **These are inherited as rules, not as evidence.** ⚠ **Nothing here has been paid for yet
in this repository.** ⚠ **When one of them is paid for, it earns a row in `CLAUDE.md` §9 and a test.**

## Responsibility

```text
read  →  parse  →  decide  →  emit
```

- MUST: ⚠ **One function does mainly one of these.**
- MUST: ⚠ **Never let a raw packet buffer flow straight into decision code** ([`layers.md`](layers.md)).
- MUST: ⚠ **Never put wording into protocol code.**
- SHOULD: ⚠ **Carve out pieces that touch neither the fd nor the clock.**
  ⚠ **Those can be tested without a network, and that is where the tests will actually live.**

## Memory and lifetime

- MUST: ⚠ **Every allocation has one named owner.** ⚠ Say who frees it, in a comment, at the point
  it is allocated.
- MUST NOT: ⚠ **Never return a pointer into a buffer whose lifetime is shorter than the caller's use.**
- SHOULD: ⚠ **Prefer a caller-supplied buffer with an explicit length** over allocating inside.
- MUST: ⚠ **Bounds are checked against what was actually read**, never against a header's claim.

## Undefined behaviour

- MUST: ⚠ **UB is not a measurement.** ⚠ **Code that works at `-O0` and breaks at `-O2` was never
  correct** — the optimiser did not break it, it exposed it.
- MUST NOT: ⚠ **Never overlay a `struct` on an unaligned packet buffer to read a field.**
  ⚠ Copy the bytes, or read them one at a time.
- MUST: ⚠ **Signed overflow, shifting by the width, and reading uninitialised memory are bugs
  even when the output looks right.**

## Errors and absence

- MUST: ⚠ **Distinguish "not there" from "could not be obtained"** (owner: `CLAUDE.md` §1).
- MUST: ⚠ **Never swallow an error.** ⚠ Leave it in a form that can be followed.
- MUST: ⚠ **One missing auxiliary thing must not take the whole stack down.**
- MUST: ⚠ **A dropped packet is counted.** ⚠ **An uncounted drop is invisible, and an invisible
  drop looks exactly like a packet that was never sent.**

## Naming

- MUST: ⚠ **Borrow the RFC's names, exactly** ([`layers.md`](layers.md)).
- MUST: Function names say ⚠ **what they do**.
- MUST: Predicates read as `is_` / `has_` / `can_` / `should_`.
- AVOID: `data1` / `tmp` / `buf2` / `flag` / `info`.
- SHOULD: ⚠ **Split on mixed responsibility, not on line count.**

## Before changing anything

- MUST: ⚠ **Look at the callers and at what it depends on.**
- MUST: ⚠ **Never widen the scope with an incidental refactor** (owner: `CLAUDE.md` §7).
