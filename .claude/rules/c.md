# C

⚠ **`MUST` = required, `SHOULD` = default, `MAY` = optional.**

## ⚠ Two kinds of rule, and they are not interchangeable

```text
Engineering constraint          Learned pitfall
grounded in the C standard,     something this repository
the protocol, or the fact       actually paid for
that the input is hostile              |
        |                              |
binds from the first line       lives in CLAUDE.md §9,
of code                         with the test that stops
        |                       it happening again
lives here, with its grounds
```

⚠ **Everything in this file is an engineering constraint.**
⚠ **It binds now.** ⚠ **It does not wait for an accident here to earn its place.**
⚠ **Each section states its grounds** — cite those, never an anecdote.

⚠ **Never demote a constraint to "we will see" because nothing has gone wrong yet.**
⚠ **Never promote one into `CLAUDE.md` §9 by inventing an incident.**
⚠ **§9 starts empty and stays empty until something is genuinely paid for.**

⚠ **A learned pitfall can add a rule here.** ⚠ **When it does, the grounds it cites is the
incident, and §9 keeps the row.** ⚠ **The two records point at each other; neither replaces the other.**

## Responsibility

⚠ **Grounds: [`layers.md`](layers.md).** A packet that has not been validated
must not reach code that decides anything.

```text
read  →  parse  →  decide  →  emit
```

- MUST: ⚠ **One function does mainly one of these.**
- MUST: ⚠ **Never let a raw packet buffer flow straight into decision code** ([`layers.md`](layers.md)).
- MUST: ⚠ **Never put wording into protocol code.**
- SHOULD: ⚠ **Carve out pieces that touch neither the fd nor the clock.**
  ⚠ **Those can be tested without a network, and that is where the tests will actually live.**

## Memory and lifetime

⚠ **Grounds: the input is hostile.** Every length and offset in a packet is an assertion
by whoever sent it, and the sender may be lying.

- MUST: ⚠ **Every allocation has one named owner.** ⚠ Say who frees it, in a comment, at the point
  it is allocated.
- MUST NOT: ⚠ **Never return a pointer into a buffer whose lifetime is shorter than the caller's use.**
- SHOULD: ⚠ **Prefer a caller-supplied buffer with an explicit length** over allocating inside.
- MUST: ⚠ **Bounds are checked against what was actually read**, never against a header's claim.

## Undefined behaviour

⚠ **Grounds: the C standard.** ⚠ **These are not opinions and not stylistic preferences.**
⚠ **A program with undefined behaviour has no defined output to be right about**, whatever it
printed the last time it ran.

- MUST: ⚠ **UB is not a measurement.** ⚠ **Code that works at `-O0` and breaks at `-O2` was never
  correct** — the optimiser did not break it, it exposed it.
- MUST NOT: ⚠ **Never overlay a `struct` on an unaligned packet buffer to read a field.**
  ⚠ Copy the bytes, or read them one at a time.
- MUST: ⚠ **Signed overflow, shifting by the width, and reading uninitialised memory are bugs
  even when the output looks right.**

## Errors and absence

⚠ **Grounds: `CLAUDE.md` §1.** ⚠ **An uncounted drop is indistinguishable from a packet that
was never sent**, and the difference is the whole subject of this project.

- MUST: ⚠ **Distinguish "not there" from "could not be obtained"** (owner: `CLAUDE.md` §1).
- MUST: ⚠ **Never swallow an error.** ⚠ Leave it in a form that can be followed.
- MUST: ⚠ **One missing auxiliary thing must not take the whole stack down.**
- MUST: ⚠ **A dropped packet is counted.** ⚠ **An uncounted drop is invisible, and an invisible
  drop looks exactly like a packet that was never sent.**

## Naming

⚠ **Grounds: [`layers.md`](layers.md).** The RFC already named everything here.
A name that differs from the RFC's is a claim, and it has to be justified.

- MUST: ⚠ **Borrow the RFC's names, exactly** ([`layers.md`](layers.md)).
- MUST: Function names say ⚠ **what they do**.
- MUST: Predicates read as `is_` / `has_` / `can_` / `should_`.
- AVOID: `data1` / `tmp` / `buf2` / `flag` / `info`.
- SHOULD: ⚠ **Split on mixed responsibility, not on line count.**

## Before changing anything

- MUST: ⚠ **Look at the callers and at what it depends on.**
- MUST: ⚠ **Never widen the scope with an incidental refactor** (owner: `CLAUDE.md` §7).
