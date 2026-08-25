# Testing

⚠ **`MUST` = required, `SHOULD` = default, `MAY` = optional.**

⚠ **Which checks to run, and in what order, is owned by [`verify`](../skills/verify/SKILL.md).**
⚠ Not here.
⚠ **This file holds only "what to confirm first".**

## Purpose

⚠ **Confirm that the required behaviour is not broken**, not that the code was written.

- MUST: ⚠ **Never call a passing test a completed verification** (owner: `CLAUDE.md` §1).
- MUST: ⚠ **A test that cannot fail is not a test.** ⚠ Break the code and watch it fail,
  ⚠ **and read the failure message to confirm it failed for the intended reason.**

## Priority

1. Parsing and validation of what arrives on the wire
2. State machine transitions
3. ⚠ **Malformed, truncated, hostile, and absent input**
4. The path a user actually exercises end to end
5. Performance detail

## Wire and parse

- MUST: ⚠ **Hold representative captured packets as fixtures**, so the parser can be tested
  with no network at all.
- MUST: ⚠ **Test the truncated packet, the zero-length payload, and the field value we do not support.**
- MUST: ⚠ **Confirm that "malformed" and "unsupported" do not get confused** ([`layers.md`](layers.md)).
- SHOULD: ⚠ **Keep it testable without an fd, a clock, or root** ([`c.md`](c.md)).

## Against something we did not write

⚠ **The point of question 3 in [`layers.md`](layers.md).**

- MUST: ⚠ **At least one check has the other end be something external** —
  the kernel stack, `ping`, `tcpdump`, or a trace captured elsewhere.
- MUST: ⚠ **Say plainly which side failed.** ⚠ **An external failure is still a FAIL,
  but it is not evidence that our code broke** (owner: `verify`).
- MUST NOT: ⚠ **Never assert what the other side will do right now.**
  ⚠ **Assert our own correctness, and record what actually came back before judging.**

## When something is fixed

- MUST: ⚠ **Every fixed bug leaves a test behind** (owner: `CLAUDE.md` §2).
- MUST: ⚠ **Confirm it fails before the fix and passes after.**

## Do not add too many

- MUST NOT: ⚠ **Never add a pile of tests that pin down the current implementation's steps.**
- SHOULD: ⚠ **Test the contract** — what goes in, what comes out, what appears on the wire.
