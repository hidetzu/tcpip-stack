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

## ⚠ When a check's subject moves

⚠ **Grounds: it happened here twice**, in hidetzu/tcpip-stack#74 and #75, and ⚠ **once the check
stopped a pull request that was about to claim something it had not re-measured.**

- MUST: ⚠ **When the thing a check asserts changes, repoint the check — never delete it.**
  ⚠ **Ask what the check was really about**, and ⚠ **it is usually still true of the new subject.**
  ⚠ Example: a case asserting "nothing is built for data the window did not cover" became
  "something is built, and it does not pretend to have taken it" — ⚠ **the subject moved and the
  assertion did not weaken.**
- MUST: ⚠ **When a check that guards a `CLAUDE.md` §9 row has to move, the row moves with it**, and
  ⚠ **the row says the wall was repointed and why.** ⚠ A row pointing at a case that no longer
  exists is a note wearing a wall's clothes.
- MUST: ⚠ **A check firing because a parameter changed is the check working.** ⚠ **Re-measure under
  the new value and repoint it** — ⚠ never widen it until it stops complaining.

## ⚠ Write a check against the constant, not against the value it has today

⚠ **Grounds: it happened here** (hidetzu/tcpip-stack#75). ⚠ A case written with
`HANDSHAKE_WINDOW` followed the number when it changed from 1 to 1460 and ⚠ **caught a real defect
that the old value had been hiding**; ⚠ cases written with the literal `5` beside it had to be
rewritten by hand and asserted nothing about the change.

- MUST: ⚠ **Name the constant the code names.** ⚠ A literal in a check is a second copy of a
  decision (`CLAUDE.md` §3), and ⚠ **the two diverge silently when the constant moves.**
- MUST: ⚠ **Where a case needs a value relative to the constant, write it relative** —
  `HANDSHAKE_WINDOW + 2`, not `1462`.
- SHOULD: ⚠ **Assert against the constant AND against the value it must not be**, when a previous
  value would be a regression. ⚠ Comparing only with the constant passes if both move back together.

## ⚠ A mutation that changes nothing is not a mutation

⚠ **Grounds: it happened here three times** (hidetzu/tcpip-stack#64, #80, #86). ⚠ Each time a
mutation was applied, every check passed, and ⚠ **the question was whether that was a gap in the
checks or a change with no effect.**

- MUST: ⚠ **Before reporting an uncaught defect, work out whether the mutation changed the
  behaviour at all.** ⚠ Example: `>=` to `>` at a boundary where the other side computes zero;
  restoring a refusal for bits that no longer reach it.
- MUST: ⚠ **Say which it was, in the report.** ⚠ **"It passed" is not a result** — ⚠ *behaviour
  preserving* and *the check does not assert this* are different findings and call for different
  work.
- MUST NOT: ⚠ **Never present a behaviour-preserving mutation as proof the check works.** ⚠ It
  proves nothing either way.

## When something is fixed

- MUST: ⚠ **Every fixed bug leaves a test behind** (owner: `CLAUDE.md` §2).
- MUST: ⚠ **Confirm it fails before the fix and passes after.**

## Do not add too many

- MUST NOT: ⚠ **Never add a pile of tests that pin down the current implementation's steps.**
- SHOULD: ⚠ **Test the contract** — what goes in, what comes out, what appears on the wire.
