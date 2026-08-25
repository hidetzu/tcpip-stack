---
name: issue-work
description: Take a tcpip-stack issue number and carry it through fetch, plan, implement, verify, self-review and PR. Use when implementing against an issue, or when an issue number appears in the request.
---

# From issue to PR

The argument is an issue number (`#` optional). With no number, ask which one.
⚠ **Never pick one.**

**Report each stage before moving to the next.** ⚠ Never run the whole thing silently.

---

## 1. Fetch the issue and its comments

```bash
gh issue view <N> --json number,title,body,labels,state,assignees
gh issue view <N> --comments
```

- **Read every comment.** ⚠ **A later comment overrides the body.**
  An owner decision made mid-flight often exists only in a comment.
- If `state` is `CLOSED`, stop and confirm before proceeding.

## 2. Read the rules

```
CLAUDE.md          how we work here
.claude/rules/     how we write it
docs/SPEC.md       what may be claimed today
docs/adr/          why it was decided that way
```

Read any ADR covering what the issue touches.

## 3. Extract Owner Decisions and Non-goals

Copy these out of the issue **verbatim** and confirm them.

- **Owner Decisions** … highest priority. ⚠ **Never change one on your own judgement**
- **Non-goals** … never widen past this
- **Acceptance Criteria** … done is judged by these alone
- **Constraints** … issue-specific limits

⚠ If a comment overrides the body, take the comment.
⚠ If body and comment conflict and you cannot tell which is authoritative, **ask**.

## 4. Produce a plan

Before implementing, produce this briefly and **get it approved**.

- Which files, and what each change does
- For each acceptance criterion, ⚠ **what will confirm it** (which check, measured how)
- ⚠ **Anything needing an owner decision — raise it here, first**
- If something must be measured before it can be decided, ⚠ **measure it now and give the number**
  (`CLAUDE.md` §7: measure before polishing)
- ⚠ **Name the RFC and section** anything behavioural is being held to

## 5. Implement

- ⚠ **The smallest change that meets the goal.** No broad refactor unrelated to the issue
- Read the existing code first. ⚠ **Never build a second implementation of the same question**
- ⚠ **Never print an internal enum at a human.** Words a person reads live in one layer
  ([`layers.md`](../../rules/layers.md))
- Change code and fix **the comments, the checks and `docs/SPEC.md` with it**
  (⚠ **a stale comment misleads harder than stale code**)

## 6. Verify

⚠ **How to run it is in [`verify`](../verify/SKILL.md).** ⚠ Not here
(rule: never two implementations of the same question — ⚠ **one of them goes stale**).

`verify` holds: the entry points and their measured cost / inner loop and final gate /
⚠ **splitting our defect from an external one** / `PASS` `FAIL` `NOT-VERIFIED`.

Two obligations belong to this stage:

- ⚠ **Pass the final gate before opening the PR.** Green in the inner loop is not "it passed"
- ⚠ **Leave every bug fixed here behind as a check.**
  ⚠ **Then break it on purpose and confirm it really fails** —
  ⚠ **and read the failure text to confirm it failed for the intended reason**

## 7. Self-review

⚠ **What to look at is in [`change-review`](../change-review/SKILL.md).** ⚠ Not here.

`change-review` holds: scope (AC, Out of Scope, one PR one reason) /
the rules (not captured ≠ not sent, denominators, meaning of recorded values) /
⚠ **stale results and ordering** / tidy-up (dead code, ⚠ stale comments) /
`PASS` `NEEDS-FIX` `HUMAN-DECISION`.

⚠ **Reading a summary produces no findings.** Read the diff.

## 8. Commit

- Conventional Commits (`<type>(<scope>): <subject>`)
- **One reason, one commit.** Never sweep other work in with `git add -A`
- Never commit to `main`. Branch (`<type>/<short-name>`)
- Put **why** and **the measured numbers** in the body

## 9. PR

- ⚠ **Take permission for `git push` every time.** Permission granted before does not carry forward
- Include `Closes #<N>`
- ⚠ **Note which checks did not run on this PR**, and watch the run on `main` after merge

## 10. Report

Leave a `Completion Report` as a comment on the issue.
If anything needs a decision, ⚠ **stop there and ask.** Never decide it.

```
Summary                  what was done
Changed                  what moved
Verification Results     what ran, and how many
Remaining Issues         what was left
Owner Decision Required  what needs deciding
```
