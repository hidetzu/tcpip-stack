---
name: loop-controller
description: Carry exactly one ready-for-ai tcpip-stack issue through gate, plan, owner approval, implement, verify, review and PR. Use for "run #<N> through the loop" or "loop-controller #<N>". Never picks an issue on its own.
---

# Loop Controller v1

⚠ **The controller holds no judgement of its own.** It calls, and transitions on the verdict returned.

```
PRECHECK -> READY_CHECK -> PLAN -> APPROVAL -> WORK -> PR -> CI -> MERGE -> STOP
                  ^                             |
                  '------ back on a NO ---------'
```

⚠ **v1 is not a queue processor.** One issue. ⚠ **Never patrols on its own.**

## ⚠ Never, under any circumstances

```
auto-merge (--auto / merge queue)     apply or remove ready-for-ai
merge bypassing protection (--admin)  rewrite or split an issue
pick an issue                         create a new issue
switch to a different issue           decide the spec or the protocol behaviour
widen the scope                       skip a check or a review
push to main                          retry without limit
merge on red or in-progress CI        skip a gate and merge
```

⚠ **Never copy a judgement standard into this file.** The list of checks, the issue criteria —
each belongs to its own skill (rule: never two implementations of the same question).

---

## 1. PRECHECK

### With no issue number

⚠ **Never pick one.** List candidates and stop.

```bash
gh issue list --state open --label ready-for-ai
```

```
STOP: no target
Candidates: <list>
⚠ Say which one by number. This will not choose.
```

### With an issue number

```bash
gh issue view <N> --json number,title,body,labels,state
gh issue view <N> --comments
```

⚠ **Stop when**

| What | ⚠ Why stop |
|---|---|
| `state` is `CLOSED` | Never touch something already finished |
| no `ready-for-ai` | ⚠ **This is the entry condition.** ⚠ **Never apply it yourself** |

### Local state

```bash
git status --short
git branch --show-current
gh pr list --state open --search "<N>"
```

⚠ **Stop when**

- ⚠ **Uncommitted changes unrelated to this issue** -> `STOP: WORKTREE NOT CLEAN`.
  ⚠ **Never stash, discard, or commit them**
- ⚠ **An open PR already closes this issue** -> ⚠ **Never open a second one.**
  If you cannot tell whether it is a continuation or a restart, stop

⚠ **Never commit to `main`.** Branch as `<type>/<short-name>`.

---

## 2. READY_CHECK

⚠ **The label is an entry condition, not a guarantee that it can be implemented.**
Both body and comments change after a label is applied. Labels get applied by mistake.

-> ⚠ **Always run [`issue-ready`](../issue-ready/SKILL.md)** (`YES` / `NO`).

⚠ **On `NO`, implement nothing.**

```
STOP: ISSUE NOT READY
Issue: #N / Label: ready-for-ai / Quality Gate: NO
Unresolved: <verbatim>
⚠ Not one line has been implemented.
```

⚠ **Never rewrite the issue, remove the label, close it, or fill in the spec.**
⚠ **Report, and nothing else.**

---

## 3. PLAN

Use the planning stage of `issue-work`. ⚠ **Never copy its contents here.**

Produce:

```
Issue / Goal / Owner Decisions / Scope / Out of Scope
Files to touch (planned) / Acceptance Criteria
Verification Plan (which checks)
Review Plan (change-review)
⚠ Where this is likely to stop
```

⚠ **If something must be measured before it can be decided, measure it now and give the number.**

---

## 4. APPROVAL (⚠ human gate)

⚠ **Ask with `AskUserQuestion`.** ⚠ Never bury it in prose.

### ⚠ What approval means (the execution contract)

Once the owner approves, ⚠ **for that one issue only**, the following count as permitted:

```
implement / fix / inner verify / final verify / review
commit / ⚠ push to that branch / open the PR
⚠ merge once CI is entirely green
```

⚠ **Not included**

```
another issue / widening scope / deciding spec or protocol behaviour
applying or removing ready-for-ai / a broad refactor
⚠ auto-merge (--auto / merge queue) / ⚠ merge bypassing protection (--admin)
⚠ merge on red or in-progress CI
```

⚠ **With merge included, the human enters at exactly one point — the approval at the start.**
⚠ **Green CI does not mean the spec is right.** ⚠ **The PR remains, so it stays readable afterwards.**

⚠ **This is the `CLAUDE.md` §8 exception, made explicit and confined to the controller.**
⚠ **Used standalone, `issue-work` still takes permission every time.** Nothing is weakened.

---

## 5. WORK (⚠ the only autonomous stretch)

```
implement (issue-work)
   |
inner verify (verify, inner loop)
   | PASS
final verify (verify, final gate)
   | PASS
review (change-review)
   | PASS
PR
```

⚠ **Where each verdict goes**

| Returned | What to do |
|---|---|
| Verify `PASS` | Continue |
| Verify `FAIL` | ⚠ **If fixable within scope**, back to implement. **Counts as one round** |
| Verify `NOT-VERIFIED` | ⚠ **Stop by default.** Only when an external cause makes a retry sensible, **retry once under the same conditions**. Then stop. ⚠ **Never edit code to make it go away** |
| Review `PASS` | Continue |
| Review `NEEDS-FIX` | ⚠ **Only the in-scope findings**, then back to implement. **Counts as one round** |
| Review `HUMAN-DECISION` | ⚠ **Stop immediately.** The controller does not decide |

⚠ **After a fix, run inner -> final -> review again.** Never skip.

### ⚠ Round limit

⚠ **Three rounds maximum** (the first implementation does not count).
On reaching it: `STOP: LOOP LIMIT REACHED`.

⚠ **The same cause, the same failing check, or the same finding repeating stops it early**
(`STOP: REPEATED FAILURE`). ⚠ **Turning the crank three times is not the point.**

⚠ **Nothing mechanically enforces this limit.**
⚠ **A static check could only confirm the limit is written down**, which is not the same as
confirming it was honoured. ⚠ Operate knowing that.

---

## 6. PR

⚠ **Only when all of these hold.**

```
[ ] Issue Quality Gate = YES
[ ] Owner approval = YES
[ ] Final verify = PASS
[ ] Required review = PASS
[ ] Unresolved human decisions = 0
[ ] Round limit not exceeded
```

Include `Closes #<N>`, and make it visible that the controller ran it.

```
Loop Controller: Quality PASS / Verify PASS / Review PASS / round 2 of 3 / no decisions pending
```

---

## 7. CI -> MERGE -> STOP

⚠ **After opening the PR, wait for CI.**

```
forbidden: --auto / merge queue / --admin / pushing to main
```

### ⚠ Merge only when all of these hold

```
[ ] the six items in §6
[ ] CI is entirely green (not one pending)
```

⚠ **On a failure, split it apart first** (`verify` §4).

| Cause | What to do |
|---|---|
| Our defect | ⚠ **Back to WORK. Counts as one round** |
| External (the environment could not be built, tooling install hung) | ⚠ **Retry once under the same conditions.** Then stop |

⚠ **Never edit code to silence CI.**
⚠ **Never merge while it is not green.**

### merge

```bash
gh pr merge <PR> --squash --delete-branch
```

⚠ Then re-fetch `main` and ⚠ **confirm the issue actually closed** (that `Closes` took effect).

⚠ **After merging, stop. Never move on to the next issue.**

### Report (⚠ same shape when it stopped early)

```
Loop Controller Report

Issue:          #N
Quality:        PASS / NO
Owner approval: YES
What was done:  <summary>
Rounds:         2 / 3
Verify:         inner PASS / final PASS
Review:         change-review PASS
PR:             #XXX (merged / not merged)
CI:             all green / <what failed>
Stopped because: complete / <stop condition>
Unresolved:     none / <list>
```

---

## 8. dry-run

`loop-controller #<N> dry-run`

⚠ **Does**: fetch the issue / confirm `ready-for-ai` / re-run `issue-ready` /
produce the plan / confirm the stop conditions.

⚠ **Does not**

```
create a branch / change a file / commit / push / open a PR / modify the issue
```

---

## 9. Stop conditions (⚠ each stops immediately)

```
no ready-for-ai              Issue Quality Gate = NO
issue is CLOSED              an owner decision is unresolved
issue / comments / SPEC / ADR conflict and authority cannot be determined
it cannot be fixed without leaving scope
the spec or the protocol behaviour would have to be newly decided
the meaning of a recorded value would have to change
the runtime structure would have to change substantially
Final verify = NOT-VERIFIED  Review = HUMAN-DECISION
the same failure repeats     round 3 reached
unrelated uncommitted changes exist
an open PR for this issue already exists
```

⚠ **Stopping is not a failure.** ⚠ **It means the boundary held.**
