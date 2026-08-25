---
name: context-maintainer
description: Find where tcpip-stack's records (SPEC / ADR / CLAUDE.md) have drifted from the implementation, and propose deletions and merges. Use at a natural break, when the scope has widened, or when the records have grown hard to check. Never deletes anything itself.
---

# Find the drift, propose the tidy-up

1. Review recently closed issues and merged PRs
2. Compare `docs/SPEC.md` against what is actually implemented
3. Check the superseded relationships between ADRs
4. Extract from `CLAUDE.md` and `.claude/rules/`:
   - duplication
   - contradiction
   - instructions that are no longer needed
   - detail that belongs in a skill
5. ⚠ **Check whether a settled decision exists only somewhere that disappears** (below)
6. Draft the corrections
7. Put "may these be deleted or merged?" to a human

---

## ⚠ What this never does

- ⚠ **Never deletes or merges anything itself.** ⚠ **It stops at step 7**
- ⚠ **Never copies a measured value out of a record as if it were current.**
  ⚠ **It is the value on the day it was written**
- ⚠ **Never rewrites "probably finished" into "finished"**

## ⚠ A decision can exist only somewhere that disappears

⚠ **Untracked files are not in git.** ⚠ **A decision that lives only there is lost.**
⚠ **A record being stale is easier to notice than a record never existing at all.**
So the skill that finds drift ⚠ **also looks for what was never written down.**

| What to collect | ⚠ How |
|---|---|
| ⚠ **A decision that exists only somewhere untracked** | Confirm it is untracked (`git check-ignore -v <path>`) before reading it |
| A decision that exists only in an issue | `gh issue list --state all --search "Owner Decisions"` |
| ⚠ **Implemented, but the reasoning was never recorded** | Compare `Owner Decisions` on closed issues against `docs/adr/` |

⚠ **Never write an ADR unprompted.** Go as far as telling a human "this never landed in an ADR".
⚠ **Never turn a mere decision into an ADR.** Until it is implemented, the issue holds it
(⚠ an ADR records **why a decision was made**, not what is planned).
⚠ **Write issue numbers with the repository name** (`hidetzu/tcpip-stack#N`).
⚠ A bare number points at something else after a migration.

---

## ⚠ Measure before saying it

```bash
git log --oneline -1
gh pr list --state merged --limit 30
gh issue list --state open
```

⚠ **Never say "there are a lot" from impression.** Count.

## What to return

```
main is at:   <commit> <title>
Checks:       <what ran, how many>   ⚠ as announced by the runner

Drifted:
  <what the record claimed -> what is measured now>

⚠ Decisions living only somewhere that disappears:
  <where, and what. ⚠ untracked note, or issue-only>

⚠ Proposed deletions and merges:
  <what, and why. ⚠ Say plainly which are unrecoverable>

⚠ Needs a human:
  <list>
```
