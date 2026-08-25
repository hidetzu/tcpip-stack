# Git

⚠ **`MUST` = required, `SHOULD` = default, `MAY` = optional.**

⚠ **Permission for `git push` and merge, how to split commits, and Conventional Commits are owned
by [`CLAUDE.md`](../../CLAUDE.md) §8.** ⚠ Not here.
⚠ **How to review a PR is owned by [`change-review`](../skills/change-review/SKILL.md).**

## ⚠ Never do these without being told

```text
git push --force
git reset --hard
git clean -fd
git checkout -- .
git restore .
```

- MUST: ⚠ **When one is genuinely needed, say what will be lost, first.**
- MUST: ⚠ **Never discard or overwrite someone's uncommitted work.**
- MUST: ⚠ **Never push to a branch someone else is working on without asking.**

## Before starting

- MUST: ⚠ **Look at the current branch and at uncommitted changes.**
- MUST: ⚠ **Keep our changes and theirs separate** (⚠ **a separate worktree makes this certain**).

## Conflicts

- MUST: ⚠ **Never discard the other side's change without understanding what it meant.**
- MUST: ⚠ **Re-run the checks after a merge or rebase.**
