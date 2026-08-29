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
git checkout -- .          ⚠ and `git checkout <path>`, which is the same
git restore .              ⚠ and `git restore <path>`
```

- MUST: ⚠ **The single-path form is the same operation.** ⚠ `git checkout src/tcp.c` discards
  everything uncommitted in that file, ⚠ **including work written minutes ago for another reason.**
  ⚠ **Grounds: `CLAUDE.md` §9** — it happened three times in one session, always while undoing a
  mutation, and ⚠ **once it was a check that noticed rather than the person.**
- MUST: ⚠ **To undo a change you made on purpose, copy the file aside first and copy it back.**
  ⚠ Every mutation that did so cost nothing.

- MUST: ⚠ **When one is genuinely needed, say what will be lost, first.**
- MUST: ⚠ **Never discard or overwrite someone's uncommitted work.**
- MUST: ⚠ **Never push to a branch someone else is working on without asking.**

## Before starting

- MUST: ⚠ **Look at the current branch and at uncommitted changes.**
- MUST: ⚠ **Keep our changes and theirs separate** (⚠ **a separate worktree makes this certain**).

## Conflicts

- MUST: ⚠ **Never discard the other side's change without understanding what it meant.**
- MUST: ⚠ **Re-run the checks after a merge or rebase.**
