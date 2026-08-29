# Rules

⚠ **This directory holds "how to write it".**
⚠ **"How to work" is [`CLAUDE.md`](../../CLAUDE.md), "what may be claimed" is
[`docs/SPEC.md`](../../docs/SPEC.md), and "why" is [`docs/adr/`](../../docs/adr/).**

⚠ **Never duplicate.** ⚠ **Written in two places, one of them goes stale.**
⚠ **If a subject already has an owner, this directory only says "look there".**

| File | What it holds |
|---|---|
| [`layers.md`](layers.md) | What question this project answers, and the Wire / Parse / State / Report split |
| [`c.md`](c.md) | Responsibility, memory, errors, naming in C |
| [`testing.md`](testing.md) | What to confirm, in what order of priority; ⚠ **what to do when a check's subject moves**, and ⚠ **when a mutation is not one** |
| [`git.md`](git.md) | Operations that are forbidden without being told |

⚠ **`MUST` = required, `SHOULD` = default, `MAY` = optional.**
⚠ **`⚠` marks "it hurts if you step on it"** (same convention as `CLAUDE.md`).

## ⚠ Subjects owned elsewhere

⚠ **Do not copy these here.**

| Subject | Owner |
|---|---|
| not captured ≠ not sent / never dress a guess as a measurement / denominators | `CLAUDE.md` §1, §6 |
| Wording a human reads (never open with what does not work) | `CLAUDE.md` §4 |
| Permission for `git push` and merge | `CLAUDE.md` §8 |
| Which checks to run, in what order | `.claude/skills/verify/SKILL.md` |
| How to review a change (scope, rules, freshness of async results) | `.claude/skills/change-review/SKILL.md` |
| Whether an issue can be handed over | `.claude/skills/issue-ready/SKILL.md` |
| ⚠ **What "What asserts it" may name** (a case, never a file) | `docs/SPEC.md` §1, and `CLAUDE.md` §9 for why |
