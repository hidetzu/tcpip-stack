# 0026 — The tiers are named after who the other end is

Date: 2026-08-29
Status: accepted
Issue: hidetzu/tcpip-stack#116

## Context

⚠ **This was left open deliberately on day one** (hidetzu/tcpip-stack#2), and
`.claude/skills/verify/SKILL.md` §0 carried the reason from then until now.

⚠ **`static` / `real` / `foreign` were named before a single test existed.** ⚠ **`real` was the
weak one**: it said how true a check is, not what it needs — ⚠ **and "how true" is not a property
a runner can have.**

### ⚠ The measurement the decision was waiting for

⚠ **Two questions were being conflated.** Both were measured (`docs/SPEC.md` §3, 2026-08-26), and
⚠ **the second came back with a different answer from the one the names assumed:**

```text
                            needs an external network?   needs a privilege the developer lacks?
static                                 no                                  no
bring up a TAP + netns                 no                     ⚠ no — the capability comes from
talk to the kernel stack               no                       a user namespace it creates itself
```

⚠ **Creating a TAP device does need `CAP_NET_ADMIN` — but not from `sudo`.** `unshare -Urn`
supplies it to an ordinary user (ADR 0001).

⚠ **So both axes are `no` for all three, and neither separates them.** ⚠ **What separates them is
who the other end is.**

## Decision

```text
static    ⚠ nothing is running at all                   (unchanged)
isolated  ⚠ the device and us, and no one else          (was `real`)
interop   ⚠ the Linux kernel, which we did not write    (was `foreign`)
```

### ⚠ The table of what was called what

| Now | Before | Where it appears |
|---|---|---|
| `make check-isolated` | `make check-real` | Makefile |
| `make check-interop` | `make check-foreign` | Makefile |
| `tests/isolated.sh` | `tests/real.sh` | the runner |
| `tests/interop.sh` | `tests/foreign.sh` | the runner |
| `isolated: N of M cases` | `real: N of M cases` | ⚠ what each runner announces |
| `interop: N of M cases` | `foreign: N of M cases` | ⚠ what each runner announces |

⚠ **Read this table when a past ADR, issue body, or completion report names a tier.** ⚠ **They keep
the words they were written with.**

### ⚠ The old targets exist, and they fail

⚠ `make check-real` and `make check-foreign` are still targets. ⚠ **They print what the tier is
called now and then fail.**

⚠ **They are not aliases.** ⚠ **An alias that quietly ran the new target would keep the old name
alive for ever**, and the whole point of the rename was that one of those names described the wrong
thing. ⚠ **A bare "No rule to make target" was the alternative, and it says nothing a reader can
act on** (`CLAUDE.md` §4).

### ⚠ Nothing written before this is edited

⚠ **`CLAUDE.md` §4: never rename in bulk** — ⚠ **changing a term does not license a sweep through
the ADRs and past discussions.** ⚠ ADR 0001, 0004, 0006, 0009, 0012, 0017 and 0021 name the old
tiers and ⚠ **were not touched**, nor was any issue body or completion report.

⚠ **Two exceptions, and both are the same rule from the other side.** `CLAUDE.md` §9's rows point
at **live walls**, and ⚠ **`.claude/rules/testing.md` requires that when a check that guards a §9
row moves, the row moves with it and says so** — ⚠ **a row pointing at a case in a file that no
longer exists is a note wearing a wall's clothes.** ⚠ **Both rows now name the new file and say
what the old one was.**

## Consequences

- ⚠ **Case counts unchanged: 22 / 12 / 19.** ⚠ **That equality is the assertion this change rests
  on** — a rename that moves a count is not a rename.
- ⚠ **`docs/SPEC.md` §3's cost rows were re-measured**, not edited. ⚠ **They named twenty-one
  `static` cases and thirteen `interop` cases and there are twenty-two and nineteen** — ⚠ **the case
  count is part of a measurement's conditions** (`CLAUDE.md` §6), ⚠ **so those rows described a tree
  that no longer exists.** ⚠ **Editing the counts and keeping the timings would have been a number
  from another scope wearing this one's label.**
- ⚠ **The `interop` tier is 38771 / 38880 / 38919 ms now, against 24157 at thirteen cases.**
  ⚠ **The growth is the six cases added since, and they wait on real time.**
- ⚠ **`static` keeps its name.** ⚠ It was never the weak one.
