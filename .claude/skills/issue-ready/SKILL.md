---
name: issue-ready
description: Judge whether a tcpip-stack issue can be handed to an AI, and shape it into something that can. Use when drafting a new issue, auditing existing ones, or deciding whether ready-for-ai may be applied. Never applies the label.
---

# Issue Quality Gate

⚠ **This is not the skill that implements an issue.** That is
[`issue-work`](../issue-work/SKILL.md). ⚠ **This runs before it.**

```
draft issue / existing issue
        |
   issue-ready       <- here. decides whether it can be handed over
        |
   the owner applies the label
        |
   issue-work
```

## ⚠ What this skill never does

- ⚠ **Never applies the `ready-for-ai` label.** The owner does.
- ⚠ **Never closes, rewrites, or splits an issue.** It proposes.
- ⚠ **Never fills in a missing spec.** When the issue, `docs/SPEC.md`, `docs/adr/` and the code
  disagree, ⚠ **do not decide which is right** — return `NEEDS-HUMAN-DECISION`.
- ⚠ **Never decides what the protocol should do.**

---

## 1. Read first

```
CLAUDE.md          how we work
docs/SPEC.md       what may be claimed today
docs/adr/          why it was decided that way
```

⚠ **Read the ADRs covering what the issue touches.** ⚠ An ADR is often newer than the issue body.

## 2. Look at the real thing

⚠ **Never treat an old issue body as the current spec.**
A number in an issue is **the value on the day it was written**, not today's.

```bash
gh issue view <N> --json number,title,body,labels,state,createdAt
gh issue view <N> --comments        # ⚠ comments override the body
```

⚠ **Re-measure on `main`.** If the issue says "N packets are dropped" or "it never replies",
confirm that is **still** true. A discrepancy is itself something to report.

---

## 3. Shape

An issue handed to an AI carries:

```
Goal                  one thing that, once true, means it is done
Background            why. ⚠ With denominator, date and conditions if measured
Scope                 what may be touched
Out of Scope          ⚠ what may not. Without this it spreads without limit
Owner Decisions       ⚠ what is already settled. The AI never overrides these
Acceptance Criteria   ⚠ in a form a machine can judge
Verification          which checks. ⚠ Including any that must be added
Human Decision        ⚠ what is not settled (if any, ready-for-ai is not allowed)
Stop Conditions       what makes it stop and ask
```

⚠ **Acceptance criteria must be machine-judgeable.**

| ⚠ Not this | This |
|---|---|
| ARP works | An ARP request for our address gets a reply whose sender hardware address equals our MAC |
| handles bad packets properly | An IPv4 header with a wrong checksum is dropped and the drop counter increments by exactly 1 |
| it is fast | Under `<stated conditions>`, the measured p90 is at or below `<value the owner set>` |
| responds correctly | ⚠ **"Correctly" cannot be judged.** Name the RFC section and the observable byte |

⚠ **A number carries the denominator of its claim, the date, and the conditions** (`CLAUDE.md` §6).
⚠ **A behavioural claim carries the RFC and section it comes from.**

### ⚠ Distinguishing outcomes (⚠ **when it applies**)

⚠ **An issue about "we do / do not respond to something" must say which outcomes it covers.**
Without that, ⚠ **the AI will pick an implementation that reports "not there" for something it
merely failed to obtain** (`CLAUDE.md` §1).

| Outcome | ⚠ What it must not be confused with |
|---|---|
| Accepted and handled | — |
| ⚠ **Malformed** — it violates the format | ⚠ **Not the same as unsupported.** The sender is wrong |
| ⚠ **Well-formed but unsupported** — we understand it and decline | ⚠ **Not the same as malformed.** The sender is fine |
| ⚠ **We have not implemented it yet** | ⚠ **Never phrased as the other side's fault** (`CLAUDE.md` §4-1) |
| ⚠ **Nothing arrived** | ⚠ **Not the same as "it was not sent."** ⚠ It may have been dropped anywhere in between |
| ⚠ **A timer expired while waiting** | ⚠ **Not an answer.** ⚠ It is the absence of one |

⚠ **Do not demand all six every time.** ⚠ **Only the ones that can occur for this issue.**
⚠ Say explicitly that the rest cannot occur (⚠ **never drop them silently**).
⚠ **Some issues do not apply at all** (build flags, file layout). ⚠ **Say "not applicable" in the verdict.**

⚠ **Never invent vocabulary in an issue.** ⚠ If a new distinction is needed, that is a **spec change**,
and a human decides (§4, clauses 1 and 8).

⚠ **Write the acceptance criteria per outcome** — not "handles it", but
⚠ **which outcome produces which observable effect** (for example: on a checksum failure, no reply
is emitted **and** the drop counter increments).

---

## 4. Judge the granularity

⚠ **Any one of these means `ready-for-ai` is not allowed.**

| # | What | ⚠ Why |
|---|---|---|
| 1 | The spec itself has to be decided | ⚠ The AI invents a spec |
| 2 | The protocol behaviour has to be chosen between valid options | Same |
| 3 | It has several independent goals | It cannot be one PR for one reason |
| 4 | Acceptance criteria are not machine-judgeable | Nobody can say it is done |
| 5 | Scope is too broad | A judgement call arrives mid-way |
| 6 | Out of Scope is missing | It spreads without limit |
| 7 | An owner decision is unresolved | ⚠ The AI decides in their place |
| 8 | It contradicts the code, SPEC, or an ADR | ⚠ The AI decides which is right |
| 9 | ⚠ **It changes what a recorded value means** | ⚠ Goes straight to the rules. A human decides |
| 10 | ⚠ **It can only be verified with privileges or an environment CI does not have** | ⚠ It cannot be shown green |
| 11 | ⚠ **Outcomes are not distinguished** (and this issue is one where they apply) | ⚠ **The AI reports "not there" for "not obtained."** §3 |

⚠ **When it is too big, propose a split.** ⚠ **Split by reason, never by file.**

---

## 5. Return the verdict

```
Issue #N  <title>

Classification: KEEP / REWRITE / SPLIT / CLOSE / NEEDS-HUMAN-DECISION

Ready for AI: YES / NO

Reason:
  <which clause it hit. If none, say all 11 were checked>

⚠ Outcome distinction:
  <applicable or not. If applicable, which outcomes are written and which are missing>

Where it disagrees with main today:
  <⚠ the re-measured result. If none: "re-measured, no discrepancy">

Split proposal:
  <only for SPLIT. by reason>

Verification:
  <which checks. Including any that must be added>

Human Decision:
  <⚠ list what a human must decide, without deciding it>
```

⚠ **`Ready for AI: YES` still does not apply the label.**
⚠ **`YES` means "an AI can implement this", not "this should be implemented."** The owner decides the latter.

---

## 6. ⚠ Drafting a new issue

⚠ **Do not fold this shape into the templates outsiders use.**
A bug report from someone outside should stay cheap to file. ⚠ **Demanding nine sections raises
the cost of reporting.**

⚠ **The §3 shape is for issues the owner writes, and for drafts this skill has shaped.**

⚠ **One issue, one reason.** Never add "and while we're here".
