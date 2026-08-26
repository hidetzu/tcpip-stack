# 0006 — Clause 10 asks whether the AI can run the verification, not whether CI can

Decided 2026-08-26. Raised by the `issue-ready` gate returning `NO` on hidetzu/tcpip-stack#17.
⚠ **ADR 0004 created this collision on the same day.** This is it being resolved.

## The decision

`.claude/skills/issue-ready/SKILL.md` clause 10 asks:

> ⚠ **The AI given this issue cannot actually run the verification it needs**

⚠ **It no longer asks whether CI can run it.**

The owner's criterion, in their words:

> そのIssueを担当するAIが、必要なVerificationを実際に実行できること

## What collided

⚠ **Clause 10 used to read "it can only be verified with privileges or an environment CI does not
have".** That wording predates ADR 0004.

ADR 0004 then decided that ⚠ **CI runs the static tier only**, because a GitHub-hosted runner refuses
`unshare -Urn`. ⚠ **It also said, in the same breath, that `real` and `foreign` still exist and are
still required before a PR** — they run where unprivileged user namespaces are permitted.

⚠ **Those two together make every issue whose proof needs a TAP device fail clause 10**, on the old
wording. hidetzu/tcpip-stack#17 was the first to hit it, hidetzu/tcpip-stack#19 would be the second,
and ⚠ **so would nearly everything left in this project** — a stack is proved on a wire, not in a
compiler.

⚠ **The gate refused to resolve it itself** and returned `NEEDS-HUMAN-DECISION`, which is what that
verdict is for: when the issue, the rules and an ADR disagree, ⚠ **the gate does not pick a winner.**

## Measured before deciding

2026-08-26, on the developer's machine — Arch Linux, kernel `7.0.2-arch1-1`, x86_64, uid 1000, no
`sudo`:

| What was measured | Result |
|---|---|
| `unshare -Urn true` | ⚠ **works** |
| `make check-real` | ⚠ **6 of 6 cases passed** |
| `kernel.apparmor_restrict_unprivileged_userns` | ⚠ **not present on this kernel** |

For contrast, on a GitHub-hosted `ubuntu-24.04` runner the same day (ADR 0004): that sysctl is `1`
and `unshare -Urn` is refused.

⚠ **So the answer to "can the verification be run" is a property of the machine, not of the issue.**
⚠ **It is measured per issue, on the machine that will do the work** — never assumed.

## Why

⚠ **Because the clause exists to stop an issue nobody can finish**, not to stop an issue CI cannot
see. An issue whose checks the assigned worker can run, and did run, ⚠ **can be carried to the end
and reported honestly.** That is what `ready-for-ai` claims and nothing more.

⚠ **The old wording confused "shown green on a runner" with "shown green".** ⚠ **In this repository
those have been different things since ADR 0004**, and pretending otherwise would have frozen the
project at the compiler.

## What was decided against, and why

- **Leaving clause 10 as it was.** ⚠ **Then nothing that touches a wire is ever `ready-for-ai`**, and
  the gate would stop on the same collision every time it ran.
- **Making the namespace tiers run in CI** by relaxing the runner's AppArmor setting. ⚠ **ADR 0004
  declined that and this ADR does not reopen it** — it is a separate question about what ADR 0001's
  "no `sudo`" covers.
- **Reading clause 10 as "the developer could run it in principle".** ⚠ **In principle is not a
  measurement.** The gate runs the tier, or confirms its environment can be built, before answering.

## The boundary this sets

- ⚠ **Clause 10 is answered by measuring, on the machine that will do the work.** ⚠ **A gate verdict
  that assumed it is not a verdict.**
- ⚠ **Nothing here weakens `verify` §6.** When the tier CI cannot run is the one that proves a
  change, ⚠ **the report says which tiers ran and where**, and ⚠ **a green tick is not evidence for
  that change.**
- ⚠ **`ready-for-ai` still claims only that an AI can carry the issue to the end.** ⚠ **It does not
  claim the issue is right, and it does not claim CI covers it.**

## What this does not claim

⚠ **Not that CI coverage does not matter.** It matters, and ADR 0004 records exactly how little of
it there is. ⚠ **This says only that the quality gate is not the place that measures it.**

⚠ **Not that every machine can run every tier.** ⚠ **Where the environment cannot be built, zero
cases run, and that is `NOT-VERIFIED` — never a pass** (ADR 0001, `verify` §6). Clause 10 then bites,
⚠ **for the right reason.**
