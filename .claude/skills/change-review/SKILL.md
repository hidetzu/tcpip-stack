---
name: change-review
description: Review a tcpip-stack change (git diff) against the issue's scope and the project rules, and return PASS / NEEDS-FIX / HUMAN-DECISION. Use before opening a PR, and when the Loop Controller reaches its review stage.
---

# Change / Scope Review

⚠ **Read `git diff` yourself.** ⚠ Never write from a summary or from memory.

⚠ **Running the checks is not this skill.** That is [`verify`](../verify/SKILL.md).
What this looks at is **whether the change itself sits inside what was asked and inside the rules**.

⚠ **Never invent a standard here.** [`CLAUDE.md`](../../../CLAUDE.md),
[`.claude/rules/`](../../rules/), [`docs/SPEC.md`](../../../docs/SPEC.md),
[`docs/adr/`](../../../docs/adr/) and the issue's Owner Decisions are authoritative.

---

## 1. What to read

```bash
git diff main...HEAD          # the change itself
git diff --stat main...HEAD   # where it moved
git log --oneline main..HEAD  # is it split by reason
```

⚠ **Never judge from `--stat` alone.** Read the contents.

---

## 2. Scope

| What to check | ⚠ How it fails |
|---|---|
| **Acceptance Criteria** | ⚠ **One at a time**, each with what confirmed it. ⚠ "Probably satisfied" is not satisfied |
| **Out of Scope / Non-goals** | Files outside it have moved |
| **One PR, one reason** | ⚠ Other work got swept in (the `git add -A` accident) |
| **Unrequested features** | Something not in the issue has appeared |
| **Incidental refactors** | Rewrites unrelated to the goal |

---

## 3. The rules

⚠ **These outrank scope.** ⚠ Inside scope but touching one of these is still `NEEDS-FIX`.

| What to check | ⚠ How it fails |
|---|---|
| **not captured ≠ not sent** | A drop or a read failure gets reported as "nothing arrived" |
| **the test passed ≠ it is correct** | A check that would pass with the behaviour removed |
| **it replied ≠ it replied for the right reason** | A reply asserted, but not the field that made it right |
| **never dress a guess as a measurement** | Probabilities, confidence figures, numbers nobody measured |
| **denominators** | A number with no scope, date, or conditions. ⚠ Numbers from different scopes side by side |
| **RFC claims** | A behaviour changed with no RFC section named. ⚠ `MUST`, `SHOULD` and silence conflated |
| **two implementations of one question** | ⚠ The same decision made in two places. ⚠ **If unavoidable, is it cross-checked mechanically?** |
| **the meaning of a recorded value** | A counter, a state name, or a unit changed meaning without saying so |
| **untrusted input** | A length taken from the packet used without checking it against what was actually read |
| **silent drops** | A packet discarded with nothing counted (⚠ indistinguishable from one that never arrived) |
| **internal state shown to a human** | A raw enum or errno reaching output |

---

## 4. ⚠ Stale results and ordering

⚠ **Does an old result overwrite the current state?**

⚠ **This is the same class of defect as a stale async response overwriting a screen**, and in a
network stack it is the normal case rather than a rare race. ⚠ **Packets arrive out of order,
arrive twice, arrive after the state that asked for them is gone, and arrive from someone else.**

| What to check | ⚠ How it fails |
|---|---|
| ⚠ **Was the premise the same when it was sent and when it came back?** | A reply is applied to state that has since moved on |
| ⚠ **A late reply overtaking a newer one** | ⚠ **A slow response arrives after, and overwrites, a newer one.** Arrival order is not send order |
| ⚠ **A sample attributed to the wrong send** | ⚠ **A measurement taken from a retransmitted exchange cannot say which transmission it belongs to.** Attributing it anyway is a guess wearing the face of a measurement |
| **Timers still armed** | The condition changed but the timer is still scheduled to fire |
| **Ordering of failure and success** | "Nothing arrived" is emitted, then an old success lands. Or the reverse |
| ⚠ **Where state is written** | ⚠ The same state written from two places (⚠ **nothing decides which is last**) |
| **Cancellation** | Something cancelled still writes its result afterwards |
| **Identity** | A response matched to a request by position or timing rather than by an identifier |

⚠ **The way to check is not to read — it is to reorder.**
⚠ **Delay it, invert the order, and see whether it actually happens.**
⚠ **Never pass it because "it is unlikely."** ⚠ On a network it is not unlikely.

⚠ **This is a correctness question, not a presentation one.** ⚠ **State overwritten by a stale
result reads, from outside, as something that was observed.**

⚠ **Do not prescribe the fix.** Generation counters, identifier matching, or cancellation are
implementation calls. ⚠ **Only judge whether it is handled.** If it is not, `NEEDS-FIX`.

---

## 5. Tidy-up

| What to check | ⚠ How it fails |
|---|---|
| **Dead code** | Functions no longer called are still there |
| ⚠ **Stale comments** | ⚠ **They mislead harder than code.** Old numbers, counts, filenames |
| ⚠ **Copied comments** | Moved to another file, ⚠ **and the numbers no longer match** |
| **Changes with no effect** | Written, but nothing changes (⚠ confirm by measuring) |
| **Fixed as a set** | implementation -> check -> comment -> README -> `docs/SPEC.md` |
| **Bare issue numbers** | ⚠ Write them with the repository name (a bare number points elsewhere after a migration) |

⚠ **Never write "confirmed" for something that was not verified.**

---

## 6. What to return

```
Verdict: PASS / NEEDS-FIX / HUMAN-DECISION

Scope:
  N files changed / M reasons        ⚠ only what was actually read

Acceptance Criteria:
  1. <AC>  -> <what confirmed it>  OK / NO / ⚠ unverified

Blocking:
  - <breaks a rule / outside scope / an AC unmet / ⚠ a stale result can overwrite current state>

Non-blocking:
  - <worth fixing, not worth blocking on>

Human Decision:
  - <spec, protocol behaviour, meaning of a recorded value>
```

| Verdict | When |
|---|---|
| **PASS** | Every AC met, nothing outside scope, no rule touched |
| **NEEDS-FIX** | ⚠ **Any AC unmet** / outside scope / a rule touched / ⚠ **a stale result can overwrite** / tidy-up outstanding |
| **HUMAN-DECISION** | ⚠ **The spec, the protocol behaviour, or the meaning of a value** must be settled first. ⚠ **Never settle it yourself** |

⚠ **One blocking item means it is not a PASS.**
⚠ **One "unverified" AC means it is not a PASS** (either `NEEDS-FIX`, or back to `verify` to measure).
