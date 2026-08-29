# tcpip-stack — how we work

This file holds **how to work**.
**What may be claimed** goes in `docs/SPEC.md`; **why a decision was made** goes in `docs/adr/`.
⚠ **How to write code** (C, the layer split, testing priorities, forbidden git operations)
lives in `.claude/rules/`.

⚠ **Never duplicate.** ⚠ **Written in two places, one of them goes stale.**
When the spec changes, fix the spec. Do not restate it here.

Before starting work, read `.claude/rules/README.md`.

⚠ **`⚠` marks "it hurts if you step on it".** ⚠ It is not decoration.

---

## 0. What this repository is

A user-space TCP/IP stack for Linux, built as an experiment in AI-assisted systems engineering.

⚠ **Both halves matter.** The stack is the artefact; how it gets built is the subject.

⚠ **This repository is the first consumer of a workflow extracted from `hidetzu/konjaku`.**
konjaku is web / UX / product, where the right answer is arguable.
Here the right answer is pinned down by an RFC and by what actually appears on the wire.
⚠ **If the same workflow holds at both ends, it is worth extracting into `claude-dev-template`.**
⚠ **What proves general belongs in the template. What is specific to this domain stays here.**

⚠ **The rules below were inherited as rules, not as evidence.**
⚠ **Every measured number and every pitfall has to be earned here, in this repository** (§6, §9).

⚠ **Inherited does not mean provisional.** A rule grounded in the C standard, in a protocol, or
in the fact that packets arrive from strangers ⚠ **binds from the first line of code** — it is
not waiting for an accident here to prove it. ⚠ **Those live in `.claude/rules/`, each with its
grounds.** ⚠ **§9 is the other thing entirely: what this repository actually paid for.**

---

## 1. The first principle

> **Correct before clever.**

Then, and only then, make it fast and make it elegant. Never swap the order.

These three lines hold in the code, in the tests, and in every report:

```
not captured      ≠  not sent
the test passed   ≠  the behaviour is correct
it replied        ≠  it replied for the right reason
```

So:

- **Never call something verified when it was not checked.**
- **Never report "absent" for something that was merely not captured.**
- **Never dress a guess up as a measurement.**

⚠ **The question is never "did the test pass".** ⚠ **It is "does that test actually assert the claim".**
A stack that answers a ping while computing the checksum wrong still answers the ping.

⚠ **Silence in an RFC is not permission.** `MUST` / `SHOULD` / `MAY` are different things,
and "the RFC does not say" is a fourth thing. ⚠ **Do not collapse them.**

---

## 2. Verification

⚠ **How to run it lives in `.claude/skills/verify/SKILL.md`.** ⚠ Not here (never two copies).

Only three things belong here.

- ⚠ **Building is not verifying.** A clean build says nothing about what goes on the wire.
- ⚠ **Every bug that gets fixed leaves a test behind.** Make it so the same thing stops the build next time.
  ⚠ **After adding it, break the code on purpose and confirm the test actually fails** —
  ⚠ and that it fails **for the reason you intended**.
- ⚠ **Green CI does not mean the spec is right.** It means nothing contradicted what was asserted.

---

## 3. Architecture boundaries

```
Keep runtime dependencies out
Keep the data path free of allocation surprises
Push work to setup time, not to per-packet time
The stack does protocol; the harness does the environment
```

⚠ **Do not introduce anything without a reason:**
a third-party networking library / an event-loop framework / a build system beyond what is needed /
threads before a single-threaded version works / kernel modules.

⚠ **Never keep two implementations that answer the same question.**
If one is unavoidable, cross-check them mechanically.
⚠ **Writing the same decision in the parser and in the test is how the two silently diverge.**

⚠ **The concrete layer split is not decided yet.** ⚠ **It belongs in an ADR before it belongs in code.**

---

## 4. Words

- **Never leak internal state into what a human reads.** Not `ERR_STATE_3`, but a sentence
  that says what happened and what to do about it.
- **Name things after the protocol concept, not after the data structure.**
  ⚠ The RFC already named everything in this domain. ⚠ **Borrow its names, and borrow them exactly.**
  ⚠ If a name here differs from the RFC's, that difference is a claim — justify it.
- **Never rename in bulk.** Changing a term does not license a sweep through the ADRs and past discussions.

### 4-1. Never open with what does not work

⚠ **This is not about hiding anything.** §1 outranks it, and **limitations are always stated**.
What changes is the **order, the subject, and the tense** — not whether it is said.

- **Say what this does first.** What it does not do comes after, with the reason
  and with what to do instead.
- **Do not use the progressive tense for a state.** "not receiving" reads as something
  happening right now on the reader's machine.
- **Never phrase our own gap as the other side's fault.** If we never implemented it,
  do not report it as "no response". ⚠ **The reader's next move depends on which it is** —
  retry, wait, or give up.
- **Do not sound stalled.** "not implemented yet" beats "unavailable": leave a reason to come back.

---

## 5. Comments

Comments here carry **why this, why this value, what is being avoided**. That is an asset.
⚠ **But a stale comment misleads harder than stale code**, because it is believed.

Change code, and update the whole set:

```
implementation → test → comment → README → docs/SPEC.md
```

⚠ **When a check reads documentation or comments, strip the comments first.**
⚠ Otherwise the check picks up the very words written to describe it.

---

## 6. How to write numbers

- **Always give the denominator of the claim.** A number from another scope is a lie about this one.
- **Never write a number that was not measured.** No probabilities, no confidence figures.
- **A measurement is reproducible or it is not a measurement.** Record **when, where, and how**:
  kernel version, MTU, how the namespace was set up, how many runs, which percentile.
- ⚠ **Report a percentile as a value that was actually observed.** ⚠ Do not interpolate.
- ⚠ **The same rules apply to anything facing outward** (README, articles, commit messages).
  ⚠ **When the same claim appears in two places, it uses the same denominator.**
  ⚠ Different scopes are fine — ⚠ **say which scope each number is.**

---

## 7. How to proceed

1. **Measure before polishing.** Before fixing anything, state what it does now, in numbers.
2. Report **observation** (measured values, captured packets) and **inference** (interpretation) separately.
3. Never report as confirmed what was not verified.
4. Do not widen a change past its `Non-goals`. The smallest change that meets the goal is the default.

### 7-1. Decide yourself vs. ask

⚠ **The default is: decide, and carry it through to the end.** Stalling costs more.
Ask only where **being wrong cannot be walked back**.

| Decide yourself | Ask |
|---|---|
| Implementation order, how to split it, where tests go | ⚠ **Anything a human reads** on screen or in output |
| What to measure and how | ⚠ **When the scope moves** (crossing `Non-goals`) |
| A bug with exactly one sensible fix | ⚠ **When what may be claimed changes** (`docs/SPEC.md`) |
| Adding docs, comments, tests | Two presentable options that **measurement cannot settle** |

- Ask with **`AskUserQuestion`**. ⚠ **Never bury the question in prose** (it gets missed).
  This asks in Slack and receives the answer back (`.claude/hooks/ask-slack.mjs`).
  ⚠ **Nothing else goes to Slack** — no progress, no completions, no failures (they would bury it).
- ⚠ **Never ask what measuring would settle.** Measure first (rule 1 above).
- ⚠ **Asking stops the work.** Finish everything that does not depend on the answer **before** asking.
- ⚠ **Record what was asked.** Once decided, put the reason in `docs/adr/`.

### 7-2. `ready-for-ai`

⚠ **This is not a priority label.** It marks "an AI can carry this to the end without a human deciding mid-way".

⚠ **Only a human applies it.** The AI goes as far as producing the verdict
(`.claude/skills/issue-ready/SKILL.md`).

⚠ **Even with the label, permission for `git push` and merge is taken every time** (§8).

---

## 8. git

- Conventional Commits (`<type>(<scope>): <subject>`).
- **Take permission for `git push` every single time.** Permission granted before does not carry forward.
  - ⚠ **One exception.** Via the Loop Controller, for **one issue approved by the owner at the start**,
    pushing to that issue's branch, opening the PR, and **merging once CI is fully green** count as approved
    (`.claude/skills/loop-controller/SKILL.md`).
    ⚠ **Auto-merge (`--auto`) and merges that bypass protection (`--admin`) are not included.**
    ⚠ **Never merge on red or in-progress CI.**
- Never sweep unrelated work in with `git add -A`. **One reason for a change, one commit.**
- Never commit directly to `main`. Branch.

---

## 9. Pitfalls we have stepped on

⚠ **This table starts empty, and that is correct.**

⚠ **Nothing goes in here that did not happen in this repository.** Not an analogy from another
project, not something plausible, not something an AI expects to be true.
⚠ **A pitfall is a measurement** (§6): it names what happened, and what to do instead.

⚠ **This is not where engineering constraints go.** A rule that holds because of the C standard,
because of a protocol, or because the input is hostile ⚠ **belongs in `.claude/rules/`, and binds
already** ([`rules/c.md`](.claude/rules/c.md) sets out the distinction).
⚠ **Never manufacture an incident to move a constraint in here**, and
⚠ **never soften a constraint on the grounds that this table has no row for it yet.**

⚠ **When you fill a row in, also leave the test behind** (§2). A row with no test is a note;
a row with a test is a wall.
⚠ **If the incident also produces a new rule, the rule goes to `.claude/rules/` citing this row.**
⚠ **Both records stay. Neither replaces the other.**

| What happened | What to do instead |
|---|---|
| `docs/SPEC.md` §1 claimed that a read that could not be made is reported as its own outcome, and named `tests/static.sh` and `tests/real.sh` as asserting it (⚠ **that file is `tests/isolated.sh` since hidetzu/tcpip-stack#116; the sentence keeps the name it was written with**). ⚠ **Neither did.** ⚠ **The gap was already written down** — the completion report on hidetzu/tcpip-stack#2 said that check was missing — ⚠ **and the row was left standing anyway.** Found in review of hidetzu/tcpip-stack#3, not by any check | ⚠ **Name the case, not the file** (`docs/SPEC.md` §1 owns this now). ⚠ **Run that case before filling the row in, and read whether it covers every clause of the claim.** ⚠ **Saying a gap in one place is not permission to claim it in another.** ⚠ **Partial wall:** `tests/static.sh` `spec_names_checks_that_exist` stops a row naming a file and no case, a row naming nothing, a case name that does not exist, and a case with nothing to attribute it to — ⚠ **it cannot stop a case that exists and does not cover the clause, which is what happened here** |
| ⚠ **`docs/SPEC.md` §2, ADR 0021 and `src/handshake.h` all said "the peer retransmits the same segment, and each arrival hands over the next octet", marked measured.** ⚠ **It never was.** ⚠ The shape came from hidetzu/tcpip-stack#64's background measurement, ⚠ **which was taken with a window of 1024**, and was carried into a sentence about the build that advertises 1. ⚠ **Re-measured 2026-08-29**: a peer that honours the window sends **one** octet at the **same** sequence number, 7 copies in 8 seconds, its `Send-Q` stuck at 5 — ⚠ **so exactly one octet is ever taken per connection, not one per arrival.** ⚠ Found while measuring for the next milestone, ⚠ **not by any check**, and it had already been through three completion reports and a PR review | ⚠ **Re-measure under the conditions the sentence describes, never carry a shape across a changed parameter** (`CLAUDE.md` §6: a number from another scope is a lie about this one). ⚠ **The window was the parameter that changed and it is the one the sentence is about** — ⚠ that is exactly where a carried-over observation is least safe. ⚠ **Wall:** `tests/interop.sh` `the_peers_send_queue_drains_once_we_acknowledge` (⚠ **the file was `tests/foreign.sh` until hidetzu/tcpip-stack#116 — ⚠ the wall did not move, its file was renamed, and `.claude/rules/testing.md` requires the row to say so**) asserts every data segment carries exactly 1 octet — ⚠ **because the window we advertise is 1** — and that the five arrive at five sequence numbers. ⚠ **Change the window without re-measuring and it fails.** ⚠ **It has fired once already**: raising the window from 1 to 1460 at hidetzu/tcpip-stack#75 stopped that PR with "the peer sent segments of 5 octets, and the window we advertise is 1", ⚠ **which is the wall doing exactly its job.** ⚠ It was re-measured and repointed: at 1460 the five octets arrive as **one** segment, ⚠ **and lowering the window without re-measuring fails it again.** ⚠ **Repointed a second time at hidetzu/tcpip-stack#119**: the window is no longer a constant but what the device's MTU leaves, ⚠ **so "lowering the window" now means bringing the device up with a smaller MTU** — ⚠ the sibling case `an_acknowledgment_never_covers_an_octet_we_did_not_take` performs the same arithmetic the code performs, from `HANDSHAKE_HEADERS_BEFORE_DATA`, ⚠ **and `the_window_on_the_wire_follows_the_mtu` asserts the two differ at 1400 and 1500** so a build ignoring the MTU cannot pass both. ⚠ **The subject moved twice and the assertion did not weaken either time.** ⚠ The wall was first `a_window_of_one_gets_one_octet_and_the_same_one_again`, which asserted the peer's `Send-Q` staying at 5 — ⚠ that stopped being true when hidetzu/tcpip-stack#74 started acknowledging, ⚠ **so it was repointed at the same mistake rather than removed** |
| ⚠ **A lowercase `should` was read as a requirement — three times in one day.** ⚠ RFC 9293 §3.10.7.4 says "an acknowledgment **should** be sent in reply" and ⚠ **§2 binds the keywords "when, and only when, they appear in all capitals"**; that passage carries no labelled one. ⚠ hidetzu/tcpip-stack#87 called it a contradiction, ⚠ **cut hidetzu/tcpip-stack#89 for it**, and both were withdrawn (#91). ⚠ The same overstatement was already in **four** comments from #80, ⚠ **through a review**; and in #86's grounds, ⚠ **found only while building the wall for the first two.** ⚠ **Cost, 2026-08-29: one issue, three pull requests.** ⚠ **ADR 0024 had warned three days earlier that the new baseline would tempt exactly this** — ⚠ **a warning is not a wall** | ⚠ **Read whether the keyword is in capitals before calling anything a requirement**, and ⚠ **quote the document's own convention beside the sentence.** ⚠ `CLAUDE.md` §1 listed four things — `MUST`, `SHOULD`, `MAY`, silence; ⚠ **a lowercase keyword is a fifth and looks exactly like the second.** ⚠ **Where a change is right for another reason, say that reason** — #86's real grounds were a measured ECN failure and a field width, not a sentence. ⚠ **Partial wall:** `tests/static.sh` `a_lowercase_keyword_is_not_called_a_requirement` refuses a quotation carrying a lowercase `should` or `must` that is introduced with "asks for", "requires" or "the document's rule". ⚠ **It caught a real regression while being written, and a fourth instance of the mistake the day after** (`docs/SPEC.md`'s options row, quoting RFC 793's lowercase "A TCP must implement all options"). ⚠ **Its window was 300 characters and straddled two Markdown table rows on the first run** — ⚠ **a false positive is a wall that stops honest work**, and it is line-bounded for Markdown now. ⚠ **It cannot stop a requirement claimed with no quotation at all**, which is the harder half |
| ⚠ **A requirement was called "not met" for having the wrong SHAPE, and the document offers that shape.** ⚠ `docs/conformance.md` and `docs/SPEC.md` §2 both said `MUST-20`'s R2 fails because this stack gives up on a **time** and not on a **count of retransmissions**. ⚠ **RFC 9293 §3.8.3 (a), two paragraphs above the sentence that was quoted, says "R1 and R2 might be measured in time units or as a count of retransmissions".** ⚠ **The quotation came from Appendix B's abbreviated label** — "Close connection on R2 retransmissions" — ⚠ **and the body was never opened.** ⚠ **Cost, 2026-08-29: the owner took a decision on it** (which of three ways to treat the retransmission schedule), ⚠ **and the option they chose was framed around a gap that was not there.** ⚠ It had been through a completion report, a PR and a grouping comment. ⚠ **The verdict itself survives** — R1 is genuinely absent, and (c) needs "a threshold R2 **greater than R1**" — ⚠ **but a right verdict resting on a false reading is not a verdict** | ⚠ **When a verdict turns on the SHAPE of a requirement, open the body section — never judge shape from Appendix B's label.** ⚠ Appendix B is a **summary**; ⚠ **its rows are four or five words and they drop the qualifying sentences**, which is exactly where permitted alternatives live. ⚠ **Read the paragraphs around the one being quoted**, not only the one that matches. ⚠ **No wall, and the reason is the same as the misquote row's**: judging this needs the document, ⚠ **and no RFC is vendored here.** ⚠ **A check could see that a "not met" row quotes Appendix B's label rather than the body**, but ⚠ **it cannot tell a short body quotation from a label**, and ⚠ **a false positive is a wall that stops honest work** (the lowercase-keyword row paid for that lesson). ⚠ **Said as a note, with what it cost named** |
| ⚠ **`git checkout <path>` was used to undo a mutation and destroyed uncommitted work — four times.** ⚠ `tests/static.sh` (2026-08-28), `src/handshake.h` and `src/tcp.c` (2026-08-29). ⚠ **Each time a correction written minutes earlier went with the mutation.** ⚠ `.claude/rules/git.md` already forbids `git checkout -- .` and `git restore .` ⚠ **without being told**; ⚠ **the single-path form is the same operation and was not read as covered.** ⚠ The third one ⚠ **was caught by a check and not by noticing** — the wall in the row above failed on the restored text. ⚠ **The fourth was 2026-08-29, `src/handshake.h` again, in a session where this very row was on screen** — ⚠ restoring a one-line mutation to `HANDSHAKE_HEADERS_BEFORE_DATA` took the whole of hidetzu/tcpip-stack#119's work on that file with it: a new enum, a new constant, a derivation and a changed signature. ⚠ **Noticed immediately, because `git status` stopped listing the file** — ⚠ **that is the tell, and it is the only one there was** | ⚠ **Copy the file to the scratchpad before mutating it, and copy it back.** ⚠ Every mutation that used a saved copy this session cost nothing; ⚠ **all three losses used git.** ⚠ **`git checkout <path>` is `git checkout -- .` aimed at one file** — `.claude/rules/git.md` says so now. ⚠ **No wall:** nothing mechanical can tell an intended revert from an accidental one, ⚠ **and pretending otherwise would be worse than saying it is a note** (§9 allows a note and names what it costs). ⚠ **The fourth time proves the note is not enough on its own**: ⚠ **the rule was written, the row was read this session, and the hand still reached for `git checkout` when a mutation had to be undone.** ⚠ **So the mutation loop itself is where the copy has to be made** — ⚠ **copy the file aside BEFORE the first mutation, not after one goes wrong**, and ⚠ **every mutation in a run restores from that copy, never from git.** ⚠ The three mutations before this one, in the same run, all restored from a scratchpad copy and cost nothing |
