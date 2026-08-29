---
name: verify
description: Decide which checks to run for tcpip-stack, in what order, run them, and return PASS / FAIL / NOT-VERIFIED. Use before submitting a change, before a PR, and when splitting apart why CI went red. Never builds new check infrastructure.
---

# Verify

⚠ **This skill does not write checks.** ⚠ **It only decides how to run the ones that exist.**

```
Worker
  |
Verify   <- here
  |- FAIL          -> back to Worker
  |- NOT-VERIFIED  -> say what went unseen. ⚠ Never call it green
  '- PASS          -> on to Review
```

⚠ **The checks themselves live in the test tree, and that is the source of truth.**
⚠ **Never copy their contents here** (rule: never two implementations of the same question).

---

## 0. ⚠ Current state of this file

⚠ **Three entry points exist**, and they are the ones §1 lists:
`make check-static`, `make check-isolated`, `make check-interop`.
⚠ **`make check` runs all three, in that order.**

⚠ **Each runner announces its own counts.** ⚠ **Copy the announced number into the report** (§7).
⚠ **Never write a count into a document** (`docs/SPEC.md` says why).

### ⚠ The tier names were decided at hidetzu/tcpip-stack#116 (2026-08-29)

⚠ **Kept, not deleted: this is why the names are what they are.**

⚠ **`static` / `real` / `foreign` were named before a single test existed**, and
⚠ **`real` was the weak one**: it said how true the test is, not what it needs.

⚠ **Two questions were being conflated. They were measured, and the second came back with a
different answer from the one the names assumed** (`docs/SPEC.md` §3, 2026-08-26):

```text
                            needs an external network?   needs a privilege the developer lacks?
static                                 no                                  no
bring up a TAP + netns                 no                     ⚠ no — the capability comes from
talk to the kernel stack               no                       a user namespace it creates itself
```

⚠ **Creating a TAP device does need `CAP_NET_ADMIN`** — ⚠ **but not from `sudo`.**
`unshare -Urn` supplies it to an ordinary user
(`docs/adr/0001-the-checks-take-their-capability-from-a-user-namespace-not-from-sudo.md`).

⚠ **So "runs without going outside" and "runs without a privilege the developer lacks" are both
`no` for all three tiers**, and neither axis separates them. ⚠ **What separates them is who the
other end is**, and ⚠ **the names say that now:**

```text
static    ⚠ nothing is running at all
isolated  ⚠ the device and us, and no one else       (was `real`)
interop   ⚠ the Linux kernel, which we did not write (was `foreign`)
```

⚠ **`make check-real` and `make check-foreign` still exist and FAIL**, saying what the tier is
called now. ⚠ **They are not aliases** — an alias that quietly ran the new target would keep the
old name alive for ever (ADR 0026).

⚠ **Past ADRs, issue bodies and completion reports keep the words they were written with**
(`CLAUDE.md` §4: never rename in bulk). ⚠ **ADR 0026 carries the table of what was called what.**

⚠ **Where unprivileged user namespaces are disabled, `isolated` and `interop` run zero cases.**
⚠ **That is `NOT-VERIFIED`, never a pass** (§4, §6). ⚠ **Both runners say so and stop.**

---

## 1. The three tiers (⚠ **the contract**)

⚠ **Every tier must exist.** ⚠ **They fail for different reasons, and the difference is the point.**

| Tier | What it sees | External network? | A privilege the developer lacks? | Measured cost |
|---|---|---|---|---|
| **static** `make check-static` | What can be known by reading: build with `-Werror`, an ASan/UBSan build, and the Report layer against a captured frame | ⚠ **no** | ⚠ **no** | ⚠ `docs/SPEC.md` §3 |
| **isolated** `make check-isolated` | ⚠ **A TAP device brought up in a namespace, with actual packets through it.** No other participant | ⚠ **no** | ⚠ **no** — `unshare -Urn` | ⚠ `docs/SPEC.md` §3 |
| **interop** `make check-interop` | ⚠ **The other end is the Linux kernel**, which is not something we wrote | ⚠ **no** | ⚠ **no** — `unshare -Urn` | ⚠ `docs/SPEC.md` §3 |

⚠ **The costs live in `docs/SPEC.md` §3 and only there.** ⚠ **A measured number written in two
places goes stale in one of them** (`CLAUDE.md` §6), and `SPEC.md` §3 is the file that owns
measurements, with their date and conditions.

⚠ **None of the three needs a network beyond this machine.** ⚠ **That is on purpose** — a check
whose result depends on somebody else's uptime cannot assert our correctness (§4).

⚠ **A clean build proves nothing about the wire.**
⚠ **Expect the isolated tier to catch most of the actual defects** — but ⚠ **that expectation is
inherited from another project, and is not yet a measurement here.** ⚠ **Replace this sentence
with a measurement once there is one.**

⚠ **One data point, and it points the other way.** Building the first TAP harness
(hidetzu/tcpip-stack#2), ⚠ **the defect that was actually found was caught by `static`** — a
pointer handed to `open_memstream` that belonged to a dead local, found by the sanitizer build.
⚠ **One defect is not a rate.** ⚠ **Do not turn this into a claim about which tier catches more.**

### ⚠ Every entry point must be able to run in part

⚠ **A check suite that can only run whole gets skipped.** So each tier needs:

```
run one named case only
count without running        <- ⚠ must not load anything heavy
report which subset it ran, on its first line of output
```

⚠ **All three do this today:**

```bash
make check-static CHECK_ARGS="--list"                    # the case names
make check-isolated   CHECK_ARGS="--count"                   # ⚠ counts without building anything
make check-interop CHECK_ARGS="--case an_arp_request_the_kernel_generated_is_read_intact"
```

⚠ **The runner announces what it ran and how many.** ⚠ **Never write the count into a document**
(`docs/SPEC.md` says why). ⚠ **Copy the announced number straight into the report** (§7).

### ⚠ Am I measuring what I think I am measuring?

⚠ **Before trusting an isolated-tier result, confirm the binary under test is the one just built,
and the device under test is the one just created.**
⚠ **A stale binary or a leftover interface from a previous run measures the previous run.**

---

## 2. Inner loop (while fixing)

⚠ **Fastest first. Stop and go back at the first failure.**

```
1. static
2. isolated, restricted to what was touched
```

⚠ **Green here is not "it passed."** ⚠ Cases were skipped. Say which.

---

## 3. Final gate (before the PR)

⚠ **Run all three tiers.** ⚠ **static alone is not enough.**

⚠ **Copy the counts each runner announced.** ⚠ **Never write "it passed"** — write what, and how many.

---

## 4. ⚠ Split the failure apart before blaming yourself

⚠ **Look at where it failed before suspecting your own change.**

| How it failed | ⚠ Is it our defect? |
|---|---|
| static failed | ⚠ **ours.** It never went outside |
| isolated failed | ⚠ **ours.** ⚠ **Nothing external is involved** — that is why this tier exists |
| interop failed | ⚠ **maybe not ours.** ⚠ **Record what actually came back before deciding** |
| the environment could not be built (namespace, privileges, tooling) | ⚠ **unrelated to the change.** ⚠ **Zero tests ran.** Say so and retry once |

⚠ **Sometimes the check is the thing that is wrong.** Fix the check, and
⚠ **leave a comment saying why it was wrong.**

⚠ **Never assert what the other side will do right now** (`.claude/rules/testing.md`).
⚠ **Assert our own correctness. Record the reply, then judge.**

---

## 5. ⚠ After adding a check

⚠ **A fixed bug leaves a check behind.** Make the same thing stop the build next time.

⚠ **Adding it is not the end.**

```
1. Break it on purpose and confirm it really fails
2. ⚠ Read the failure message and confirm it failed for the reason you intended
3. If you added files, ⚠ git add them before running
```

⚠ **A check that inspects tracked files will never see an untracked one.**
Running before `git add` and calling it green is a real way to be wrong.

⚠ **Never leave only the negative half.** Pair it.
⚠ Example: a check that asserts "this was removed" stays green when ⚠ **everything** is removed.
⚠ Put a check on the side that was supposed to stay.

⚠ **Cross-check against something derived a different way.**
⚠ Counting the same thing twice by the same method proves only that the method is consistent.

---

## 6. ⚠ Green CI does not mean unseen things are fine

⚠ **Some tiers cannot run everywhere.** In particular, ⚠ **anything needing privileges or secrets
does not run on a PR from a fork.**

⚠ **In this repository, CI runs `static` and only `static`** (ADR 0004 says why, with the
measurement). ⚠ **A green tick on a PR is one tier of three.** ⚠ **`isolated` and `interop` still have to
be run before the PR, and the report says where they ran.**

⚠ **When a tier did not run, that is `NOT-VERIFIED`, not `PASS`.**

⚠ **Not every change needs every tier.** ⚠ **But the rule for deciding lives in one place, in code,
and never in prose here** — ⚠ **written in two places, one goes stale, and this is the file where
that happened before.**
⚠ **When in doubt, run everything.** ⚠ **Never create a gap by narrowing.**

---

## 7. What to return

```
Verdict: PASS / FAIL / NOT-VERIFIED

Ran:
  <entry point>  <result>  <count>      ⚠ never list what was not run

Failed:
  - <the failure text, verbatim>
  - <ours, or external>

Not verified:
  - <which check did not run, and why>

Regression guard:
  EXISTING / ADDED-AND-PROVEN / NONE    ⚠ would this stop next time?

Mutation check:
  <with the fix removed, did it FAIL ⚠ for the intended reason? ⚠ failure text verbatim>

Next:
  - <back to Worker, or on to Review>
```

### ⚠ Regression guard is one of exactly three

| Value | When |
|---|---|
| **EXISTING** | ⚠ **A check already catches this, ⚠ and that was confirmed by watching it catch it** |
| **ADDED-AND-PROVEN** | A check was added, ⚠ **broken on purpose, and seen to fail for the intended reason** (§5) |
| **NONE** | ⚠ **Neither.** ⚠ **State why** |

⚠ **There is no `ADDED`.** ⚠ Merely adding is not `ADDED-AND-PROVEN`.
⚠ **`EXISTING` is not "probably catches it."** ⚠ Without watching it fail, it is `NONE`.
⚠ **A bug fix with `NONE` is not a `PASS`.** Make it `NOT-VERIFIED` and say
⚠ **why it cannot be left as a check.**

### ⚠ "It failed" is not enough for the mutation check

⚠ **Read whether it failed for the reason you intended.**
If it failed for another reason (link order, a syntax error, a timeout),
⚠ **that check is not yet asserting the claim.**
⚠ **Record the failure text verbatim.** A summary makes the next reader redo the work.

| Verdict | When |
|---|---|
| **PASS** | ⚠ **All three tiers ran and all three passed.** ⚠ If a bug was fixed, ⚠ **Regression guard is not `NONE`** |
| **FAIL** | Anything failed. ⚠ **External causes are still FAIL** — say "external" and recommend a rerun |
| **NOT-VERIFIED** | ⚠ **A check did not run.** A partial run, a fork PR, or an environment that could not be built |

⚠ **Never write PASS while a check went unrun.**
⚠ **Never leave Regression guard or Mutation check empty.** Write "not applicable" if it is.
