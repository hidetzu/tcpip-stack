# 0004 — CI runs the static tier only

Decided 2026-08-26. Raised while wiring the checks up to GitHub Actions.
⚠ **This does not weaken ADR 0001.** It is the boundary ADR 0001 set, meeting a real machine.

## The decision

`.github/workflows/checks.yml` runs `make check-static`, and nothing else.

⚠ **`make check-real` and `make check-foreign` are not run on a GitHub-hosted runner**, and
⚠ **they are not run there with `continue-on-error` either.**

⚠ **A green tick on this repository means the static tier passed.** ⚠ **It does not mean the stack
was exercised against a device.**

## Measured before deciding

GitHub-hosted runner, image `ubuntu-24.04`, kernel `6.17.0-1022-azure`, 2026-08-26,
run 32974105000 on hidetzu/tcpip-stack#13:

| What was measured | Result |
|---|---|
| `make check-static` on the runner | ⚠ **passed**, 6 of 6 cases |
| `kernel.unprivileged_userns_clone` | `1` — ⚠ **user namespaces are enabled** |
| `kernel.apparmor_restrict_unprivileged_userns` | `1` |
| `unshare -Urn true` | ⚠ **refused** |
| `make check-real` / `make check-foreign` there | ⚠ **0 cases ran**, both tiers |

⚠ **The cause is AppArmor, not a missing capability and not our code.** Ubuntu has restricted
unprivileged user namespaces by default since 23.10, and the runner image carries that default.
⚠ **The check environment could not be built, so zero cases ran** — `verify` §4 calls that unrelated
to whatever change is being tested, and it is.

Both runners printed exactly what ADR 0001's boundary said they would:

```
real: the check environment could not be built here: unshare -Urn was refused.
real: 0 cases ran. Nothing was checked, and nothing was disproved either.
```

## Why

⚠ **Because the alternative is a tick over a tier that did not run.**

`verify` §6: when a tier did not run, that is `NOT-VERIFIED`, never a pass. ⚠ **A job that reported
"0 cases ran" and went green would make "we could not check" indistinguishable from "we checked" —
the same defect as reporting a packet that was never captured as one that was never sent
(`CLAUDE.md` §1).** ⚠ **That is the failure this whole repository is about.** It is not going in the
CI configuration.

The static tier, by contrast, ⚠ **needs no fd, no clock, no namespace and no privilege.** It builds
with `-Werror`, builds again under ASan and UBSan, runs the Report layer against the captured frame,
runs the Parse layer, and checks that `docs/SPEC.md` §1 names cases that exist. ⚠ **There is no
honest reason for that not to run on every push**, and now it does.

## What was decided against, and why

- **Lifting the restriction on the runner** with `sudo sysctl -w
  kernel.apparmor_restrict_unprivileged_userns=0`. ⚠ **It would work.** It was declined because it
  makes the answer to "does this need a privilege the developer lacks?" depend on a host that was
  reconfigured to say no, ⚠ **and deciding whether ADR 0001's "no `sudo`" covers the host as well as
  the check is a larger decision than CI needs to take.** ⚠ **If it is ever wanted, it is reopened
  here first.**
- **A job that runs the two tiers and is allowed to fail.** See *Why*. ⚠ **`continue-on-error` on a
  tier that ran zero cases prints a tick for something nobody checked.**
- **Leaving the red job standing** as a permanent NOT-VERIFIED marker. ⚠ **A CI that is always red
  stops being read**, and it would make "merge once CI is entirely green" impossible to satisfy for
  every future change.
- **Running the two tiers in a container.** ⚠ **Not measured.** It may well work, and ⚠ **it is not
  claimed either way here** — it was not tried, and an untried option is not evidence.

## The boundary this sets

- ⚠ **`real` and `foreign` still exist and are still required before a PR** (`verify` §3). They run
  where unprivileged user namespaces are permitted — today, the developer's machine.
- ⚠ **Every report says which tiers ran and where.** ⚠ **"CI is green" is never written as if it
  meant all three.**
- ⚠ **When a runner that permits `unshare -Urn` is available**, this ADR is reopened rather than
  worked around.

## What this does not claim

⚠ **Not that the two tiers cannot run on any runner.** They were refused on one image on one day,
and that is what is recorded. ⚠ **Not that a container would fail** — that was not tried.
⚠ **Not that the stack is verified by CI.** ⚠ **One tier of three ran there.**
