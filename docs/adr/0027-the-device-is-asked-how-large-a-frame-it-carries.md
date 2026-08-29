# 0027 — The device is asked how large a frame it carries

Date: 2026-08-29
Status: accepted
Issue: hidetzu/tcpip-stack#115

## Context

⚠ `docs/SPEC.md` §2 has said since hidetzu/tcpip-stack#75 that ⚠ **nothing here reads the MTU the
device was actually brought up with**, and that `HANDSHAKE_WINDOW`'s 1460 is ⚠ **a number chosen for
an MTU of 1500 rather than derived from one.**

⚠ **The Appendix B audit turned that into a dependency**: `MUST-14` asks for the MSS Option, and
⚠ **an MSS cannot be honest without an MTU.** ⚠ **Owner Decision 2026-08-29: the MSS comes from the
device MTU and not from a constant someone chose.**

### ⚠ What was measured before anything was written

Arch Linux `7.0.2-arch1-1`, x86_64, `unshare -Urn` as uid 1000, tap0.
⚠ **Three runs of each, every run identical.**

```text
SIOCGIFMTU on the TUN fd                     ⚠ EINVAL (22)
SIOCGIFMTU on an AF_INET SOCK_DGRAM socket   ⚠ succeeds, unprivileged, returns 1400
MTU of a device the stack creates itself     ⚠ 1500, always
TUNSETIFF over a pre-made tap0 at MTU 1400   ⚠ succeeds, and the MTU stays 1400
smallest MTU a tap accepts                   ⚠ 68      (46 and below refused)
largest MTU a tap accepts                    ⚠ 65521   (65535 and above refused)
```

⚠ **The first line is why this needed an owner decision at all**: ⚠ **there is no way to read the
MTU without a second fd.**

## Decision

### ⚠ Owner Decision 1 — a device that cannot be asked does not stop the stack

⚠ **The read fails, the stack carries on with `TAP_FRAME_BYTES_WHEN_UNKNOWN`, and the report says
both things**: that the device could not be asked, and ⚠ **that the number now in use was chosen
here and not reported by the device.**

⚠ **Grounds**: one missing auxiliary thing must not take the whole stack down
(`.claude/rules/c.md`). ⚠ **The counter-argument was that the MTU is not auxiliary once the window
depends on it** — ⚠ **which is true, and it is why the sentence exists.** ⚠ **"Could not be
obtained" is never printed as "it is 1500"** (`CLAUDE.md` §1).

### ⚠ Owner Decision 3 — an `AF_INET` socket may enter the Wire layer

⚠ **Measured above: the TUN fd cannot answer.** ⚠ **Owner of the socket: `tap_ask_mtu`.** It is
opened, used and closed before the function returns, and ⚠ **nothing of it escapes**
(`.claude/rules/c.md`: every allocation has one named owner).

⚠ **Setup time, never per packet** (`CLAUDE.md` §3). ⚠ `tests/static.sh`
`the_mtu_is_read_in_one_place` asserts both halves: only `src/tap.c` names `SIOCGIFMTU`, and
⚠ **no file on the path a packet takes calls the function.**

### ⚠ `ask`, not the other verb

⚠ **The function was first spelled with `read`**, and ⚠ **`tests/static.sh`
`the_old_program_name_is_gone` fired on it** — that spelling is the shape of the name this program
used to carry, and the case allows exactly one survivor.

⚠ **The check was not widened to let a second one through** (`.claude/rules/testing.md`: never widen
a check until it stops complaining). ⚠ **It was the name that moved**, and ⚠ **`ask` is the more
accurate verb anyway**: this is an `ioctl` question, not a read of octets.

⚠ **It then fired a second time, on the comment explaining the first** — ⚠ **that case does not
strip comments**, and ⚠ **a check reading prose written about itself is exactly what `CLAUDE.md` §5
warns of.** ⚠ **The comment was reworded; the check was not touched.**

## Consequences

- ⚠ **`docs/SPEC.md` §2's "Reading the device's MTU" row is gone**, and ⚠ **two rows replace it**,
  ⚠ **narrower and both true**: the window is still a constant, and the failing branch is not
  asserted.
- ⚠ **The window is NOT derived from the MTU here.** ⚠ **That is hidetzu/tcpip-stack#119 and a
  separate owner decision** — ⚠ this change alters no claim about `HANDSHAKE_WINDOW`, ⚠ **so
  `CLAUDE.md` §9's window wall does not move and was not touched.**
- ⚠ **The `listening on <device>` line is unchanged, byte for byte.** ⚠ Its wording is an owner
  decision from hidetzu/tcpip-stack#2; ⚠ **the MTU gets a line of its own rather than being appended
  to a decision this issue was not given.**
- ⚠ **The failing path has no check, and that is written down rather than assumed.**
  ⚠ **Measured**: deleting the whole `else` at the call site — so a failed read would print the
  constant as though the device had reported it — ⚠ **left every check green.** ⚠ **That is the
  checks not asserting it, not a mutation with no effect** (`.claude/rules/testing.md` asks which).
  ⚠ **No harness here can make the read fail**: the device exists by the time it is asked, because
  the fd created it, and ⚠ **contriving a failure would be testing the contrivance.**
- ⚠ **`AC 5` of the issue — an MTU too small to leave a window — was dropped from this change and
  belongs to hidetzu/tcpip-stack#119.** ⚠ **Measured: the kernel refuses an MTU below 68, and 68
  leaves 28**, so there is no window to run out of until one is derived.
