# 0001 — The checks take their capability from a user namespace, not from sudo

Decided 2026-08-26. Raised by hidetzu/tcpip-stack#2.

## The decision

Every check that needs a TAP device creates it inside `unshare -Urn` — a new user namespace
and a new network namespace, entered by an ordinary user.

⚠ **No check uses `sudo`.** ⚠ **No binary carries `cap_net_admin` through `setcap`.**
⚠ **No check depends on a device created out of band with `ip tuntap add`.**

## Why

Creating a TAP device needs `CAP_NET_ADMIN` in the user namespace that owns the network
namespace the interface will live in. ⚠ **That is not the same as needing to be root.**

Measured before deciding (Arch Linux, kernel `7.0.2-arch1-1`, x86_64, 2026-08-26,
`unshare -Urn`, uid 1000, no `sudo`):

| What was measured | Result |
|---|---|
| `ip tuntap add dev tap0 mode tap` inside the namespace | worked |
| `ioctl(TUNSETIFF)` from a C program inside the namespace | worked |
| `ip addr add` / `ip link set up` on that device | worked |
| the kernel putting an ARP request on the device after `ping` | worked |

⚠ **`/dev/net/tun` is `crw-rw-rw-` on this machine**, so opening it is not the privileged part.
The privileged part is `TUNSETIFF`, and a user namespace supplies it.

## What was decided against, and why

- **`sudo` inside a check.** A check that asks for a password cannot run unattended, and one that
  runs as root can damage the machine's real networking. ⚠ **The namespace makes that impossible
  rather than unlikely.**
- **`setcap cap_net_admin+ep` on the built binary.** It would put the capability on the artefact
  rather than on the check, so the product would carry a privilege into ordinary use.
- **A persistent device created before the checks run.** State that outlives a run is state a run
  can inherit from the previous one, and then a check measures the previous run
  (`.claude/skills/verify/SKILL.md` §1).

## The boundary this sets

- ⚠ **A check that cannot run without a privilege the developer already has does not belong in the
  suite.** If one turns out to need more, that is a decision to reopen here, not to work around.
- ⚠ **Where unprivileged user namespaces are disabled, zero checks run.** That is `NOT-VERIFIED`,
  ⚠ **never a pass** (`verify` §4, §6). The runners say so and stop.

## What this does not claim

⚠ **Not that the stack works without `CAP_NET_ADMIN`.** It needs it. It gets it inside a namespace
it owns, from an ordinary user, without `sudo`.
