# tcpip-stack

A user-space TCP/IP stack for Linux, built as an experiment in AI-assisted systems engineering.

**What runs today: `tap-read`.** It creates and attaches to a TAP device in the current network
namespace, and reports the ethernet frames the kernel puts on it — length per frame, and the raw
bytes on request. ⚠ **`tap-read` itself only reads.** The wire underneath it can hand a frame to the
device — and ⚠ **nothing yet decides what to send**, so the program has no reason to.

⚠ **The namespace is not `tap-read`'s doing.** It uses whichever network namespace it is started
in. The checks put a fresh one there with `unshare -Urn`
([ADR 0001](docs/adr/0001-the-checks-take-their-capability-from-a-user-namespace-not-from-sudo.md)),
and running `tap-read` outside one would create the device on the machine's real networking.

⚠ **What may be claimed is [`docs/SPEC.md`](docs/SPEC.md), and only that.**

## Why this exists

Two repositories, one workflow:

```
                 AI-assisted engineering
                           |
          +----------------+----------------+
          |                                 |
       konjaku                        tcpip-stack
     web / UX / product             C / Linux / RFC
     arguable answers               pinned-down answers
          |                                 |
          +----------------+----------------+
                           |
              the same rules, checks and telemetry
```

The question is whether a way of working that holds where the right answer is arguable
still holds where the right answer is written down in an RFC and visible on the wire.

⚠ **What proves general across both gets extracted into `claude-dev-template`.**
⚠ **What is specific to one domain stays in that repository.**

## Running it

```bash
make                 # build/tap-read
make check           # all three tiers
```

Reading the ARP request the kernel sends when it wants an address it does not know
(⚠ **a real run, 2026-08-26, kernel `7.0.2-arch1-1`** — the hardware address is whatever the
kernel picked for `tap0` on that run):

```sh
unshare -Urn sh -c '
  ./build/tap-read --count 1 --hex &
  until ip link show tap0 >/dev/null 2>&1; do sleep 0.05; done
  ip addr add 10.0.0.1/24 dev tap0
  ip link set tap0 up
  ping -c 1 -W 1 10.0.0.2 >/dev/null 2>&1
  wait
'
```

```text
listening on tap0
frame 1  42 bytes
  0000  ff ff ff ff ff ff 7a cb  0a 48 09 fa 08 06 00 01
  0010  08 00 06 04 00 01 7a cb  0a 48 09 fa 0a 00 00 01
  0020  00 00 00 00 00 00 0a 00  00 02
read 1 frame, 0 read errors
```

⚠ **`tap-read` does not know that is an ARP request.** It reports a length and the bytes.

There is a Parse layer now. `src/ethernet.c` reads the 14-octet ethernet header — destination
address, source address, length/type
([ADR 0003](docs/adr/0003-what-the-length-type-field-means-and-what-the-parse-layer-refuses-to-guess.md)),
and `src/arp.c` reads the fixed part of an ARP packet — RFC 826's `ar$hrd`, `ar$pro`, `ar$hln`,
`ar$pln`, `ar$op` and the four addresses
([ADR 0005](docs/adr/0005-arp-names-come-from-rfc-826-and-the-numbers-do-not.md)).
Each keeps a malformed packet, one whose shape it cannot place, and one it can read but does not act
on as three separate answers.

⚠ **Nothing prints what they find yet**, which is why the run above says only a length, and
⚠ **nothing decides** — answering an ARP request is still to come. The sending half of the wire is
there and proved against the kernel's own counters for the device; ⚠ **what to put in a frame is
what is missing.**

The three tiers differ in who the other end is: nobody (`check-static`), the device and us
(`check-real`), and the Linux kernel (`check-foreign`). Each runs one named case on its own and
counts without building anything:

```bash
make check-static  CHECK_ARGS="--list"
make check-real    CHECK_ARGS="--case count_zero_reads_nothing"
```

⚠ **No check uses `sudo`.** The capability to create a TAP device comes from the user namespace
`unshare -Urn` creates
([ADR 0001](docs/adr/0001-the-checks-take-their-capability-from-a-user-namespace-not-from-sudo.md)).
⚠ **Where unprivileged user namespaces are disabled, two of the three tiers run zero cases and say
so** — that is `NOT-VERIFIED`, never a pass.

⚠ **CI runs the static tier, and only that** — the build with `-Werror`, the ASan/UBSan build, the
Report and Parse layers against the captured frame, and the `docs/SPEC.md` §1 check. A GitHub-hosted
runner refuses `unshare -Urn` (AppArmor, measured 2026-08-26), so `check-real` and `check-foreign`
run where unprivileged user namespaces are permitted — today, a developer's machine
([ADR 0004](docs/adr/0004-ci-runs-the-static-tier-only.md)).
⚠ **A green tick therefore means the static tier passed. It does not mean the stack was exercised
against a device.**

## Environment

Linux is the source of truth for development. The stack talks to the kernel through
`/dev/net/tun`, and the test environment is built out of network namespaces so that
experiments cannot disturb ordinary networking.

Development tooling is Node (the hooks under `.claude/` use only Node built-ins —
there are no npm dependencies). The product itself is C.

## First milestone

**Our own code answers a ping.** Not TCP — ethernet frames, ARP, IPv4, ICMP echo, through a TAP
device, inside a namespace, verified against `ping` and `tcpdump`.

⚠ **Not there yet.** Reading frames off the device is the first step of it; nothing replies to
anything.

## Where things are written down

| Question | File |
|---|---|
| How do we work? | [`CLAUDE.md`](CLAUDE.md) |
| How do we write it? | [`.claude/rules/`](.claude/rules/) |
| What may we claim? | [`docs/SPEC.md`](docs/SPEC.md) |
| Why was it decided that way? | [`docs/adr/`](docs/adr/) |

## Licence

MIT — see [`LICENSE`](LICENSE).
