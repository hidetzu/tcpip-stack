# tcpip-stack

A user-space TCP/IP stack for Linux, built as an experiment in AI-assisted systems engineering.

**What runs today: `tcpip-stack`.** It creates and attaches to a TAP device in the current network
namespace, and reports the ethernet frames the kernel puts on it — length per frame, and the raw
bytes on request. ⚠ **Given `--mac` and `--ipv4` it also answers the ARP requests and the ICMP echo
requests that ask for that address**, and ⚠ **`ping` reports 0% packet loss against it.** Without
those two options it only reads.

⚠ **The namespace is not `tcpip-stack`'s doing.** It uses whichever network namespace it is
started in. The checks put a fresh one there with `unshare -Urn`
([ADR 0001](docs/adr/0001-the-checks-take-their-capability-from-a-user-namespace-not-from-sudo.md)),
and running `tcpip-stack` outside one would create the device on the machine's real networking.

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
make                 # build/tcpip-stack
make check           # all three tiers
```

Answering a ping with our own code (⚠ **a real run, 2026-08-28, kernel `7.0.2-arch1-1`** — the
kernel's hardware address is whatever it picked for `tap0` on that run, and the IPv6 frames it
sends unprompted are left in rather than tidied away):

```sh
unshare -Urn sh -c '
  ./build/tcpip-stack --mac 02:00:00:00:00:02 --ipv4 10.0.0.2 --timeout 1500 &
  until ip link show tap0 >/dev/null 2>&1; do sleep 0.05; done
  ip addr add 10.0.0.1/24 dev tap0
  ip link set tap0 up
  LC_ALL=C ping -c 3 -i 0.3 -W 1 10.0.0.2
  wait
'
```

What `ping` said:

```text
--- 10.0.0.2 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 609ms
rtt min/avg/max/mdev = 0.054/0.065/0.079/0.010 ms
```

What the stack said:

```text
listening on tap0
frame 1  42 bytes
  ff:ff:ff:ff:ff:ff <- f6:22:9f:90:78:d7, length/type 0x0806
  answered it: 10.0.0.2 is ours, and 10.0.0.1 was told our hardware address
frame 2  98 bytes
  02:00:00:00:00:02 <- f6:22:9f:90:78:d7, length/type 0x0800
  answered it: 10.0.0.2 is ours, and 10.0.0.1 got its 56 octets back
frame 3  90 bytes
  33:33:00:00:00:16 <- f6:22:9f:90:78:d7, length/type 0x86dd
frame 4  86 bytes
  33:33:ff:90:78:d7 <- f6:22:9f:90:78:d7, length/type 0x86dd
frame 5  98 bytes
  02:00:00:00:00:02 <- f6:22:9f:90:78:d7, length/type 0x0800
  answered it: 10.0.0.2 is ours, and 10.0.0.1 got its 56 octets back
frame 6  98 bytes
  02:00:00:00:00:02 <- f6:22:9f:90:78:d7, length/type 0x0800
  answered it: 10.0.0.2 is ours, and 10.0.0.1 got its 56 octets back
frame 7  90 bytes
  33:33:00:00:00:16 <- f6:22:9f:90:78:d7, length/type 0x86dd
frame 8  90 bytes
  33:33:00:00:00:16 <- f6:22:9f:90:78:d7, length/type 0x86dd
frame 9  70 bytes
  33:33:00:00:00:02 <- f6:22:9f:90:78:d7, length/type 0x86dd
frame 10  90 bytes
  33:33:00:00:00:16 <- f6:22:9f:90:78:d7, length/type 0x86dd
listened on tap0 for 1500 ms after frame 10 and read no more. That does not say whether anything more was sent.
read 10 frames, 0 read errors
0 frames were malformed, 0 carried an IEEE 802.3 Length, 0 carried a length/type the standard does not define
answered 1 ARP request. 0 were not for us, 0 were malformed, 0 named an address space we cannot place, 0 had an opcode we do not act on
answered 3 echo requests. 0 were not for us, 0 carried a protocol we do not act on
0 internet headers were malformed, 0 were ones we do not read yet, 0 had a checksum that does not agree, 0 were fragments
0 ICMP messages were malformed, 0 had a type we do not act on, 0 had a checksum that does not agree
0 replies could not be built, which would be ours and not the sender's
```

⚠ **`0x0806` and `0x0800` are printed as the values they are, never as names.** A name would be a
lie for a VLAN-tagged frame, and ⚠ **`0x0800` → IPv4 has never been taken from a standard in this
repository** — it is what the kernel put on a device while doing IPv4
([ADR 0003](docs/adr/0003-what-the-length-type-field-means-and-what-the-parse-layer-refuses-to-guess.md)).
⚠ **Without `--mac` and `--ipv4` nothing is answered**, and the run above says only what it read.

⚠ **The last line of the timer is not a failure.** ⚠ Nothing more arrived here, and that does not
say whether anything more was sent (`CLAUDE.md` §1).

## Environment

Linux is the source of truth for development. The stack talks to the kernel through
`/dev/net/tun`, and the test environment is built out of network namespaces so that
experiments cannot disturb ordinary networking.

Development tooling is Node (the hooks under `.claude/` use only Node built-ins —
there are no npm dependencies). The product itself is C.

## First milestone

**Our own code answers a ping.** Not TCP — ethernet frames, ARP, IPv4, ICMP echo, through a TAP
device, inside a namespace, verified against something we did not write.

⚠ **Met, on 2026-08-28.** ⚠ **`ping` reports 0% packet loss**, and the verdict is not ours: the
Linux kernel checks the internet header checksum and the ICMP checksum before it accepts a reply
(`tests/foreign.sh` `ping_reports_no_loss_against_our_own_stack`).

⚠ **And that alone would not prove we validated anything.** ⚠ **A stack that answers a ping while
computing the checksum wrong still answers the ping**, so a second check carries the other half:
an echo request whose ICMP checksum does not agree is not answered, and is counted
(`tests/static.sh` `echo_responder`). ⚠ **Neither replaces the other.**

⚠ **What is not in it:** TCP, UDP, fragment reassembly, IPv4 `Options`, routing, any ICMP type but
echo. ⚠ [`docs/SPEC.md`](docs/SPEC.md) §2 says which of those are decisions and which are simply
not written yet.

## Where things are written down

| Question | File |
|---|---|
| How do we work? | [`CLAUDE.md`](CLAUDE.md) |
| How do we write it? | [`.claude/rules/`](.claude/rules/) |
| What may we claim? | [`docs/SPEC.md`](docs/SPEC.md) |
| Why was it decided that way? | [`docs/adr/`](docs/adr/) |

## Licence

MIT — see [`LICENSE`](LICENSE).
