# 0008 — The State layer arrives as its own file, and the identity is given rather than derived

Decided 2026-08-27. Raised by hidetzu/tcpip-stack#19.

## The decision

⚠ **`src/arp_responder.c` is the State layer**: it decides what an arriving ARP packet means for us
and counts what was decided. ⚠ **Flat in `src/`, per ADR 0002**, which said one file per layer that
has something in it. ⚠ **State now has something in it.**

```text
src/tap.c            Wire     the octets that arrived, and the ones handed back
src/ethernet.c       Parse    the ethernet header
src/arp.c            Parse    an ARP packet, read and built (ADR 0007)
src/arp_responder.c  State    ⚠ what it means for us, and the counts
src/report.c         Report   every sentence a human reads
src/tcpip_stack.c    the program: options, the loop, the exit code
```

⚠ **No directories.** ADR 0002's trigger — a protocol with more than one layer of its own — has
still not fired in a way that needs them.

## Why the identity is given and never derived

Owner Decision 1 on hidetzu/tcpip-stack#19:

> Stack identityは起動引数で明示する。TAP deviceのMAC/IPを正本にしない。--macと--ipv4を使う。

⚠ **Measured, four runs on 2026-08-26 and 2026-08-27:** tap0's hardware address was
`a6:50:b4:34:2e:71`, `96:2f:bd:50:68:7c`, `32:b7:30:49:6b:ed` and `36:08:47:91:1e:b0`.
⚠ **The kernel picks a fresh one every run.**

⚠ **And it is the wrong end of the wire.** A TAP device's address belongs to the kernel's side; we
are the host at the other end. ⚠ **Deriving from it would make us claim to be the machine we are
talking to.**

⚠ **Both options or neither** (Owner Decision 6). ⚠ **Half an identity is refused, not quietly
ignored**: a stack that silently declined to answer would look exactly like one nobody asked.

## Why the answered count is not incremented where the answer is decided

⚠ **`arp_respond()` counts the four reasons for not answering. It does not count `answered`.**

⚠ **A reply that was built is not a reply that left.** `CLAUDE.md` §1's first line, in the sending
direction: the program increments `answered` only once `tap_write_frame()` has taken the whole
frame.

⚠ **What this does not cover, and it is said rather than hidden:** a send that fails is not counted
anywhere of its own. ⚠ **It is not invisible** — the only way it has been made to fail is the device
being taken away, and the read that follows fails, is counted, and is reported (hidetzu/tcpip-stack#4,
#17). ⚠ **If a send is ever made to fail while reads keep working, that gap becomes real and this ADR
is reopened.**

## What was decided against, and why

- **Deciding inside `src/arp.c`.** ⚠ **ADR 0007 says that file decides nothing** — it knows the wire
  format in both directions and nothing else.
- **Deciding inside `src/tcpip_stack.c`.** ADR 0002 calls that file the program: options, the loop,
  the exit code. ⚠ **Protocol decisions there would mix the program with the stack**, and ⚠ **they
  could then only be checked by running the program**, not in the static tier.
- **Folding a received ARP reply into `not-for-us`.** ⚠ **`not-for-us` is about whose address was
  asked for; a reply is about what was asked.** It is counted as an opcode we do not act on.
  ⚠ **This mapping was derived, not given** — Owner Decision 2 named the four reasons and did not
  say which one a reply falls under.
- **A `--mac` defaulted to something fixed.** ⚠ Every instance on a segment would then claim the
  same hardware address.

## The boundary this sets

- ⚠ **No wording in this layer.** A decision and a reason travel upward; `src/report.c` turns them
  into sentences, and ⚠ **the internal names never reach a terminal** (`CLAUDE.md` §4).
- ⚠ **Four reasons, four counters, never folded** (Owner Decisions 2 and 4). ⚠ **Three of them are
  the parser's outcomes surviving the trip upward**, which is the only thing that made keeping them
  apart worth doing (ADR 0005).
- ⚠ **Nothing is remembered.** There is no ARP cache and `docs/SPEC.md` §2 says so as a decision.

## What this does not claim

⚠ **Not that RFC 826 asks for no more than replying.** ⚠ **What it says beyond that was not read**,
and `docs/SPEC.md` §2 records the absence of a cache as a decision rather than as a reading of the
document.

⚠ **Not that the stack answers a ping.** ⚠ **It answers ARP and nothing above it.** Measured: `ping`
still reports 100% packet loss, because nothing answers an ICMP echo request.
