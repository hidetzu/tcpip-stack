# 0012 — What goes in a reply we build, and why `ping` alone is not the proof

Date: 2026-08-28
Status: accepted
Issue: hidetzu/tcpip-stack#35

## Context

This is where hidetzu/tcpip-stack#32, #33 and #34 meet: the stack answers the
ICMP echo request the Linux kernel sends it, and `README.md`'s first milestone is
finally either true or not.

⚠ **Two things had to be settled that no document settles**, and they are both
owner decisions.

### ⚠ The proof inverts here, and it does not invert all the way

hidetzu/tcpip-stack#19 had to insist that `ping` succeeding was **not** the
criterion: ARP was answered and `ping` still reported 100% loss.

⚠ **Here `ping` succeeding is a criterion, and a strong one.** The kernel checks
the internet header checksum and the ICMP checksum before it accepts a reply, so
⚠ **0% loss is somebody else's arithmetic agreeing with ours**
(`.claude/rules/layers.md`, question 3).

⚠ **And it is still not enough.** `CLAUDE.md` §1, in as many words:

> ⚠ **A stack that answers a ping while computing the checksum wrong still
> answers the ping.**

⚠ **A stack that never validated an incoming checksum would pass the ping check
too.** ⚠ So the second check is not optional and is not a nicety.

## Decision

### Owner Decision 1 — the wording is ARP's shape, unchanged

⚠ **`answered it:` and `no answer: <reason>`, the two-line shape already on the
screen for ARP.** ⚠ A reader learns one rule, not two.

⚠ **Ten reasons, ten sentences, and not one internal name among them**
(`CLAUDE.md` §4). ⚠ **Two of the ten are about us and say so** — "one we do not
read yet" and "we could not build the reply. That is ours, not the sender's"
(§4-1: never phrase our own gap as the other side's fault).

### Owner Decision 2 — the reply's internet header

```
Time to Live     64
Don't Fragment   clear
Identification   0
```

⚠ **Time to Live 64 and Don't Fragment clear are what the Linux kernel does.**
⚠ Measured on this machine, 2026-08-28, Arch Linux `7.0.2-arch1-1`, x86_64,
`unshare -Urn` as uid 1000, tap MTU 1500: ⚠ **5 runs, all five `ttl=64` and
`flags=0x0`.** ⚠ **An observation about the kernel, and not a claim that RFC 791
asks for either.**

⚠ **Identification is 0 and does not vary.** ⚠ Nothing here fragments, so there
is nothing for a receiver to match pieces by. ⚠ **The same kernel puts a
different value in every reply** — `0x3995 / 0x5932 / 0x93ac / 0x7eb4 / 0xd2dd`
across those five runs — ⚠ **and no grounds for copying that were read, so it is
not copied.**

⚠ **Worth recording because it is the kind of thing that looks like a rule:** the
kernel sets Don't Fragment on the requests it *sends* (`40 00` in
`tests/fixtures/icmp-echo-request-98.hex`) and ⚠ **clears it on the replies it
answers with.** ⚠ Observed, not explained.

### Owner Decision 3 — nothing is added to the command line

⚠ **`--mac` and `--ipv4` are enough.** The ethernet destination and the IPv4
destination come from the frame that arrived; the sources are the two addresses
already given. ⚠ **A `--ttl` nobody has needed would be an option invented for a
second case that does not exist** (`.claude/rules/layers.md`).

### Owner Decision 4 — a `Total Length` below its own header is malformed

⚠ **Left open on purpose by hidetzu/tcpip-stack#33** (ADR 0010): its approved
decision order had no row for it and that change did not invent one.

⚠ **It is decided here because this is where it bites.** The ICMP message runs
from the end of the header to `Total Length`, and ⚠ **that subtraction is
unsigned.** ⚠ A header contradicting itself is the sender being wrong, which is
what malformed means.

### ⚠ Whose address, before what protocol

⚠ **`echo_respond` asks "is it for us" before "is it a protocol we act on".**
⚠ **This is the other way round from `arp_respond`, on purpose:** there,
"not for us" is about `ar$tpa`, which only means anything once the opcode says
the packet is a request. ⚠ **Here the destination address means the same thing in
every datagram**, so a datagram addressed to somebody else is not ours to have an
opinion about the protocol of.

### ⚠ How far the ICMP message runs

⚠ **From `Total Length`, never from how many octets arrived.** ⚠ A short frame is
padded up to the wire's minimum, and ⚠ that padding is not part of the message
the checksum covers. ⚠ `padding_after_the_datagram_is_not_part_of_the_message`
is what holds it.

### ⚠ A reply that could not be built is ours, and is counted

⚠ **A tenth reason beyond the nine the protocols give.** ⚠ It is not the
sender's, and the sentence says so. ⚠ **Counted rather than dropped in silence**:
an uncounted drop is invisible, and an invisible drop looks exactly like a
datagram that never arrived (`.claude/rules/c.md`).

⚠ **A caller supplying a buffer at least as long as the frame that arrived
cannot reach it** — an echo reply is exactly as long as the echo request it
answers. ⚠ It is still handled, because "cannot happen" is not a reason to leave
a path unwritten.

## Consequences

- ⚠ **`ping` reports 0% packet loss** (`tests/foreign.sh`
  `ping_reports_no_loss_against_our_own_stack`), and ⚠ **an echo request whose
  ICMP checksum does not agree is not answered and is counted**
  (`tests/static.sh` `echo_responder`). ⚠ **Neither replaces the other.**
- ⚠ **AC 5 does not hold as literally written, and here is the measurement.**
  It asks that "breaking a parser must not be what makes it fail". ⚠ Measured
  2026-08-28: with `src/icmp.c` built to leave the reply's Type as a request,
  ⚠ **`static` failed 2 of 13 cases and the ping case failed too.** ⚠ **That is
  correct**: the ping case asserts that the kernel accepts what we send, so a
  broken builder must break it. ⚠ **What ADR 0009 actually asks for holds** — the
  case reads no octet of any frame and asks no parser of ours anything; its
  verdict is `ping`'s. ⚠ **And the frame-reading foreign case stayed green under
  the same break**, which is the independence that clause is really about.
- ⚠ **The reply is built into a buffer of its own, not over the frame that
  arrived**, even though every builder allows the overlap. ⚠ A reader comparing
  what came in with what went out must be able to.
- ⚠ **`ethernet.c` gains a header builder** so the offsets stay in one file
  (ADR 0007). ⚠ It is handed the length/type and never decides one; ⚠ `report.c`
  still never turns that value into a protocol name (ADR 0003).
- ⚠ **`0x0800` and protocol `1` are observations, not readings.** They are octets
  the Linux kernel put on a TAP device, recorded as such — the standing ADR 0005
  gave ARP's numbers. ⚠ Using a value to decide what to build is not the same as
  printing it as a claim.
