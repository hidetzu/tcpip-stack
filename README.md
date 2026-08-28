# tcpip-stack

A user-space TCP/IP stack for Linux, built as an experiment in AI-assisted systems engineering.

**What runs today: `tcpip-stack`.** It creates and attaches to a TAP device in the current network
namespace, and reports the ethernet frames the kernel puts on it — length per frame, and the raw
bytes on request. ⚠ **Given `--mac` and `--ipv4` it also answers the ARP requests and the ICMP echo
requests that ask for that address**, and ⚠ **`ping` reports 0% packet loss against it.** ⚠ **Add
`--tcp-port` and the Linux kernel's own `connect()` succeeds against it: `ss` reports the connection
established.** ⚠ **When the other side closes, its `FIN` is acknowledged and this end closes in the same segment,
and the connection is finished once that is acknowledged in return** — ⚠ `ss` on the peer then
reports `TIME-WAIT`, which is its own. ⚠ **Data that arrives is taken and discarded**, an octet at a
time, ⚠ **without the sender being told at the time** — [`docs/SPEC.md`](docs/SPEC.md) §2 says what
is missing. ⚠ Nothing else is sent. Without those options it only reads.

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

Answering a ping, a connection request and a close with our own code (⚠ **a real run, 2026-08-29,
kernel `7.0.2-arch1-1`** — the kernel's hardware address and its source port are whatever it picked
on that run, and the IPv6 frames it sends unprompted are left in rather than tidied away):

```sh
unshare -Urn sh -c '
  ./build/tcpip-stack --mac 02:00:00:00:00:02 --ipv4 10.0.0.2 --tcp-port 80 --timeout 1500 &
  until ip link show tap0 >/dev/null 2>&1; do sleep 0.05; done
  ip addr add 10.0.0.1/24 dev tap0
  ip link set tap0 up
  LC_ALL=C ping -c 2 -i 0.3 -W 1 10.0.0.2
  python3 -c "
import socket, subprocess, time
s = socket.socket(); s.connect((\"10.0.0.2\", 80))
print(subprocess.run([\"ss\", \"-tn\"], capture_output=True, text=True).stdout, end=\"\")
s.close(); time.sleep(0.5)
print(subprocess.run([\"ss\", \"-tan\"], capture_output=True, text=True).stdout, end=\"\")
"
  wait
'
```

What `ping` said:

```text
2 packets transmitted, 2 received, 0% packet loss, time 306ms
rtt min/avg/max/mdev = 0.059/0.117/0.175/0.058 ms
```

What `ss` said, while the connection was open and again after `close()`:

```text
State     Recv-Q Send-Q Local Address:Port  Peer Address:Port
ESTAB     0      0           10.0.0.1:54972     10.0.0.2:80

State     Recv-Q Send-Q Local Address:Port  Peer Address:Port
TIME-WAIT 0      0           10.0.0.1:54972     10.0.0.2:80
```

⚠ **`TIME-WAIT` is the kernel's own state**, entered only once it has had our close and acknowledged
it. ⚠ **It is the peer's, and this stack never enters it** — RFC 793 puts it on the side that closed
first. ⚠ **How long it stays there is the peer's business and nothing here can shorten it.**

What the stack said (⚠ **the ethernet header line of every frame is left out
here; a real run prints one for each**):

```text
listening on tap0
  answered it: 10.0.0.2 is ours, and 10.0.0.1 was told our hardware address
  answered it: 10.0.0.2 is ours, and 10.0.0.1 got its 56 octets back
  answered it: 10.0.0.2 is ours, and 10.0.0.1 got its 56 octets back
  10.0.0.1:54972 asked to open a connection; now waiting for it to
    confirm (SYN-RECEIVED)
  10.0.0.1:54972 confirmed it; the connection is open (ESTABLISHED)
  10.0.0.1:54972 has closed its side; we read the FIN, closed ours in the same
    segment, and are waiting for that to be acknowledged (LAST-ACK)
  10.0.0.1:54972 acknowledged our own close; the connection is finished and
    the room it held is free again (CLOSED)
listened on tap0 for 1500 ms after frame 13 and read no more. That does not say whether anything more was sent.
read 13 frames, 0 read errors
0 frames were malformed, 0 carried an IEEE 802.3 Length, 0 carried a length/type the standard does not define
answered 1 ARP request. 0 were not for us, 0 were malformed, 0 named an address space we cannot place, 0 had an opcode we do not act on
answered 2 echo requests. 0 were not for us, 0 carried a protocol we do not act on
0 internet headers were malformed, 0 were ones we do not read yet, 0 had a checksum that does not agree, 0 were fragments
0 ICMP messages were malformed, 0 had a type we do not act on, 0 had a checksum that does not agree
0 replies could not be built, which would be ours and not the sender's
0 TCP headers were malformed and 0 had a checksum that does not agree
1 connection was opened and 1 answered. 0 asked again
1 reached open. 0 acknowledged a number we are not waiting for, 0 arrived for no connection we hold, 0 arrived where the connection's state did not expect them
1 of our own closes left the device and 0 went out again because nobody had acknowledged them. 1 connection finished, and 0 were given up on with our close unacknowledged
0 answers went out again because nobody had confirmed them
0 connections were given up on after nobody confirmed them
0 octets of data were taken and discarded, and 0 segments carried data none of which was inside the window we promised
the other side closed 1 connection. 0 FINs arrived that were not the next thing we were waiting for, and 0 named a connection we hold nothing for
0 were refused for want of room and 0 answers never left the device, which are ours and not the sender's
```

⚠ **`0x0806` and `0x0800` are printed as the values they are, never as names.** A name would be a
lie for a VLAN-tagged frame, and ⚠ **`0x0800` → IPv4 has never been taken from a standard in this
repository** — it is what the kernel put on a device while doing IPv4
([ADR 0003](docs/adr/0003-what-the-length-type-field-means-and-what-the-parse-layer-refuses-to-guess.md)).

⚠ **This run is not the one that stood here before.** ⚠ The previous one, on 2026-08-28, ended with
four lines of `nothing in this connection's state expects that` and a connection that was never
closed. ⚠ **It was re-run rather than edited** (hidetzu/tcpip-stack#67 AC 6): a worked example
patched by hand is no longer a record of anything.

⚠ **The last line of the timer is not a failure.** ⚠ Nothing more arrived here, and that does not
say whether anything more was sent (`CLAUDE.md` §1).

## Environment

Linux is the source of truth for development. The stack talks to the kernel through
`/dev/net/tun`, and the test environment is built out of network namespaces so that
experiments cannot disturb ordinary networking.

Development tooling is Node (the hooks under `.claude/` use only Node built-ins —
there are no npm dependencies). The product itself is C.

## Milestones

### The connection can be closed

⚠ **Met, on 2026-08-29.** ⚠ **`close()` from the Linux kernel completes against this stack and the
kernel enters `TIME-WAIT`** (`tests/foreign.sh`
`the_kernel_reaches_time_wait_and_our_block_is_free_again`). ⚠ **That state is entered only once it
has had our `FIN` and acknowledged it**, so ⚠ **reaching it is somebody else's judgement on our
sequence numbers, not ours.**

⚠ **What is deliberately not claimed:** ⚠ **the connection disappearing from `ss` after 2 MSL.**
⚠ That wait is the peer's own and ⚠ **nothing here can shorten it** — a check that waited it out
would be measuring the Linux kernel's timer and not this stack.

⚠ **And a second `connect()` succeeding straight afterwards is evidence about our own connection
block being free again, and about nothing on the peer.** ⚠ The first connection is still in
`TIME-WAIT` over there while it succeeds, ⚠ **which is exactly why the two are never spoken of as
one thing.**

⚠ **The same lesson as the ping and the handshake applies:** a stack that closed back on any `FIN`
at all would reach `TIME-WAIT` too. ⚠ **A `FIN` 500 past the window we promised draws no close from
us and is counted apart, and the same `FIN` at the sequence number we are waiting for, in the same
run, draws one** (`tests/foreign.sh` `a_fin_whose_sequence_number_we_do_not_expect_is_not_answered`).

⚠ **What it cost:** ⚠ **the foreign tier went from 8747 ms at six cases to 20517 ms at ten**, and
⚠ **the growth is not the case count** — the four cases added over this milestone all wait on real
time. ⚠ [`docs/SPEC.md`](docs/SPEC.md) §3 owns those numbers, with the runs listed.

### The stack keeps its own time

⚠ **Met, on 2026-08-29.** ⚠ **A connection nobody confirms is answered again on
the wire — twice, a second apart — and then given up on**, counted by an
`AF_PACKET` socket rather than by our own output (`tests/real.sh`
`the_answer_really_goes_out_again`).

⚠ **The State layer still reads no clock.** It is handed a moment, which is what
keeps every one of its checks running with no waiting at all
([ADR 0018](docs/adr/0018-the-state-layer-is-handed-a-moment-and-never-reads-one.md)).

⚠ **What is not in it:** ⚠ **RFC 793 says the retransmission timeout must be
determined from a round trip, and nothing here measures one** — a fixed second is
used instead, which is the document's own example lower bound.
[`docs/SPEC.md`](docs/SPEC.md) §2 records that as our gap.

### The kernel's own `connect()` succeeds

⚠ **Met, on 2026-08-28.** ⚠ **`connect()` from the Linux kernel completes against this stack and
`ss -tn` reports the connection established** (`tests/foreign.sh`
`the_kernel_opens_a_connection_to_us`). The kernel checks the TCP checksum over a pseudo-header and
the acknowledgment number before it completes one, so ⚠ **that verdict is not ours.**

⚠ **And the same lesson as the ping applies:** a stack that never validated a checksum on the way in
would complete this handshake too. ⚠ A SYN whose TCP checksum does not agree is not answered and is
counted, ⚠ **and the same segment with the right checksum, in the same run, is answered.**

⚠ **What is in it after that, and what is not.** ⚠ The answer advertises a window of 1460 octets —
⚠ **what one frame carries at the MTU the checks use** — and ⚠ **the number has moved twice, each
time after what backs it moved.** ⚠ With a window of 0 the kernel's own `close()` produces no `FIN`
at all; ⚠ **at 1 the `FIN` arrives**; ⚠ at 1460 a peer sends a whole segment at once. ⚠ Data the
window covers is ⚠ **acknowledged and then discarded** — there is nobody to give it to — and
⚠ **the peer's `Send-Q` reaches 0**, measured 2026-08-29. ⚠ Before that it resent the same octet
seven times and its queue never emptied.

⚠ **The `FIN` is read**, with `RCV.NXT` advanced over it by exactly one, after any data it rides
with. ⚠ **`TIME-WAIT` is not ours**: the document puts it on the side that closed first, and this
stack never does. ⚠ **The document's `CLOSE-WAIT` waits for a local user to close, and there is no
user here** — so what happens instead is a decision, recorded in
[ADR 0022](docs/adr/0022-a-fin-is-read-and-the-user-rfc-793-waits-for-does-not-exist.md): the
`FIN`'s arrival *is* the close.

⚠ **So one segment goes back carrying `FIN,ACK`** — their close acknowledged and ours sent together
— and the connection enters `LAST-ACK`. ⚠ **The other side's verdict, not ours**: measured
2026-08-29, ⚠ **the kernel sent its `FIN` five times before this and once after**, and `ss` then
reports `TIME-WAIT`.
⚠ Why one segment and not two, and why `LAST-ACK` and not what RFC 793's CLOSE Call prints, are in
[ADR 0023](docs/adr/0023-our-close-rides-the-acknowledgment-of-theirs.md).

⚠ **What is still not sent**: three places RFC 793 §3.9 asks for a reset produce a counted reason and
no segment, and ⚠ **a segment we refuse draws nothing** — the document asks for an acknowledgment
there too. ⚠ **The initial sequence number is fixed, which is a known weakness outside a private
namespace** — [`docs/SPEC.md`](docs/SPEC.md) §2 says so plainly.

⚠ **Whether the kernel then lets the connection go** is the milestone above.

### Our own code answers a ping

**Not TCP** — ethernet frames, ARP, IPv4, ICMP echo, through a TAP device, inside a namespace,
verified against something we did not write.

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
