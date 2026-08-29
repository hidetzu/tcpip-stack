# 0034 — A congestion window, beside the one they advertised

Date: 2026-08-29
Status: accepted
Issue: hidetzu/tcpip-stack#132

## Context

⚠ RFC 9293 §3.8.2: "A TCP endpoint **MUST** implement the basic congestion control algorithms slow
start, congestion avoidance, and exponential backoff of RTO (`MUST-19`)."

⚠ **Exponential backoff arrived at hidetzu/tcpip-stack#131.** ⚠ **This is the other two.**

⚠ RFC 5681 is normative for them since ADR 0024's amendment, ⚠ **and only for them** — the scope
table there keeps §3.2's fast retransmit and fast recovery out, ⚠ **because `MUST-19` names three
algorithms and those are not among them.**

## Decision

### ⚠ `SMSS` is the effective send MSS, and no second idea is introduced

⚠ RFC 5681 §2: "The SMSS is the size of the largest segment that the sender can transmit. This value
can be based on the maximum transmission unit of the network ..., RMSS ..., or other factors."

⚠ **That is exactly what `handshake_effective_send_mss` returns** (RFC 9293 `MUST-16`), ⚠ **so
"how large a segment may be" is decided in one place** (`CLAUDE.md` §3).

⚠ **`FlightSize` is `SND.NXT - SND.UNA`**, which the send driver already computed.

### ⚠ Which equation, and what kind of keyword each one carries

```text
slow start            cwnd += min(N, SMSS)        ⚠ equation (2), RECOMMENDed
congestion avoidance  cwnd += SMSS*SMSS/cwnd      ⚠ equation (3), a MAY
```

⚠ **The `MUST` above equation 2 is "increments cwnd by at most SMSS bytes for each ACK", and
equation 2 satisfies it.** ⚠ **Neither equation is itself required**, and ⚠ **saying which keyword
each carries is the point** — `CLAUDE.md` §9's third row is about collapsing them.

⚠ **Equation 3 can truncate to zero and the code guards it.** ⚠ The smallest `SMSS` a tap can give is
28 and `cwnd` is bounded by sixteen bits: ⚠ **28 × 28 ÷ 65535 is zero.** ⚠ **A window that stopped
growing for ever would be a stall the document does not ask for**, so the growth is at least one
octet — ⚠ **far below the "one full-sized segment per RTT" ceiling the `MUST` puts on it.**

### ⚠ `IW` is applied at the first send, not at the handshake

⚠ RFC 5681 calls `IW` "the size of the sender's congestion window after the three-way handshake is
completed." ⚠ **It needs `SMSS`, and `SMSS` needs the device's MTU, which the receive path is not
handed.** ⚠ So it is applied at the first send, ⚠ **with a flag rather than a zero sentinel**: a zero
would be indistinguishable from a window legitimately cut to nothing.

## Consequences

- ⚠ **`MUST-19` is met, and each of its three algorithms is asserted apart** — ⚠ a check that only
  showed the window changing could not tell slow start from congestion avoidance.
- ⚠ **`ssthresh` uses `FlightSize` and a check asserts it is not `cwnd/2`.** ⚠ **The document names
  that mistake**, so the check names it too.
- ⚠ **Only `MUST-20` (b) is left of the retransmission schedule**: negative advice to a routing layer
  that does not exist here.

### ⚠ Three things measuring changed, and none of them was the code

- ⚠ **A device-tier drop rule added 0.4 s into the connection never fired**: ⚠ **all 30000 octets had
  already left.** ⚠ The rule is in place before the connection now, ⚠ **and it matches only a
  full-sized data segment**, so the handshake still completes.
- ⚠ **A static case's acknowledgment carried a window of zero** and nothing more went out.
  ⚠ **`SND.WND` is read from every segment the peer sends** — ⚠ **the helper's silence was the
  peer's word, not a defect**, and the case says so now.
- ⚠ **A case acknowledged an empty window and reported "it did not grow"** for a build that grows
  correctly. ⚠ **More has to go out before an acknowledgment can cover anything new.**

### ⚠ The isolated tier's cost has an unexplained spread and it is reported

⚠ **24493 / 25593 / 32763 ms across three runs.** ⚠ **Nothing here measured why**, and
⚠ **it is not carried as a claim that the tier got faster** — the previous row's slowest and this
one's slowest are the same. ⚠ **Reported rather than averaged away** (`CLAUDE.md` §6).
