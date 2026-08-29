# Conformance — held to RFC 9293 Appendix B

⚠ **RFC 9293 (STD 7) is the normative baseline** (ADR 0024). ⚠ **Appendix B is its requirement
summary**, adapted from RFC 1122.

⚠ **Counted 2026-08-29, from the document: 119 unique requirement IDs — 69 `MUST`, 31 `SHLD`,
1 `REC`, 18 `MAY` — across 19 sections.**

⚠ **This file is filled one section at a time.** ⚠ **A section with no rows here has not been read**,
and ⚠ **that is different from having no requirements.**

---

## ⚠ What a verdict means

| Verdict | What it says |
|---|---|
| **met** | ⚠ **with the case that asserts it named** — ⚠ a case, never a file (`docs/SPEC.md` §1) |
| **not met** | ⚠ **with the issue cut for it** |
| **does not arise** | ⚠ **the requirement is conditional on something not implemented**, and ⚠ **the condition is quoted** |
| ⚠ **cannot be judged** | ⚠ **what was read is recorded and nothing is chosen** |

⚠ **Every row quotes the requirement.** ⚠ **A verdict with no quotation is not a verdict**
(`CLAUDE.md` §1).

⚠ **A bare `MUST` is never "does not arise".** ⚠ It is met or it is not.

⚠ **Never write a count of these rows into a document** — ⚠ the runner announces counts, and
`docs/SPEC.md` says why.

---

## ISN Selection (hidetzu/tcpip-stack#94)

| ID | Requirement, quoted | Verdict |
|---|---|---|
| `MUST-8` | "A TCP implementation MUST use the above type of 'clock' for clock-driven selection of initial sequence numbers" — the clock being "a 32-bit counter that typically increments at least once every roughly 4 microseconds" | ⚠ **not met** — hidetzu/tcpip-stack#98. ⚠ `HANDSHAKE_INITIAL_SEND_SEQUENCE` is the constant `0xdeadbeef` (ADR 0016). ⚠ **`docs/SPEC.md` §2 already named it as a known weakness**; ⚠ **it has a label now** |
| `SHLD-1` | "SHOULD generate its initial sequence numbers with the expression: `ISN = M + F(localip, localport, remoteip, remoteport, secretkey)`" | ⚠ **not met** — hidetzu/tcpip-stack#98. ⚠ Same constant, no `M` and no `F` |
| `MUST-9` | Of that `F`: "MUST NOT be computable from the outside" | ⚠ **does not arise** — ⚠ **there is no `F`.** ⚠ **And that is worse, not better**: `MUST-9` guards a secret this stack does not have, and `MUST-8`/`SHLD-1` are the two it fails |

## Opening Connections (hidetzu/tcpip-stack#94)

| ID | Requirement, quoted | Verdict |
|---|---|---|
| `MUST-10` | "A TCP implementation MUST support simultaneous open attempts" | ⚠ **does not arise** — ⚠ a simultaneous open needs both ends to send a `SYN`, and ⚠ **this stack never sends one**: it has no active `OPEN` (`docs/SPEC.md` §2) |
| `MUST-11` | "a TCP implementation MUST keep track of whether a connection has reached SYN-RECEIVED state as the result of a passive OPEN or an active OPEN" | ⚠ **does not arise** — ⚠ **there is only one way to reach it here.** ⚠ Nothing is kept, and nothing could differ. ⚠ **RFC 9293 §3.10.7.4 uses that knowledge and this stack does not act on it either** — `docs/SPEC.md` §2-1 names that separately |
| `MUST-41` | "MUST NOT ... interfere with a previously created connection record" | ⚠ **does not arise** — ⚠ there is one passive `OPEN`, given by `--tcp-port`, and ⚠ **nothing can call it twice** |
| `MUST-42` | "A TCP implementation that supports multiple concurrent connections MUST provide an OPEN call that will functionally allow an application to LISTEN on a port while a connection block with the same local port is in SYN-SENT or SYN-RECEIVED state" | ⚠ **does not arise** — ⚠ **the requirement is conditional on supporting multiple concurrent connections**, and `CONNECTIONS_AT_ONCE` is 1 (ADR 0015, and `docs/SPEC.md` §2) |
| `MUST-44` | "Ask IP for src address for SYN if necessary" | ⚠ **does not arise** — ⚠ **no `SYN` is ever sent**, and the address is given by `--ipv4` |
| `MUST-45` | "* Otherwise, use local addr of connection" | ⚠ **met** — every segment we build carries `id->local.address`, which is the connection's. ⚠ `tests/static.sh` `handshake` → `the_answer_is_the_one_the_document_describes` reads the built datagram back and asserts it |
| `MUST-46` | "MUST NOT ... OPEN to broadcast/multicast IP address" | ⚠ **does not arise** — ⚠ **nothing here performs an active `OPEN`** |
| `MUST-57` | "A TCP implementation MUST silently discard an incoming SYN segment that is addressed to a broadcast or multicast address" | ⚠ **not met** — hidetzu/tcpip-stack#99. ⚠ **Measured 2026-08-29**: with `--ipv4 10.0.0.255`, a `SYN` addressed to `10.0.0.255` ⚠ **opened a connection and was answered.** ⚠ Nothing in the parse or the state machine asks whether a destination is broadcast or multicast; ⚠ **the only test is whether it equals the address we were given** |

## Closing Connections (hidetzu/tcpip-stack#94)

| ID | Requirement, quoted | Verdict |
|---|---|---|
| `SHLD-2` | "RST can contain data" | ⚠ **does not arise** — ⚠ **no `RST` is ever sent** (`docs/SPEC.md` §2 names the three places the document asks for one) |
| `MUST-12` | "If the local TCP connection is closed by the remote side due to a FIN or RST received from the remote side, then the local application MUST be informed whether it closed normally or was aborted" | ⚠ **does not arise** — ⚠ **there is no local application** (ADR 0022). ⚠ **The closing is reported to a human instead**, which is not what this requires and is not offered as if it were |
| `MAY-1` | "Half-duplex close connections" | ⚠ **not taken** — ⚠ a `MAY`. ⚠ ADR 0022 decided the `FIN`'s arrival is the close, so ⚠ **this end never stays open after the other closes** |
| `SHLD-3` | "* if such a TCP endpoint ... data is received after CLOSE is called, its TCP implementation SHOULD send a RST to show that data was lost" | ⚠ **does not arise** — ⚠ **conditional on the half-duplex close `MAY-1` offers**, which is not taken |
| `MUST-13` | "When a connection is closed actively, it MUST linger in the TIME-WAIT state for a time 2xMSL" | ⚠ **does not arise** — ⚠ **this stack never closes actively** (ADR 0022; RFC 9293 Figures 6 and 13 put `TIME-WAIT` on the side that does) |
| `MAY-2` | "* it MAY accept a new SYN from the remote TCP endpoint to reopen the connection directly from TIME-WAIT state" | ⚠ **does not arise** — ⚠ conditional on `TIME-WAIT`, which is never entered |
| `SHLD-4` | "* Use Timestamps to reduce TIME-WAIT" | ⚠ **does not arise** — ⚠ same condition, and ⚠ **no option is implemented** (`docs/SPEC.md` §2) |
