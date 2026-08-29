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
| `MUST-57` | "A TCP implementation MUST silently discard an incoming SYN segment that is addressed to a broadcast or multicast address ... This prevents connection state and replies from being erroneously created" | ⚠ **met in part** since hidetzu/tcpip-stack#99, ⚠ **and the part is named rather than the whole claimed.** ⚠ **Met**: the limited broadcast `255.255.255.255` and multicast `224.0.0.0/4` — refused before any state is taken or reply built, counted on their own. ⚠ **Not met**: a directed broadcast such as `10.0.0.255`, ⚠ **which cannot be told from a host address without a netmask, and nothing here has one.** ⚠ `tests/static.sh` `handshake` → `a_segment_addressed_to_everyone_is_refused` asserts both halves — ⚠ **including that a directed broadcast IS still answered**, so the gap cannot close by accident. ⚠ `tests/foreign.sh` `a_syn_to_everyone_is_not_answered` on the wire |

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

## Window (hidetzu/tcpip-stack#95)

| ID | Requirement, quoted | Verdict |
|---|---|---|
| `MUST-1` | "The window size MUST be treated as an unsigned number, or else large window sizes will appear like negative windows and TCP will not work" | ⚠ **met** — `struct tcp_header.window` is `uint16_t` and is read with `read_16`. ⚠ `tests/static.sh` `tcp_header` → `the_kernels_syn_is_read_as_it_holds_it` asserts it against the kernel's own SYN. ⚠ **And nothing consults it**: this stack never sends data, so ⚠ **there is no `SND.WND`** |
| `REC-1` | "It is RECOMMENDED that implementations will reserve 32-bit fields for the send and receive window sizes in the connection record and do all window computations with 32 bits" | ⚠ **not taken** — ⚠ **the connection record has no window field at all.** ⚠ The offered window is the constant `HANDSHAKE_WINDOW`, and the peer's is never stored |
| `SHLD-14` | "SHOULD NOT ... shrink the window from the right" | ⚠ **does not arise** — ⚠ **the offered window is a constant and never shrinks** (ADR 0021) |
| `SHLD-15` | "* Send new data when window shrinks" | ⚠ **does not arise** — ⚠ conditional on shrinking, and ⚠ **nothing here sends data** |
| `SHLD-16` | "* Retransmit old unacked data within window" | ⚠ **does not arise** — ⚠ **no data of ours is ever unacknowledged**, because none is sent |
| `SHLD-17` | "SHOULD NOT ... time out a connection for data past the right edge" | ⚠ **does not arise** — ⚠ same condition |
| `MUST-34` | "Robust against shrinking window" | ⚠ **does not arise** — ⚠ **a sender's requirement**, and this stack sends no data |
| `MAY-8` | "A TCP implementation MAY keep its offered receive window closed indefinitely" | ⚠ **not taken** — ⚠ the offered window is 1460 and constant |
| `MUST-35` | "Use standard probing logic" | ⚠ **does not arise** — ⚠ probing is what a sender does into a closed window |
| `MUST-36` | "Probing of zero (offered) windows MUST be supported" | ⚠ **does not arise** — ⚠ same: ⚠ **this stack never has data to probe with** |
| `SHLD-29` | "* First probe after RTO" | ⚠ **does not arise** — ⚠ conditional on probing |
| `SHLD-30` | "* Exponential backoff" | ⚠ **does not arise** — ⚠ same |
| `MUST-37` | "As long as the receiving TCP peer continues to send acknowledgments in response to the probe segments, the sending TCP peer MUST allow the connection to stay open" | ⚠ **does not arise** — ⚠ **the requirement is on the sending peer**, and this stack is never it |
| `MAY-7` | "Retransmit old data beyond SND.UNA+SND.WND" | ⚠ **not taken** — ⚠ there is no old data |
| `MUST-66` | "A TCP receiver MUST process the RST and URG fields of all incoming segments, even when the receive window is zero" | ⚠ **met** since hidetzu/tcpip-stack#101. ⚠ A `RST` the window covers ends the connection and releases the block — §3.10.7.4: "Enter the CLOSED state, delete the TCB, and return"; ⚠ one outside it is ⚠ **dropped with nothing sent**, which is the first step's own exception "(unless the RST bit is set, if so drop the segment and return)". ⚠ A segment carrying `URG` is ⚠ **counted and said**, since there is nobody to signal (ADR 0022). ⚠ **RFC 5961's three checks are not implemented** — the document makes them conditional and ADR 0024 clause 3 does not pull in a deferred document. ⚠ `tests/static.sh` `handshake` → `a_reset_ends_the_connection`, `a_reset_outside_the_window_changes_nothing`, `an_urgent_segment_is_counted_and_said`; `tests/foreign.sh` `a_reset_ends_a_connection_on_the_wire` |

## Generating ACKs (hidetzu/tcpip-stack#95)

| ID | Requirement, quoted | Verdict |
|---|---|---|
| `MUST-58` | "In general, the processing of received segments MUST be implemented to aggregate ACK segments whenever possible" | ⚠ **met, and vacuously** — ⚠ **nothing is ever queued**, so there is never more than one segment to aggregate over. ⚠ **Said as vacuous rather than claimed as an implementation** |
| `SHLD-31` | "Queue out-of-order segments" | ⚠ **not taken** — ⚠ **nothing is held**; `docs/SPEC.md` §2 names it, and it is why a segment beginning ahead is refused |
| `MUST-59` | "if the TCP endpoint is processing a series of queued segments, it MUST process them all before sending any ACK segments" | ⚠ **does not arise** — ⚠ **conditional on a queue**, and `SHLD-31` above is not taken |
| `MAY-13` | "Send ACK for out-of-order segment" | ⚠ **taken** since hidetzu/tcpip-stack#80 — ⚠ a segment we refuse draws one saying where we are. ⚠ `tests/static.sh` `handshake` → `a_segment_we_refuse_draws_an_acknowledgment` |
| `SHLD-18` | "Delayed ACKs" | ⚠ **not taken** — ⚠ one acknowledgment per accepted segment. ⚠ hidetzu/tcpip-stack#74 measured that the question did not arise at a window of 1; ⚠ **at 1460 it could, and it is still not taken** |
| `MUST-40` | "* Delay < 0.5 seconds" | ⚠ **does not arise** — ⚠ conditional on delaying, which `SHLD-18` is not |
| `SHLD-19` | "* Every 2nd full-sized segment or 2*RMSS ACK'd" | ⚠ **does not arise** — ⚠ same condition |
| `MUST-39` | "A TCP implementation MUST include a SWS avoidance algorithm in the receiver"; §3.8.6.2.2: "The receiver's SWS avoidance algorithm determines when the right window edge may be advanced" | ⚠ **met by construction** (Owner Decision, hidetzu/tcpip-stack#102). ⚠ **The algorithm governs window updates, and this stack sends none**: the offered window is the same in every segment it builds, so ⚠ **the right window edge advances exactly with `RCV.NXT` and never by a small increment.** ⚠ **The grounds are a check, not the argument**: `tests/static.sh` `handshake` → `every_segment_we_build_carries_the_same_window`, ⚠ **which reads all four shapes** — the answer, the acknowledgment for data, the acknowledgment for a refused segment, and our close. ⚠ **It read three until #102**: the fourth arrived at hidetzu/tcpip-stack#80 and the case did not follow, ⚠ **which is `CLAUDE.md` §9's first row happening again** |

## Sending Data (hidetzu/tcpip-stack#95)

| ID | Requirement, quoted | Verdict |
|---|---|---|
| `MUST-49` | "Time to Live (TTL): The TTL value used to send TCP segments MUST be configurable" | ⚠ **met** since hidetzu/tcpip-stack#103 — `--ttl`, 1 to 255, default 64. ⚠ `tests/static.sh` `handshake` → `the_time_to_live_we_send_with_is_the_callers` reads the built header back at four values; ⚠ `tests/foreign.sh` `the_time_to_live_we_were_given_reaches_the_wire` reads it off the wire ⚠ **at 42, which is not the default** — otherwise neither could tell a setting from a constant. ⚠ **The ICMP echo reply shares the value** (Owner Decision), which ⚠ **claims slightly more than this requirement asks** |
| `MUST-38` | "Sender SWS-Avoidance Algorithm" | ⚠ **does not arise** — ⚠ **this stack sends no data** |
| `SHLD-7` | "Nagle algorithm" | ⚠ **does not arise** — ⚠ same |
| `MUST-17` | "* Application can disable Nagle algorithm" | ⚠ **does not arise** — ⚠ conditional on Nagle, and ⚠ **there is no application** (ADR 0022) |
