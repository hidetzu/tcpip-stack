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
| **not met** | ⚠ **with the issue cut for it** — ⚠ **or, where the audit stopped short of cutting one, with the row in `docs/SPEC.md` §2 and the group it belongs to named below.** ⚠ **What it may never be is a "not met" with nothing behind it anywhere** |
| **does not arise** | ⚠ **the requirement is conditional on something not implemented**, and ⚠ **the condition is quoted** |
| ⚠ **cannot be judged** | ⚠ **what was read is recorded and nothing is chosen** |

⚠ **Every row quotes the requirement.** ⚠ **A verdict with no quotation is not a verdict**
(`CLAUDE.md` §1).

⚠ **A bare `MUST` is never "does not arise".** ⚠ It is met or it is not.

⚠ **Never write a count of these rows into a document** — ⚠ the runner announces counts, and
`docs/SPEC.md` says why.

---

---

## ⚠ The seven not yet met, in three groups

⚠ **Seven `MUST`s came back not met at hidetzu/tcpip-stack#96.** ⚠ **The issue's Stop Condition
said to report the list rather than cut seven issues**, and ⚠ **that is what happened — none was
cut.** ⚠ **They are not seven independent gaps.** ⚠ Reading them together, they are three, and
⚠ **the three differ in what has to be decided before anything can be written.**

| Group | The requirements | ⚠ What has to happen first |
|---|---|---|
| ⚠ **The source address** | `MUST-63` | ⚠ **Done** at hidetzu/tcpip-stack#112 — ⚠ **met in part, never met**, and `docs/SPEC.md` §2 keeps the row for the directed broadcast. ⚠ The one decision it needed (which forms) was taken 2026-08-29 and is ADR 0025 |
| ⚠ **The option machinery** | `MUST-4`, `MUST-14` | ⚠ **A design decision, and it has a dependency outside itself**: sending an MSS Option means knowing an MSS, ⚠ **and reading the device's MTU is itself a `docs/SPEC.md` §2 gap.** ⚠ Also the first time a segment we build stops being five fixed words |
| ⚠ **The retransmission schedule** | `MUST-18`, `MUST-19`, `MUST-20`, `MUST-23` | ⚠ **One gap seen from four sides**, not four gaps: a constant interval, no round-trip measurement, one give-up on a **time** where the document counts **retransmissions**, and that time being three seconds against three minutes. ⚠ **ADR 0019 is the standing decision and it is explicit that both numbers are ours** |

⚠ **The middle and last groups cannot be handed over as they stand** — ⚠ **each would make the AI
decide what may be claimed**, which `CLAUDE.md` §7-1 puts on the owner. ⚠ **The first can, once its
one question is answered.**

⚠ **Neither `MUST-19` nor `MUST-23` is a small change wearing a large label.** ⚠ `MUST-23` looks
like moving one constant from `3000` to `180000`; ⚠ **`docs/SPEC.md` §3 owns what the real tier
costs, and a check that waits three minutes changes it by an order of magnitude** — ⚠ **which is
the reason ADR 0019 gives for the value being what it is.**

---

## ⚠ Findings a verdict column cannot carry

⚠ **A verdict says whether the behaviour is there.** ⚠ **It does not say how it got there, or
whether anything asserts it** — and ⚠ **twice in this audit those were the interesting half.**
⚠ **Recorded here so that reading down the verdict column does not read as more conformance than
was earned** (`CLAUDE.md` §1).

| ID | Its verdict | ⚠ What the verdict does not say |
|---|---|---|
| `MUST-64` | **met** | ⚠ **Nothing asserts it on purpose.** The option walk is byte-wise and assumes no alignment, ⚠ **so the behaviour is there** — but ⚠ **no case feeds an unaligned option deliberately.** `end_of_option_list_stops_the_walk` and `no_option_is_interpreted` happen to exercise it. ⚠ **Happening to exercise a thing is not asserting it**, and ⚠ **a byte-wise walk could be rewritten word-wise tomorrow with every case still green.** ⚠ **A gap in the checks, not in the code**, and it is `docs/SPEC.md` §2's row |
| `MAY-4` | **taken** | ⚠ **Taken by accident.** `Identification` is always `0` (ADR 0012), ⚠ **so every retransmission does carry the same one** — ⚠ **but not one line was written to make that so**, and ⚠ **nothing would notice if `Identification` started varying.** ⚠ **An option we happen to satisfy is not an option we chose** |

⚠ **Neither of these is a defect in the stack.** ⚠ **Both are places where a later change could
take the behaviour away and no check would say so**, which is the only reason they are written down.

## ISN Selection (hidetzu/tcpip-stack#94)

| ID | Requirement, quoted | Verdict |
|---|---|---|
| `MUST-8` | "A TCP implementation MUST use the above type of 'clock' for clock-driven selection of initial sequence numbers" — the clock being "a 32-bit counter that typically increments at least once every roughly 4 microseconds" | ⚠ **met** since hidetzu/tcpip-stack#98. ⚠ The number is the moment divided by 4000 nanoseconds, truncated to 32 bits — ⚠ **the document's clock is a 32-bit counter that wraps, and the sequence space wraps with it.** ⚠ `tests/static.sh` `handshake` → `the_initial_sequence_number_follows_the_clock`, ⚠ **with no clock and no waiting** (ADR 0018): one step moves it by one, a moment shorter than a step does not, ⚠ **and a retransmitted `SYN` a minute later is still answered with the same number** (ADR 0016) |
| `SHLD-1` | "SHOULD generate its initial sequence numbers with the expression: `ISN = M + F(localip, localport, remoteip, remoteport, secretkey)`" | ⚠ **refused, with a reason** (Owner Decision, hidetzu/tcpip-stack#98). ⚠ `F` needs a secret key and a pseudo-random function, ⚠ **and this repository has neither and no cryptographic dependency**; `CLAUDE.md` §3 forbids introducing one without a reason. ⚠ **So the number is still guessable by anyone who can read a clock**, and `docs/SPEC.md` §2 says so — ⚠ **a `SHOULD` refused is a decision, not an omission, and `MUST-8` is not offered as the whole answer** |
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
| `MUST-57` | "A TCP implementation MUST silently discard an incoming SYN segment that is addressed to a broadcast or multicast address ... This prevents connection state and replies from being erroneously generated" | ⚠ **met in part** since hidetzu/tcpip-stack#99, ⚠ **and the part is named rather than the whole claimed.** ⚠ **Met**: the limited broadcast `255.255.255.255` and multicast `224.0.0.0/4` — refused before any state is taken or reply built, counted on their own. ⚠ **Not met**: a directed broadcast such as `10.0.0.255`, ⚠ **which cannot be told from a host address without a netmask, and nothing here has one.** ⚠ `tests/static.sh` `handshake` → `a_segment_addressed_to_everyone_is_refused` asserts both halves — ⚠ **including that a directed broadcast IS still answered**, so the gap cannot close by accident. ⚠ `tests/foreign.sh` `a_syn_to_everyone_is_not_answered` on the wire |

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

## TCP Checksums (hidetzu/tcpip-stack#96)

| ID | Requirement, quoted | Verdict |
|---|---|---|
| `MUST-2` | "The TCP checksum is never optional.  The sender MUST generate it" | ⚠ **met** — every segment is built through `tcp_build_segment`, which writes it. ⚠ `tests/static.sh` `handshake` → `the_answer_is_the_one_the_document_describes` reads the answer back with `tcp_parse_header`, ⚠ **which judges the checksum first**, so reaching OK is the assertion |
| `MUST-3` | "the receiver MUST check it" | ⚠ **met** — ⚠ **it is an outcome of the parse and not a call a caller can forget** (ADR 0014). ⚠ `tests/static.sh` `tcp_header` → `the_kernels_checksum_is_reproduced`, and `tests/foreign.sh` `a_syn_whose_checksum_does_not_agree_is_not_answered` against the kernel |

## TCP Options (hidetzu/tcpip-stack#96)

| ID | Requirement, quoted | Verdict |
|---|---|---|
| `MUST-4` | "Support the mandatory option set" | ⚠ **not met** — ⚠ **the set includes the MSS Option** (`MUST-14` below), and none is implemented |
| `MUST-5` | "A TCP implementation MUST be able to receive a TCP Option in any segment" | ⚠ **met** — the walk runs for any segment whose `Data Offset` is above the fixed header. ⚠ `tests/static.sh` `tcp_header` → `the_kernels_syn_is_read_as_it_holds_it` (the kernel's own SYN carries twenty octets of them) |
| `MUST-6` | "A TCP implementation MUST (MUST-6) ignore without error any TCP Option it does not implement, assuming that the option has a length field" | ⚠ **met** — ⚠ **not one option is interpreted**; the walk finds where the data begins and reads nothing. ⚠ `tests/static.sh` `tcp_header` → `no_option_is_interpreted` |
| `MUST-68` | "All TCP Options except End of Option List Option (EOL) and No-Operation (NOP) MUST have length fields, including all future options" | ⚠ **does not arise as a sender** — ⚠ **no option is ever sent.** ⚠ As a receiver it is the assumption `MUST-6` rests on, and the walk relies on it |
| `MUST-7` | "TCP implementations MUST be prepared to handle an illegal option length (e.g., zero); a suggested procedure is to reset the connection and log the error cause" | ⚠ **met** — the segment is refused as malformed and counted, ⚠ **and the walk terminates**: `tests/static.sh` `tcp_header` → `an_option_list_that_does_not_walk_is_malformed`, ⚠ **whose finishing at all is the proof.** ⚠ **No reset is sent, and the procedure is "suggested" rather than required** — `docs/SPEC.md` §2 names the gap |
| `MUST-64` | "receivers MUST be prepared to process options even if they do not begin on a word boundary" | ⚠ **met** — the walk is byte-wise and no alignment is assumed. ⚠ **No case feeds an unaligned option on purpose**, and ⚠ **that is a gap in the checks rather than in the code**: `end_of_option_list_stops_the_walk` and `no_option_is_interpreted` happen to exercise it, ⚠ **which is not the same as asserting it** |
| `MUST-14` | "TCP endpoints MUST implement both sending and receiving the MSS Option" | ⚠ **not met** — ⚠ **no option is implemented at all** (`docs/SPEC.md` §2) |
| `SHLD-5` (IPv4) | "Send MSS Option unless 536" | ⚠ **not taken** — conditional on sending the option |
| `SHLD-5` (IPv6) | "Send MSS Option unless 1220" | ⚠ **does not arise** — ⚠ **nothing here reads or writes IPv6** |
| `MAY-3` | "Send MSS Option always" | ⚠ **not taken** |
| `MUST-15` (IPv4) | "implementations MUST assume a default send MSS of 536 (576 - 40) for IPv4" | ⚠ **does not arise** — ⚠ **no segment this stack sends carries data**, so there is no send MSS to default |
| `MUST-15` (IPv6) | "or 1220 (1280 - 60) for IPv6" | ⚠ **does not arise** — no IPv6 |
| `MUST-16` | "The maximum size of a segment that a TCP endpoint really sends, the 'effective send MSS', MUST be the smaller of the send MSS ... and the MMS_S" | ⚠ **does not arise** — ⚠ same: nothing sends data |
| `SHLD-6` | "MSS accounts for varying MTU" | ⚠ **does not arise** — ⚠ same, and ⚠ **nothing reads the MTU either** (`docs/SPEC.md` §2) |
| `MUST-65` | "MSS not sent on non-SYN segments" | ⚠ **met vacuously** — ⚠ **it is never sent on any segment.** ⚠ Said as vacuous rather than claimed as a rule being kept |
| `MUST-67` | "MSS value based on MMS_R" | ⚠ **does not arise** — conditional on sending it |
| `MUST-69` | "The content of the header beyond the End of Option List Option MUST be header padding of zeros" | ⚠ **met vacuously** — ⚠ every header this stack builds has `Data Offset` 5, ⚠ **so there is nothing beyond** |

## Retransmissions (hidetzu/tcpip-stack#96)

| ID | Requirement, quoted | Verdict |
|---|---|---|
| `MUST-19` | "A TCP endpoint MUST implement the basic congestion control algorithms slow start, congestion avoidance, and exponential backoff of RTO to avoid creating congestion collapse conditions" | ⚠ **not met** — ⚠ **none of the three exists.** ⚠ The retransmission interval is a constant second (ADR 0019) |
| `MUST-18` | "The RTO MUST be computed according to the algorithm in [RFC 6298], including Karn's algorithm for taking RTT samples" | ⚠ **not met** — ⚠ **nothing here measures a round trip**, which `docs/SPEC.md` §2 has named since hidetzu/tcpip-stack#57. ⚠ **It has a label now** |
| `MAY-4` | "Retransmit with same IP identity" | ⚠ **taken, and by accident** — ⚠ `Identification` is always 0 (ADR 0012), so ⚠ **every retransmission does carry the same one.** ⚠ Said as accidental rather than claimed as a choice |

## Connection Failures (hidetzu/tcpip-stack#96)

| ID | Requirement, quoted | Verdict |
|---|---|---|
| `MUST-20` (R1) | "The following procedure MUST be used to handle excessive retransmissions of data segments ... give negative advice to IP on R1 retransmissions" | ⚠ **not met** — ⚠ **there is no R1 and nothing is said to IP.** ⚠ There is one give-up moment and no threshold before it |
| `MUST-20` (R2) | "Close connection on R2 retransmissions" | ⚠ **met in effect and not in shape** — ⚠ the connection IS given up on and released (ADR 0019), ⚠ **but on a time and not on a count of retransmissions**, and ⚠ **there is no R2 to set.** ⚠ Recorded as **not met**, because reading a `MUST` as satisfied by something with the same effect and a different shape is what `CLAUDE.md` §9 has rows about |
| `MUST-21` | "ALP can set R2" | ⚠ **does not arise** — ⚠ **there is no application** (ADR 0022) |
| `SHLD-9` | "Inform ALP of R1<=retxs<R2" | ⚠ **does not arise** — same |
| `SHLD-10` | "Recommended value for R1" | ⚠ **does not arise** — conditional on there being an R1 |
| `SHLD-11` | "Recommended value for R2" | ⚠ **does not arise** — conditional on there being an R2 |
| `MUST-22` | "Same mechanism for SYNs" | ⚠ **met** — ⚠ **one schedule covers a connection still opening and one waiting for our close to be acknowledged** (`the_one_waiting`), and hidetzu/tcpip-stack#66 kept them the same rather than giving closing its own |
| `MUST-23` | "* R2 at least 3 minutes for SYN" | ⚠ **not met** — ⚠ `HANDSHAKE_GIVE_UP_AFTER_MILLISECONDS` is **3000**, ⚠ **three seconds against a required three minutes.** ⚠ ADR 0019 chose it for what a check can afford and ⚠ **recorded that as exactly what it was** — ⚠ it now has a requirement to be measured against |

## Address Validation (hidetzu/tcpip-stack#96)

| ID | Requirement, quoted | Verdict |
|---|---|---|
| `MUST-46` | "MUST NOT ... OPEN to broadcast/multicast IP address" | ⚠ **does not arise** — judged at hidetzu/tcpip-stack#94: nothing here performs an active `OPEN` |
| `MUST-63` | "An incoming SYN with an invalid source address MUST be ignored either by TCP or by the IP layer ... (see Section 3.2.1.3)" | ⚠ **met in part** since hidetzu/tcpip-stack#112, ⚠ **and the part is named rather than the whole claimed.** ⚠ **Was not met at all**: measured 2026-08-29, a `SYN` sourced from `255.255.255.255` ⚠ **opened a connection and was answered.** ⚠ **Met**, each quoted from the section RFC 9293 sends the reader to — RFC 1122 §3.2.1.3: `0.0.0.0/8` (a)(b) "MUST NOT be sent, except as a source address as part of an initialization procedure", `127.0.0.0/8` (g) "MUST NOT appear outside a host", `255.255.255.255` (c) "MUST NOT be used as a source address". ⚠ **And `224.0.0.0/4`, whose grounds are OUTSIDE §3.2.1.3** — the multicast address model, ⚠ **recorded as reaching past the citation rather than quoted to it** (ADR 0025). ⚠ **Not met**: a directed broadcast, §3.2.1.3 (d)(e)(f), ⚠ **which cannot be told from a host address without a netmask.** ⚠ `tests/static.sh` `handshake` → `a_syn_from_an_impossible_source_is_refused` asserts every form above, ⚠ **the six boundary addresses one octet outside each range**, and ⚠ **that a directed broadcast source IS still answered.** ⚠ `tests/foreign.sh` `a_syn_from_an_impossible_source_is_not_answered` on the wire |
| `MUST-57` | "Silently discard SYN to bcast/mcast addr" | ⚠ **met in part** — judged at hidetzu/tcpip-stack#99; a directed broadcast is not recognised |
