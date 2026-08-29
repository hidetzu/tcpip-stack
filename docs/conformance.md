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

## ⚠ What is not yet met, in groups

⚠ **Seventeen requirements are not met across the whole of Appendix B** — ⚠ **seven from hidetzu/tcpip-stack#96 (one since closed) and eleven from hidetzu/tcpip-stack#97.**

⚠ **Seven `MUST`s came back not met at hidetzu/tcpip-stack#96.** ⚠ **The issue's Stop Condition
said to report the list rather than cut seven issues**, and ⚠ **that is what happened — none was
cut.** ⚠ **They are not seven independent gaps.** ⚠ Reading them together, they are three, and
⚠ **the three differ in what has to be decided before anything can be written.**

| Group | The requirements | ⚠ What has to happen first |
|---|---|---|
| ⚠ **The source address** | `MUST-63` | ⚠ **Done** at hidetzu/tcpip-stack#112 — ⚠ **met in part, never met**, and `docs/SPEC.md` §2 keeps the row for the directed broadcast. ⚠ The one decision it needed (which forms) was taken 2026-08-29 and is ADR 0025 |
| ⚠ **The option machinery** | `MUST-4`, `MUST-14` | ⚠ **A design decision, and it has a dependency outside itself**: sending an MSS Option means knowing an MSS, ⚠ **and reading the device's MTU is itself a `docs/SPEC.md` §2 gap.** ⚠ Also the first time a segment we build stops being five fixed words |
| ⚠ **The retransmission schedule** | `MUST-18`, `MUST-19`, `MUST-20`, `MUST-23` | ⚠ **One gap seen from four sides**, not four gaps: a constant interval, no round-trip measurement, ⚠ **no R1 at all** — so no "threshold R2 greater than R1" — and the give-up time being three seconds against three minutes. ⚠ **Corrected 2026-08-29: the give-up being a TIME is not a gap.** §3.8.3 (a) offers time units as one of the two shapes. ⚠ **ADR 0019 is the standing decision and it is explicit that both numbers are ours** |

⚠ **The middle and last groups cannot be handed over as they stand** — ⚠ **each would make the AI
decide what may be claimed**, which `CLAUDE.md` §7-1 puts on the owner. ⚠ **The first can, once its
one question is answered.**

### ⚠ And four more groups, from hidetzu/tcpip-stack#97

⚠ **Eleven more came back not met, ⚠ so that issue's Stop Condition fired too and no issue was cut.**

| Group | The requirements | ⚠ What it is |
|---|---|---|
| ⚠ **The urgent mechanism** | `MUST-30`, `MUST-31`, `MUST-32`, `MUST-33`, `MUST-62` | ⚠ **The section hidetzu/tcpip-stack#97 named in advance as the one that would be got wrong.** ⚠ **The bit and the pointer are read and nothing is supported** — ⚠ calling any of it *does not arise* would make a mandated feature's absence look inapplicable |
| ⚠ **ICMP errors reaching a connection** | `MUST-54`, `SHLD-26` | ⚠ **There is no path from ICMP to a connection.** ⚠ **`MUST-55` and `MUST-56` come out met BY ACCIDENT** — not acting is what those two happen to ask for |
| ⚠ **An interface for an application** | `MUST-43`, `MUST-47`, `MUST-48` | ⚠ **There is no user of this stack** (ADR 0022). ⚠ **Two of the three effects exist in another shape** (`--ipv4`, `--ttl`), ⚠ **and an effect in a different shape is not the requirement met** |
| ⚠ **ECN** | `SHLD-8` | ⚠ **One `SHOULD`, alone.** ⚠ Accepting a `SYN` that carries the bits is not implementing the mechanism |

⚠ **The first three of these are not the same kind of work as the option machinery or the
retransmission schedule.** ⚠ **They are downstream of one absence — there is nothing above this
stack to serve** — ⚠ **and ADR 0022 records that as a decision, not an oversight.** ⚠ **Whether
that stays the shape of this project is the owner's, and it is a larger question than any of the
requirements below.**

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
| `MUST-57` | "A TCP implementation MUST silently discard an incoming SYN segment that is addressed to a broadcast or multicast address ... This prevents connection state and replies from being erroneously generated" | ⚠ **met in part** since hidetzu/tcpip-stack#99, ⚠ **and the part is named rather than the whole claimed.** ⚠ **Met**: the limited broadcast `255.255.255.255` and multicast `224.0.0.0/4` — refused before any state is taken or reply built, counted on their own. ⚠ **Not met**: a directed broadcast such as `10.0.0.255`, ⚠ **which cannot be told from a host address without a netmask, and nothing here has one.** ⚠ `tests/static.sh` `handshake` → `a_segment_addressed_to_everyone_is_refused` asserts both halves — ⚠ **including that a directed broadcast IS still answered**, so the gap cannot close by accident. ⚠ `tests/interop.sh` `a_syn_to_everyone_is_not_answered` on the wire |

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
| `MUST-66` | "A TCP receiver MUST process the RST and URG fields of all incoming segments, even when the receive window is zero" | ⚠ **met** since hidetzu/tcpip-stack#101. ⚠ A `RST` the window covers ends the connection and releases the block — §3.10.7.4: "Enter the CLOSED state, delete the TCB, and return"; ⚠ one outside it is ⚠ **dropped with nothing sent**, which is the first step's own exception "(unless the RST bit is set, if so drop the segment and return)". ⚠ A segment carrying `URG` is ⚠ **counted and said**, since there is nobody to signal (ADR 0022). ⚠ **RFC 5961's three checks are not implemented** — the document makes them conditional and ADR 0024 clause 3 does not pull in a deferred document. ⚠ `tests/static.sh` `handshake` → `a_reset_ends_the_connection`, `a_reset_outside_the_window_changes_nothing`, `an_urgent_segment_is_counted_and_said`; `tests/interop.sh` `a_reset_ends_a_connection_on_the_wire` |

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
| `MUST-49` | "Time to Live (TTL): The TTL value used to send TCP segments MUST be configurable" | ⚠ **met** since hidetzu/tcpip-stack#103 — `--ttl`, 1 to 255, default 64. ⚠ `tests/static.sh` `handshake` → `the_time_to_live_we_send_with_is_the_callers` reads the built header back at four values; ⚠ `tests/interop.sh` `the_time_to_live_we_were_given_reaches_the_wire` reads it off the wire ⚠ **at 42, which is not the default** — otherwise neither could tell a setting from a constant. ⚠ **The ICMP echo reply shares the value** (Owner Decision), which ⚠ **claims slightly more than this requirement asks** |
| `MUST-38` | "Sender SWS-Avoidance Algorithm" | ⚠ **does not arise** — ⚠ **this stack sends no data** |
| `SHLD-7` | "Nagle algorithm" | ⚠ **does not arise** — ⚠ same |
| `MUST-17` | "* Application can disable Nagle algorithm" | ⚠ **does not arise** — ⚠ conditional on Nagle, and ⚠ **there is no application** (ADR 0022) |

## TCP Checksums (hidetzu/tcpip-stack#96)

| ID | Requirement, quoted | Verdict |
|---|---|---|
| `MUST-2` | "The TCP checksum is never optional.  The sender MUST generate it" | ⚠ **met** — every segment is built through `tcp_build_segment`, which writes it. ⚠ `tests/static.sh` `handshake` → `the_answer_is_the_one_the_document_describes` reads the answer back with `tcp_parse_header`, ⚠ **which judges the checksum first**, so reaching OK is the assertion |
| `MUST-3` | "the receiver MUST check it" | ⚠ **met** — ⚠ **it is an outcome of the parse and not a call a caller can forget** (ADR 0014). ⚠ `tests/static.sh` `tcp_header` → `the_kernels_checksum_is_reproduced`, and `tests/interop.sh` `a_syn_whose_checksum_does_not_agree_is_not_answered` against the kernel |

## TCP Options (hidetzu/tcpip-stack#96)

| ID | Requirement, quoted | Verdict |
|---|---|---|
| `MUST-4` | "Support the mandatory option set" | ⚠ **not met** — ⚠ **the set includes the MSS Option**, and ⚠ **`MUST-14` is still not met** (below). ⚠ Since hidetzu/tcpip-stack#123 the option is **sent and read**; ⚠ **that is not the same as supported**, and this row follows `MUST-14` rather than leading it |
| `MUST-5` | "A TCP implementation MUST be able to receive a TCP Option in any segment" | ⚠ **met** — the walk runs for any segment whose `Data Offset` is above the fixed header. ⚠ `tests/static.sh` `tcp_header` → `the_kernels_syn_is_read_as_it_holds_it` (the kernel's own SYN carries twenty octets of them) |
| `MUST-6` | "A TCP implementation MUST (MUST-6) ignore without error any TCP Option it does not implement, assuming that the option has a length field" | ⚠ **met** — ⚠ **not one option is interpreted**; the walk finds where the data begins and reads nothing. ⚠ `tests/static.sh` `tcp_header` → `no_option_is_interpreted` |
| `MUST-68` | "All TCP Options except End of Option List Option (EOL) and No-Operation (NOP) MUST have length fields, including all future options" | ⚠ **met as a sender** since hidetzu/tcpip-stack#123 — ⚠ **the one option sent carries its length**, and the length is written from the document's own constant rather than from the size of what was written. ⚠ As a receiver it is the assumption `MUST-6` rests on, and the walk relies on it |
| `MUST-7` | "TCP implementations MUST be prepared to handle an illegal option length (e.g., zero); a suggested procedure is to reset the connection and log the error cause" | ⚠ **met** — the segment is refused as malformed and counted, ⚠ **and the walk terminates**: `tests/static.sh` `tcp_header` → `an_option_list_that_does_not_walk_is_malformed`, ⚠ **whose finishing at all is the proof.** ⚠ **No reset is sent, and the procedure is "suggested" rather than required** — `docs/SPEC.md` §2 names the gap |
| `MUST-64` | "receivers MUST be prepared to process options even if they do not begin on a word boundary" | ⚠ **met** — the walk is byte-wise and no alignment is assumed. ⚠ **No case feeds an unaligned option on purpose**, and ⚠ **that is a gap in the checks rather than in the code**: `end_of_option_list_stops_the_walk` and `no_option_is_interpreted` happen to exercise it, ⚠ **which is not the same as asserting it** |
| `MUST-14` | "TCP endpoints MUST implement both sending and receiving the MSS Option" | ⚠ **not met, ⚠ and it moved a long way** (hidetzu/tcpip-stack#123). ⚠ **What is proven**: the option is **sent** on the `SYN,ACK` with a value derived from the device's MTU, and one that **arrives is read** — ⚠ **measured against the Linux kernel on the wire**, `tests/interop.sh` `the_mss_option_goes_both_ways_with_the_kernel`: our `SYN,ACK` carried 1360 at MTU 1400 and the kernel's `SYN` carried 1360. ⚠ **What is NOT proven, and is why this is still not met**: ⚠ **`send_mss` reaches no consumer.** ⚠ Nothing here originates data, so ⚠ **there is no segment whose size the received value constrains** — ⚠ **`MUST-16`'s effective send MSS is the consumer, and it does not exist.** ⚠ **hidetzu/tcpip-stack#123 Owner Decision, verbatim**: "受信値が実際の SendMSS / effective send MSS に使われ、送信 segment の大きさを制約する consumer まで接続された時点で再判定してください。#96 と同じ基準を維持します。" ⚠ `tests/static.sh` `handshake` → `the_segment_size_we_are_told_is_kept_and_used_by_nothing` asserts both halves, ⚠ **including that nothing uses it** |
| `SHLD-5` (IPv4) | "TCP implementations SHOULD send an MSS Option in every SYN segment when its receive MSS differs from the default 536 for IPv4" | ⚠ **met** since hidetzu/tcpip-stack#123 — ⚠ **the option rides every `SYN,ACK` this stack builds**, and ⚠ **the receive MSS differs from 536 for every MTU but 576**, which no check brings a device up at. ⚠ `tests/static.sh` `handshake` → `the_answer_is_the_one_the_document_describes` |
| `SHLD-5` (IPv6) | "Send MSS Option unless 1220" | ⚠ **does not arise** — ⚠ **nothing here reads or writes IPv6** |
| `MAY-3` | "and MAY send it always" | ⚠ **not taken** — ⚠ **and it is nearly indistinguishable from taken here.** ⚠ The option rides every `SYN,ACK`, ⚠ **but the only `SYN` this stack ever builds is a `SYN,ACK`**, so ⚠ **"always" and "when it differs from 536" have not been told apart by anything.** ⚠ Said as not taken because ⚠ **no line was written to send it regardless of the value** |
| `MUST-15` (IPv4) | "If an MSS Option is not received at connection setup, TCP implementations MUST assume a default send MSS of 536 (576 - 40) for IPv4" | ⚠ **met in the assuming and not in the using** (hidetzu/tcpip-stack#123). ⚠ **A `SYN` with no MSS Option leaves `send_mss` at 536 and `send_mss_was_told_to_us` false** — ⚠ **absent and "they said 536" are kept apart**, which is the distinction this requirement rests on. ⚠ **But no segment this stack sends carries data**, so ⚠ **the assumed value constrains nothing** — ⚠ **the same gap `MUST-14` has, and it closes with the same consumer.** ⚠ `the_segment_size_we_are_told_is_kept_and_used_by_nothing` |
| `MUST-15` (IPv6) | "or 1220 (1280 - 60) for IPv6" | ⚠ **does not arise** — no IPv6 |
| `MUST-16` | "The maximum size of a segment that a TCP endpoint really sends, the 'effective send MSS', MUST be the smaller (MUST-16) of the send MSS ... and the largest transmission size permitted by ..." | ⚠ **does not arise** — ⚠ **nothing here sends data, so there is no segment whose size to bound.** ⚠ **It is the consumer `MUST-14` and `MUST-15` are waiting on**: ⚠ **both halves of the input exist now** — the send MSS in the TCB (hidetzu/tcpip-stack#123) and the device's MTU (hidetzu/tcpip-stack#115) — ⚠ **and nothing takes the smaller of them because nothing needs one.** ⚠ **Recorded as the structural gap rather than as three separate ones.** ⚠ **What it will be judged by, set by the owner 2026-08-29 and written down before any of it is built**, verbatim: ⚠ **「5 bytes を送れることではなく、MSS より大きいデータを渡したとき、effective send MSS を超えない複数 segment として相手へ届くこと」** — ⚠ **so a check that sends one small segment proves nothing here.** ⚠ It is the same shape as the ping and the handshake: ⚠ **a stack that sent five octets would pass a check that only ever handed it five** |
| `SHLD-6` | "MSS accounts for varying MTU" | ⚠ **does not arise** — ⚠ same, and ⚠ **nothing reads the MTU either** (`docs/SPEC.md` §2) |
| `MUST-65` | "MSS not sent on non-SYN segments" | ⚠ **met, ⚠ and no longer vacuously** (hidetzu/tcpip-stack#123). ⚠ **It was met by never sending the option at all**; ⚠ **it is met by a decision now**: the option rides the `SYN,ACK` and nothing else. ⚠ `the_segment_size_we_are_told_is_kept_and_used_by_nothing` asserts an acknowledgment for data carries none — ⚠ **and that assertion first walked past a mutation that put the option on every segment**, because it sat inside a test for a reply that was never built; ⚠ **it demands one now** |
| `MUST-67` | "MSS value based on MMS_R" | ⚠ **met** since hidetzu/tcpip-stack#123 — ⚠ **the value is the device's MTU less an internet header and a TCP header**, which is what can be received whole; ⚠ **this stack refuses a fragment outright** (ADR 0010), so nothing larger arrives. ⚠ **Derived, never chosen** — hidetzu/tcpip-stack#123 Owner Decision refused an owner constant, ⚠ **and the MTU is measurable since hidetzu/tcpip-stack#115** |
| `MUST-69` | "The content of the header beyond the End of Option List Option MUST be header padding of zeros" | ⚠ **met, ⚠ and still vacuously, for a different reason** (hidetzu/tcpip-stack#123). ⚠ **No End of Option List is ever sent**: the MSS Option is four octets — exactly one 32-bit word — ⚠ **so a header carrying only it needs no padding and no terminator.** ⚠ **The day a second option is sent this stops being vacuous** |

## Retransmissions (hidetzu/tcpip-stack#96)

| ID | Requirement, quoted | Verdict |
|---|---|---|
| `MUST-19` | "A TCP endpoint MUST implement the basic congestion control algorithms slow start, congestion avoidance, and exponential backoff of RTO to avoid creating congestion collapse conditions" | ⚠ **not met** — ⚠ **none of the three exists.** ⚠ The retransmission interval is a constant second (ADR 0019) |
| `MUST-18` | "The RTO MUST be computed according to the algorithm in [RFC 6298], including Karn's algorithm for taking RTT samples" | ⚠ **not met** — ⚠ **nothing here measures a round trip**, which `docs/SPEC.md` §2 has named since hidetzu/tcpip-stack#57. ⚠ **It has a label now** |
| `MAY-4` | "Retransmit with same IP identity" | ⚠ **taken, and by accident** — ⚠ `Identification` is always 0 (ADR 0012), so ⚠ **every retransmission does carry the same one.** ⚠ Said as accidental rather than claimed as a choice |

## Connection Failures (hidetzu/tcpip-stack#96)

| ID | Requirement, quoted | Verdict |
|---|---|---|
| `MUST-20` (R1) | §3.8.3 (b): "When the number of transmissions of the same segment reaches or exceeds threshold R1, pass negative advice (see Section 3.3.1.4 of [19]) to the IP layer, to trigger dead-gateway diagnosis" | ⚠ **not met** — ⚠ **there is no R1 and nothing is said to IP.** ⚠ There is one give-up moment and no threshold before it |
| `MUST-20` (R2) | §3.8.3 (c): "When the number of transmissions of the same segment reaches a threshold R2 greater than R1, close the connection" | ⚠ **not met**, ⚠ **and the reason this row first gave was wrong.** ⚠ **It said the give-up being a TIME rather than a COUNT was the gap.** ⚠ **§3.8.3 (a), two paragraphs above the sentence quoted, says the opposite**: "R1 and R2 **might be measured in time units or as a count of retransmissions** (with the current RTO and corresponding backoffs as a conversion factor, if needed)" — ⚠ **so a time is a shape the document offers, and this stack has one.** ⚠ **What is actually missing is (c)'s own words: "a threshold R2 **greater than R1**", and there is no R1.** ⚠ **The verdict does not change; the reason does** (`CLAUDE.md` §9) |
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
| `MUST-63` | "An incoming SYN with an invalid source address MUST be ignored either by TCP or by the IP layer ... (see Section 3.2.1.3)" | ⚠ **met in part** since hidetzu/tcpip-stack#112, ⚠ **and the part is named rather than the whole claimed.** ⚠ **Was not met at all**: measured 2026-08-29, a `SYN` sourced from `255.255.255.255` ⚠ **opened a connection and was answered.** ⚠ **Met**, each quoted from the section RFC 9293 sends the reader to — RFC 1122 §3.2.1.3: `0.0.0.0/8` (a)(b) "MUST NOT be sent, except as a source address as part of an initialization procedure", `127.0.0.0/8` (g) "MUST NOT appear outside a host", `255.255.255.255` (c) "MUST NOT be used as a source address". ⚠ **And `224.0.0.0/4`, whose grounds are OUTSIDE §3.2.1.3** — the multicast address model, ⚠ **recorded as reaching past the citation rather than quoted to it** (ADR 0025). ⚠ **Not met**: a directed broadcast, §3.2.1.3 (d)(e)(f), ⚠ **which cannot be told from a host address without a netmask.** ⚠ `tests/static.sh` `handshake` → `a_syn_from_an_impossible_source_is_refused` asserts every form above, ⚠ **the six boundary addresses one octet outside each range**, and ⚠ **that a directed broadcast source IS still answered.** ⚠ `tests/interop.sh` `a_syn_from_an_impossible_source_is_not_answered` on the wire |
| `MUST-57` | "Silently discard SYN to bcast/mcast addr" | ⚠ **met in part** — judged at hidetzu/tcpip-stack#99; a directed broadcast is not recognised |

## ⚠ Where there is no application (hidetzu/tcpip-stack#97)

⚠ **Written once, and referred to rather than repeated.**

⚠ **ADR 0022: there is no user of this stack.** ⚠ Nothing calls `OPEN`, `SEND`, `RECEIVE`, `CLOSE`
or `ABORT`; the program attaches to a device, answers what arrives, and reports. ⚠ **So every
requirement phrased as "the application MUST be able to ..." or "MUST inform the application layer"
is about an interface that does not exist.**

⚠ **A bare `MUST` of that shape is `not met`, never `does not arise`** — ⚠ **the legend above says
so, and the reason is that "not applicable" is a claim.** ⚠ **A TCP no application can use has not
met a requirement about serving applications; it has avoided the subject.**

⚠ **A `SHOULD` or a `MAY` of that shape is `does not arise` or `not taken`**, with the condition
quoted. ⚠ **The difference is the keyword's, not ours.**

---

## PUSH flag (hidetzu/tcpip-stack#97)

| ID | Requirement, quoted | Verdict |
|---|---|---|
| `MAY-15` | "A TCP endpoint MAY implement PUSH flags on SEND calls" | ⚠ **not taken** — ⚠ **there are no `SEND` calls** (ADR 0022) |
| `MUST-60` | "**If PUSH flags are not implemented**, then the sending TCP peer: (1) MUST NOT buffer data indefinitely" | ⚠ **met, and vacuously — ⚠ which is not a virtue.** ⚠ **The condition IS true**: `MAY-15` is not taken, so this arises. ⚠ **There is no send queue at all** — this stack originates no data, so nothing can be buffered indefinitely. ⚠ **It must be re-judged the moment anything is queued to send**, and nothing would notice |
| `MUST-61` | "and (2) MUST set the PSH bit in the last buffered segment (i.e., when there is no more queued data to be sent)" | ⚠ **met, and vacuously** — same condition, same reason. ⚠ **`PSH` is never set on anything this stack builds, and there has never been queued data for it to be the last of** |
| `MAY-16` | "the TCP implementation MAY aggregate the data internally without sending it" | ⚠ **not taken** — ⚠ no `SEND` calls to aggregate |
| `MAY-17` | "A TCP receiver MAY pass a received PSH bit to the application layer via the PUSH flag in the interface ..., but it is not required" | ⚠ **not taken, and it could not be** — ⚠ **there is no application layer to pass it to.** ⚠ The bit is read as part of the control bits and nothing acts on it |
| `SHLD-27` | "The transmitter SHOULD collapse successive bits when it packetizes data, to send the largest possible segment" | ⚠ **does not arise** — ⚠ **nothing here packetizes data.** ⚠ Every segment this stack builds is a fixed header with no payload (ADR 0017) |
| `SHLD-28` | "a TCP implementation SHOULD send a maximum-sized segment whenever possible" | ⚠ **does not arise** — same condition: ⚠ **there are no data segments to size** |

## Urgent Data (hidetzu/tcpip-stack#97)

⚠ **This is the section hidetzu/tcpip-stack#97 named in advance as the one that would be got wrong.**
⚠ **Calling any of it "does not arise" would make a mandated feature's absence look like an
inapplicable clause.**

| ID | Requirement, quoted | Verdict |
|---|---|---|
| `MUST-30` | "TCP implementations MUST still include support for the urgent mechanism" | ⚠ **not met** — ⚠ **there is no support of any kind.** ⚠ The `URG` bit and the `Urgent Pointer` are read (`MUST-66`, hidetzu/tcpip-stack#101) and ⚠ **a segment carrying `URG` is counted and reported as `urgent and nobody to tell`** — ⚠ **reading a field is not supporting a mechanism.** ⚠ **The sentence before it, `SHLD-13`, says new applications should not use it; the document still requires the support** |
| `MUST-62` | "The urgent pointer MUST point to the sequence number of the octet following the urgent data" | ⚠ **not met, as part of `MUST-30`** — ⚠ **nothing this stack builds ever sets `URG`**, so the field is always zero and never points at anything. ⚠ **Recorded as not met rather than vacuous**: ⚠ it is one clause of a mechanism the document requires, and ⚠ **splitting it off as inapplicable would hide the whole** |
| `MUST-31` | "A TCP implementation MUST support a sequence of urgent data of any length" | ⚠ **not met, as part of `MUST-30`** — ⚠ no length is supported, including zero |
| `MUST-32` | "A TCP implementation MUST (MUST-32) inform the application layer asynchronously whenever it receives an urgent pointer and there was previously no pending urgent data, or whenever the urgent pointer advances" | ⚠ **not met** — ⚠ **there is no application layer** (see the section above). ⚠ **The human watching is told, and that is not the same thing**: a line on a terminal is not an asynchronous report to a program |
| `MUST-33` | "The TCP implementation MUST (MUST-33) provide a way for the application to learn how much urgent data remains to be read" | ⚠ **not met** — ⚠ no application, and ⚠ **no urgent data is ever held to be counted** |
| `SHLD-13` | "New applications SHOULD NOT set the URGENT flag ... due to implementation differences and middlebox issues" | ⚠ **does not arise** — ⚠ **this binds an application, and there is none** (ADR 0022). ⚠ **It is quoted here because it is the sentence `MUST-30` answers**: ⚠ the document tells applications not to use the mechanism and still requires implementations to carry it |

## Send Keep-alive Packets (hidetzu/tcpip-stack#97)

⚠ **The clean case this issue exists to separate.** ⚠ **Every row below is conditional in the
document's own words on a feature that is optional and not taken** — ⚠ **so these really are
`does not arise`, and saying so costs nothing.**

| ID | Requirement, quoted | Verdict |
|---|---|---|
| `MAY-5` | "Implementers MAY include 'keep-alives' in their TCP implementations ..., although this practice is not universally accepted" | ⚠ **not taken** — ⚠ **nothing here sends a probe on an idle connection.** ⚠ **This is the condition every row below hangs on** |
| `MUST-24` | "**If keep-alives are included**, the application MUST be able to turn them on or off for each TCP connection" | ⚠ **does not arise** — ⚠ **the condition is quoted and it is false.** ⚠ **Two reasons, either alone sufficient**: keep-alives are not included, and there is no application |
| `MUST-25` | "and they MUST default to off" | ⚠ **does not arise** — same sentence, same condition |
| `MUST-26` | "Keep-alive packets MUST only be sent when no sent data is outstanding, and no data or acknowledgment packets have been received for the connection within an interval" | ⚠ **does not arise** — ⚠ **there are no keep-alive packets to constrain** (`MAY-5`) |
| `MUST-27` | "This interval MUST be configurable" | ⚠ **does not arise** — ⚠ **there is no interval** (`MUST-26`) |
| `MUST-28` | "and MUST default to no less than two hours" | ⚠ **does not arise** — same |
| `MUST-29` | "**if a keep-alive mechanism is implemented** it MUST NOT interpret failure to respond to any specific probe as a dead connection" | ⚠ **does not arise** — ⚠ **the condition is quoted and it is false.** ⚠ **The reasoning behind it does apply here and is honoured elsewhere**: this stack never reports a peer as dead on the strength of one absent answer (`CLAUDE.md` §1) |
| `SHLD-12` | "An implementation SHOULD send a keep-alive segment with no data" | ⚠ **does not arise** — ⚠ no keep-alive segment is sent at all |
| `MAY-6` | "however, it MAY be configurable to send a keep-alive segment containing one garbage octet, for compatibility with erroneous TCP implementations" | ⚠ **not taken** — ⚠ conditional on `SHLD-12`, which does not arise |

## IP Options (hidetzu/tcpip-stack#97)

⚠ **A datagram whose `IHL` is greater than 5 — which is what carrying options means — is refused
one layer below TCP**, as `IPV4_PARSE_NOT_HANDLED`: ⚠ **well-formed but unsupported, counted on its
own, and never silently dropped** (`.claude/rules/layers.md`, ADR 0010).

⚠ **So "does not arise" here means "a refusal of ours keeps the condition false", which is a
different thing from a condition that cannot occur** — ⚠ **and `docs/SPEC.md` §2 names the refusal.**

| ID | Requirement, quoted | Verdict |
|---|---|---|
| `MUST-50` | "**When received options are passed up to TCP from the IP layer**, a TCP implementation MUST ignore options that it does not understand" | ⚠ **does not arise** — ⚠ **no option is ever passed up**: the datagram carrying one is refused at the internet layer before TCP is reached. ⚠ **The condition is quoted, and the reason it is false is ours** |
| `MAY-10` | "A TCP implementation MAY support the Timestamp (MAY-10) and Record Route (MAY-11) Options" | ⚠ **not taken** — ⚠ **the IP Timestamp Option**, not the TCP one (`MAY-3`, judged at hidetzu/tcpip-stack#96) — ⚠ **two different options with similar names, and this row names which** |
| `MAY-11` | "and Record Route (MAY-11) Options" | ⚠ **not taken** — same sentence |
| `MUST-51` | "An application MUST be able to specify a source route **when it actively opens a TCP connection**" | ⚠ **does not arise** — ⚠ **nothing here performs an active `OPEN`**, which is the same ground `MUST-46` was judged on at hidetzu/tcpip-stack#94 |
| `MUST-52` | "and this MUST take precedence over a source route received in a datagram" | ⚠ **does not arise** — ⚠ conditional on `MUST-51`'s source route, which cannot be specified |
| `MUST-53` | "**When a TCP connection is OPENed passively and a packet arrives with a completed IP Source Route Option** (containing a return route), TCP implementations MUST save the return route and use it for all segments sent on this connection" | ⚠ **does not arise, ⚠ and this is the one to read carefully.** ⚠ **The first half of the condition IS true** — every connection here is opened passively. ⚠ **The second half is kept false by us**: a datagram carrying the option is refused at the internet layer. ⚠ **So this is not a requirement that cannot apply; it is one we have arranged not to reach**, and ⚠ **it becomes live the day `IHL > 5` is accepted** |
| `SHLD-24` | "If a different source route arrives in a later segment, the later definition SHOULD override the earlier one" | ⚠ **does not arise** — ⚠ conditional on `MUST-53`'s saved route |

## Receiving ICMP Messages from IP (hidetzu/tcpip-stack#97)

| ID | Requirement, quoted | Verdict |
|---|---|---|
| `MUST-54` | "TCP implementations MUST act on an ICMP error message passed up from the IP layer, directing it to the connection that created the error. The necessary demultiplexing information can be found in the IP header contained within the ICMP message" | ⚠ **not met** — ⚠ **there is no path from ICMP to a connection.** ⚠ **This stack does read ICMP** — it answers an echo request — ⚠ **and an ICMP error is refused as `ICMP_TYPE_NOT_HANDLED`, counted, and never handed to TCP.** ⚠ **A bare `MUST` about a capability every TCP is expected to have: not met, not inapplicable** |
| `MUST-55` | "TCP implementations MUST silently discard any received ICMP Source Quench messages" | ⚠ **met, ⚠ and by accident** — ⚠ **nothing acts on it because nothing acts on any ICMP error** (`MUST-54`). ⚠ **"Silently" forbids a reply on the wire and not a line telling the human**, the same reading `MUST-57` took at hidetzu/tcpip-stack#99, ⚠ **and no reply is built for it.** ⚠ **Said as accidental rather than claimed as a choice**: ⚠ it would still be met if the whole ICMP layer were deleted, which is not what the requirement is for |
| `MUST-56` | "Since these Unreachable messages indicate soft error conditions, a TCP implementation MUST NOT abort the connection" | ⚠ **met, ⚠ and vacuously** — ⚠ **no connection is ever aborted on an ICMP message, because none reaches a connection** (`MUST-54`). ⚠ **A `MUST NOT` satisfied by never being in a position to do the thing.** ⚠ **It must be re-judged the day `MUST-54` is met** |
| `SHLD-25` | "and it SHOULD make the information available to the application" | ⚠ **does not arise** — ⚠ **there is no application** (see the section above), ⚠ **and no information is held to make available** |
| `SHLD-26` | "These are hard error conditions, so TCP implementations SHOULD abort the connection" | ⚠ **not met** — ⚠ **and this one is NOT vacuous.** ⚠ **ICMP hard errors do arrive at this machine**; they are refused at the ICMP layer and never reach the connection they name. ⚠ **The condition can occur and we have arranged not to see it** — ⚠ **which is different from `MUST-56`, where not acting is what the document asks for** |

## TCP/ALP Interface Services (hidetzu/tcpip-stack#97)

⚠ **Judged against there being no user of this stack** (ADR 0022). ⚠ **The reasoning is in the
section above and is not repeated per row.**

| ID | Requirement, quoted | Verdict |
|---|---|---|
| `MUST-43` | "The optional 'local IP address' parameter MUST be supported to allow the specification of the local IP address. This enables applications that need to select the local IP address used when multihoming is present" | ⚠ **not met** — ⚠ **and the capability exists in another shape, which is exactly why this is not called met.** ⚠ `--ipv4` chooses the address this stack answers for. ⚠ **But `MUST-43` is about a parameter of the `OPEN` call, and there is no `OPEN` call** — ⚠ **the same reading `MUST-20`'s R2 got at hidetzu/tcpip-stack#96: an effect in a different shape is not the requirement met** |
| `MUST-47` | "There MUST be a mechanism for reporting soft TCP error conditions to the application" | ⚠ **not met** — ⚠ **there is no application and no `ERROR_REPORT` routine.** ⚠ **A line on a terminal is not this**: the document's mechanism is upcalled into a program |
| `MUST-48` | "The application layer MUST be able to specify the Differentiated Services field for segments that are sent on a connection" | ⚠ **not met** — ⚠ **no application, and the field is written as 0 by the builder and is not a caller's to set** (ADR 0012). ⚠ **`--ttl` was given a caller at hidetzu/tcpip-stack#103 and this field was not** |
| `SHLD-20` | "an application program that does not want to receive such ERROR_REPORT calls SHOULD be able to effectively disable these calls" | ⚠ **does not arise** — ⚠ conditional on `MUST-47`'s mechanism, which does not exist |
| `SHLD-21` | "the application SHOULD be able to change the Differentiated Services field during the connection lifetime" | ⚠ **does not arise** — ⚠ conditional on `MUST-48` |
| `SHLD-22` | "TCP implementations SHOULD pass the current Differentiated Services field value without change to the IP layer, when it sends segments on the connection" | ⚠ **does not arise** — ⚠ **there is no value to pass**: nothing sets one, and the builder writes 0 unconditionally |
| `SHLD-23` | "Generally, an application SHOULD NOT change the Diffserv field value during the course of a connection" | ⚠ **does not arise** — ⚠ **this binds an application, and there is none** |
| `MAY-9` | "TCP implementations MAY pass the most recently received Differentiated Services field up to the application" | ⚠ **not taken** — ⚠ **the field is not read on the way in either.** ⚠ `Type of Service` is parsed into the header struct and nothing consumes it |
| `MAY-14` | "The FLUSH call MAY be implemented" | ⚠ **not taken** — ⚠ **there is no send queue to flush** and no call to make |

## RFC 5961 Support (hidetzu/tcpip-stack#97)

| ID | Requirement, quoted | Verdict |
|---|---|---|
| `MAY-12` | "RFC 5961 [9], Section 5 describes a potential blind data injection attack, and mitigation that implementations MAY choose to include" | ⚠ **not taken** — ⚠ **and worth saying plainly, because this stack takes segments from strangers**: the acceptance test for an `ACK` is the window check RFC 9293 §3.10.7.4 gives and ⚠ **not RFC 5961's narrower one.** ⚠ **A `MAY` refused is a decision only if the decision was taken** — ⚠ **this one was not; it is being recorded now** (`docs/SPEC.md` §2) |

## Explicit Congestion Notification (hidetzu/tcpip-stack#97)

| ID | Requirement, quoted | Verdict |
|---|---|---|
| `SHLD-8` | "A TCP endpoint SHOULD implement ECN as described in RFC 3168" | ⚠ **not met** — ⚠ **nothing here negotiates ECN or sets `ECE` or `CWR` on anything it builds.** ⚠ **What was done instead is narrower and it was measured** (hidetzu/tcpip-stack#86): the `ECE`/`CWR` bits are given names and a `SYN` carrying them ⚠ **is no longer thrown away.** ⚠ **Measured 2026-08-29 before that change: the ECN-capable first `SYN` was refused, and the connection only opened because the Linux kernel retried without the bits** — ⚠ **so this stack looked as if it worked, on somebody else's fallback.** ⚠ `tests/interop.sh` `a_syn_carrying_the_ecn_bits_is_the_one_that_opens_it` holds that. ⚠ **Accepting a bit is not implementing the mechanism** |

## Alternative Congestion Control (hidetzu/tcpip-stack#97)

| ID | Requirement, quoted | Verdict |
|---|---|---|
| `MAY-18` | "An endpoint MAY implement such alternative algorithms provided that the algorithms are conformant with the TCP specifications from the IETF Standards Track as described in RFC 2914, RFC 5033 [7], and RFC 8961 [15]" | ⚠ **not taken** — ⚠ **conditional on there being a congestion control algorithm to substitute for, and `MUST-19` records that there is none.** ⚠ **Not taken rather than does not arise**: ⚠ the `MAY` offers alternatives to the basic algorithms, and ⚠ **not having the basic ones is `MUST-19`'s row, not this one's** |
