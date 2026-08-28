# ADR 0022 — A FIN is read, and the user RFC 793 waits for does not exist

Date: 2026-08-29
Status: accepted
Issue: hidetzu/tcpip-stack#65

## Context

⚠ **hidetzu/tcpip-stack#64 opened the window, and the `FIN` started arriving** — measured, and
recorded in ADR 0021. ⚠ Until this issue every one of them was counted as a segment the
connection's state did not expect: ⚠ **6 of 6 in one `close()`, measured 2026-08-29 on `main`**,
with the `FIN` and the bare acknowledgments in the same number.

⚠ **RFC 793 had not been read on closing.** ⚠ It has been now — the whole document, from
`https://www.rfc-editor.org/rfc/rfc793.txt`, ⚠ **not through a summary** (the standing ADR 0016
set).

## ⚠ What the reading settled, so that nothing here is recalled

### ⚠ `TIME-WAIT` is not ours

⚠ **Figure 6 and Figure 13 both put `TIME-WAIT` on the side that closed first.** The passive side —
ours — runs:

```text
ESTABLISHED  --rcv FIN / snd ACK-->  CLOSE-WAIT  --CLOSE / snd FIN-->  LAST-ACK  --rcv ACK-->  CLOSED
```

⚠ **So no timer outlives a connection here**, and ⚠ **hidetzu/tcpip-stack#65's second Human
Decision never arose.** ⚠ hidetzu/tcpip-stack#57's schedule is untouched.

### ⚠ A FIN occupies exactly one sequence number, after the data

⚠ The glossary: "A control bit (finis) occupying one sequence number, which indicates that the
sender will send no more data or control occupying sequence space."

⚠ §3.3: "the FIN is considered to occur after the last actual data octet in a segment in which it
occurs."

⚠ §3.9, eighth step: "advance RCV.NXT over the FIN."

⚠ **So the FIN is read after the data, never before**, and `RCV.NXT` ends one past where the FIN
sits. ⚠ **Off by one here is the error that still looks like it works**, which is why
`a_fin_sits_after_the_data_it_rides_with` asserts the number against the FIN's own sequence number
and not against whatever `RCV.NXT` happens to be.

### ⚠ A FIN with no acknowledgment is dropped before the FIN is ever looked at

⚠ §3.9, fifth step: "if the ACK bit is off drop the segment and return." ⚠ **That is the document's
rule and not ours**, and it is why a bare `FIN` closes nothing here.

### ⚠ A FIN we hold nothing for has its own reason

⚠ §3.9, eighth step: "Do not process the FIN if the state is CLOSED, LISTEN or SYN-SENT since the
SEG.SEQ cannot be validated; drop the segment and return." ⚠ **Holding nothing is our LISTEN**, and
⚠ the document giving it its own sentence is why it is counted apart rather than folded in with
every other stray segment.

### ⚠ One segment can open a connection and close it

⚠ §3.9, fifth step for SYN-RECEIVED: "If SND.UNA =< SEG.ACK =< SND.NXT then enter ESTABLISHED state
and continue processing." ⚠ **The FIN check is one of the steps that continue.**

⚠ **Never observed here** — the Linux kernel sends its acknowledgment and its `FIN` apart, every
run. ⚠ It is implemented because the document says it, and ⚠ **it is named as unobserved rather
than presented as measured.**

## Decision

### ⚠ Owner Decision 1 — the arrival of a FIN is treated as the CLOSE this stack has no user to make

⚠ **RFC 793 defines `CLOSE-WAIT` as "waiting for a connection termination request from the local
user."** ⚠ **There is no local user here**, and §3.5 leans on one throughout: "Note that a TCP
receiving a FIN will ACK but not send its own FIN until its user has CLOSED the connection also."

⚠ **So the document's `CLOSE-WAIT` cannot be followed as written** — waiting for a user that does
not exist is waiting for ever.

⚠ **The owner's decision, taken on 2026-08-29**: the arrival of a `FIN` is treated as the `CLOSE`
that user would have made. ⚠ **The connection enters `CLOSE-WAIT` and this stack intends to close**;
hidetzu/tcpip-stack#66 is what sends the `FIN` and reaches `LAST-ACK`.

⚠ **This is our decision and not the document's**, and it is recorded as such. ⚠ **The alternative
was to stay in `CLOSE-WAIT` for ever**, which is the document's literal behaviour with no user and
⚠ which would have stopped the milestone here.

### ⚠ What this issue does not do

⚠ **Nothing is sent.** ⚠ The eighth step also says "send an acknowledgment for the FIN", and
⚠ **that is hidetzu/tcpip-stack#66's.** ⚠ `docs/SPEC.md` §2 names the gap rather than leaving it
silent.

⚠ **Nothing signals a user and nothing returns a pending RECEIVE** — the other two things that step
asks for. ⚠ There is neither.

## ⚠ A contradiction inside the document, recorded rather than resolved

⚠ **The CLOSE Call section says of `CLOSE-WAIT`: "Queue this request until all preceding SENDs have
been segmentized; then send a FIN segment, enter CLOSING state."**

⚠ **Figure 6 and Figure 13 both say `LAST-ACK`**, and `LAST-ACK`'s own definition — "waiting for an
acknowledgment of the connection termination request previously sent to the remote TCP" — is what
that transition describes.

⚠ **This is not settled here**, because ⚠ **nothing in this issue enters either state.**
⚠ hidetzu/tcpip-stack#66 is where it has to be decided, and ⚠ **it is written down now so that
whoever gets there does not silently pick one.**

## Consequences

- ⚠ **`CONNECTION_CLOSE_WAIT` exists and `LAST-ACK` does not.** ⚠ A state with no transition into it
  would be a claim that we implement it (the standing rule in `src/connection.h`).
- ⚠ **The retransmission schedule does not cover a connection past `ESTABLISHED`**, and
  `a_connection_that_has_seen_a_fin_is_due_nothing` asserts it — ⚠ answering a `SYN-ACK` again at
  something that has said goodbye would be the defect.
- ⚠ **Every retransmitted `FIN` is counted apart from the one that closed the connection.**
  ⚠ Measured 2026-08-29: 1 read and 5 retransmissions in one `close()`, ⚠ **because nothing
  acknowledges it** — which is exactly the gap #66 closes.
- ⚠ **A connection in `CLOSE-WAIT` is never released**, so ⚠ **the one block stays taken.** ⚠ That
  is not new — nothing frees a block on its own (ADR 0015) — but ⚠ **it now applies to a connection
  the other side has finished with**, and `docs/SPEC.md` §2 says so.
