# 0015 — Connection state lives in one block, and nothing frees it on its own

Date: 2026-08-28
Status: accepted
Issue: hidetzu/tcpip-stack#42

## Context

⚠ **This is the first thing in this repository that lives between frames.**

Everything before it is a pure function of one frame: `arp_respond` and
`echo_respond` are handed octets and the addresses we answer with, and they are
done. ⚠ **`docs/SPEC.md` §2 records "no ARP cache" as a decision rather than an
omission.** ⚠ Nothing has ever needed to remember.

⚠ **Measured on `main`, 2026-08-28, before starting.** Two things turn up in a
grep for a clock or for state, and ⚠ **neither is either**:

| What turns up | ⚠ What it actually is |
|---|---|
| `struct timespec` in `src/tap.c` | ⚠ **Not a clock.** It converts a caller's millisecond limit into `ppoll`'s. ⚠ **There is no way to read the time from protocol code.** |
| `static volatile sig_atomic_t stop_requested` in `src/tcpip_stack.c` | ⚠ A signal flag. ⚠ **Not connection state.** |

⚠ **`.claude/rules/layers.md` named the TCB in the State layer from the start.**
⚠ **`CLAUDE.md` §3 says the concrete layer split belongs in an ADR before it
belongs in code**, which is why this decision came before the transitions.

### The rule this is written against

> ⚠ **Never abstract because a second case might appear someday.**
> ⚠ **Generalise once the second case actually exists.** — `.claude/rules/layers.md`

⚠ **So this is not a connection-table framework.** ⚠ A hash, an allocator, or
room for a thousand would each be inventing a second case.

### The names

RFC 793, read verbatim on 2026-08-28 from `rfc-editor.org` and cross-checked
against `datatracker.ietf.org`. ⚠ **The two agreed:**

```
To store this information we imagine that there is a data structure called a
Transmission Control Block (TCB).

To provide for unique addresses within each TCP, we concatenate an internet
address identifying the TCP with a port identifier to create a socket which
will be unique throughout all networks connected together.

A connection is fully specified by the pair of sockets at the ends.

A local socket may participate in many connections to different foreign sockets.
```

⚠ **`struct transmission_control_block`, `struct socket`, `struct connection_id`
carry those names.** ⚠ A connection is identified by the pair of sockets and
⚠ **never by where it sits in an array** (`.claude/skills/change-review/SKILL.md`
§4: matching by position or by arrival order is the defect).

## Decision

### ⚠ Owner Decision 1 — room for one connection

⚠ **`CONNECTIONS_AT_ONCE` is 1.**

⚠ **The grounds are a measurement, not a preference for small numbers.**
⚠ **There is no clock and no `FIN` handling in this milestone, so a block that
is taken stays taken.** ⚠ **N=1 and N=8 reach the same wall by the same path** —
⚠ a larger number only postpones it while looking like a table.

⚠ Measured, same conditions, 2026-08-28: ⚠ **one `connect()` makes one
connection** — 3 runs, all three `distinct connections: 1, TCP frames: 7`, the
seven being the kernel's own retransmissions of one SYN from one source port.

⚠ **Comparing by identity does not go away with one slot** (AC 6), and ⚠ **the
full path is reachable in a check trivially**, which a larger number would have
made contrived.

⚠ **What the refused one is reported as** — approved wording, in the two-line
shape ARP and ICMP already print:

```
  no answer: we are already holding a connection, and this build has
    room for one. That is ours, not the sender's

1 connection was refused for want of room, which is ours and not the sender's
```

⚠ **It is ours and it says so** (`CLAUDE.md` §4-1). ⚠ **The sentence is not in
`src/report.c` yet, on purpose:** nothing calls this from the program until
hidetzu/tcpip-stack#44, and ⚠ **a line with no caller is a line no check
exercises.** ⚠ This ADR carries it until then.

### ⚠ Owner Decision 2 — no clock is a deliberate gap, for the handshake only

⚠ **`docs/SPEC.md` §2 records it as a decision, with the reason and with its
limit.**

⚠ **The peer's timer is what covers us.** Measured, same conditions: ⚠ **the
kernel retransmits an unanswered SYN 7 times** in one `connect()`, 3 runs of 3.
⚠ **So a SYN-ACK of ours that goes missing gets asked for again**, by the other
side, without a timer here.

⚠ **And this holds for the handshake and nowhere else.** ⚠ **The moment data or
closing is involved, what needs retransmitting is ours and the peer only
waits.** ⚠ **§2's row says that**, so the row cannot be read later as "a clock is
not needed".

### Ownership, and nothing allocated

⚠ **Nothing in `src/connection.c` allocates and nothing frees.** ⚠ A caller
supplies a `struct connections` and it lives exactly as long as that does
(`.claude/rules/c.md`: prefer a caller-supplied buffer with an explicit length;
`CLAUDE.md` §3: keep the data path free of allocation surprises).

⚠ **`connections_forget_everything` must be called first**, so that a block that
was never given a value is never read.

### Taking one we already hold is not a second one

⚠ **The kernel retransmits.** ⚠ A retransmitted SYN is the same connection, so
`connections_take` hands back the block that already holds it — ⚠ **and does not
count a refusal for it.**

## Consequences

- ⚠ **`src/connection.c` has no caller in the program**
  (hidetzu/tcpip-stack#44). The `Makefile` says so where the sources are listed.
- ⚠ **Two lines are not provable today, and that is said rather than glossed.**
  ⚠ The block is cleared when it is taken and again when it is released; ⚠
  **removing either breaks no check.** ⚠ The block holds `in_use` and an id, the
  id is overwritten on the next line, and `connections_find` looks at `in_use`
  first — ⚠ **there is nothing that could survive to be read.** ⚠ They are there
  for the state and the sequence numbers hidetzu/tcpip-stack#43 adds, and
  ⚠ **that is when they become provable.** ⚠ Both lines carry a comment saying
  exactly this (`CLAUDE.md` §1: never call something verified when it was not
  checked).
- ⚠ **A refused connection hands back nothing**, so a caller cannot write into a
  block it was not given, and ⚠ **the refusal is counted** — an uncounted refusal
  is invisible, and an invisible refusal looks exactly like a segment that never
  arrived.
- ⚠ **`struct connection_counts` holds one number today.** ⚠ It exists so the
  refusal has somewhere to go now, the same shape `struct arp_counts` and
  `struct echo_counts` have.
