# 0035 — An ICMP error is matched to the connection that caused it

Date: 2026-08-29
Status: accepted
Issue: hidetzu/tcpip-stack#138

## Context

⚠ RFC 9293 §3.9.2.2: "TCP implementations **MUST** act on an ICMP error message passed up from the
IP layer, directing it to the connection that created the error (`MUST-54`)."

⚠ **Before this, an ICMP error was refused at the ICMP layer as a Type this stack does not act on**,
counted, ⚠ **and never handed to TCP.**

⚠ **Two verdicts were met by accident because of that** (hidetzu/tcpip-stack#97): ⚠ `MUST-55`'s
silent discard of a Source Quench and ⚠ `MUST-56`'s not aborting on a soft error. ⚠ **Both would
still have been met if the whole ICMP layer were deleted**, ⚠ **which is not what either requirement
is for.**

## Decision

### ⚠ The classification is the Parse layer's; what to do about it is the State layer's

⚠ `icmp_class_of_error` is a pure function from a type and a code to one of four classes.
⚠ **`handshake_receive_error` is what acts.** ⚠ **Neither knows the other's job**
(`.claude/rules/layers.md`).

### ⚠ Silence is a fourth class, and it is named

⚠ §3.9.2.2 classifies Destination Unreachable codes 0, 1, 5 as soft and 2 to 4 as hard.
⚠ **Sixteen codes exist and six are named.** ⚠ **Silence in an RFC is not permission and it is not a
class** (`CLAUDE.md` §1).

⚠ So `ICMP_ERROR_NOT_CLASSIFIED` is its own answer: ⚠ **counted, said, and the connection left
alone** — ⚠ **the safe direction, said as a choice of ours and not as a reading.**

### ⚠ `SHLD-26` is taken, and the document names the doubt in the same breath

> These are hard error conditions, so TCP implementations **SHOULD** abort the connection
> (`SHLD-26`). [35] notes that **some implementations do not abort connections** when an ICMP hard
> error is received for a connection that is in any of the synchronized states.

⚠ **Taken anyway.** ⚠ **A `SHOULD` followed is a decision as much as one refused**, and the sentence
that qualifies it is quoted beside the code rather than left for a reader to find.

### ⚠ A quoted header cannot be read by the function that reads a whole datagram

⚠ **This was found by measuring, not by reading.** ⚠ The kernel sent a real ICMP error and
⚠ **nothing was counted at all.**

⚠ `ipv4_parse_header` refuses a datagram whose `Total Length` names more octets than arrived —
⚠ **exactly right for something off the wire.** ⚠ **RFC 792 carries back "the internet header plus
the first 64 bits" and nothing more**, so ⚠ **`Total Length` almost always exceeds what is present,
and that is the sender being correct.**

⚠ **So `ipv4_parse_quoted_header` exists.** ⚠ **Everything else is checked the same way**, including
the header checksum: ⚠ **this is untrusted input twice over** — it arrived from outside, and
⚠ **it claims to be something we sent.**

⚠ **`IPV4_PARSE_OK` from it means "the header is readable" and never "the datagram is whole"**, and
`docs/SPEC.md` §2 says so.

## Consequences

- ⚠ **`MUST-54` and `SHLD-26` are met.** ⚠ **`MUST-55` and `MUST-56` stopped being accidents** and a
  check asserts a soft error leaves the connection and a hard one does not — ⚠ **so the two cannot
  be confused.**
- ⚠ **`SHLD-25` still does not arise**: there is no application. ⚠ **The information exists now**,
  and ⚠ **a human reading a terminal is not the application it asks for.**
- ⚠ **Nothing is ever sent for an error.** ⚠ `MUST-55`'s "silently" forbids it for a source quench,
  ⚠ **and none of the others asks for a segment either** — the document asks for a connection to be
  left alone or ended.
- ⚠ **The diversion in `src/tcpip_stack.c` has the same shape the TCP one already had**: only a
  datagram for us carrying ICMP is looked at, ⚠ **and anything else still reaches `echo_respond` and
  is counted there**, so those numbers keep meaning what they meant.

### ⚠ A device-tier rule added after the connection opened never fired

⚠ **The same measurement hidetzu/tcpip-stack#132 made, in a second place**: with the reject rule
added 0.05 s after `connect()` returned, ⚠ **all 3000 octets had already left and nothing was ever
rejected.** ⚠ **It is in place before the connection now**, matching only a full-sized data segment
so the handshake still completes.
