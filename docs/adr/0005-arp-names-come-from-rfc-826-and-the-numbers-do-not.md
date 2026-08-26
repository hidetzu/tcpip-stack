# 0005 — ARP's names come from RFC 826, and the numbers do not

Decided 2026-08-26. Raised by hidetzu/tcpip-stack#16.
⚠ **This is also where ADR 0002's own question is answered**, because ARP is the second protocol it
said to wait for.

## The decision

### 1. An opcode we do not handle is its own outcome

Owner Decision 1 on hidetzu/tcpip-stack#16, in the owner's words:

> Unknown/unhandled operation は、malformed・well-formed-but-unsupported とは別の第 3 outcome として
> 保持する。

```text
ARP_PARSE_MALFORMED                    the octets do not hold what the packet says they hold
ARP_PARSE_ADDRESS_SPACES_NOT_HANDLED   well formed; a hardware or protocol address space,
                                       or a length, this parser cannot place
ARP_PARSE_OPCODE_NOT_HANDLED           ⚠ well formed, placeable, and an opcode we do not act on
```

⚠ **Three values, never folded.** ⚠ **Two of them sharing a value would make a count of one
indistinguishable from a count of the other**, which is the same defect as an uncounted drop
(`.claude/rules/c.md`).

### 2. The names are RFC 826's. ⚠ The numbers are not.

Owner Decision 2, in the owner's words:

> RFC 上の名前が確認できない限り、RFC 由来の名称だとは主張しない。

⚠ **RFC 826 was read on 2026-08-26** — fetched from `rfc-editor.org` and ⚠ **cross-checked against
the copy at `datatracker.ietf.org`**, because a single retrieval summarised by a machine is not a
reading (`verify` §5: cross-check against something derived a different way). ⚠ **Both agreed
verbatim.**

⚠ **Confirmed in the document, and used:**

```text
16.bit: (ar$hrd) Hardware address space
16.bit: (ar$pro) Protocol address space
 8.bit: (ar$hln) byte length of each hardware address
 8.bit: (ar$pln) byte length of each protocol address
16.bit: (ar$op)  opcode (ares_op$REQUEST | ares_op$REPLY)
nbytes: (ar$sha) Hardware address of sender of this packet
mbytes: (ar$spa) Protocol address of sender of this packet
nbytes: (ar$tha) Hardware address of target of this packet (if known)
mbytes: (ar$tpa) Protocol address of target

ares_op$REQUEST (= 1, high byte transmitted first) and ares_op$REPLY (= 2)
```

⚠ **Also confirmed: RFC 826 uses no RFC 2119 keywords.** ⚠ **So nothing built on it may say the RFC
requires something** (`CLAUDE.md` §1: `MUST` / `SHOULD` / silence are different things).

⚠ **The issue text that raised this called the fields "hardware type", "protocol type" and
"operation".** ⚠ **None of those is what the document says.** It says *address space* and *opcode*.
⚠ **That difference is the whole reason Owner Decision 2 exists**, and it is why the identifiers in
`src/arp.h` read as they do.

⚠ **NOT taken from RFC 826:** the numeric value `0x0001` for ethernet and `0x0800` for IPv4.
⚠ **They were not looked for and are not attributed.** They are what the Linux kernel put on an
ethernet TAP device while asking for an IPv4 address, in `tests/fixtures/arp-request-42.hex`.
⚠ **An observation, recorded as one.**

### 3. `src/` stays flat

ADR 0002 said ⚠ **"Directories are revisited when a second protocol exists, not before."** ARP is
that second protocol, so the question is now live, and the answer is: ⚠ **`src/arp.c` and
`src/arp.h`, beside `ethernet.c`, flat.**

### 4. Truncation is decided before support

A packet may be short *and* carry lengths we do not place. ⚠ **It is reported as malformed.**

## Why

**On 3.** ADR 0002's grounds have not changed: two files that each hold one layer of one protocol are
not a structure that needs directories, and ⚠ **a directory named after a layer that has one file in
it decides where ARP, IPv4 and ICMP will live before two of them exist.** ⚠ **The trigger it named
has fired and the answer is still "not yet" — but it is now a decision that was taken, not one that
was deferred.** ⚠ **When a protocol arrives that has both a Parse file and a State file, that is the
moment to look again.**

**On 4.** ⚠ **`ar$hln` and `ar$pln` are the sender's assertion**, and the sender may be lying
(`.claude/rules/c.md`). Deciding support first would answer "we do not handle that length" for a
packet that is short by 500 octets — ⚠ **that answer says the sender is fine, and this one is not.**
⚠ **A packet that does not contain what it claims to contain is malformed whether or not we would
have placed those lengths.**

## What was decided against, and why

- **Two outcomes, with the unhandled opcode swept into "unsupported".** Owner Decision 1. ⚠ **The
  shape of a packet we cannot place and an opcode we choose not to act on are different facts about
  different things.**
- **Two malformed values**, one for "shorter than the fixed fields" and one for "shorter than its own
  lengths". ⚠ **The issue fixed three rejection outcomes and this stays at three.** ⚠ **If counting
  them apart ever matters, that is a decision to take here, not to drift into.**
- **Writing "hardware type" and "operation" because they read more naturally.** ⚠ **They are not the
  document's words**, and `.claude/rules/layers.md` says a name that differs from the RFC's is a
  claim.
- **Filling nothing in when the packet is declined.** The five fixed fields were read perfectly well
  for both declining answers, and ⚠ **withholding them would make "we could not read it" and "we
  read it and do not act on it" look the same.**

## The boundary this sets

- ⚠ **No wording lives in the Parse layer.** A declined packet comes back as a reason, and
  `src/report.c` stays the only place a sentence is written.
- ⚠ **The four addresses are meaningful only when the packet was accepted.** Until `ar$hln` and
  `ar$pln` are lengths this parser places, there is nowhere to put them.
- ⚠ **`ar$tha` is "(if known)" in the document.** ⚠ **All-zero there is a value the sender chose, not
  an unfilled field**, and nothing may report it as absent.

## What this does not claim

⚠ **Not that RFC 826 gives no numeric values for hardware address spaces.** ⚠ **They were not looked
for**, and the values used here are grounded on a capture instead.

⚠ **Not that nothing above ARP is read.** Nothing above ethernet's header is read at all yet; this
adds one packet format and no behaviour. ⚠ **Nothing decides and nothing sends**
(hidetzu/tcpip-stack#17, #18, #19).
