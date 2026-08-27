# 0011 — What RFC 792 says about an echo, and what the order of the answers is

Date: 2026-08-28
Status: accepted
Issue: hidetzu/tcpip-stack#34

## Context

The Parse layer had to read an ICMP echo message and build the reply to it.
⚠ **RFC 792 had never been read in this repository.** ⚠ It was read verbatim on
2026-08-28 from `rfc-editor.org` and cross-checked against the copy at
`datatracker.ietf.org`. ⚠ **The two agreed.**

### What was read, quoted

```
Type: 8 for echo message; 0 for echo reply message.

Code: 0

Checksum: The checksum is the 16-bit ones's complement of the one's complement
sum of the ICMP message starting with the ICMP Type.

For computing the checksum , the checksum field should be zero.

Identifier: If code = 0, an identifier to aid in matching echos and replies,
may be zero.

Sequence Number: If code = 0, a sequence number to aid in matching echos and
replies, may be zero.

Description: The data received in the echo message must be returned in the echo
reply message.

To form an echo reply message, the source and destination addresses are simply
reversed, the type code changed to 0, and the checksum recomputed.
```

⚠ **The names in `src/icmp.h` are those** — `type`, `code`, `checksum`,
`identifier`, `sequence_number`, `data` (`.claude/rules/c.md`: borrow the RFC's
names, exactly).

### ⚠ What was NOT read, and is therefore not claimed

- ⚠ **RFC 792 uses no RFC 2119 keywords.** ⚠ Its lower-case "must be returned"
  is not `MUST`, and this repository does not translate one into the other
  (`CLAUDE.md` §1). ⚠ **The same position RFC 826 and RFC 791 are in here.**
- ⚠ **What a receiver does about a Code that is not 0 is not stated** in what was
  read. ⚠ **Nor is what it does about a Type it does not implement.**
- ⚠ Nothing was read about any other ICMP type. ⚠ Destination unreachable, time
  exceeded and redirect were not looked at.
- ⚠ **"the source and destination addresses are simply reversed" is about the
  IPv4 addresses**, which are not in `src/icmp.c` at all. ⚠ What the document
  leaves an ICMP builder to do is the Type and the Checksum, and that is what it
  does — hidetzu/tcpip-stack#35 owns the addresses.

## Decision

### ⚠ Four answers, and the order they are decided in

```
fewer octets than the fixed fields   -> malformed
the checksum does not agree          -> its own answer
the Type is not 8                    -> a Type we do not act on
the Code is not 0                    -> malformed
otherwise                            -> accepted
```

⚠ **Owner Decision 1 — a Code that is not 0 is malformed.** ⚠ The grounds are the
document's `Code: 0`; ⚠ **the conclusion drawn from it is ours.** The sender did
not do what the document says, which is what *malformed* means here and is not
what *unsupported* means (`.claude/rules/layers.md`). ⚠ **RFC 792 does not say to
reject such a message**, and this is not presented as if it did. ⚠ **The same
shape as ADR 0010's reserved flag bit.**

⚠ **Owner Decision 2 — an echo reply is a Type we do not act on.** ⚠ Not
accepted, not malformed. ⚠ The issue's Out of Scope named "any type other than
echo request and echo reply", which left Type 0 unreadable either way; ⚠ it is
settled here.

### ⚠ Why the checksum is decided before any field's content

⚠ **The checksum tells you whether these are the octets the sender sent.** Judging
a Type or a Code first would ⚠ **blame the sender for octets that were changed in
flight**, and *malformed* means the sender is wrong. ⚠ **This is the shape
ADR 0010 already has** for the internet header.

### ⚠ Why the Type is decided before the Code

⚠ **RFC 792 gives `Code: 0` inside the echo message's own description**, and
"Identifier: **If code = 0** …" shows the document leaving room for other codes
to mean other things elsewhere. ⚠ **So for a Type we do not act on, nothing that
was read says what its Code may be** — calling it malformed would be a claim
about a message this repository has not read the definition of.

⚠ **This is where the approved plan and the code differ, and it is said out
loud.** ⚠ **The plan for hidetzu/tcpip-stack#34 listed the Code above the Type**;
⚠ **that list was the set of answers, and this is the order.** ⚠ Reversing it is
two lines, and `the_order_the_answers_are_decided_in` is what would have to change
with it.

### ⚠ The checksum is verified without copying the message

⚠ **`internet_checksum_with_field_cleared` was added to `src/checksum.h`.**
⚠ **Not a second implementation** — `checksum.c` has one loop and both entry
points go through it, and `internet_checksum` is that function with no field
cleared (`CLAUDE.md` §3).

⚠ **Why it was needed:** clearing the field is the caller's job, so a caller
holding octets it may not write has to copy them first. ⚠ That is fine for an
internet header, which is at most 60 octets. ⚠ **It is not fine for an ICMP
message: RFC 792 puts no limit on how long `Data` is**, and a fixed scratch array
in `src/icmp.c` would be a limit this repository invented.

⚠ **What was NOT done:** the widely-used shortcut of summing a block that still
carries its checksum and expecting zero. ⚠ **It was not found in what was read of
RFC 1071** (ADR is `src/checksum.h`'s own comment), so nothing relies on it.

### `Data` is borrowed, not copied

⚠ **`struct icmp_echo` holds a pointer into the caller's octets and a length**,
with the owner named at the field (`.claude/rules/c.md`). ⚠ Copying would need a
maximum length, and there is none to take from the document.

⚠ **The builder uses `memmove`**, because a caller answering in place has the
request's `Data` pointing into the very buffer being written.

## Consequences

- ⚠ **Nothing here decides whether to answer, and nothing sends.**
  hidetzu/tcpip-stack#35 owns both.
- ⚠ **The reply is held against octets the Linux kernel produced**, not against
  an expectation typed out here. ⚠ `tests/fixtures/icmp-echo-reply-98.hex` is the
  kernel's answer to exactly the request in `icmp-echo-request-98.hex`, and its
  provenance says how it was provoked.
- ⚠ **The reply carries the request's Code across.** ⚠ Only Code 0 can reach the
  builder through the parser, so this is the same octet either way; ⚠ it is
  written as "carried across" because the document names one field to change and
  the Code is not it.
- ⚠ An ICMP message with no `Data` at all is accepted. ⚠ Nothing read forbids it,
  and the reply to it is the eight fixed octets.
