# 0007 — A protocol's octets are described in one file, both directions

Decided 2026-08-27. Raised by hidetzu/tcpip-stack#18.

## The decision

⚠ **Reading an ARP packet and building one live in `src/arp.c`.** Not two files, not two layers.

⚠ **`.claude/rules/layers.md` names four layers — Wire, Parse, State, Report — and there is no Emit
layer.** `.claude/rules/c.md` names four *steps*: `read → parse → decide → emit`. ⚠ **Those are not
the same list, and this is where the difference first bites.**

⚠ **Building octets is the same layer as reading them: the one that knows the wire format.**
Here that layer is called Parse, and ⚠ **`docs/SPEC.md` labels the row `Parse` for that reason.**

## Why

⚠ **Because the field offsets must exist once.**

`src/arp.c` holds five `#define`s that say where `ar$hrd`, `ar$pro`, `ar$hln`, `ar$pln` and `ar$op`
sit. ⚠ **A builder in another file would need the same five**, and `CLAUDE.md` §3 is explicit about
what happens next:

> ⚠ **Writing the same decision in the parser and in the test is how the two silently diverge.**

⚠ **A parser and a builder that disagree about an offset are worse than either being wrong alone**:
we would read a field from one place and write it to another, and every check that round-trips
through both would pass.

⚠ **One file, one description of the format.** Read and write both take their offsets from it.

## What was decided against, and why

- **`src/arp_parse.c` and `src/arp_build.c`.** ⚠ **The offsets would be written twice.** If it is
  ever done, ⚠ **the two must be cross-checked mechanically** (`CLAUDE.md` §3), the way `tap.c`
  checks itself against `IFNAMSIZ` and `arp.c` against `ETHERNET_ADDRESS_BYTES`.
- **An `emit/` directory, or a fifth layer.** ⚠ **ADR 0002's reasoning has not changed**: a directory
  named after a layer with one file in it decides where IPv4 and ICMP will live before they exist.
  ⚠ **And a fifth layer would be a change to `.claude/rules/layers.md`, which is not this issue's to
  make.**
- **Putting the builder in the Wire layer** (`src/tap.c`). ⚠ Wire is the octets that arrived or were
  handed to the fd, and it knows nothing about what they mean. ⚠ **Giving it ARP would be the exact
  mixing `layers.md` forbids.**

## The boundary this sets

- ⚠ **Nothing in this file decides anything.** `arp_build_reply()` builds the reply it is told to
  build; ⚠ **whether a request deserves an answer belongs to its caller**
  (hidetzu/tcpip-stack#19).
- ⚠ **Nothing in this file reaches for an address.** What we answer with is handed in, because
  ⚠ **the TAP device's own hardware address is the kernel's end of the wire and changes every run**
  (hidetzu/tcpip-stack#19 Owner Decision 1).
- ⚠ **When IPv4 and ICMP arrive, they arrive the same way**: one file per protocol, both directions,
  flat in `src/` until something actually forces otherwise (ADR 0002, ADR 0005).

## What this does not claim

⚠ **Not that `layers.md` is wrong to have no Emit layer.** It says only that building and reading
the same format belong together, and that this repository calls that layer Parse.

⚠ **Not that a protocol will never need its own directory.** ⚠ **ADR 0002's trigger is still what it
was** — a second protocol with more than one layer of its own — ⚠ **and it has still not fired.**
