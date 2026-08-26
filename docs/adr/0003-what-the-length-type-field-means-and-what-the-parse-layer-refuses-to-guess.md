# 0003 — What the length/type field means, and what the Parse layer refuses to guess

Decided 2026-08-26. Raised by hidetzu/tcpip-stack#9.
⚠ **The two decisions below are the owner's**, taken on that issue before a line was written.
⚠ **ADR 0002 is not reopened.** It said Parse arrives as its own file once there is something to
parse; this is that, and `src/ethernet.c` is where it went.

## The decision

### 1. The length/type field has three answers, not two

```text
>= 0x0600 (1536)     a Type. Ethernet II                accepted
<= 0x05DC (1500)     an IEEE 802.3 Length               well-formed, and not Ethernet II
0x05DD .. 0x05FF     ⚠ neither of the above             ⚠ its own answer
```

⚠ **The third one is not folded into either of the others.**

The owner's words, kept as they were given:

> 1501–1535 は Length としても Type としても定義された範囲に入らないため、malformed や unsupported に
> 意味を足さず、undefined length/type value のような独立した理由として扱う。reserved という語も
> 規格上確認できない限り使わない。

⚠ **The word "reserved" is not used anywhere for this range**, because this repository has not read
the standard's text for it. ⚠ **What IEEE 802.3 says about 1501–1535 is not confirmed here**, and
⚠ **that gap is the reason this answer exists** rather than something to paper over with a citation
nobody checked (`CLAUDE.md` §1: never dress a guess up as a measurement).

### 2. A VLAN-tagged frame is read as any other value

`0x8100` is a length/type value like any other. ⚠ **The tag is not read**, and the parser does not
know one is there.

⚠ **The consequence, and it is not optional:** for a tagged frame the value reported ⚠ **does not
name what the frame carries** — the real length/type sits behind the tag and nothing in `src/` looks
at it. ⚠ **Nothing may present it as if it did** (hidetzu/tcpip-stack#10 carries this into the
wording).

### 3. Where it lives

`src/ethernet.c` and `src/ethernet.h`, flat in `src/`, per ADR 0002.

⚠ **It is not linked into `tap-read`.** Nothing in the program calls it yet, and ⚠ **dead code in
the product is worse than a layer waiting for its consumer.** It is compiled at `-O2` with `-Werror`
and both sanitizers by the check that exercises it.

## Why

⚠ **Because `CLAUDE.md` §1 already decided the shape of this**, and the length/type field is the
first place in this repository where it bites:

> ⚠ **Silence in an RFC is not permission.** `MUST` / `SHOULD` / `MAY` are different things,
> and "the RFC does not say" is a fourth thing. ⚠ **Do not collapse them.**

Calling 1501–1535 *malformed* says the sender is wrong, and nothing read here supports that.
Calling it *unsupported* says we understood it and declined, and we did not understand it — there is
nothing to understand, because we have not confirmed that the standard assigns it a meaning.
⚠ **Both would be a claim about a thing we did not check.** A third answer claims only what is true:
the field is not in either range this parser knows.

The same reasoning is why `<= 0x05DC` is *unsupported* and not *malformed*. ⚠ **An IEEE 802.3 frame
is perfectly well-formed.** It simply is not the framing this stack reads, and
`.claude/rules/layers.md` requires those two to stay apart because ⚠ **they call for different
behaviour on the wire.**

## What was decided against, and why

- **Two answers, with 1501–1535 swept into "malformed".** ⚠ It makes a count of real malformed
  frames indistinguishable from a count of this, and an uncountable thing is invisible
  (`.claude/rules/c.md`).
- **Parsing the 802.1Q tag now.** ⚠ **Zero tagged frames were observed** in the survey on
  hidetzu/tcpip-stack#9 (28 frames, 3 runs), and `.claude/rules/layers.md` says to generalise once
  the second case actually exists, not because one might.
- **Returning a payload length from this layer.** ⚠ A frame that filled the read buffer has a length
  nobody knows (`src/tap.h`). ⚠ **A number invented here would be a claim wearing the clothes of a
  measurement.** The caller already knows how many octets it read.
- **Filling nothing in when the frame is declined.** For both declining answers the 14 octets were
  there and were read perfectly well. ⚠ **Refusing to hand them back would make "we could not read
  it" and "we read it and do not handle it" look the same** (`CLAUDE.md` §1).

## The boundary this sets

- ⚠ **No wording lives in the Parse layer.** A frame that is not accepted comes back as a reason,
  the way `struct tap_failure` does, and `src/report.c` stays the only place a sentence is written.
- ⚠ **Nothing above ethernet is interpreted here.** When ARP or IPv4 arrives it arrives as its own
  file, for the same reason ADR 0002 gave.
- ⚠ **When a tagged frame has to actually be understood, this ADR is reopened** — not worked around
  in the reporting layer.

## What this does not claim

⚠ **Not that 1501–1535 cannot occur**, and ⚠ **not that the standard is silent about it.** It claims
only that ⚠ **this repository has not read what the standard says**, and that until it has, the value
gets an answer that asserts nothing further.

⚠ **Not that no VLAN-tagged frame will arrive.** None appeared in the survey; that is one kernel on
one fresh tap, and it is not a statement about what a sender may do.
