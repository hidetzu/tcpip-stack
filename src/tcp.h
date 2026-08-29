/* Parse — the header of a TCP segment, checked and in host terms.
 *
 * ⚠ Nothing here writes a word a human reads, nothing here decides anything,
 * and nothing here remembers anything between calls
 * (`.claude/rules/layers.md`). A segment that is not accepted comes back as a
 * reason; `report.c` is the only place that becomes a sentence.
 *
 * ⚠ The names below are RFC 793's own, read on 2026-08-28 from rfc-editor.org
 * and cross-checked against the copy at datatracker.ietf.org. ⚠ Both agreed,
 * and this is what they say (ADR 0013):
 *
 *     Source Port: 16 bits.  The source port number.
 *     Destination Port: 16 bits.  The destination port number.
 *     Sequence Number: 32 bits.
 *     Acknowledgment Number: 32 bits.
 *     Data Offset: 4 bits - The number of 32 bit words in the TCP Header.
 *     Reserved: 6 bits - Reserved for future use.  Must be zero.
 *     Control Bits: 6 bits (from left to right):
 *       URG: Urgent Pointer field significant
 *       ACK: Acknowledgment field significant
 *       PSH: Push Function
 *       RST: Reset the connection
 *       SYN: Synchronize sequence numbers
 *       FIN: No more data from sender
 *     Window: 16 bits.
 *     Checksum: 16 bits.
 *     Urgent Pointer: 16 bits.
 *
 * ⚠ It is "Acknowledgment", with no "e" in the middle. ⚠ The document spells it
 * that way and so does this file (`.claude/rules/c.md`: borrow the RFC's names,
 * exactly).
 *
 * ⚠ RFC 793 does not use the RFC 2119 keywords in capitals. ⚠ So nothing here
 * or in any wording built on it may say the RFC requires something
 * (`CLAUDE.md` §1) — the same standing RFC 826, 791 and 792 are in here.
 *
 * ⚠ The checksum IS checked here, and that is a decision rather than a detail
 * (hidetzu/tcpip-stack#41 Owner Decision 1). ⚠ It covers a pseudo-header that is
 * not in the segment, so this function has to be handed the two addresses —
 * ⚠ RFC 793: "The checksum also covers a 96 bit pseudo header conceptually
 * prefixed to the TCP header. This pseudo header contains the Source Address,
 * the Destination Address, the Protocol, and TCP length."
 *
 * ⚠ Why it is not a separate call: ⚠ **a caller can forget a separate call.** A
 * parsed header would then exist whose checksum nobody judged, the checks would
 * stay green, and ⚠ the handshake would complete anyway — which is
 * `CLAUDE.md` §1's sentence about answering a ping while computing the checksum
 * wrong, in TCP's clothes. ⚠ This way that state cannot exist. */
#ifndef TCP_H
#define TCP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* ⚠ src/tcp.c deliberately includes nothing from the layer below it. ⚠ The two
 * addresses arrive as four octets each and the length as a number: the
 * dependency is RFC 793's, and the direction Wire -> Parse -> State stays clean
 * (`.claude/rules/layers.md`). */
#define TCP_ADDRESS_BYTES 4

/* ⚠ RFC 793: "Data Offset: 4 bits - The number of 32 bit words in the TCP
 * Header." ⚠ So a header is Data Offset of these. */
#define TCP_HEADER_LENGTH_UNIT 4

/* The header before any Options, in units of the above.
 *
 * ⚠ **Grounds: RFC 9293 §3.1**, the baseline since ADR 0024: "Options: [TCP
 * Option]; size(Options) == (DOffset-5)*32; ⚠ **present only when DOffset > 5**".
 *
 * ⚠ **It used to be ours**, and it said so: RFC 793 states no minimum for Data
 * Offset where RFC 791 does for `IHL`, and ⚠ **the contradiction of a header
 * claiming to be shorter than its own fixed fields was our reading** (ADR 0013).
 * ⚠ **RFC 9293 states it, so the claim is the document's** — ⚠ and nothing about
 * the code changed when that was found (hidetzu/tcpip-stack#87). */
#define TCP_HEADER_LENGTH_MINIMUM 5

/* ⚠ Data Offset is four bits wide, so it cannot exceed this. */
#define TCP_HEADER_LENGTH_MAXIMUM 15

/* The fixed part, in octets. ⚠ Derived, never written as 20. */
#define TCP_FIXED_HEADER_BYTES (TCP_HEADER_LENGTH_MINIMUM * TCP_HEADER_LENGTH_UNIT)

/* The Control Bits, in the order the document lists them, left to right.
 *
 * ⚠ **Eight, not six.** ⚠ RFC 793 listed six and called the two above them
 * `Reserved`. ⚠ RFC 9293 §3.1 — the normative baseline since ADR 0024 —
 * assigns them: "The currently assigned control bits are CWR, ECE, URG, ACK,
 * PSH, RST, SYN, and FIN", with `Reserved` reduced to four bits.
 *
 * ⚠ **`CWR` and `ECE` belong to ECN, and nothing here implements ECN.**
 * ⚠ They are read and ⚠ **acted on by nothing** — ADR 0024 clause 3 adds a
 * function RFC 9293 defers only when that function is implemented
 * (hidetzu/tcpip-stack#86). */
#define TCP_CONTROL_CWR 0x80u
#define TCP_CONTROL_ECE 0x40u
#define TCP_CONTROL_URG 0x20u
#define TCP_CONTROL_ACK 0x10u
#define TCP_CONTROL_PSH 0x08u
#define TCP_CONTROL_RST 0x04u
#define TCP_CONTROL_SYN 0x02u
#define TCP_CONTROL_FIN 0x01u

/* The value a `Protocol` field carries for TCP, as the pseudo-header needs it.
 *
 * ⚠ Grounds, and they are NOT RFC 793: ⚠ **this was not taken from the
 * document.** RFC 793 names the field in the pseudo-header and does not give its
 * value. ⚠ It is octet 9 of the internet header in
 * tests/fixtures/tcp-syn-74.hex, put there by the Linux kernel while carrying
 * TCP. ⚠ An observation, and it is recorded as one — the same standing ADR 0005
 * gave ARP's numbers and ADR 0012 gave ICMP's.
 *
 * ⚠ It is not a parameter. ⚠ A pseudo-header for a TCP segment always carries
 * TCP's own number, and a parameter would only be a value a caller could get
 * wrong (hidetzu/tcpip-stack#41). */
#define TCP_PROTOCOL_NUMBER 6u

/* ⚠ RFC 793's option-kinds, quoted: "End of option list", "No-Operation",
 * "Maximum Segment Size". ⚠ Only the first two are named here, because ⚠ they
 * are the two the walk has to know about — they are Case 1, "a single octet of
 * option-kind", and every other kind is Case 2.
 *
 * ⚠ Maximum Segment Size is deliberately not named: nothing here interprets an
 * option, and a constant for one would be the beginning of doing so. */
#define TCP_OPTION_END_OF_OPTION_LIST 0u
#define TCP_OPTION_NO_OPERATION 1u

/* RFC 9293 §3.2, quoted: "Maximum Segment Size Option Data: 16 bits ... Kind: 2,
 * Length: 4".
 *
 * ⚠ Four octets is exactly one 32-bit word, ⚠ **so a header carrying only this
 * option needs no padding and no End of Option List** — `Data Offset` goes from
 * 5 to 6 and nothing else moves (hidetzu/tcpip-stack#123). */
#define TCP_OPTION_MAXIMUM_SEGMENT_SIZE 2u
#define TCP_OPTION_MAXIMUM_SEGMENT_SIZE_BYTES 4u

/* Why a segment was not accepted. ⚠ An enum never reaches a human
 * (`CLAUDE.md` §4). */
enum tcp_parse {
    TCP_PARSE_OK = 0,

    /* ⚠ Malformed: the octets do not hold what the header says they hold, or
     * the header breaks what the document states. ⚠ Whoever sent it is wrong.
     * ⚠ **Three inputs land here** — fewer octets than the fixed fields need; a
     * Data Offset below or beyond what a header can be; and ⚠ an option list
     * that does not walk (ADR 0013).
     *
     * ⚠ **It was four until hidetzu/tcpip-stack#86.** ⚠ A `Reserved` that is
     * not zero was one of them, and ⚠ **RFC 9293 §3.1 says a receiver must
     * ignore it.** ⚠ **This counter means less than it did**, and
     * `docs/SPEC.md` §2-1 says so rather than letting the number quietly change
     * what it stands for.
     *
     * ⚠ There is no "well-formed but unsupported" answer in this file, and that
     * is not an oversight: ⚠ reading a header declines nothing. ⚠ Options are
     * walked past rather than refused, because ⚠ the Linux kernel's own SYN
     * carries twenty octets of them (tests/fixtures/tcp-syn-74.hex) and a
     * parser that refused them would refuse every real SYN there is. */
    TCP_PARSE_MALFORMED,

    /* ⚠ Its own answer. ⚠ A segment whose checksum does not agree is not one we
     * may act on, and it is not the sender being wrong about the format —
     * ⚠ something changed it, or it was never right. ⚠ Counting it with
     * malformed would hide it (ADR 0010 and ADR 0011 kept the same two apart). */
    TCP_PARSE_CHECKSUM_DISAGREES
};

/* What the options said, in host terms.
 *
 * ⚠ **This is the Parse layer's answer, not the octets** — a caller never sees
 * the option list (`.claude/rules/layers.md`).
 *
 * ⚠ **A struct rather than a field**, because ⚠ the next option to be given a
 * meaning must not change every signature again. ⚠ It holds one today and that
 * is not an abstraction for a case that might appear — ⚠ **`MUST-4`'s mandatory
 * set is exactly `{MSS}` for this build**, and the walk already refuses what it
 * cannot read. */
struct tcp_options {
    /* ⚠ Whether one was there at all, ⚠ **separately from its value.**
     *
     * ⚠ RFC 9293 `MUST-15`: "If an MSS Option is not received at connection
     * setup, TCP implementations MUST assume a default send MSS of 536".
     * ⚠ **Absent and zero are different answers**, and a caller that could not
     * tell them apart would have to guess which
     * (`CLAUDE.md` §1). */
    bool has_maximum_segment_size;
    uint16_t maximum_segment_size;
};

struct tcp_header {
    uint16_t source_port;
    uint16_t destination_port;
    uint32_t sequence_number;
    uint32_t acknowledgment_number;
    uint8_t data_offset;   /* in 32-bit words, as the document counts */
    /* ⚠ **Four bits**, and ⚠ **a set one changes nothing.**
     *
     * ⚠ RFC 9293 §3.1, verbatim: "A set of control bits reserved for future
     * use.  Must be zero in generated segments and must be ignored in received
     * segments if the corresponding future features are not implemented by the
     * sending or receiving host." ⚠ **Both keywords are lowercase and the
     * passage carries no labelled one**, so ⚠ **it describes rather than
     * requires** (§2, and `CLAUDE.md` §9).
     *
     * ⚠ **Four bits is a different kind of claim**: it is the field's
     * definition, ⚠ **and this build was reading six.**
     *
     * ⚠ Until hidetzu/tcpip-stack#86 a set one made the segment malformed —
     * ⚠ **our reading of RFC 793's "Must be zero", recorded as ours**
     * (ADR 0013). ⚠ **The grounds for ignoring it now are measured**: an
     * ECN-capable peer's first SYN was thrown away.
     *
     * ⚠ **Carried so a caller can see it**, and ⚠ nothing here reads it. */
    uint8_t reserved;
    uint8_t control_bits;  /* the six above */
    uint16_t window;
    uint16_t checksum;     /* ⚠ carried, never verified here */
    uint16_t urgent_pointer;

    /* ⚠ What the option list meant. ⚠ Filled by the walk, and ⚠ **empty when
     * `Data Offset` is 5** — which is not the same as an option list that said
     * nothing. */
    struct tcp_options options;

    /* ⚠ Where the data begins, counted from the start of the segment.
     * ⚠ This is what walking the options buys, and ⚠ it is the only thing the
     * options are read for. ⚠ It is `data_offset` in octets, and it is
     * meaningful only when OK is returned. */
    size_t data_begins_at;

    /* ⚠ How many octets of data the segment carries: `segment_bytes` less
     * `data_begins_at`, and ⚠ meaningful only when OK is returned.
     *
     * ⚠ It is derived here rather than by each caller on purpose. ⚠ Both
     * numbers it comes from are already checked against each other above, and
     * ⚠ a caller doing the subtraction itself would be a second place deciding
     * the same question — which is how the two silently diverge
     * (`CLAUDE.md` §3). ⚠ It cannot underflow: `segment_bytes < header_bytes`
     * is malformed and never reaches here. */
    size_t data_bytes;
};

/* Read the header of one TCP segment.
 *
 * `segment` is what followed the internet header, and `segment_bytes` is ⚠ what
 * was actually read, never what anything claims about itself
 * (`.claude/rules/c.md`). `header` must not be NULL.
 *
 * ⚠ *header is zeroed first, and filled as far as the octets allowed — so a
 * caller can say which port was asked for without reading them itself, even for
 * a segment it declines. ⚠ Meaningful only when the answer is not malformed.
 *
 * ⚠ The options are walked and ⚠ not one of them is interpreted. RFC 793 says
 * "A TCP must implement all options"; ⚠ **this file implements none of them**,
 * and that gap is named in `docs/SPEC.md` §2 rather than left silent.
 *
 * ⚠ `segment_bytes` MUST be the segment as the internet header's `Total Length`
 * bounds it, ⚠ **not as many octets as arrived.** ⚠ RFC 793: "The TCP Length is
 * the TCP header length plus the data length in octets (this is not an
 * explicitly transmitted quantity, but is computed)". ⚠ It is computed from this
 * number, so ⚠ a frame padded up to the wire's minimum makes the checksum
 * disagree — and ⚠ the only thing that comes back is "it does not agree", with
 * nothing pointing at the padding. ⚠ `src/echo_responder.c` already bounds an
 * ICMP message this way and the same is required here.
 *
 * ⚠ It follows that `segment_bytes` fits in sixteen bits, because `Total Length`
 * is a sixteen-bit field. ⚠ The `TCP Length` written into the pseudo-header is
 * that many octets, and ⚠ a caller that handed over more would get a checksum
 * that does not agree, with nothing saying why. ⚠ The requirement is stated
 * rather than left to be discovered.
 *
 * `source_address` and `destination_address` are the internet header's, four
 * octets each, ⚠ in the order they were on the wire.
 *
 * ⚠ The order the answers are decided in, and why it is this order (ADR 0014):
 *
 *     fewer octets than the fixed fields   ⚠ the checksum field itself has not
 *                                            arrived, so nothing can be judged
 *     the checksum does not agree          ⚠ before any field's content:
 *                                            blaming the sender for octets that
 *                                            were changed in flight would be
 *                                            the wrong answer
 *     Data Offset below the fixed header   malformed
 *     Data Offset beyond what arrived      malformed
 *     Reserved is not zero                 malformed
 *     the option list does not walk        malformed
 *     otherwise                            accepted */
enum tcp_parse tcp_parse_header(const uint8_t *segment, size_t segment_bytes,
                                const uint8_t *source_address,
                                const uint8_t *destination_address,
                                struct tcp_header *header);

/* Why a segment was not built. ⚠ An enum never reaches a human. */
enum tcp_build {
    TCP_BUILD_OK = 0,

    /* ⚠ The caller's buffer cannot hold the whole segment. ⚠ Refused, never
     * truncated: half a segment carries a checksum computed over octets that
     * are not there. */
    TCP_BUILD_BUFFER_TOO_SMALL
};

/* Build a segment with no data, into a caller's buffer.
 *
 * ⚠ `fields` supplies the ports, the two sequence numbers, the `Control Bits`,
 * the `Window` — ⚠ **and, since hidetzu/tcpip-stack#123, `fields->options`.**
 * ⚠ `Data Offset`, `Reserved`, `Urgent Pointer` and `Checksum` are this
 * function's, ⚠ **not the caller's to get wrong**: ⚠ **the first now follows the
 * options**, the next two are zero, and the last is computed over whatever
 * length resulted.
 *
 * ⚠ **Until hidetzu/tcpip-stack#123 no option was sent** (hidetzu/tcpip-stack#44
 * Owner Decision 2), on the grounds that ⚠ **sending something we cannot read
 * would be a claim we cannot back.** ⚠ **That ground is gone for this one
 * option**: the walk reads an MSS Option now, so ⚠ **the same option is
 * understood in both directions** (ADR 0029).
 *
 * ⚠ **Only the MSS Option, and only when `fields->options` asks for it.**
 * ⚠ `Data Offset` stays 5 when it does not, so ⚠ **every segment built before
 * this change is byte for byte what it was.**
 *
 * `source_address` and `destination_address` are the internet header's, ⚠ in the
 * order they will be on the wire — ⚠ **ours first**, which is the reverse of
 * what `tcp_parse_header` was handed for the same exchange.
 *
 * ⚠ Nothing is written unless the whole segment fits. On OK, *built_bytes is
 * how much was written. */
enum tcp_build tcp_build_segment(const struct tcp_header *fields,
                                 const uint8_t *source_address,
                                 const uint8_t *destination_address,
                                 uint8_t *segment, size_t segment_bytes,
                                 size_t *built_bytes);

#endif /* TCP_H */
