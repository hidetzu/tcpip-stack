/* The internet checksum.
 *
 * ⚠ RFC 1071, read from rfc-editor.org on 2026-08-27 and ⚠ cross-checked
 * against the copy at datatracker.ietf.org. ⚠ Both agreed verbatim, and these
 * are the two things that were read:
 *
 *   "To generate a checksum, the checksum field itself is cleared, the 16-bit
 *    1's complement sum is computed over the octets concerned, and the 1's
 *    complement of this sum is placed in the checksum field."
 *
 *   [A,B] +' [C,D] +' ... +' [Z,0]
 *
 * ⚠ The second line is the odd case: the final octet is paired with a zero.
 *
 * ⚠ What was NOT read, and is therefore not claimed: whether that zero is
 * transmitted — the document does not say — and ⚠ whether summing a block that
 * still carries its checksum yields zero. ⚠ That shortcut is widely used and
 * ⚠ it was not found in what was read, so nothing here relies on it.
 *
 * ⚠ Nothing here knows what an IPv4 or ICMP header is. It is handed octets and
 * a length (hidetzu/tcpip-stack#32). */
#ifndef CHECKSUM_H
#define CHECKSUM_H

#include <stddef.h>
#include <stdint.h>

/* The 1's complement of the 16-bit 1's complement sum over `count` octets.
 *
 * ⚠ Both directions are this one function, because they are the same
 * arithmetic and ⚠ two copies of it would be two things to get wrong
 * (`CLAUDE.md` §3):
 *
 *   to place one   clear the field, call this, put the result in the field
 *   to check one   clear the field, call this, compare with what was carried
 *
 * ⚠ Clearing the field is the caller's job. This function is not told where any
 * field is and must not guess.
 *
 * ⚠ With `count` of 0 it returns 0xffff — the 1's complement of an empty sum.
 * ⚠ That is what this implementation does, decided and asserted here; ⚠ it is
 * not quoted from RFC 1071, which was not read on the point. */
uint16_t internet_checksum(const uint8_t *octets, size_t count);

/* The same sum, with the two-octet field at `field_offset` counted as zero.
 *
 * ⚠ Why this exists at all: clearing the field is the caller's job above, and a
 * caller holding octets it may not write has to copy them first. ⚠ That is fine
 * where the length has a ceiling — an internet header is at most 60 octets
 * (`src/ipv4.c`) — and ⚠ it is not fine for an ICMP message, whose Data RFC 792
 * puts no limit on. ⚠ A fixed scratch array there would be a limit this
 * repository invented (hidetzu/tcpip-stack#34).
 *
 * ⚠ Not a second implementation. ⚠ Both entry points run the one loop in
 * checksum.c, and `internet_checksum` is this function with no field cleared.
 *
 * ⚠ `field_offset` must be even and must leave two octets inside `count`.
 * ⚠ An offset that is not even is not skipped — the sum pairs octets from the
 * start, so a field starting mid-pair is not a word this loop ever forms. Every
 * checksum field in this repository starts on an even octet: 10 in an internet
 * header, 2 in an ICMP message. */
uint16_t internet_checksum_with_field_cleared(const uint8_t *octets, size_t count,
                                              size_t field_offset);

/* The same sum over two blocks that are not next to each other in memory.
 *
 * ⚠ Why this exists: a TCP checksum covers a pseudo-header that is not in the
 * segment at all — ⚠ RFC 793: "The checksum also covers a 96 bit pseudo header
 * conceptually prefixed to the TCP header." ⚠ The two cannot be handed to the
 * calls above as one block without copying the segment somewhere, and ⚠ a
 * segment has no length limit worth inventing one for (the reason ADR 0011 gave
 * for `internet_checksum_with_field_cleared`, and it holds again).
 *
 * ⚠ Not a second implementation. ⚠ All three entry points run the one loop in
 * checksum.c; the two above are this one with no prefix.
 *
 * ⚠ `prefix_count` MUST be even. ⚠ Grounds, and it is not style: RFC 1071 pairs
 * octets from the start and ⚠ RFC 793 says "the last octet is padded on the
 * right with zeros" — ⚠ **once, at the very end**. A prefix of odd length would
 * put a pad in the middle and the answer would be wrong while looking right.
 * ⚠ Measured: [11 22 33] then [44 55] gives 0x7788 added block by block and
 * 0x6699 as one block. ⚠ Every pseudo-header in this repository is 12 octets, so
 * ⚠ nothing here can reach that — and the requirement is stated rather than
 * relied upon (`CLAUDE.md` §1).
 *
 * ⚠ `field_offset` is an offset into `octets`, never into the prefix: the field
 * being cleared is the one carried in the block that was really sent. ⚠ An
 * offset at or past `count` clears nothing, which is how a caller placing a
 * checksum asks for the plain sum. */
uint16_t internet_checksum_of_two(const uint8_t *prefix, size_t prefix_count,
                                  const uint8_t *octets, size_t count,
                                  size_t field_offset);

#endif /* CHECKSUM_H */
