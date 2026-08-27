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

#endif /* CHECKSUM_H */
