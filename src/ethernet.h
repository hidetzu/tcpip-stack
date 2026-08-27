/* Parse — the header of an ethernet frame, checked and in host terms.
 *
 * ⚠ Nothing here writes a word a human reads, and nothing here decides what to
 * do next (`.claude/rules/layers.md`). A frame that is not accepted comes back
 * as a reason; `report.c` is the only place that becomes a sentence.
 *
 * ⚠ Nothing here interprets a payload. The header is 14 octets and that is
 * where this layer stops (hidetzu/tcpip-stack#9). */
#ifndef ETHERNET_H
#define ETHERNET_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* ⚠ IEEE 802.3 calls these the destination address, the source address and the
 * length/type field. The names are borrowed exactly, and a name that differed
 * would be a claim (`.claude/rules/layers.md`). */
#define ETHERNET_ADDRESS_BYTES 6
#define ETHERNET_HEADER_BYTES 14

/* The two ranges this parser holds the field to, fixed on
 * hidetzu/tcpip-stack#9 before a line was written.
 *
 * ⚠ A value of 0x05DD..0x05FF falls in neither. ⚠ This repository has not read
 * what IEEE 802.3 says about that gap, so nothing here claims it says anything:
 * the value is kept as its own answer rather than folded into either of the
 * others (ADR 0003, hidetzu/tcpip-stack#9 Owner Decision 1). */
#define ETHERNET_LENGTH_MAX 0x05DCu /* at or below this, the field is a Length */
#define ETHERNET_TYPE_MIN 0x0600u   /* at or above this, the field is a Type */

/* Why a frame was not accepted. ⚠ An enum never reaches a human (`CLAUDE.md` §4). */
enum ethernet_parse {
    ETHERNET_PARSE_OK = 0,

    /* ⚠ Malformed: there were not 14 octets to read. Whoever sent it is wrong. */
    ETHERNET_PARSE_SHORTER_THAN_THE_HEADER,

    /* ⚠ Well-formed and unsupported: the field holds an IEEE 802.3 Length, so
     * the frame is not Ethernet II. ⚠ The sender is fine; we do not handle it.
     * ⚠ That is a different answer from malformed and it stays different
     * (`.claude/rules/layers.md`). */
    ETHERNET_PARSE_LENGTH_NOT_A_TYPE,

    /* ⚠ Neither of the two above. ⚠ "The standard does not say" is its own
     * thing and is not collapsed into the others (`CLAUDE.md` §1). */
    ETHERNET_PARSE_LENGTH_TYPE_UNDEFINED
};

struct ethernet_header {
    uint8_t destination[ETHERNET_ADDRESS_BYTES];
    uint8_t source[ETHERNET_ADDRESS_BYTES];
    uint16_t length_type;
};

/* Read the header of one frame.
 *
 * `frame` must point at `frame_bytes` readable octets and `header` must not be
 * NULL. ⚠ `frame_bytes` is what was actually read, never what anything claims
 * about itself (`.claude/rules/c.md`).
 *
 * ⚠ *header is filled whenever the 14 octets were there — including for the two
 * answers that decline the frame, because those were read perfectly well and
 * simply are not handled. ⚠ Unreadable and not-handled are different, and the
 * caller can tell them apart without guessing.
 *
 * ⚠ Nothing is returned about how long the frame was. The caller already knows
 * how many octets it read, and ⚠ a frame that filled the read buffer has a
 * length nobody knows (`src/tap.h`). A number invented here would be a claim
 * wearing the clothes of a measurement (`CLAUDE.md` §1). */
enum ethernet_parse ethernet_parse_header(const uint8_t *frame, size_t frame_bytes,
                                          struct ethernet_header *header);

/* Write the 14 octets of a header at the front of a caller's buffer.
 *
 * ⚠ `frame_bytes` is what the buffer holds, and nothing is written unless the
 * header fits. Returns true when it was written.
 *
 * ⚠ Read and write live in one file so the offsets exist once (ADR 0007).
 * ⚠ Nothing here decides what the length/type should be — it is handed in, and
 * a value is never turned into a protocol name here or anywhere (ADR 0003). */
bool ethernet_build_header(const uint8_t *destination, const uint8_t *source,
                           uint16_t length_type, uint8_t *frame, size_t frame_bytes);

#endif /* ETHERNET_H */
