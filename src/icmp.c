#include "icmp.h"

#include <string.h>

#include "checksum.h"

/* Where each field sits, written as the layout so nothing drifts. */
#define TYPE_OFFSET 0
#define CODE_OFFSET 1
#define CHECKSUM_OFFSET 2
#define IDENTIFIER_OFFSET 4
#define SEQUENCE_NUMBER_OFFSET 6

/* ⚠ Network byte order, one octet at a time. ⚠ Never a struct overlaid on the
 * buffer (`.claude/rules/c.md`). */
static uint16_t read_16(const uint8_t *at)
{
    return (uint16_t)(((uint16_t)at[0] << 8) | at[1]);
}

static void write_16(uint8_t *at, uint16_t value)
{
    at[0] = (uint8_t)(value >> 8);
    at[1] = (uint8_t)(value & 0xffu);
}

enum icmp_parse icmp_parse_echo(const uint8_t *message, size_t message_bytes,
                                struct icmp_echo *echo)
{
    memset(echo, 0, sizeof *echo);

    /* ⚠ Checked against what was actually read, before an octet is touched. */
    if (message_bytes < ICMP_FIXED_BYTES) {
        return ICMP_PARSE_MALFORMED;
    }

    echo->type = message[TYPE_OFFSET];
    echo->code = message[CODE_OFFSET];
    echo->checksum = read_16(message + CHECKSUM_OFFSET);
    echo->identifier = read_16(message + IDENTIFIER_OFFSET);
    echo->sequence_number = read_16(message + SEQUENCE_NUMBER_OFFSET);
    echo->data = message + ICMP_FIXED_BYTES;
    echo->data_bytes = message_bytes - ICMP_FIXED_BYTES;

    /* ⚠ RFC 792: "The checksum is the ... sum of the ICMP message starting with
     * the ICMP Type", and "For computing the checksum , the checksum field
     * should be zero." ⚠ So the check is the generation done again, compared
     * with what arrived — ⚠ not a second way of asking the same question
     * (`CLAUDE.md` §3).
     *
     * ⚠ The whole message, not just the fixed fields: the Data is inside what
     * the sum covers, and a check over eight octets would pass for a payload
     * that had been changed in flight. */
    if (internet_checksum_with_field_cleared(message, message_bytes, CHECKSUM_OFFSET) !=
        echo->checksum) {
        return ICMP_PARSE_CHECKSUM_DISAGREES;
    }

    /* ⚠ Before the Code, deliberately. RFC 792 gives `Code: 0` inside the echo
     * message's own description, so ⚠ for a Type we do not act on there is
     * nothing here that says what its Code may be (ADR 0011). */
    if (echo->type != ICMP_TYPE_ECHO) {
        return ICMP_PARSE_TYPE_NOT_HANDLED;
    }

    /* ⚠ RFC 792, for an echo message: "Code: 0". ⚠ Anything else and the sender
     * did not do what the document says (Owner Decision 1). ⚠ The document does
     * not tell a receiver to reject it — that conclusion is ours (ADR 0011). */
    if (echo->code != ICMP_CODE_ECHO) {
        return ICMP_PARSE_MALFORMED;
    }

    return ICMP_PARSE_OK;
}

enum icmp_build icmp_build_echo_reply(const struct icmp_echo *request,
                                      uint8_t *message, size_t message_bytes,
                                      size_t *reply_bytes)
{
    size_t needed = ICMP_FIXED_BYTES + request->data_bytes;

    /* ⚠ Decided before a single octet is written, so a refused build leaves the
     * caller's buffer exactly as it was. */
    if (message_bytes < needed) {
        return ICMP_BUILD_BUFFER_TOO_SMALL;
    }

    /* ⚠ The Data first, and with memmove: `request->data` is allowed to point
     * into this same buffer, which is what answering in place looks like. */
    if (request->data_bytes > 0) {
        memmove(message + ICMP_FIXED_BYTES, request->data, request->data_bytes);
    }

    message[TYPE_OFFSET] = (uint8_t)ICMP_TYPE_ECHO_REPLY;
    message[CODE_OFFSET] = request->code;
    write_16(message + IDENTIFIER_OFFSET, request->identifier);
    write_16(message + SEQUENCE_NUMBER_OFFSET, request->sequence_number);

    /* ⚠ "For computing the checksum , the checksum field should be zero." */
    write_16(message + CHECKSUM_OFFSET, 0);
    write_16(message + CHECKSUM_OFFSET, internet_checksum(message, needed));

    *reply_bytes = needed;
    return ICMP_BUILD_OK;
}
