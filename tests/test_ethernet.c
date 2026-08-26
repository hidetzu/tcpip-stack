/* Static-tier check of the Parse layer.
 *
 * ⚠ No TAP device, no namespace, no clock, no elevated capability. It hands
 * octets to the parser and reads back what it made of them.
 *
 * ⚠ Running cases and reading fixtures is `tests/check.h`. ⚠ Only what is
 * asserted lives here.
 *
 * ⚠ Two ways of pinning the parser down, on purpose:
 *   - against the captured fixture, with the expected octets read out of the
 *     file rather than typed in here a second time (`CLAUDE.md` §3)
 *   - against frames built here, where the two octets of the length/type field
 *     are written separately from the value expected of them, ⚠ so byte order
 *     is asserted rather than restated from the implementation */
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "check.h"
#include "ethernet.h"
#include "tap.h"

/* ---- building a frame to hand over -------------------------------------- */

/* Addresses that are told apart at a glance, so a parser that returned one of
 * them twice, or read them the wrong way round, is caught. */
static const unsigned char DESTINATION[ETHERNET_ADDRESS_BYTES] = {
    0x02, 0x00, 0x00, 0x00, 0x00, 0xdd
};
static const unsigned char SOURCE[ETHERNET_ADDRESS_BYTES] = {
    0x02, 0x00, 0x00, 0x00, 0x00, 0x55
};

static void frame_with_length_type(unsigned char *frame, size_t frame_bytes,
                                   unsigned char high, unsigned char low)
{
    memset(frame, 0, frame_bytes);
    memcpy(frame, DESTINATION, ETHERNET_ADDRESS_BYTES);
    memcpy(frame + ETHERNET_ADDRESS_BYTES, SOURCE, ETHERNET_ADDRESS_BYTES);
    frame[ETHERNET_ADDRESS_BYTES * 2] = high;
    frame[ETHERNET_ADDRESS_BYTES * 2 + 1] = low;
}

/* Hands over one frame of exactly the header's length and reports what came
 * back, so a case can state one expectation per line. */
static bool answers(const char *what, unsigned char high, unsigned char low,
                    enum ethernet_parse expected_answer, unsigned expected_length_type)
{
    unsigned char frame[ETHERNET_HEADER_BYTES];
    frame_with_length_type(frame, sizeof frame, high, low);

    struct ethernet_header header;
    memset(&header, 0, sizeof header);
    enum ethernet_parse answer = ethernet_parse_header(frame, sizeof frame, &header);

    bool ok = true;
    if (answer != expected_answer) {
        fprintf(stderr, "  %s: expected answer %d, got %d\n", what, (int)expected_answer,
                (int)answer);
        ok = false;
    }
    if (header.length_type != expected_length_type) {
        fprintf(stderr, "  %s: length/type from octets %02x %02x should be 0x%04x, got 0x%04x\n",
                what, high, low, expected_length_type, header.length_type);
        ok = false;
    }
    if (memcmp(header.destination, DESTINATION, ETHERNET_ADDRESS_BYTES) != 0 ||
        memcmp(header.source, SOURCE, ETHERNET_ADDRESS_BYTES) != 0) {
        fprintf(stderr, "  %s: the addresses did not come back as they were put in\n", what);
        ok = false;
    }
    return ok;
}

/* ---- the cases ---------------------------------------------------------- */

/* ⚠ The expected values are read back out of the fixture, never typed in here
 * (`CLAUDE.md` §3). What this catches is a wrong offset, a swap of source and
 * destination, and an off-by-one; ⚠ what it cannot catch is both sides agreeing
 * on a wrong byte order, which is what the built frames below are for. */
static bool case_the_captured_arp_request_parses_to_what_the_file_holds(void)
{
    unsigned char frame[TAP_FRAME_BUFFER_BYTES];
    long bytes = check_load_fixture("arp-request-42.hex", frame, sizeof frame);
    if (bytes < 0) {
        return false;
    }

    struct ethernet_header header;
    memset(&header, 0, sizeof header);
    enum ethernet_parse answer = ethernet_parse_header(frame, (size_t)bytes, &header);

    bool ok = true;
    if (answer != ETHERNET_PARSE_OK) {
        fprintf(stderr, "  the captured ARP request was not accepted: answer %d\n", (int)answer);
        ok = false;
    }
    if (memcmp(header.destination, frame, ETHERNET_ADDRESS_BYTES) != 0) {
        fprintf(stderr, "  the destination is not the fixture's first six octets\n");
        ok = false;
    }
    if (memcmp(header.source, frame + ETHERNET_ADDRESS_BYTES, ETHERNET_ADDRESS_BYTES) != 0) {
        fprintf(stderr, "  the source is not the fixture's second six octets\n");
        ok = false;
    }
    unsigned from_the_file = ((unsigned)frame[ETHERNET_ADDRESS_BYTES * 2] << 8) |
                             frame[ETHERNET_ADDRESS_BYTES * 2 + 1];
    if (header.length_type != from_the_file) {
        fprintf(stderr, "  the length/type is 0x%04x and the file holds 0x%04x\n",
                header.length_type, from_the_file);
        ok = false;
    }
    return ok;
}

/* ⚠ Malformed: there were not 14 octets to read. */
static bool case_a_frame_shorter_than_the_header_is_malformed(void)
{
    unsigned char frame[ETHERNET_HEADER_BYTES];
    frame_with_length_type(frame, sizeof frame, 0x08, 0x00);

    bool ok = true;
    for (size_t bytes = 0; bytes < ETHERNET_HEADER_BYTES; bytes++) {
        struct ethernet_header header;
        enum ethernet_parse answer = ethernet_parse_header(frame, bytes, &header);
        if (answer != ETHERNET_PARSE_SHORTER_THAN_THE_HEADER) {
            fprintf(stderr, "  %zu octets should be too few for a header, answer was %d\n",
                    bytes, (int)answer);
            ok = false;
        }
    }
    /* ⚠ The other half. A check that only says "too short is refused" stays
     * green when everything is refused (`verify` §5). */
    struct ethernet_header header;
    if (ethernet_parse_header(frame, ETHERNET_HEADER_BYTES, &header) !=
        ETHERNET_PARSE_OK) {
        fprintf(stderr, "  exactly 14 octets is a header and was not accepted\n");
        ok = false;
    }
    return ok;
}

/* ⚠ A read that returned nothing is malformed, not an empty frame, and the
 * buffer must not be touched to decide that. */
static bool case_a_zero_length_read_is_malformed(void)
{
    unsigned char frame[ETHERNET_HEADER_BYTES];
    frame_with_length_type(frame, sizeof frame, 0x08, 0x00);

    struct ethernet_header header;
    bool ok = true;
    /* What read(2) returning 0 actually looks like: a real buffer, nothing in it. */
    if (ethernet_parse_header(frame, 0, &header) != ETHERNET_PARSE_SHORTER_THAN_THE_HEADER) {
        fprintf(stderr, "  a zero-length read should be too short for a header\n");
        ok = false;
    }
    /* ⚠ And with no buffer at all, which is how "the octets are not touched
     * before the length is checked" is asserted rather than assumed. */
    if (ethernet_parse_header(NULL, 0, &header) != ETHERNET_PARSE_SHORTER_THAN_THE_HEADER) {
        fprintf(stderr, "  no buffer at all should be too short for a header\n");
        ok = false;
    }
    return ok;
}

/* ⚠ Well-formed and unsupported: an IEEE 802.3 Length, so not Ethernet II.
 * ⚠ The sender is fine. This is not malformed and must not be reported as it. */
static bool case_an_802_3_length_is_well_formed_and_unsupported(void)
{
    bool ok = answers("a small 802.3 length", 0x00, 0x26,
                      ETHERNET_PARSE_LENGTH_NOT_A_TYPE, 0x0026u);
    ok = answers("a zero length/type", 0x00, 0x00,
                 ETHERNET_PARSE_LENGTH_NOT_A_TYPE, 0x0000u) && ok;
    /* ⚠ The boundary itself: 1500 is still a Length. */
    ok = answers("the largest 802.3 length", 0x05, 0xdc,
                 ETHERNET_PARSE_LENGTH_NOT_A_TYPE, 0x05dcu) && ok;
    return ok;
}

/* ⚠ Neither a Length nor a Type. ⚠ "The standard does not say" is its own
 * answer and is not folded into the other two
 * (ADR 0003, hidetzu/tcpip-stack#9 Owner Decision 1). */
static bool case_a_length_type_the_standard_does_not_define_is_its_own_answer(void)
{
    bool ok = answers("just above the largest Length", 0x05, 0xdd,
                      ETHERNET_PARSE_LENGTH_TYPE_UNDEFINED, 0x05ddu);
    ok = answers("just below the smallest Type", 0x05, 0xff,
                 ETHERNET_PARSE_LENGTH_TYPE_UNDEFINED, 0x05ffu) && ok;
    return ok;
}

/* ⚠ A Type we cannot do anything with yet is still a header we read correctly.
 * ⚠ Not implemented is not the sender's fault (`CLAUDE.md` §4-1), and at this
 * layer it is not an answer at all — the header parsed. */
static bool case_a_type_with_no_payload_parser_is_still_accepted(void)
{
    /* ⚠ The boundary: 1536 is the smallest Type. */
    bool ok = answers("the smallest Type", 0x06, 0x00, ETHERNET_PARSE_OK, 0x0600u);
    ok = answers("IPv4", 0x08, 0x00, ETHERNET_PARSE_OK, 0x0800u) && ok;
    ok = answers("ARP", 0x08, 0x06, ETHERNET_PARSE_OK, 0x0806u) && ok;
    ok = answers("IPv6", 0x86, 0xdd, ETHERNET_PARSE_OK, 0x86ddu) && ok;
    ok = answers("the largest length/type there is", 0xff, 0xff,
                 ETHERNET_PARSE_OK, 0xffffu) && ok;
    return ok;
}

/* ⚠ Owner Decision 2 (hidetzu/tcpip-stack#9): a tagged frame is read as any
 * other value and the tag is not read. ⚠ So 0x8100 is what comes back, and
 * ⚠ nothing may present that as what the frame carries — the real length/type
 * is behind the tag and nothing here looks at it. */
static bool case_a_vlan_tagged_frame_is_accepted_as_any_other_value(void)
{
    return answers("an 802.1Q tag", 0x81, 0x00, ETHERNET_PARSE_OK, 0x8100u);
}

/* ⚠ A frame that filled the read buffer has a length nobody knows
 * (`src/tap.h`). ⚠ Its header is at the front and reads the same as any other;
 * this layer returns nothing about the length, so there is nothing to be wrong
 * about (`CLAUDE.md` §1). */
static bool case_a_frame_that_filled_the_read_buffer_still_parses_its_header(void)
{
    unsigned char frame[TAP_FRAME_BUFFER_BYTES];
    frame_with_length_type(frame, sizeof frame, 0x86, 0xdd);

    struct ethernet_header filled;
    memset(&filled, 0, sizeof filled);
    enum ethernet_parse answer = ethernet_parse_header(frame, sizeof frame, &filled);

    struct ethernet_header short_one;
    memset(&short_one, 0, sizeof short_one);
    enum ethernet_parse short_answer =
        ethernet_parse_header(frame, ETHERNET_HEADER_BYTES, &short_one);

    bool ok = true;
    if (answer != ETHERNET_PARSE_OK) {
        fprintf(stderr, "  a frame filling the read buffer was not accepted: answer %d\n",
                (int)answer);
        ok = false;
    }
    if (answer != short_answer || memcmp(&filled, &short_one, sizeof filled) != 0) {
        fprintf(stderr, "  filling the read buffer changed what the header says\n");
        ok = false;
    }
    return ok;
}

/* ⚠ Three reasons, three values. ⚠ Two of them sharing a value would make a
 * count of one indistinguishable from a count of the other, which is the whole
 * subject of `CLAUDE.md` §1. */
static bool case_the_reasons_a_frame_is_not_accepted_are_three_distinct_values(void)
{
    const enum ethernet_parse reasons[] = {
        ETHERNET_PARSE_SHORTER_THAN_THE_HEADER,
        ETHERNET_PARSE_LENGTH_NOT_A_TYPE,
        ETHERNET_PARSE_LENGTH_TYPE_UNDEFINED,
    };
    const size_t count = sizeof reasons / sizeof reasons[0];

    bool ok = true;
    for (size_t i = 0; i < count; i++) {
        if (reasons[i] == ETHERNET_PARSE_OK) {
            fprintf(stderr, "  reason %zu has the same value as being accepted\n", i);
            ok = false;
        }
        for (size_t j = i + 1; j < count; j++) {
            if (reasons[i] == reasons[j]) {
                fprintf(stderr, "  reasons %zu and %zu are the same value\n", i, j);
                ok = false;
            }
        }
    }
    return ok;
}

/* ---- running them ------------------------------------------------------- */

static const struct test_case cases[] = {
    { "the_captured_arp_request_parses_to_what_the_file_holds",
      case_the_captured_arp_request_parses_to_what_the_file_holds },
    { "a_frame_shorter_than_the_header_is_malformed",
      case_a_frame_shorter_than_the_header_is_malformed },
    { "a_zero_length_read_is_malformed", case_a_zero_length_read_is_malformed },
    { "an_802_3_length_is_well_formed_and_unsupported",
      case_an_802_3_length_is_well_formed_and_unsupported },
    { "a_length_type_the_standard_does_not_define_is_its_own_answer",
      case_a_length_type_the_standard_does_not_define_is_its_own_answer },
    { "a_type_with_no_payload_parser_is_still_accepted",
      case_a_type_with_no_payload_parser_is_still_accepted },
    { "a_vlan_tagged_frame_is_accepted_as_any_other_value",
      case_a_vlan_tagged_frame_is_accepted_as_any_other_value },
    { "a_frame_that_filled_the_read_buffer_still_parses_its_header",
      case_a_frame_that_filled_the_read_buffer_still_parses_its_header },
    { "the_reasons_a_frame_is_not_accepted_are_three_distinct_values",
      case_the_reasons_a_frame_is_not_accepted_are_three_distinct_values },
};

#define CASE_COUNT (sizeof cases / sizeof cases[0])

int main(int argc, char **argv)
{
    return check_main("ethernet", cases, CASE_COUNT, argc, argv);
}
