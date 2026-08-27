/* Static-tier check of the internet header parser.
 *
 * ⚠ Every case starts from `icmp-echo-request-98.hex` — ⚠ octets the Linux
 * kernel put on a TAP device, not a header typed out here
 * (`.claude/rules/testing.md`: hold captured packets as fixtures).
 *
 * ⚠ What is asserted is the outcome, one input at a time
 * (hidetzu/tcpip-stack#33). ⚠ A parser that answered "malformed" to everything
 * would pass a suite that only ever fed it broken headers, so the accepted case
 * and the eight rejected ones are all here together.
 *
 * ⚠ Where a case has to break one field, it repairs the header checksum
 * afterwards with `internet_checksum` — ⚠ deliberately the same function
 * `src/ipv4.c` uses, so this file is not a second implementation of that
 * question (`CLAUDE.md` §3). ⚠ What holds that function honest is
 * `tests/test_checksum.c`, against numbers the kernel computed. ⚠ Without the
 * repair every case below would come back as the checksum outcome and would
 * assert nothing about the field it was named for. */
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "check.h"
#include "checksum.h"
#include "ethernet.h"
#include "ipv4.h"

/* ⚠ Where each field sits, read here rather than asked of the parser. ⚠ This is
 * a second copy of the layout in `src/ipv4.c`, and it is on purpose: a check
 * that asked the parser where a field was would agree with it by construction.
 * ⚠ The cross-check that stops the two drifting is
 * `every_field_is_read_as_the_capture_holds_it`, which reads all fourteen
 * octets by hand and requires the parsed header to match
 * (`CLAUDE.md` §3: if unavoidable, cross-check them mechanically). */
#define AT_VERSION_AND_LENGTH 0
#define AT_TYPE_OF_SERVICE 1
#define AT_TOTAL_LENGTH 2
#define AT_IDENTIFICATION 4
#define AT_FLAGS_AND_OFFSET 6
#define AT_TIME_TO_LIVE 8
#define AT_PROTOCOL 9
#define AT_HEADER_CHECKSUM 10
#define AT_SOURCE_ADDRESS 12
#define AT_DESTINATION_ADDRESS 16

/* One datagram under test: the octets that followed the ethernet header, and
 * how many of them the case decided had arrived. */
struct datagram {
    unsigned char octets[128];
    size_t bytes;
};

static bool load_the_echo_request(struct datagram *into)
{
    unsigned char frame[256];
    long bytes = check_load_fixture("icmp-echo-request-98.hex", frame, sizeof frame);
    if (bytes < 0) {
        return false;
    }
    if (bytes != 98) {
        fprintf(stderr, "  the captured echo request is 98 octets, this one is %ld\n", bytes);
        return false;
    }
    into->bytes = (size_t)bytes - ETHERNET_HEADER_BYTES;
    memcpy(into->octets, frame + ETHERNET_HEADER_BYTES, into->bytes);
    return true;
}

static unsigned read_16(const unsigned char *at)
{
    return ((unsigned)at[0] << 8) | at[1];
}

static void write_16(unsigned char *at, unsigned value)
{
    at[0] = (unsigned char)(value >> 8);
    at[1] = (unsigned char)(value & 0xff);
}

/* ⚠ RFC 1071's generation, applied again after a case broke a field. */
static void repair_the_header_checksum(struct datagram *datagram)
{
    size_t header_bytes =
        (size_t)(datagram->octets[AT_VERSION_AND_LENGTH] & 0x0f) * IPV4_HEADER_LENGTH_UNIT;
    write_16(datagram->octets + AT_HEADER_CHECKSUM, 0);
    write_16(datagram->octets + AT_HEADER_CHECKSUM,
             internet_checksum(datagram->octets, header_bytes));
}

static const char *name_of(enum ipv4_parse answer)
{
    switch (answer) {
    case IPV4_PARSE_OK:
        return "IPV4_PARSE_OK";
    case IPV4_PARSE_MALFORMED:
        return "IPV4_PARSE_MALFORMED";
    case IPV4_PARSE_NOT_HANDLED:
        return "IPV4_PARSE_NOT_HANDLED";
    case IPV4_PARSE_CHECKSUM_DISAGREES:
        return "IPV4_PARSE_CHECKSUM_DISAGREES";
    case IPV4_PARSE_FRAGMENT:
        return "IPV4_PARSE_FRAGMENT";
    }
    return "a value with no name";
}

static bool answer_is(const char *what, const struct datagram *datagram,
                      enum ipv4_parse expected)
{
    struct ipv4_header header;
    enum ipv4_parse answer = ipv4_parse_header(datagram->octets, datagram->bytes, &header);
    if (answer != expected) {
        fprintf(stderr, "  %s: expected %s, got %s\n", what, name_of(expected),
                name_of(answer));
        return false;
    }
    return true;
}

/* ⚠ The cross-check named at the top of this file. Every field is read from the
 * octets by hand and the parsed header must agree, field by field. */
static bool case_every_field_is_read_as_the_capture_holds_it(void)
{
    struct datagram datagram;
    if (!load_the_echo_request(&datagram)) {
        return false;
    }
    const unsigned char *o = datagram.octets;

    struct ipv4_header header;
    enum ipv4_parse answer = ipv4_parse_header(o, datagram.bytes, &header);
    if (answer != IPV4_PARSE_OK) {
        fprintf(stderr, "  the captured echo request came back as %s\n", name_of(answer));
        return false;
    }

    bool ok = true;
#define SAME(field, expected)                                                        \
    do {                                                                             \
        unsigned long got = (unsigned long)(header.field);                           \
        unsigned long want = (unsigned long)(expected);                              \
        if (got != want) {                                                           \
            fprintf(stderr, "  %s: the octets say %lu, the header says %lu\n",        \
                    #field, want, got);                                              \
            ok = false;                                                              \
        }                                                                            \
    } while (0)

    SAME(version, o[AT_VERSION_AND_LENGTH] >> 4);
    SAME(internet_header_length, o[AT_VERSION_AND_LENGTH] & 0x0f);
    SAME(type_of_service, o[AT_TYPE_OF_SERVICE]);
    SAME(total_length, read_16(o + AT_TOTAL_LENGTH));
    SAME(identification, read_16(o + AT_IDENTIFICATION));
    SAME(flags, read_16(o + AT_FLAGS_AND_OFFSET) >> 13);
    SAME(fragment_offset, read_16(o + AT_FLAGS_AND_OFFSET) & 0x1fff);
    SAME(time_to_live, o[AT_TIME_TO_LIVE]);
    SAME(protocol, o[AT_PROTOCOL]);
    SAME(header_checksum, read_16(o + AT_HEADER_CHECKSUM));
#undef SAME

    if (memcmp(header.source_address, o + AT_SOURCE_ADDRESS, IPV4_ADDRESS_BYTES) != 0) {
        fputs("  source_address does not match the octets\n", stderr);
        ok = false;
    }
    if (memcmp(header.destination_address, o + AT_DESTINATION_ADDRESS,
               IPV4_ADDRESS_BYTES) != 0) {
        fputs("  destination_address does not match the octets\n", stderr);
        ok = false;
    }

    /* ⚠ The other half: the capture is one particular datagram, and a parser
     * that returned zeroes for everything would satisfy nothing above only if
     * the octets are actually non-trivial. ⚠ These four are what the kernel
     * chose, and they are checked as values (`verify` §5). */
    if (header.version != IPV4_VERSION || header.internet_header_length != 5 ||
        header.time_to_live == 0 || header.protocol == 0) {
        fprintf(stderr, "  the capture no longer holds version 4, IHL 5, a non-zero "
                        "Time to Live and a non-zero Protocol: %u/%u/%u/%u\n",
                header.version, header.internet_header_length, header.time_to_live,
                header.protocol);
        ok = false;
    }
    return ok;
}

/* ⚠ RFC 791 counts the fixed header as five 32-bit words. Fewer octets than
 * that arrived and nothing can be read at all. */
static bool case_fewer_octets_than_a_header_needs(void)
{
    struct datagram datagram;
    if (!load_the_echo_request(&datagram)) {
        return false;
    }
    bool ok = true;
    size_t needed = IPV4_HEADER_LENGTH_MINIMUM * IPV4_HEADER_LENGTH_UNIT;
    for (size_t bytes = 0; bytes < needed; bytes++) {
        datagram.bytes = bytes;
        char what[64];
        snprintf(what, sizeof what, "%zu octets arrived", bytes);
        if (!answer_is(what, &datagram, IPV4_PARSE_MALFORMED)) {
            ok = false;
        }
    }
    /* ⚠ The other half: exactly a header's worth is not malformed for being
     * short. ⚠ Total Length is set to match, so the case asserts the boundary
     * and not something else. */
    datagram.bytes = needed;
    write_16(datagram.octets + AT_TOTAL_LENGTH, (unsigned)needed);
    repair_the_header_checksum(&datagram);
    if (!answer_is("exactly a header's worth arrived", &datagram, IPV4_PARSE_OK)) {
        ok = false;
    }
    return ok;
}

/* ⚠ RFC 791: "Note that the minimum value for a correct header is 5."
 * ⚠ The document calls it not correct, so the sender is wrong: malformed, and
 * ⚠ not "well-formed but unsupported" (hidetzu/tcpip-stack#33 Owner Decision 2). */
static bool case_an_internet_header_length_below_five_is_malformed(void)
{
    bool ok = true;
    for (unsigned length = 0; length < IPV4_HEADER_LENGTH_MINIMUM; length++) {
        struct datagram datagram;
        if (!load_the_echo_request(&datagram)) {
            return false;
        }
        datagram.octets[AT_VERSION_AND_LENGTH] =
            (unsigned char)((IPV4_VERSION << 4) | length);
        /* ⚠ Not repaired: with an IHL below 5 there is no header length to
         * compute a checksum over. ⚠ What this asserts is that the length is
         * judged before the checksum is, which is the approved order. */
        char what[64];
        snprintf(what, sizeof what, "IHL %u", length);
        if (!answer_is(what, &datagram, IPV4_PARSE_MALFORMED)) {
            ok = false;
        }
    }
    return ok;
}

/* ⚠ RFC 791: "Bit 0: reserved, must be zero." ⚠ Set means the sender broke what
 * the document states (Owner Decision 2, ADR 0010). */
static bool case_the_reserved_flag_bit_is_malformed(void)
{
    struct datagram datagram;
    if (!load_the_echo_request(&datagram)) {
        return false;
    }
    unsigned flags_and_offset = read_16(datagram.octets + AT_FLAGS_AND_OFFSET);
    write_16(datagram.octets + AT_FLAGS_AND_OFFSET,
             flags_and_offset | ((unsigned)IPV4_FLAG_RESERVED << 13));
    repair_the_header_checksum(&datagram);
    return answer_is("the reserved bit set", &datagram, IPV4_PARSE_MALFORMED);
}

/* ⚠ Both lengths in the header are assertions by whoever sent them, and both
 * are checked against what actually arrived (`.claude/rules/c.md`). */
static bool case_a_length_larger_than_what_arrived_is_malformed(void)
{
    bool ok = true;

    struct datagram datagram;
    if (!load_the_echo_request(&datagram)) {
        return false;
    }
    /* The header claims six words; twenty octets are here. */
    datagram.bytes = IPV4_HEADER_LENGTH_MINIMUM * IPV4_HEADER_LENGTH_UNIT;
    datagram.octets[AT_VERSION_AND_LENGTH] = (unsigned char)((IPV4_VERSION << 4) | 6);
    if (!answer_is("IHL 6 with 20 octets here", &datagram, IPV4_PARSE_MALFORMED)) {
        ok = false;
    }

    if (!load_the_echo_request(&datagram)) {
        return false;
    }
    /* The datagram claims one octet more than arrived. */
    write_16(datagram.octets + AT_TOTAL_LENGTH, (unsigned)datagram.bytes + 1);
    repair_the_header_checksum(&datagram);
    char what[64];
    snprintf(what, sizeof what, "Total Length %zu with %zu octets here",
             datagram.bytes + 1, datagram.bytes);
    if (!answer_is(what, &datagram, IPV4_PARSE_MALFORMED)) {
        ok = false;
    }

    /* ⚠ The other half: exactly as many as it claims is not malformed. */
    if (!load_the_echo_request(&datagram)) {
        return false;
    }
    write_16(datagram.octets + AT_TOTAL_LENGTH, (unsigned)datagram.bytes);
    repair_the_header_checksum(&datagram);
    if (!answer_is("Total Length equal to what arrived", &datagram, IPV4_PARSE_OK)) {
        ok = false;
    }
    return ok;
}

/* ⚠ Truncation is decided before support, the order ADR 0005 set for ARP.
 * ⚠ A datagram that does not hold what it says it holds is malformed whether or
 * not we would have handled it.
 *
 * ⚠ An earlier version of this case fed in nineteen octets, which the first
 * length gate catches before either question is reached — ⚠ it passed with the
 * support test moved in front of the truncation test, and so asserted nothing
 * about the order it is named for. ⚠ Every input below carries at least a fixed
 * header, so the two tests are the only ones left to order. */
static bool case_truncation_is_decided_before_support(void)
{
    bool ok = true;
    size_t fixed = IPV4_HEADER_LENGTH_MINIMUM * IPV4_HEADER_LENGTH_UNIT;

    /* ⚠ An unsupported version, and a header claiming six words with five
     * words' worth here. ⚠ Both questions are live and truncation must win. */
    struct datagram datagram;
    if (!load_the_echo_request(&datagram)) {
        return false;
    }
    datagram.octets[AT_VERSION_AND_LENGTH] = (unsigned char)((6 << 4) | 6);
    datagram.bytes = fixed;
    if (!answer_is("version 6, IHL 6, 20 octets here", &datagram, IPV4_PARSE_MALFORMED)) {
        ok = false;
    }

    /* ⚠ The same, with Total Length as the lie instead of IHL. */
    if (!load_the_echo_request(&datagram)) {
        return false;
    }
    datagram.octets[AT_VERSION_AND_LENGTH] =
        (unsigned char)((6 << 4) | IPV4_HEADER_LENGTH_MINIMUM);
    write_16(datagram.octets + AT_TOTAL_LENGTH, (unsigned)datagram.bytes + 1);
    repair_the_header_checksum(&datagram);
    if (!answer_is("version 6, Total Length one octet longer than arrived", &datagram,
                   IPV4_PARSE_MALFORMED)) {
        ok = false;
    }

    /* ⚠ Options and a lie about the length together: unsupported must not win
     * over a header that is not all here either. */
    if (!load_the_echo_request(&datagram)) {
        return false;
    }
    datagram.octets[AT_VERSION_AND_LENGTH] = (unsigned char)((IPV4_VERSION << 4) | 15);
    datagram.bytes = fixed;
    if (!answer_is("IHL 15 with 20 octets here", &datagram, IPV4_PARSE_MALFORMED)) {
        ok = false;
    }

    /* ⚠ The other half: with nothing truncated, the same unsupported version is
     * reported as unsupported. ⚠ Without this the case would pass for a parser
     * that answered malformed to everything. */
    if (!load_the_echo_request(&datagram)) {
        return false;
    }
    datagram.octets[AT_VERSION_AND_LENGTH] =
        (unsigned char)((6 << 4) | IPV4_HEADER_LENGTH_MINIMUM);
    repair_the_header_checksum(&datagram);
    if (!answer_is("version 6, nothing truncated", &datagram, IPV4_PARSE_NOT_HANDLED)) {
        ok = false;
    }
    return ok;
}

/* ⚠ Its own outcome. ⚠ A header whose checksum does not agree is neither the
 * sender getting the format wrong nor something we decline to handle. */
static bool case_a_header_checksum_that_disagrees_is_its_own_outcome(void)
{
    bool ok = true;
    /* ⚠ Every octet of the header in turn, so this cannot pass by catching one
     * lucky position (`verify` §5). */
    for (size_t i = 0; i < IPV4_HEADER_LENGTH_MINIMUM * IPV4_HEADER_LENGTH_UNIT; i++) {
        struct datagram datagram;
        if (!load_the_echo_request(&datagram)) {
            return false;
        }
        /* ⚠ Skipped: flipping these changes which outcome is correct, and this
         * case is about the checksum and nothing else. */
        if (i == AT_VERSION_AND_LENGTH || i == AT_TOTAL_LENGTH ||
            i == AT_TOTAL_LENGTH + 1 || i == AT_FLAGS_AND_OFFSET ||
            i == AT_FLAGS_AND_OFFSET + 1) {
            continue;
        }
        datagram.octets[i] = (unsigned char)(datagram.octets[i] ^ 0xff);
        char what[64];
        snprintf(what, sizeof what, "octet %zu of the header flipped", i);
        if (!answer_is(what, &datagram, IPV4_PARSE_CHECKSUM_DISAGREES)) {
            ok = false;
        }
    }
    return ok;
}

/* ⚠ Well-formed and unsupported: the sender is fine, we do not handle it.
 * ⚠ Never counted with malformed (`.claude/rules/layers.md`). */
static bool case_a_version_that_is_not_four_is_not_handled(void)
{
    bool ok = true;
    for (unsigned version = 0; version < 16; version++) {
        if (version == IPV4_VERSION) {
            continue;
        }
        struct datagram datagram;
        if (!load_the_echo_request(&datagram)) {
            return false;
        }
        datagram.octets[AT_VERSION_AND_LENGTH] =
            (unsigned char)((version << 4) | IPV4_HEADER_LENGTH_MINIMUM);
        repair_the_header_checksum(&datagram);
        char what[64];
        snprintf(what, sizeof what, "version %u", version);
        if (!answer_is(what, &datagram, IPV4_PARSE_NOT_HANDLED)) {
            ok = false;
        }
    }
    return ok;
}

/* ⚠ A header longer than five words carries Options, and Options are not read
 * here. ⚠ The sender is fine: unsupported, not malformed. */
static bool case_a_header_carrying_options_is_not_handled(void)
{
    bool ok = true;
    for (unsigned length = IPV4_HEADER_LENGTH_MINIMUM + 1;
         length <= IPV4_HEADER_LENGTH_MAXIMUM; length++) {
        struct datagram datagram;
        if (!load_the_echo_request(&datagram)) {
            return false;
        }
        datagram.octets[AT_VERSION_AND_LENGTH] =
            (unsigned char)((IPV4_VERSION << 4) | length);
        repair_the_header_checksum(&datagram);
        char what[64];
        snprintf(what, sizeof what, "IHL %u", length);
        if (!answer_is(what, &datagram, IPV4_PARSE_NOT_HANDLED)) {
            ok = false;
        }
    }
    return ok;
}

/* ⚠ Its own outcome (Owner Decision 1). ⚠ A fragment is perfectly well formed;
 * reassembly is simply not written, and folding it in with an unsupported
 * version would mix two counts that mean different things. */
static bool case_a_fragment_is_its_own_outcome(void)
{
    bool ok = true;

    struct datagram datagram;
    if (!load_the_echo_request(&datagram)) {
        return false;
    }
    /* More Fragments set, offset still zero: the first piece. */
    write_16(datagram.octets + AT_FLAGS_AND_OFFSET, (unsigned)IPV4_FLAG_MORE_FRAGMENTS << 13);
    repair_the_header_checksum(&datagram);
    if (!answer_is("More Fragments set", &datagram, IPV4_PARSE_FRAGMENT)) {
        ok = false;
    }

    if (!load_the_echo_request(&datagram)) {
        return false;
    }
    /* ⚠ A non-zero offset with More Fragments clear: the last piece. ⚠ Missing
     * this is how a stack reassembles nothing and reports success. */
    write_16(datagram.octets + AT_FLAGS_AND_OFFSET, 1);
    repair_the_header_checksum(&datagram);
    if (!answer_is("a non-zero Fragment Offset", &datagram, IPV4_PARSE_FRAGMENT)) {
        ok = false;
    }

    /* ⚠ The other half: Don't Fragment is not a fragment. ⚠ The capture has it
     * set already, so a parser testing the wrong bit would fail here. */
    if (!load_the_echo_request(&datagram)) {
        return false;
    }
    write_16(datagram.octets + AT_FLAGS_AND_OFFSET, (unsigned)IPV4_FLAG_DONT_FRAGMENT << 13);
    repair_the_header_checksum(&datagram);
    if (!answer_is("Don't Fragment set", &datagram, IPV4_PARSE_OK)) {
        ok = false;
    }
    return ok;
}

/* ⚠ Nothing above the header is looked at (hidetzu/tcpip-stack#33 Out of
 * Scope). ⚠ Asserted by breaking every octet after the header and requiring the
 * same answer — including the ICMP checksum the kernel computed. */
static bool case_nothing_beyond_the_header_is_read(void)
{
    struct datagram datagram;
    if (!load_the_echo_request(&datagram)) {
        return false;
    }
    size_t header_bytes = IPV4_HEADER_LENGTH_MINIMUM * IPV4_HEADER_LENGTH_UNIT;
    for (size_t i = header_bytes; i < datagram.bytes; i++) {
        datagram.octets[i] = (unsigned char)(datagram.octets[i] ^ 0xff);
    }
    return answer_is("every octet after the header inverted", &datagram, IPV4_PARSE_OK);
}

/* ⚠ A caller must be able to say which address was asked for even when it
 * declines the datagram, without reading the octets itself. */
static bool case_the_addresses_are_filled_in_for_a_datagram_we_decline(void)
{
    struct datagram datagram;
    if (!load_the_echo_request(&datagram)) {
        return false;
    }
    unsigned char source[IPV4_ADDRESS_BYTES];
    unsigned char destination[IPV4_ADDRESS_BYTES];
    memcpy(source, datagram.octets + AT_SOURCE_ADDRESS, IPV4_ADDRESS_BYTES);
    memcpy(destination, datagram.octets + AT_DESTINATION_ADDRESS, IPV4_ADDRESS_BYTES);

    datagram.octets[AT_VERSION_AND_LENGTH] =
        (unsigned char)((6 << 4) | IPV4_HEADER_LENGTH_MINIMUM);
    repair_the_header_checksum(&datagram);

    struct ipv4_header header;
    enum ipv4_parse answer = ipv4_parse_header(datagram.octets, datagram.bytes, &header);
    if (answer != IPV4_PARSE_NOT_HANDLED) {
        fprintf(stderr, "  expected IPV4_PARSE_NOT_HANDLED, got %s\n", name_of(answer));
        return false;
    }
    if (memcmp(header.source_address, source, IPV4_ADDRESS_BYTES) != 0 ||
        memcmp(header.destination_address, destination, IPV4_ADDRESS_BYTES) != 0) {
        fputs("  the addresses were not filled in for a datagram we declined\n", stderr);
        return false;
    }
    return true;
}

/* ⚠ Nothing is left over from a previous call. ⚠ A header filled in by the
 * caller and then handed to a read that fails must come back zeroed, or a
 * caller reads the last datagram's addresses as this one's. */
static bool case_a_read_that_cannot_be_made_leaves_nothing_behind(void)
{
    struct ipv4_header header;
    memset(&header, 0xaa, sizeof header);

    static const unsigned char nothing[1] = { 0 };
    if (ipv4_parse_header(nothing, 0, &header) != IPV4_PARSE_MALFORMED) {
        fputs("  zero octets did not come back malformed\n", stderr);
        return false;
    }

    struct ipv4_header zeroed;
    memset(&zeroed, 0, sizeof zeroed);
    if (memcmp(&header, &zeroed, sizeof header) != 0) {
        fputs("  the header still held what was in it before the call\n", stderr);
        return false;
    }
    return true;
}

static const struct test_case cases[] = {
    { "every_field_is_read_as_the_capture_holds_it",
      case_every_field_is_read_as_the_capture_holds_it },
    { "fewer_octets_than_a_header_needs", case_fewer_octets_than_a_header_needs },
    { "an_internet_header_length_below_five_is_malformed",
      case_an_internet_header_length_below_five_is_malformed },
    { "the_reserved_flag_bit_is_malformed", case_the_reserved_flag_bit_is_malformed },
    { "a_length_larger_than_what_arrived_is_malformed",
      case_a_length_larger_than_what_arrived_is_malformed },
    { "truncation_is_decided_before_support", case_truncation_is_decided_before_support },
    { "a_header_checksum_that_disagrees_is_its_own_outcome",
      case_a_header_checksum_that_disagrees_is_its_own_outcome },
    { "a_version_that_is_not_four_is_not_handled",
      case_a_version_that_is_not_four_is_not_handled },
    { "a_header_carrying_options_is_not_handled",
      case_a_header_carrying_options_is_not_handled },
    { "a_fragment_is_its_own_outcome", case_a_fragment_is_its_own_outcome },
    { "nothing_beyond_the_header_is_read", case_nothing_beyond_the_header_is_read },
    { "the_addresses_are_filled_in_for_a_datagram_we_decline",
      case_the_addresses_are_filled_in_for_a_datagram_we_decline },
    { "a_read_that_cannot_be_made_leaves_nothing_behind",
      case_a_read_that_cannot_be_made_leaves_nothing_behind },
};

int main(int argc, char **argv)
{
    return check_main("ipv4", cases, sizeof cases / sizeof cases[0], argc, argv);
}
