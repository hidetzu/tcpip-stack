/* Static-tier check of the TCP header parser.
 *
 * ⚠ Every case starts from `tcp-syn-74.hex` — ⚠ octets the Linux kernel put on
 * a TAP device while opening a connection, not a header typed out here
 * (`.claude/rules/testing.md`: hold captured packets as fixtures).
 *
 * ⚠ The fixture is why this file exists at all: the kernel's own SYN carries a
 * 40-octet header, ⚠ **20 octets of which are options**. A parser that refused
 * options would refuse every real SYN there is (hidetzu/tcpip-stack#40).
 *
 * ⚠ Nothing here checks a checksum. It is computed over a pseudo-header that is
 * not in the segment (hidetzu/tcpip-stack#41). */
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "check.h"
#include "checksum.h"
#include "ethernet.h"
#include "ipv4.h"
#include "tcp.h"

/* ⚠ Where each field sits, read here rather than asked of the parser — the same
 * deliberate second copy `tests/test_ipv4.c` and `tests/test_icmp.c` keep, and
 * ⚠ the cross-check that stops the two drifting is
 * `the_kernels_syn_is_read_as_it_holds_it` (`CLAUDE.md` §3). */
#define AT_SOURCE_PORT 0
#define AT_DESTINATION_PORT 2
#define AT_SEQUENCE_NUMBER 4
#define AT_ACKNOWLEDGMENT_NUMBER 8
#define AT_OFFSET_AND_RESERVED 12
#define AT_CONTROL_BITS 13
#define AT_WINDOW 14
#define AT_CHECKSUM 16
#define AT_URGENT_POINTER 18

struct segment {
    unsigned char octets[256];
    size_t bytes;
    /* ⚠ The two addresses the pseudo-header needs, carried with the segment so a
     * case never has to remember to pass them. ⚠ Read out of the same captured
     * frame, never typed here. */
    unsigned char source_address[TCP_ADDRESS_BYTES];
    unsigned char destination_address[TCP_ADDRESS_BYTES];
};

/* The TCP segment inside the captured frame, found by reading the internet
 * header's own length — never by writing 34 here. */
static bool load_the_syn(struct segment *into)
{
    unsigned char frame[256];
    long bytes = check_load_fixture("tcp-syn-74.hex", frame, sizeof frame);
    if (bytes < 0) {
        return false;
    }
    if (bytes != 74) {
        fprintf(stderr, "  the captured SYN is 74 octets, this one is %ld\n", bytes);
        return false;
    }
    size_t header_bytes =
        (size_t)(frame[ETHERNET_HEADER_BYTES] & 0x0f) * IPV4_HEADER_LENGTH_UNIT;
    size_t at = ETHERNET_HEADER_BYTES + header_bytes;
    into->bytes = (size_t)bytes - at;
    memcpy(into->octets, frame + at, into->bytes);
    memcpy(into->source_address, frame + ETHERNET_HEADER_BYTES + 12, TCP_ADDRESS_BYTES);
    memcpy(into->destination_address, frame + ETHERNET_HEADER_BYTES + 16,
           TCP_ADDRESS_BYTES);
    return true;
}

/* ⚠ RFC 793's own generation, applied again after a case broke a field.
 * ⚠ Without it every case below would come back as the checksum answer and would
 * assert nothing about the field it was named for. */
static void repair_the_checksum(struct segment *s)
{
    unsigned char pseudo[12];
    memcpy(pseudo, s->source_address, TCP_ADDRESS_BYTES);
    memcpy(pseudo + TCP_ADDRESS_BYTES, s->destination_address, TCP_ADDRESS_BYTES);
    pseudo[8] = 0;
    pseudo[9] = TCP_PROTOCOL_NUMBER;
    pseudo[10] = (unsigned char)(s->bytes >> 8);
    pseudo[11] = (unsigned char)(s->bytes & 0xff);

    unsigned sum = internet_checksum_of_two(pseudo, sizeof pseudo, s->octets, s->bytes,
                                            AT_CHECKSUM);
    s->octets[AT_CHECKSUM] = (unsigned char)(sum >> 8);
    s->octets[AT_CHECKSUM + 1] = (unsigned char)(sum & 0xff);
}

static unsigned read_16(const unsigned char *at)
{
    return ((unsigned)at[0] << 8) | at[1];
}

static unsigned long read_32(const unsigned char *at)
{
    return ((unsigned long)at[0] << 24) | ((unsigned long)at[1] << 16) |
           ((unsigned long)at[2] << 8) | at[3];
}

static const char *name_of(enum tcp_parse answer)
{
    switch (answer) {
    case TCP_PARSE_OK:
        return "TCP_PARSE_OK";
    case TCP_PARSE_MALFORMED:
        return "TCP_PARSE_MALFORMED";
    case TCP_PARSE_CHECKSUM_DISAGREES:
        return "TCP_PARSE_CHECKSUM_DISAGREES";
    }
    return "a value with no name";
}

static bool answer_is(const char *what, const struct segment *s, enum tcp_parse expected)
{
    struct tcp_header header;
    enum tcp_parse answer = tcp_parse_header(s->octets, s->bytes, s->source_address,
                                             s->destination_address, &header);
    if (answer != expected) {
        fprintf(stderr, "  %s: expected %s, got %s\n", what, name_of(expected),
                name_of(answer));
        return false;
    }
    return true;
}

/* Writes a six-bit Reserved across the two octets it lives in. */
static void write_reserved(struct segment *s, unsigned reserved)
{
    s->octets[AT_OFFSET_AND_RESERVED] =
        (unsigned char)((s->octets[AT_OFFSET_AND_RESERVED] & 0xf0) |
                        ((reserved >> 2) & 0x0f));
    s->octets[AT_CONTROL_BITS] =
        (unsigned char)((s->octets[AT_CONTROL_BITS] & 0x3f) | ((reserved & 0x03) << 6));
}

static void write_data_offset(struct segment *s, unsigned words)
{
    s->octets[AT_OFFSET_AND_RESERVED] =
        (unsigned char)((words << 4) | (s->octets[AT_OFFSET_AND_RESERVED] & 0x0f));
}

/* ⚠ The cross-check. Every field is read from the octets by hand and the parsed
 * header must agree, field by field. */
static bool case_the_kernels_syn_is_read_as_it_holds_it(void)
{
    struct segment s;
    if (!load_the_syn(&s)) {
        return false;
    }
    const unsigned char *o = s.octets;

    struct tcp_header header;
    enum tcp_parse answer =
        tcp_parse_header(o, s.bytes, s.source_address, s.destination_address, &header);
    if (answer != TCP_PARSE_OK) {
        fprintf(stderr, "  the captured SYN came back as %s\n", name_of(answer));
        return false;
    }

    bool ok = true;
#define SAME(field, expected)                                                     \
    do {                                                                          \
        unsigned long got = (unsigned long)(header.field);                        \
        unsigned long want = (unsigned long)(expected);                           \
        if (got != want) {                                                        \
            fprintf(stderr, "  %s: the octets say %lu, the header says %lu\n",     \
                    #field, want, got);                                           \
            ok = false;                                                           \
        }                                                                         \
    } while (0)

    SAME(source_port, read_16(o + AT_SOURCE_PORT));
    SAME(destination_port, read_16(o + AT_DESTINATION_PORT));
    SAME(sequence_number, read_32(o + AT_SEQUENCE_NUMBER));
    SAME(acknowledgment_number, read_32(o + AT_ACKNOWLEDGMENT_NUMBER));
    SAME(data_offset, o[AT_OFFSET_AND_RESERVED] >> 4);
    SAME(reserved, ((o[AT_OFFSET_AND_RESERVED] & 0x0f) << 2) | (o[AT_CONTROL_BITS] >> 6));
    SAME(control_bits, o[AT_CONTROL_BITS] & 0x3f);
    SAME(window, read_16(o + AT_WINDOW));
    SAME(checksum, read_16(o + AT_CHECKSUM));
    SAME(urgent_pointer, read_16(o + AT_URGENT_POINTER));
    SAME(data_begins_at, (size_t)(o[AT_OFFSET_AND_RESERVED] >> 4) * TCP_HEADER_LENGTH_UNIT);
#undef SAME

    /* ⚠ The other half: the capture is one particular segment, and a parser that
     * returned zeroes throughout would satisfy everything above only if the
     * octets are non-trivial. ⚠ These are what the kernel actually chose. */
    if (header.control_bits != TCP_CONTROL_SYN) {
        fprintf(stderr, "  the capture no longer holds a bare SYN: control bits 0x%02x\n",
                header.control_bits);
        ok = false;
    }
    if (header.data_offset <= TCP_HEADER_LENGTH_MINIMUM) {
        fprintf(stderr, "  the capture no longer carries options: data offset %u\n",
                header.data_offset);
        ok = false;
    }
    if (header.sequence_number == 0 || header.window == 0 || header.checksum == 0 ||
        header.source_port == 0) {
        fputs("  the capture no longer holds a non-zero sequence number, window, "
              "checksum and source port\n", stderr);
        ok = false;
    }
    /* ⚠ And what a SYN holds that a later segment would not. */
    if (header.acknowledgment_number != 0 || header.urgent_pointer != 0 ||
        header.reserved != 0) {
        fputs("  the captured SYN no longer has a zero acknowledgment number, "
              "urgent pointer and reserved\n", stderr);
        ok = false;
    }
    return ok;
}

/* ⚠ RFC 793's fields above Options occupy five 32-bit words. Fewer octets than
 * that arrived and nothing can be read at all. */
static bool case_fewer_octets_than_the_fixed_fields(void)
{
    struct segment s;
    if (!load_the_syn(&s)) {
        return false;
    }
    bool ok = true;
    for (size_t bytes = 0; bytes < TCP_FIXED_HEADER_BYTES; bytes++) {
        s.bytes = bytes;
        char what[64];
        snprintf(what, sizeof what, "%zu octets arrived", bytes);
        if (!answer_is(what, &s, TCP_PARSE_MALFORMED)) {
            ok = false;
        }
    }
    /* ⚠ The other half: exactly the fixed fields, with a Data Offset that says
     * so, is a header we accept. */
    s.bytes = TCP_FIXED_HEADER_BYTES;
    write_data_offset(&s, TCP_HEADER_LENGTH_MINIMUM);
    repair_the_checksum(&s);
    if (!answer_is("exactly the fixed fields arrived", &s, TCP_PARSE_OK)) {
        ok = false;
    }
    return ok;
}

/* ⚠ A header saying it is shorter than its own fixed fields is contradicting
 * itself. ⚠ RFC 793 states no minimum for Data Offset — this is our reading,
 * and ADR 0013 records it as ours. */
static bool case_a_data_offset_below_the_fixed_header_is_malformed(void)
{
    bool ok = true;
    for (unsigned words = 0; words < TCP_HEADER_LENGTH_MINIMUM; words++) {
        struct segment s;
        if (!load_the_syn(&s)) {
            return false;
        }
        write_data_offset(&s, words);
        repair_the_checksum(&s);
        char what[64];
        snprintf(what, sizeof what, "data offset %u", words);
        if (!answer_is(what, &s, TCP_PARSE_MALFORMED)) {
            ok = false;
        }
    }
    return ok;
}

/* ⚠ The header's own length is an assertion by whoever sent it, checked against
 * what actually arrived (`.claude/rules/c.md`). */
static bool case_a_data_offset_beyond_what_arrived_is_malformed(void)
{
    bool ok = true;
    for (unsigned words = TCP_HEADER_LENGTH_MINIMUM; words <= TCP_HEADER_LENGTH_MAXIMUM;
         words++) {
        struct segment s;
        if (!load_the_syn(&s)) {
            return false;
        }
        write_data_offset(&s, words);
        /* One octet short of what the header claims. */
        s.bytes = (size_t)words * TCP_HEADER_LENGTH_UNIT - 1;
        /* ⚠ Repaired after the length is set: the TCP Length in the
         * pseudo-header is this extent, so the two move together. */
        repair_the_checksum(&s);
        char what[64];
        snprintf(what, sizeof what, "data offset %u with %zu octets here", words, s.bytes);
        if (!answer_is(what, &s, TCP_PARSE_MALFORMED)) {
            ok = false;
        }
    }

    /* ⚠ The other half: exactly as many octets as it claims is not malformed.
     * ⚠ The options are made all No-Operation so this case turns on the length
     * and on nothing else. */
    for (unsigned words = TCP_HEADER_LENGTH_MINIMUM; words <= TCP_HEADER_LENGTH_MAXIMUM;
         words++) {
        struct segment s;
        if (!load_the_syn(&s)) {
            return false;
        }
        write_data_offset(&s, words);
        s.bytes = (size_t)words * TCP_HEADER_LENGTH_UNIT;
        memset(s.octets + TCP_FIXED_HEADER_BYTES, TCP_OPTION_NO_OPERATION,
               s.bytes - TCP_FIXED_HEADER_BYTES);
        repair_the_checksum(&s);
        char what[64];
        snprintf(what, sizeof what, "data offset %u with exactly that many octets", words);
        if (!answer_is(what, &s, TCP_PARSE_OK)) {
            ok = false;
        }
    }
    return ok;
}

/* ⚠ RFC 793: "Reserved: 6 bits - Reserved for future use.  Must be zero."
 * ⚠ Set means the sender broke what the document states. ⚠ The document does not
 * tell a receiver to reject it — that is our reading, the third time this
 * repository has drawn it from the same shape of sentence (ADR 0013).
 *
 * ⚠ All six bits, and they do not live in one octet: four are the low half of
 * one and two are the top of the next. ⚠ A parser that read only the four would
 * pass a case that tried only the values below 4. */
static bool case_a_reserved_that_is_not_zero_is_malformed(void)
{
    bool ok = true;
    for (unsigned reserved = 1; reserved < 64; reserved++) {
        struct segment s;
        if (!load_the_syn(&s)) {
            return false;
        }
        write_reserved(&s, reserved);
        repair_the_checksum(&s);
        char what[64];
        snprintf(what, sizeof what, "reserved %u", reserved);
        if (!answer_is(what, &s, TCP_PARSE_MALFORMED)) {
            ok = false;
        }
    }

    /* ⚠ The other half: a zero Reserved with every Control Bit set is accepted,
     * so this case cannot pass for a parser that reads the wrong bits. */
    struct segment s;
    if (!load_the_syn(&s)) {
        return false;
    }
    write_reserved(&s, 0);
    s.octets[AT_CONTROL_BITS] = (unsigned char)(s.octets[AT_CONTROL_BITS] | 0x3f);
    repair_the_checksum(&s);
    if (!answer_is("reserved 0 with every control bit set", &s, TCP_PARSE_OK)) {
        ok = false;
    }
    return ok;
}

/* ⚠ The six Control Bits are six separate things, and ⚠ none of them may be
 * read as part of Reserved. */
static bool case_each_control_bit_is_read_on_its_own(void)
{
    static const struct { unsigned bit; const char *name; } bits[] = {
        { TCP_CONTROL_URG, "URG" }, { TCP_CONTROL_ACK, "ACK" },
        { TCP_CONTROL_PSH, "PSH" }, { TCP_CONTROL_RST, "RST" },
        { TCP_CONTROL_SYN, "SYN" }, { TCP_CONTROL_FIN, "FIN" },
    };
    bool ok = true;
    for (size_t i = 0; i < sizeof bits / sizeof bits[0]; i++) {
        struct segment s;
        if (!load_the_syn(&s)) {
            return false;
        }
        write_reserved(&s, 0);
        s.octets[AT_CONTROL_BITS] =
            (unsigned char)((s.octets[AT_CONTROL_BITS] & 0xc0) | bits[i].bit);
        repair_the_checksum(&s);

        struct tcp_header header;
        if (tcp_parse_header(s.octets, s.bytes, s.source_address, s.destination_address,
                             &header) != TCP_PARSE_OK) {
            fprintf(stderr, "  %s alone was declined\n", bits[i].name);
            ok = false;
            continue;
        }
        if (header.control_bits != bits[i].bit) {
            fprintf(stderr, "  %s alone was read as 0x%02x\n", bits[i].name,
                    header.control_bits);
            ok = false;
        }
        if (header.reserved != 0) {
            fprintf(stderr, "  %s alone left reserved at %u\n", bits[i].name,
                    header.reserved);
            ok = false;
        }
    }

    /* ⚠ The other half, and it needs a segment we DECLINE: with Reserved zero,
     * a parser that never masked the Control Bits reports the same six bits and
     * every case above passes. ⚠ So set the two Reserved bits that share the
     * octet and require them not to appear among the Control Bits.
     *
     * ⚠ The segment comes back malformed — Reserved is not zero — and ⚠ the
     * fields are still filled, which is this parser's contract for a segment it
     * declines. ⚠ An earlier version of this case had no such input, and
     * ⚠ removing the mask left it passing. */
    for (unsigned reserved = 1; reserved <= 3; reserved++) {
        struct segment s;
        if (!load_the_syn(&s)) {
            return false;
        }
        write_reserved(&s, reserved);
        s.octets[AT_CONTROL_BITS] =
            (unsigned char)((s.octets[AT_CONTROL_BITS] & 0xc0) | TCP_CONTROL_SYN);
        repair_the_checksum(&s);

        struct tcp_header header;
        if (tcp_parse_header(s.octets, s.bytes, s.source_address, s.destination_address,
                             &header) != TCP_PARSE_MALFORMED) {
            fprintf(stderr, "  reserved %u was not declined\n", reserved);
            ok = false;
            continue;
        }
        if (header.control_bits != TCP_CONTROL_SYN) {
            fprintf(stderr, "  reserved %u leaked into the control bits: 0x%02x\n",
                    reserved, header.control_bits);
            ok = false;
        }
        if (header.reserved != reserved) {
            fprintf(stderr, "  reserved %u was read as %u\n", reserved, header.reserved);
            ok = false;
        }
    }
    return ok;
}

/* ⚠ The one that is a hang and not a wrong answer. ⚠ An option-length of 0
 * leaves the walk where it is, and this case finishing at all is the proof that
 * it does not (`.claude/rules/c.md`: everything here is untrusted input). */
static bool case_an_option_list_that_does_not_walk_is_malformed(void)
{
    bool ok = true;

    /* A header with room for four octets of options, filled by hand. */
    static const struct {
        unsigned char options[4];
        size_t option_bytes;
        const char *what;
    } bad[] = {
        { { 2, 0, 0, 0 }, 4, "an option-length of 0" },
        { { 2, 1, 0, 0 }, 4, "an option-length of 1, which cannot count its own two octets" },
        { { 2, 5, 0, 0 }, 4, "an option-length running past the options" },
        { { 2, 0, 0, 0 }, 1, "an option-kind with no length octet after it" },
        { { 1, 1, 2, 0 }, 4, "a length of 0 reached after two No-Operations" },
    };

    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        struct segment s;
        if (!load_the_syn(&s)) {
            return false;
        }
        size_t header_bytes = TCP_FIXED_HEADER_BYTES + bad[i].option_bytes;
        /* ⚠ Options are a multiple of 32 bits inside the header, so the odd
         * length above is reached by claiming a whole word and cutting the walk
         * short with what the octets hold. */
        size_t words = (header_bytes + TCP_HEADER_LENGTH_UNIT - 1) / TCP_HEADER_LENGTH_UNIT;
        write_data_offset(&s, (unsigned)words);
        s.bytes = words * TCP_HEADER_LENGTH_UNIT;
        memset(s.octets + TCP_FIXED_HEADER_BYTES, TCP_OPTION_NO_OPERATION,
               s.bytes - TCP_FIXED_HEADER_BYTES);
        memcpy(s.octets + TCP_FIXED_HEADER_BYTES, bad[i].options, bad[i].option_bytes);
        repair_the_checksum(&s);
        if (!answer_is(bad[i].what, &s, TCP_PARSE_MALFORMED)) {
            ok = false;
        }
    }

    /* ⚠ The other half: the kernel's own option list walks. ⚠ Without this the
     * case would pass for a parser that called every option list broken. */
    struct segment s;
    if (!load_the_syn(&s)) {
        return false;
    }
    if (!answer_is("the kernel's own options", &s, TCP_PARSE_OK)) {
        ok = false;
    }
    return ok;
}

/* ⚠ RFC 793: "Note that the list of options may be shorter than the data offset
 * field might imply", and End of Option List "is used at the end of all
 * options". ⚠ So what follows it is padding, and padding is not walked. */
static bool case_end_of_option_list_stops_the_walk(void)
{
    struct segment s;
    if (!load_the_syn(&s)) {
        return false;
    }
    size_t options_at = TCP_FIXED_HEADER_BYTES;
    /* ⚠ After the end marker, four octets that would NOT walk if they were
     * read: an option-kind with a length of 0. */
    s.octets[options_at] = TCP_OPTION_END_OF_OPTION_LIST;
    s.octets[options_at + 1] = 2;
    s.octets[options_at + 2] = 0;
    s.octets[options_at + 3] = 0;
    write_data_offset(&s, TCP_HEADER_LENGTH_MINIMUM + 1);
    s.bytes = (size_t)(TCP_HEADER_LENGTH_MINIMUM + 1) * TCP_HEADER_LENGTH_UNIT;
    repair_the_checksum(&s);

    bool ok = answer_is("padding after the end of the option list", &s, TCP_PARSE_OK);

    /* ⚠ The other half: the same four octets WITHOUT the end marker in front of
     * them are malformed, so this case cannot pass for a parser that never
     * walked at all. */
    struct segment without;
    if (!load_the_syn(&without)) {
        return false;
    }
    without.octets[options_at] = 2;
    without.octets[options_at + 1] = 0;
    without.octets[options_at + 2] = 0;
    without.octets[options_at + 3] = 0;
    write_data_offset(&without, TCP_HEADER_LENGTH_MINIMUM + 1);
    without.bytes = (size_t)(TCP_HEADER_LENGTH_MINIMUM + 1) * TCP_HEADER_LENGTH_UNIT;
    repair_the_checksum(&without);
    if (!answer_is("the same octets with no end marker", &without, TCP_PARSE_MALFORMED)) {
        ok = false;
    }
    return ok;
}

/* ⚠ Not one option is interpreted (hidetzu/tcpip-stack#40 Out of Scope).
 *
 * ⚠ Asserted by parsing the kernel's own option list and then a completely
 * different one of the same length, and requiring ⚠ every reported field to be
 * identical — ⚠ **except the checksum, which is not an exception but the point:
 * the options are inside the sum**, so two different lists must give two
 * different checksums. ⚠ Both halves are asserted here.
 *
 * ⚠ An earlier version of this case compared the whole struct and required it
 * to be identical. ⚠ That was true only while nothing checked the checksum
 * (hidetzu/tcpip-stack#41), and it stopped being true with this change rather
 * than drifting.
 *
 * ⚠ RFC 793 says "A TCP must implement all options". ⚠ This implements none, and
 * `docs/SPEC.md` §2 names that gap rather than leaving it silent. */
static bool case_no_option_is_interpreted(void)
{
    struct segment kernels;
    if (!load_the_syn(&kernels)) {
        return false;
    }
    struct tcp_header from_kernels;
    if (tcp_parse_header(kernels.octets, kernels.bytes, kernels.source_address,
                         kernels.destination_address, &from_kernels) != TCP_PARSE_OK) {
        fputs("  the kernel's own SYN was declined\n", stderr);
        return false;
    }

    struct segment other = kernels;
    size_t options_at = TCP_FIXED_HEADER_BYTES;
    size_t options_bytes = from_kernels.data_begins_at - options_at;
    /* ⚠ A different list entirely, and the same length: all No-Operation. */
    memset(other.octets + options_at, TCP_OPTION_NO_OPERATION, options_bytes);
    repair_the_checksum(&other);

    struct tcp_header from_other;
    if (tcp_parse_header(other.octets, other.bytes, other.source_address,
                         other.destination_address, &from_other) != TCP_PARSE_OK) {
        fputs("  a list of No-Operations was declined\n", stderr);
        return false;
    }

    bool ok = true;
#define SAME(field)                                                             \
    do {                                                                        \
        if ((unsigned long)from_kernels.field != (unsigned long)from_other.field) { \
            fprintf(stderr, "  %s changed when only the options changed\n",      \
                    #field);                                                    \
            ok = false;                                                         \
        }                                                                       \
    } while (0)

    SAME(source_port);
    SAME(destination_port);
    SAME(sequence_number);
    SAME(acknowledgment_number);
    SAME(data_offset);
    SAME(reserved);
    SAME(control_bits);
    SAME(window);
    SAME(urgent_pointer);
    SAME(data_begins_at);
#undef SAME

    /* ⚠ The checksum, on the other hand, MUST have changed. ⚠ RFC 793: "All
     * options are included in the checksum." ⚠ If it had not, the options would
     * not be in the sum and the whole of this file's checksum work would be
     * asserting nothing about them. */
    if (from_kernels.checksum == from_other.checksum) {
        fputs("  the checksum did not change when the options did, so they are "
              "not in the sum\n", stderr);
        ok = false;
    }

    /* ⚠ And the data still begins where the Data Offset says, not where the
     * options happened to end. */
    if (from_other.data_begins_at !=
        (size_t)from_other.data_offset * TCP_HEADER_LENGTH_UNIT) {
        fputs("  the data does not begin where the data offset says\n", stderr);
        ok = false;
    }
    return ok;
}

/* ⚠ The one held against something we did not write: the number the Linux
 * kernel put in its own SYN.
 *
 * ⚠ The intact fixture coming back as OK already says the two agree — the
 * checksum is judged before anything else. ⚠ This case says it in its own right,
 * and ⚠ says what happens when each octet that goes into the sum is changed. */
static bool case_the_kernels_checksum_is_reproduced(void)
{
    struct segment intact;
    if (!load_the_syn(&intact)) {
        return false;
    }
    struct tcp_header header;
    if (tcp_parse_header(intact.octets, intact.bytes, intact.source_address,
                         intact.destination_address, &header) != TCP_PARSE_OK) {
        fputs("  the kernel's own SYN did not come back accepted\n", stderr);
        return false;
    }
    /* ⚠ The kernel wrote this number, and we did not. */
    if (header.checksum == 0) {
        fputs("  the capture no longer carries a checksum\n", stderr);
        return false;
    }

    bool ok = true;

    /* ⚠ Every octet of the segment in turn. */
    for (size_t i = 0; i < intact.bytes; i++) {
        struct segment s = intact;
        s.octets[i] = (unsigned char)(s.octets[i] ^ 0xff);
        char what[64];
        snprintf(what, sizeof what, "segment octet %zu flipped", i);
        if (!answer_is(what, &s, TCP_PARSE_CHECKSUM_DISAGREES)) {
            ok = false;
        }
    }

    /* ⚠ And every octet of the two addresses — ⚠ **which are not in the segment
     * at all.** ⚠ This is the only thing that proves the pseudo-header is really
     * in the sum: a parser that summed the segment alone would pass every line
     * above (RFC 793: "This gives the TCP protection against misrouted
     * segments"). */
    for (size_t i = 0; i < TCP_ADDRESS_BYTES; i++) {
        struct segment s = intact;
        s.source_address[i] = (unsigned char)(s.source_address[i] ^ 0xff);
        char what[64];
        snprintf(what, sizeof what, "source address octet %zu flipped", i);
        if (!answer_is(what, &s, TCP_PARSE_CHECKSUM_DISAGREES)) {
            ok = false;
        }

        struct segment d = intact;
        d.destination_address[i] = (unsigned char)(d.destination_address[i] ^ 0xff);
        snprintf(what, sizeof what, "destination address octet %zu flipped", i);
        if (!answer_is(what, &d, TCP_PARSE_CHECKSUM_DISAGREES)) {
            ok = false;
        }
    }
    return ok;
}

/* ⚠ RFC 793: "The TCP Length is the TCP header length plus the data length in
 * octets (this is not an explicitly transmitted quantity, but is computed)".
 *
 * ⚠ So it comes from the extent this function was handed, and ⚠ a caller that
 * hands over what ARRIVED — a frame padded up to the wire's minimum — gets a
 * checksum that does not agree, with nothing pointing at the padding.
 * ⚠ `src/tcp.h` states the requirement; this is what happens when it is not met,
 * measured rather than argued. */
static bool case_the_tcp_length_comes_from_the_extent_it_was_handed(void)
{
    struct segment intact;
    if (!load_the_syn(&intact)) {
        return false;
    }
    bool ok = true;

    for (size_t padding = 1; padding <= 6; padding++) {
        struct segment padded = intact;
        for (size_t i = 0; i < padding; i++) {
            padded.octets[padded.bytes + i] = 0;
        }
        padded.bytes += padding;
        char what[80];
        snprintf(what, sizeof what, "%zu octets of padding counted into the segment",
                 padding);
        if (!answer_is(what, &padded, TCP_PARSE_CHECKSUM_DISAGREES)) {
            ok = false;
        }
    }

    /* ⚠ The other half: the same octets bounded correctly are accepted, so this
     * case is about the length and not about the zeros. */
    if (!answer_is("the segment bounded as the internet header says", &intact,
                   TCP_PARSE_OK)) {
        ok = false;
    }
    return ok;
}

/* ⚠ How many octets of data the segment carries, ⚠ **derived here so that the
 * layer above never subtracts two numbers itself** (`src/tcp.h`).
 *
 * ⚠ What it exists to stop is the State layer taking delivery of octets that
 * are not there, or missing octets that are. ⚠ Both directions are asserted:
 * the kernel's own SYN carries none, and appending data changes it by exactly
 * what was appended — ⚠ **not by the options, which sit in front of it.** */
static bool case_the_data_length_comes_from_what_was_handed_over(void)
{
    struct segment bare;
    if (!load_the_syn(&bare)) {
        return false;
    }
    bool ok = true;

    struct tcp_header header;
    if (tcp_parse_header(bare.octets, bare.bytes, bare.source_address,
                         bare.destination_address, &header) != TCP_PARSE_OK) {
        fputs("  the kernel's own SYN was declined\n", stderr);
        return false;
    }
    /* ⚠ The kernel's SYN carries options and no data. ⚠ A `data_bytes` that
     * counted the options would be non-zero here. */
    if (header.data_bytes != 0) {
        fprintf(stderr, "  a SYN carrying no data reported %zu octets of it\n",
                header.data_bytes);
        ok = false;
    }

    for (size_t appended = 1; appended <= 5; appended++) {
        struct segment with_data = bare;
        for (size_t i = 0; i < appended; i++) {
            with_data.octets[with_data.bytes + i] = (unsigned char)('a' + i);
        }
        with_data.bytes += appended;
        repair_the_checksum(&with_data);

        struct tcp_header carrying;
        if (tcp_parse_header(with_data.octets, with_data.bytes,
                             with_data.source_address, with_data.destination_address,
                             &carrying) != TCP_PARSE_OK) {
            fprintf(stderr, "  a segment carrying %zu octets was declined\n", appended);
            ok = false;
            continue;
        }
        if (carrying.data_bytes != appended) {
            fprintf(stderr, "  %zu octets were appended and %zu were reported\n",
                    appended, carrying.data_bytes);
            ok = false;
        }
        /* ⚠ And the header did not move: the data is what changed. */
        if (carrying.data_begins_at != header.data_begins_at) {
            fputs("  appending data moved where the data begins\n", stderr);
            ok = false;
        }
    }
    return ok;
}

/* ⚠ The order, asserted rather than assumed (ADR 0014).
 *
 * ⚠ The checksum is decided before any field's content, so a segment whose
 * octets were changed in flight is never reported as the sender's mistake —
 * the order ADR 0010 and ADR 0011 already set for IPv4 and ICMP.
 *
 * ⚠ Every other case in this file repairs the checksum after breaking a field,
 * so ⚠ **all of them pass whichever way round the two are judged.** ⚠ Measured:
 * moving the Reserved check in front of the checksum left
 * `a_reserved_that_is_not_zero_is_malformed` passing. ⚠ This case is the only
 * thing that holds the order. */
static bool case_the_order_the_answers_are_decided_in(void)
{
    bool ok = true;

    /* Reserved set AND the checksum left alone, so both are wrong at once. */
    struct segment s;
    if (!load_the_syn(&s)) {
        return false;
    }
    write_reserved(&s, 1);
    if (!answer_is("reserved set with the checksum left alone", &s,
                   TCP_PARSE_CHECKSUM_DISAGREES)) {
        ok = false;
    }

    /* A Data Offset below the fixed header, and the checksum left alone. */
    if (!load_the_syn(&s)) {
        return false;
    }
    write_data_offset(&s, 0);
    if (!answer_is("data offset 0 with the checksum left alone", &s,
                   TCP_PARSE_CHECKSUM_DISAGREES)) {
        ok = false;
    }

    /* An option list that does not walk, and the checksum left alone. */
    if (!load_the_syn(&s)) {
        return false;
    }
    s.octets[TCP_FIXED_HEADER_BYTES] = 2;
    s.octets[TCP_FIXED_HEADER_BYTES + 1] = 0;
    if (!answer_is("an option length of 0 with the checksum left alone", &s,
                   TCP_PARSE_CHECKSUM_DISAGREES)) {
        ok = false;
    }

    /* ⚠ The other half: each of those on its own, with the checksum repaired,
     * still gives its own answer — or the three above would pass for a parser
     * that answered CHECKSUM_DISAGREES to everything. */
    if (!load_the_syn(&s)) {
        return false;
    }
    write_reserved(&s, 1);
    repair_the_checksum(&s);
    if (!answer_is("reserved set alone", &s, TCP_PARSE_MALFORMED)) {
        ok = false;
    }

    /* ⚠ And fewer octets than the fixed fields still wins over the checksum:
     * the checksum field itself has not arrived, so there is nothing to compare
     * against. */
    if (!load_the_syn(&s)) {
        return false;
    }
    s.bytes = TCP_FIXED_HEADER_BYTES - 1;
    if (!answer_is("one octet short of the fixed fields", &s, TCP_PARSE_MALFORMED)) {
        ok = false;
    }
    return ok;
}

/* ⚠ Nothing is left over from a previous call. ⚠ A header filled in by the
 * caller and then handed to a read that fails must come back zeroed, or the
 * caller reads the last segment's ports as this one's. */
static bool case_a_read_that_cannot_be_made_leaves_nothing_behind(void)
{
    struct tcp_header header;
    memset(&header, 0xaa, sizeof header);

    static const unsigned char nothing[1] = { 0 };
    static const unsigned char an_address[TCP_ADDRESS_BYTES] = { 10, 0, 0, 1 };
    if (tcp_parse_header(nothing, 0, an_address, an_address, &header) !=
        TCP_PARSE_MALFORMED) {
        fputs("  zero octets did not come back malformed\n", stderr);
        return false;
    }

    struct tcp_header zeroed;
    memset(&zeroed, 0, sizeof zeroed);
    if (memcmp(&header, &zeroed, sizeof header) != 0) {
        fputs("  the header still held what was in it before the call\n", stderr);
        return false;
    }
    return true;
}

static const struct test_case cases[] = {
    { "the_kernels_syn_is_read_as_it_holds_it",
      case_the_kernels_syn_is_read_as_it_holds_it },
    { "fewer_octets_than_the_fixed_fields", case_fewer_octets_than_the_fixed_fields },
    { "a_data_offset_below_the_fixed_header_is_malformed",
      case_a_data_offset_below_the_fixed_header_is_malformed },
    { "a_data_offset_beyond_what_arrived_is_malformed",
      case_a_data_offset_beyond_what_arrived_is_malformed },
    { "a_reserved_that_is_not_zero_is_malformed",
      case_a_reserved_that_is_not_zero_is_malformed },
    { "each_control_bit_is_read_on_its_own", case_each_control_bit_is_read_on_its_own },
    { "an_option_list_that_does_not_walk_is_malformed",
      case_an_option_list_that_does_not_walk_is_malformed },
    { "end_of_option_list_stops_the_walk", case_end_of_option_list_stops_the_walk },
    { "no_option_is_interpreted", case_no_option_is_interpreted },
    { "the_kernels_checksum_is_reproduced", case_the_kernels_checksum_is_reproduced },
    { "the_tcp_length_comes_from_the_extent_it_was_handed",
      case_the_tcp_length_comes_from_the_extent_it_was_handed },
    { "the_data_length_comes_from_what_was_handed_over",
      case_the_data_length_comes_from_what_was_handed_over },
    { "the_order_the_answers_are_decided_in", case_the_order_the_answers_are_decided_in },
    { "a_read_that_cannot_be_made_leaves_nothing_behind",
      case_a_read_that_cannot_be_made_leaves_nothing_behind },
};

int main(int argc, char **argv)
{
    return check_main("tcp", cases, sizeof cases / sizeof cases[0], argc, argv);
}
