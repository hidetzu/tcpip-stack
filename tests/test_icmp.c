/* Static-tier check of the ICMP echo parser and the reply builder.
 *
 * ⚠ Both fixtures are octets the Linux kernel put on a TAP device, and ⚠ the
 * reply is the kernel's answer to exactly the request in the other file — the
 * provenance in `icmp-echo-reply-98.hex` says how. ⚠ So the two can be compared
 * field for field, and ⚠ what our builder produces is held against something we
 * did not write (`.claude/rules/layers.md`, question 3).
 *
 * ⚠ A hand-written expectation and a hand-written implementation agree by
 * construction. ⚠ That is the whole reason the reply was captured rather than
 * typed (hidetzu/tcpip-stack#34).
 *
 * ⚠ Where a case breaks one field it repairs the checksum afterwards with
 * `internet_checksum_with_field_cleared` — deliberately the same function
 * `src/icmp.c` uses, so this file is not a second implementation of that
 * question (`CLAUDE.md` §3). ⚠ Without the repair every case below would come
 * back as the checksum answer and would assert nothing about the field it was
 * named for. */
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "check.h"
#include "checksum.h"
#include "ethernet.h"
#include "icmp.h"
#include "ipv4.h"

/* ⚠ Where each field sits, read here rather than asked of the parser — the same
 * deliberate second copy `tests/test_ipv4.c` keeps, and ⚠ the cross-check that
 * stops the two drifting is `the_captured_request_is_read_as_it_holds_it`,
 * which reads all eight octets by hand and requires the parsed message to match
 * (`CLAUDE.md` §3). */
#define AT_TYPE 0
#define AT_CODE 1
#define AT_CHECKSUM 2
#define AT_IDENTIFIER 4
#define AT_SEQUENCE_NUMBER 6

/* One ICMP message under test, and how many octets the case decided arrived. */
struct message {
    unsigned char octets[256];
    size_t bytes;
};

/* ⚠ The ICMP message inside a captured frame, found by reading the internet
 * header's own length — never by writing 34 here. */
static bool load_the_icmp_of(const char *fixture, struct message *into)
{
    unsigned char frame[256];
    long bytes = check_load_fixture(fixture, frame, sizeof frame);
    if (bytes < 0) {
        return false;
    }
    if (bytes != 98) {
        fprintf(stderr, "  %s is 98 octets in this repository, this one is %ld\n",
                fixture, bytes);
        return false;
    }
    size_t header_bytes =
        (size_t)(frame[ETHERNET_HEADER_BYTES] & 0x0f) * IPV4_HEADER_LENGTH_UNIT;
    size_t at = ETHERNET_HEADER_BYTES + header_bytes;
    into->bytes = (size_t)bytes - at;
    memcpy(into->octets, frame + at, into->bytes);
    return true;
}

static bool load_the_request(struct message *into)
{
    return load_the_icmp_of("icmp-echo-request-98.hex", into);
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

/* ⚠ RFC 792's generation, applied again after a case broke a field. */
static void repair_the_checksum(struct message *m)
{
    write_16(m->octets + AT_CHECKSUM,
             internet_checksum_with_field_cleared(m->octets, m->bytes, AT_CHECKSUM));
}

static const char *name_of(enum icmp_parse answer)
{
    switch (answer) {
    case ICMP_PARSE_OK:
        return "ICMP_PARSE_OK";
    case ICMP_PARSE_MALFORMED:
        return "ICMP_PARSE_MALFORMED";
    case ICMP_PARSE_TYPE_NOT_HANDLED:
        return "ICMP_PARSE_TYPE_NOT_HANDLED";
    case ICMP_PARSE_CHECKSUM_DISAGREES:
        return "ICMP_PARSE_CHECKSUM_DISAGREES";
    }
    return "a value with no name";
}

static bool answer_is(const char *what, const struct message *m, enum icmp_parse expected)
{
    struct icmp_echo echo;
    enum icmp_parse answer = icmp_parse_echo(m->octets, m->bytes, &echo);
    if (answer != expected) {
        fprintf(stderr, "  %s: expected %s, got %s\n", what, name_of(expected),
                name_of(answer));
        return false;
    }
    return true;
}

/* ⚠ The cross-check named at the top. Every field is read from the octets by
 * hand and the parsed message must agree. */
static bool case_the_captured_request_is_read_as_it_holds_it(void)
{
    struct message m;
    if (!load_the_request(&m)) {
        return false;
    }

    struct icmp_echo echo;
    enum icmp_parse answer = icmp_parse_echo(m.octets, m.bytes, &echo);
    if (answer != ICMP_PARSE_OK) {
        fprintf(stderr, "  the captured echo request came back as %s\n", name_of(answer));
        return false;
    }

    bool ok = true;
#define SAME(field, expected)                                                   \
    do {                                                                        \
        unsigned long got = (unsigned long)(echo.field);                        \
        unsigned long want = (unsigned long)(expected);                         \
        if (got != want) {                                                      \
            fprintf(stderr, "  %s: the octets say %lu, the message says %lu\n",  \
                    #field, want, got);                                         \
            ok = false;                                                         \
        }                                                                       \
    } while (0)

    SAME(type, m.octets[AT_TYPE]);
    SAME(code, m.octets[AT_CODE]);
    SAME(checksum, read_16(m.octets + AT_CHECKSUM));
    SAME(identifier, read_16(m.octets + AT_IDENTIFIER));
    SAME(sequence_number, read_16(m.octets + AT_SEQUENCE_NUMBER));
    SAME(data_bytes, m.bytes - ICMP_FIXED_BYTES);
#undef SAME

    if (echo.data != m.octets + ICMP_FIXED_BYTES) {
        fputs("  data does not point at the octets after the fixed fields\n", stderr);
        ok = false;
    }

    /* ⚠ The other half: the capture is one particular message, and these are
     * what the kernel actually chose. ⚠ Without this the case would pass for a
     * parser that returned zeroes throughout (`verify` §5). */
    if (echo.type != ICMP_TYPE_ECHO || echo.code != ICMP_CODE_ECHO ||
        echo.checksum == 0 || echo.data_bytes == 0) {
        fprintf(stderr, "  the capture no longer holds an echo request with a non-zero "
                        "checksum and some data: type %u, code %u, checksum 0x%04x, "
                        "%zu octets of data\n",
                echo.type, echo.code, echo.checksum, echo.data_bytes);
        ok = false;
    }
    return ok;
}

/* ⚠ Nothing can be read at all below the fixed fields. */
static bool case_fewer_octets_than_the_fixed_fields(void)
{
    struct message m;
    if (!load_the_request(&m)) {
        return false;
    }
    bool ok = true;
    for (size_t bytes = 0; bytes < ICMP_FIXED_BYTES; bytes++) {
        m.bytes = bytes;
        char what[64];
        snprintf(what, sizeof what, "%zu octets arrived", bytes);
        if (!answer_is(what, &m, ICMP_PARSE_MALFORMED)) {
            ok = false;
        }
    }
    /* ⚠ The other half: exactly the fixed fields and no data is a message we
     * accept, so the case asserts the boundary and not something else. */
    m.bytes = ICMP_FIXED_BYTES;
    repair_the_checksum(&m);
    if (!answer_is("exactly the fixed fields arrived", &m, ICMP_PARSE_OK)) {
        ok = false;
    }
    return ok;
}

/* ⚠ RFC 792, for an echo message: "Code: 0". ⚠ Anything else and the sender did
 * not do what the document says — malformed, and ⚠ not "a type we do not act
 * on" (hidetzu/tcpip-stack#34 Owner Decision 1). */
static bool case_a_code_that_is_not_zero_is_malformed(void)
{
    bool ok = true;
    for (unsigned code = 1; code < 256; code++) {
        struct message m;
        if (!load_the_request(&m)) {
            return false;
        }
        m.octets[AT_CODE] = (unsigned char)code;
        repair_the_checksum(&m);
        char what[64];
        snprintf(what, sizeof what, "code %u", code);
        if (!answer_is(what, &m, ICMP_PARSE_MALFORMED)) {
            ok = false;
        }
    }
    return ok;
}

/* ⚠ Its own answer, and ⚠ an echo reply is one of them
 * (hidetzu/tcpip-stack#34 Owner Decision 2). ⚠ The sender is fine. */
static bool case_a_type_we_do_not_act_on_is_its_own_answer(void)
{
    bool ok = true;
    bool saw_echo_reply = false;
    for (unsigned type = 0; type < 256; type++) {
        if (type == ICMP_TYPE_ECHO) {
            continue;
        }
        struct message m;
        if (!load_the_request(&m)) {
            return false;
        }
        m.octets[AT_TYPE] = (unsigned char)type;
        repair_the_checksum(&m);
        char what[64];
        snprintf(what, sizeof what, "type %u", type);
        if (!answer_is(what, &m, ICMP_PARSE_TYPE_NOT_HANDLED)) {
            ok = false;
        }
        if (type == ICMP_TYPE_ECHO_REPLY) {
            saw_echo_reply = true;
        }
    }
    /* ⚠ Owner Decision 2 is about one particular type, so it is named here
     * rather than left to a loop bound that could change. */
    if (!saw_echo_reply) {
        fputs("  the echo reply's own type was never tried\n", stderr);
        ok = false;
    }
    return ok;
}

/* ⚠ Its own answer, folded into neither of the others. ⚠ Every octet of the
 * message in turn — including the data, which the sum covers. */
static bool case_a_checksum_that_does_not_agree_is_its_own_answer(void)
{
    struct message intact;
    if (!load_the_request(&intact)) {
        return false;
    }
    bool ok = true;
    for (size_t i = 0; i < intact.bytes; i++) {
        struct message m = intact;
        m.octets[i] = (unsigned char)(m.octets[i] ^ 0xff);
        char what[64];
        snprintf(what, sizeof what, "octet %zu flipped", i);
        if (!answer_is(what, &m, ICMP_PARSE_CHECKSUM_DISAGREES)) {
            ok = false;
        }
    }
    return ok;
}

/* ⚠ The order, asserted rather than assumed (ADR 0011).
 *
 * ⚠ The checksum is decided before any field's content, so a message whose
 * octets were changed in flight is never reported as the sender's mistake.
 * ⚠ The Type is decided before the Code, because RFC 792 gives `Code: 0` only
 * inside the echo message's own description. */
static bool case_the_order_the_answers_are_decided_in(void)
{
    bool ok = true;

    /* A type we do not act on, and a checksum that does not agree. */
    struct message m;
    if (!load_the_request(&m)) {
        return false;
    }
    m.octets[AT_TYPE] = 3;
    if (!answer_is("type 3 with the checksum left alone", &m,
                   ICMP_PARSE_CHECKSUM_DISAGREES)) {
        ok = false;
    }

    /* A code we call malformed, and a checksum that does not agree. */
    if (!load_the_request(&m)) {
        return false;
    }
    m.octets[AT_CODE] = 7;
    if (!answer_is("code 7 with the checksum left alone", &m,
                   ICMP_PARSE_CHECKSUM_DISAGREES)) {
        ok = false;
    }

    /* ⚠ Both wrong at once, checksum repaired: the Type wins, so the Code of a
     * message we do not act on is never called malformed. */
    if (!load_the_request(&m)) {
        return false;
    }
    m.octets[AT_TYPE] = 3;
    m.octets[AT_CODE] = 7;
    repair_the_checksum(&m);
    if (!answer_is("type 3 and code 7", &m, ICMP_PARSE_TYPE_NOT_HANDLED)) {
        ok = false;
    }

    /* ⚠ The other half: each on its own still gives its own answer, or the
     * three above would pass for a parser that answered one thing always. */
    if (!load_the_request(&m)) {
        return false;
    }
    m.octets[AT_TYPE] = 3;
    repair_the_checksum(&m);
    if (!answer_is("type 3 alone", &m, ICMP_PARSE_TYPE_NOT_HANDLED)) {
        ok = false;
    }
    if (!load_the_request(&m)) {
        return false;
    }
    m.octets[AT_CODE] = 7;
    repair_the_checksum(&m);
    if (!answer_is("code 7 alone", &m, ICMP_PARSE_MALFORMED)) {
        ok = false;
    }
    return ok;
}

/* ⚠ The one that matters: our builder against the octets the Linux kernel
 * answered with, compared one for one (AC 4). */
static bool case_the_kernels_reply_is_rebuilt_octet_for_octet(void)
{
    struct message request;
    struct message kernels_reply;
    if (!load_the_request(&request) ||
        !load_the_icmp_of("icmp-echo-reply-98.hex", &kernels_reply)) {
        return false;
    }

    struct icmp_echo echo;
    if (icmp_parse_echo(request.octets, request.bytes, &echo) != ICMP_PARSE_OK) {
        fputs("  the captured request did not parse\n", stderr);
        return false;
    }

    unsigned char ours[256];
    memset(ours, 0xaa, sizeof ours);
    size_t reply_bytes = 0;
    if (icmp_build_echo_reply(&echo, ours, sizeof ours, &reply_bytes) != ICMP_BUILD_OK) {
        fputs("  the reply would not build into a buffer that is plainly large enough\n",
              stderr);
        return false;
    }

    bool ok = true;
    if (reply_bytes != kernels_reply.bytes) {
        fprintf(stderr, "  the kernel's reply is %zu octets and ours is %zu\n",
                kernels_reply.bytes, reply_bytes);
        return false;
    }
    for (size_t i = 0; i < reply_bytes; i++) {
        if (ours[i] != kernels_reply.octets[i]) {
            fprintf(stderr, "  octet %zu: the kernel put %02x and we put %02x\n", i,
                    kernels_reply.octets[i], ours[i]);
            ok = false;
        }
    }

    /* ⚠ And the two captures really are the same exchange, or the comparison
     * above would be against an unrelated message. ⚠ Checked on the fields the
     * document says come back unchanged. */
    if (read_16(kernels_reply.octets + AT_IDENTIFIER) != echo.identifier ||
        read_16(kernels_reply.octets + AT_SEQUENCE_NUMBER) != echo.sequence_number) {
        fputs("  the two fixtures are not the same exchange: identifier or sequence "
              "number differ\n", stderr);
        ok = false;
    }
    return ok;
}

/* ⚠ RFC 792: "The data received in the echo message must be returned in the
 * echo reply message." ⚠ Asserted with data that is not the fixture's, at
 * several lengths including none at all (AC 5). */
static bool case_the_data_is_carried_across_whatever_its_length(void)
{
    static const size_t lengths[] = { 0, 1, 2, 3, 17, 200 };
    bool ok = true;

    for (size_t n = 0; n < sizeof lengths / sizeof lengths[0]; n++) {
        size_t data_bytes = lengths[n];
        unsigned char data[200];
        for (size_t i = 0; i < data_bytes; i++) {
            /* ⚠ Not the fixture's payload, and not a constant either: a builder
             * that wrote one repeated octet would pass a constant. */
            data[i] = (unsigned char)(0x5a ^ (i * 7 + 1));
        }

        struct icmp_echo request;
        memset(&request, 0, sizeof request);
        request.type = ICMP_TYPE_ECHO;
        request.code = ICMP_CODE_ECHO;
        request.identifier = 0xbeef;
        request.sequence_number = 0x0102;
        request.data = data;
        request.data_bytes = data_bytes;

        unsigned char reply[256];
        memset(reply, 0xaa, sizeof reply);
        size_t reply_bytes = 0;
        if (icmp_build_echo_reply(&request, reply, sizeof reply, &reply_bytes) !=
            ICMP_BUILD_OK) {
            fprintf(stderr, "  %zu octets of data would not build\n", data_bytes);
            ok = false;
            continue;
        }
        if (reply_bytes != ICMP_FIXED_BYTES + data_bytes) {
            fprintf(stderr, "  %zu octets of data gave a %zu-octet reply\n", data_bytes,
                    reply_bytes);
            ok = false;
            continue;
        }
        if (data_bytes > 0 && memcmp(reply + ICMP_FIXED_BYTES, data, data_bytes) != 0) {
            fprintf(stderr, "  %zu octets of data did not come back unchanged\n",
                    data_bytes);
            ok = false;
        }
        if (reply[AT_TYPE] != ICMP_TYPE_ECHO_REPLY) {
            fprintf(stderr, "  %zu octets of data: the type came back as %u\n", data_bytes,
                    reply[AT_TYPE]);
            ok = false;
        }
        if (read_16(reply + AT_IDENTIFIER) != request.identifier ||
            read_16(reply + AT_SEQUENCE_NUMBER) != request.sequence_number) {
            fprintf(stderr, "  %zu octets of data: the identifier or sequence number "
                            "did not come back\n", data_bytes);
            ok = false;
        }

        /* ⚠ The checksum we wrote, asserted without computing it a second way:
         * ⚠ the parser checks the checksum BEFORE the type, so a reply that
         * comes back as "a type we do not act on" is one whose checksum agreed.
         * ⚠ A wrong one would come back as the checksum answer instead. */
        struct message built;
        memcpy(built.octets, reply, reply_bytes);
        built.bytes = reply_bytes;
        char what[64];
        snprintf(what, sizeof what, "the reply we built for %zu octets of data",
                 data_bytes);
        if (!answer_is(what, &built, ICMP_PARSE_TYPE_NOT_HANDLED)) {
            ok = false;
        }
    }
    return ok;
}

/* ⚠ Refused, never truncated, and ⚠ not one octet written — asserted for every
 * size below what the reply needs (AC 6). */
static bool case_a_buffer_too_small_is_refused_and_nothing_is_written(void)
{
    struct message request;
    if (!load_the_request(&request)) {
        return false;
    }
    struct icmp_echo echo;
    if (icmp_parse_echo(request.octets, request.bytes, &echo) != ICMP_PARSE_OK) {
        fputs("  the captured request did not parse\n", stderr);
        return false;
    }
    size_t needed = ICMP_FIXED_BYTES + echo.data_bytes;

    bool ok = true;
    for (size_t room = 0; room < needed; room++) {
        unsigned char buffer[256];
        memset(buffer, 0xaa, sizeof buffer);
        size_t reply_bytes = 12345;

        if (icmp_build_echo_reply(&echo, buffer, room, &reply_bytes) !=
            ICMP_BUILD_BUFFER_TOO_SMALL) {
            fprintf(stderr, "  %zu octets of room was not refused\n", room);
            ok = false;
            continue;
        }
        for (size_t i = 0; i < sizeof buffer; i++) {
            if (buffer[i] != 0xaa) {
                fprintf(stderr, "  %zu octets of room: octet %zu was written into\n",
                        room, i);
                ok = false;
                break;
            }
        }
    }

    /* ⚠ The other half: exactly enough room is not refused, or the loop above
     * would pass for a builder that refused everything. */
    unsigned char buffer[256];
    size_t reply_bytes = 0;
    if (icmp_build_echo_reply(&echo, buffer, needed, &reply_bytes) != ICMP_BUILD_OK) {
        fprintf(stderr, "  exactly %zu octets of room was refused\n", needed);
        ok = false;
    }
    return ok;
}

/* ⚠ Answering in place: the request's data pointing into the very buffer the
 * reply is written to. ⚠ That is what a caller holding one frame will do, and
 * a plain memcpy is undefined behaviour when the two overlap
 * (`.claude/rules/c.md`). */
static bool case_the_reply_may_be_built_over_the_request(void)
{
    struct message request;
    if (!load_the_request(&request)) {
        return false;
    }
    struct icmp_echo echo;
    if (icmp_parse_echo(request.octets, request.bytes, &echo) != ICMP_PARSE_OK) {
        fputs("  the captured request did not parse\n", stderr);
        return false;
    }

    /* Built somewhere else first, to have something to compare against. */
    unsigned char apart[256];
    size_t apart_bytes = 0;
    if (icmp_build_echo_reply(&echo, apart, sizeof apart, &apart_bytes) != ICMP_BUILD_OK) {
        fputs("  the reply would not build into a separate buffer\n", stderr);
        return false;
    }

    /* ⚠ Now over the request itself. `echo.data` points into request.octets. */
    size_t in_place_bytes = 0;
    if (icmp_build_echo_reply(&echo, request.octets, sizeof request.octets,
                              &in_place_bytes) != ICMP_BUILD_OK) {
        fputs("  the reply would not build over the request\n", stderr);
        return false;
    }
    if (in_place_bytes != apart_bytes ||
        memcmp(request.octets, apart, apart_bytes) != 0) {
        fputs("  building over the request gave different octets from building apart\n",
              stderr);
        return false;
    }
    return true;
}

/* ⚠ Nothing is left over from a previous call. ⚠ A message filled in by the
 * caller and then handed to a read that fails must come back zeroed, or the
 * caller reads the last message's data pointer as this one's. */
static bool case_a_read_that_cannot_be_made_leaves_nothing_behind(void)
{
    struct icmp_echo echo;
    memset(&echo, 0xaa, sizeof echo);

    static const unsigned char nothing[1] = { 0 };
    if (icmp_parse_echo(nothing, 0, &echo) != ICMP_PARSE_MALFORMED) {
        fputs("  zero octets did not come back malformed\n", stderr);
        return false;
    }

    struct icmp_echo zeroed;
    memset(&zeroed, 0, sizeof zeroed);
    if (memcmp(&echo, &zeroed, sizeof echo) != 0) {
        fputs("  the message still held what was in it before the call\n", stderr);
        return false;
    }
    return true;
}

/* ⚠ hidetzu/tcpip-stack#138. ⚠ Reading an error message, ⚠ **and telling the
 * three ways it can fail apart** — RFC 792 promises "The internet header plus
 * the first 64 bits of the original datagram's data", ⚠ **so fewer is the sender
 * being wrong and is not the same as a Type we do not act on.** */
static bool case_an_error_message_is_read_or_refused_for_its_own_reason(void)
{
    bool ok = true;
    /* ⚠ Type 3 code 1, then four unused octets, then a twenty-octet internet
     * header and eight octets of the datagram's data. ⚠ Built by hand so the
     * case does not depend on the builder it is checking. */
    uint8_t message[8 + 28];
    memset(message, 0, sizeof message);
    message[0] = ICMP_TYPE_DESTINATION_UNREACHABLE;
    message[1] = 1u;
    message[8] = 0x45u;                       /* version 4, five words */
    uint16_t sum = internet_checksum_with_field_cleared(message, sizeof message, 2u);
    message[2] = (uint8_t)(sum >> 8);
    message[3] = (uint8_t)(sum & 0xffu);

    struct icmp_error error;
    if (icmp_parse_error(message, sizeof message, &error) != ICMP_ERROR_PARSE_OK ||
        error.type != ICMP_TYPE_DESTINATION_UNREACHABLE || error.code != 1u ||
        error.carried != message + 8 || error.carried_bytes != 28u) {
        fputs("  a well-formed unreachable message was not read\n", stderr);
        ok = false;
    }

    /* ⚠ One octet short of what RFC 792 promises: ⚠ **malformed**, ⚠ and NOT
     * "a type we do not act on". */
    {
        uint8_t shorter[8 + 27];
        memcpy(shorter, message, sizeof shorter);
        uint16_t s2 = internet_checksum_with_field_cleared(shorter, sizeof shorter, 2u);
        shorter[2] = (uint8_t)(s2 >> 8);
        shorter[3] = (uint8_t)(s2 & 0xffu);
        if (icmp_parse_error(shorter, sizeof shorter, &error) != ICMP_ERROR_PARSE_MALFORMED) {
            fputs("  27 carried octets was not called malformed, and RFC 792 "
                  "promises 28\n", stderr);
            ok = false;
        }
    }
    /* ⚠ And exactly what it promises IS enough — ⚠ **without this the check "one
     * short is refused" would pass for a build that refuses everything**
     * (`verify` §5). */
    if (icmp_parse_error(message, sizeof message, &error) != ICMP_ERROR_PARSE_OK) {
        fputs("  exactly 28 carried octets was refused\n", stderr);
        ok = false;
    }

    /* ⚠ An echo is not an error, and ⚠ **that is its own answer**: the sender is
     * fine and nothing here should act on it. */
    {
        uint8_t echo[8 + 28];
        memcpy(echo, message, sizeof echo);
        echo[0] = ICMP_TYPE_ECHO;
        if (icmp_parse_error(echo, sizeof echo, &error) != ICMP_ERROR_PARSE_NOT_AN_ERROR) {
            fputs("  an echo was not told apart from an error\n", stderr);
            ok = false;
        }
    }

    /* ⚠ A changed octet: ⚠ **its own answer, and decided before the code is
     * believed** (ADR 0011's order). */
    {
        uint8_t changed[8 + 28];
        memcpy(changed, message, sizeof changed);
        changed[9] ^= 0xffu;
        if (icmp_parse_error(changed, sizeof changed, &error) !=
            ICMP_ERROR_PARSE_CHECKSUM_DISAGREES) {
            fputs("  a changed octet was not caught by the checksum\n", stderr);
            ok = false;
        }
    }
    return ok;
}

static const struct test_case cases[] = {
    { "the_captured_request_is_read_as_it_holds_it",
      case_the_captured_request_is_read_as_it_holds_it },
    { "fewer_octets_than_the_fixed_fields", case_fewer_octets_than_the_fixed_fields },
    { "a_code_that_is_not_zero_is_malformed", case_a_code_that_is_not_zero_is_malformed },
    { "a_type_we_do_not_act_on_is_its_own_answer",
      case_a_type_we_do_not_act_on_is_its_own_answer },
    { "a_checksum_that_does_not_agree_is_its_own_answer",
      case_a_checksum_that_does_not_agree_is_its_own_answer },
    { "the_order_the_answers_are_decided_in", case_the_order_the_answers_are_decided_in },
    { "the_kernels_reply_is_rebuilt_octet_for_octet",
      case_the_kernels_reply_is_rebuilt_octet_for_octet },

    { "an_error_message_is_read_or_refused_for_its_own_reason",
      case_an_error_message_is_read_or_refused_for_its_own_reason },
    { "the_data_is_carried_across_whatever_its_length",
      case_the_data_is_carried_across_whatever_its_length },
    { "a_buffer_too_small_is_refused_and_nothing_is_written",
      case_a_buffer_too_small_is_refused_and_nothing_is_written },
    { "the_reply_may_be_built_over_the_request",
      case_the_reply_may_be_built_over_the_request },
    { "a_read_that_cannot_be_made_leaves_nothing_behind",
      case_a_read_that_cannot_be_made_leaves_nothing_behind },
};

int main(int argc, char **argv)
{
    return check_main("icmp", cases, sizeof cases / sizeof cases[0], argc, argv);
}
