/* Static-tier check of the State layer: what an arriving IPv4 datagram means for
 * us, and what we did about it.
 *
 * ⚠ No TAP device, no namespace, no clock (ADR 0008's shape is what makes that
 * possible). ⚠ It asserts that the ten reasons stay ten things, which is the
 * whole reason they were kept apart (hidetzu/tcpip-stack#35 AC 4).
 *
 * ⚠ The one that matters most is
 * `an_icmp_checksum_that_does_not_agree_is_not_answered_and_is_counted`.
 * ⚠ Without it, `ping` reporting 0% loss would pass for a stack that never
 * checked a checksum on the way in (`CLAUDE.md` §1, AC 2). */
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "check.h"
#include "checksum.h"
#include "echo_responder.h"
#include "ethernet.h"

static const unsigned char OUR_MAC[6] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x02 };
static const unsigned char OUR_IPV4[4] = { 10, 0, 0, 2 };
static const unsigned char THEIR_MAC[6] = { 0x02, 0x11, 0x11, 0x11, 0x11, 0x11 };

/* Offsets inside the datagram, read here rather than asked of the parser — the
 * same deliberate second copy `tests/test_ipv4.c` keeps. */
#define AT_VERSION_AND_LENGTH 0
#define AT_TOTAL_LENGTH 2
#define AT_FLAGS_AND_OFFSET 6
#define AT_PROTOCOL 9
#define AT_HEADER_CHECKSUM 10
#define AT_SOURCE_ADDRESS 12
#define AT_DESTINATION_ADDRESS 16

struct datagram {
    unsigned char octets[256];
    size_t bytes;
};

/* The IPv4 datagram of a captured frame, found by reading the internet header's
 * own length — never by writing 34 here. */
static bool load_the_datagram_of(const char *fixture, struct datagram *into)
{
    unsigned char frame[256];
    long bytes = check_load_fixture(fixture, frame, sizeof frame);
    if (bytes < 0) {
        return false;
    }
    into->bytes = (size_t)bytes - ETHERNET_HEADER_BYTES;
    memcpy(into->octets, frame + ETHERNET_HEADER_BYTES, into->bytes);
    return true;
}

static bool load_the_request(struct datagram *into)
{
    return load_the_datagram_of("icmp-echo-request-98.hex", into);
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

static void repair_the_header_checksum(struct datagram *d)
{
    size_t header_bytes =
        (size_t)(d->octets[AT_VERSION_AND_LENGTH] & 0x0f) * IPV4_HEADER_LENGTH_UNIT;
    write_16(d->octets + AT_HEADER_CHECKSUM,
             internet_checksum_with_field_cleared(d->octets, header_bytes,
                                                  AT_HEADER_CHECKSUM));
}

/* Hands one datagram over and reports what came back.
 *
 * ⚠ `which_count` is checked for moving by exactly one, and ⚠ the whole struct
 * is checked for nothing else having moved: a reason reported under one name
 * and counted under another is the defect this file exists to stop. */
static bool answered(const char *what, const struct datagram *d,
                     enum echo_decision decision, enum echo_reason reason,
                     size_t which_count_offset)
{
    struct echo_counts counts;
    memset(&counts, 0, sizeof counts);
    struct echo_counts before = counts;

    unsigned char reply[512];
    memset(reply, 0xaa, sizeof reply);
    struct echo_outcome outcome;
    echo_respond(d->octets, d->bytes, IPV4_TIME_TO_LIVE_WE_SEND, THEIR_MAC, OUR_MAC, OUR_IPV4, reply, sizeof reply,
                 &outcome, &counts);

    bool ok = true;
    if (outcome.decision != decision || outcome.reason != reason) {
        fprintf(stderr, "  %s: expected decision %d reason %d, got %d and %d\n", what,
                (int)decision, (int)reason, (int)outcome.decision, (int)outcome.reason);
        ok = false;
    }

    unsigned long moved = *(unsigned long *)((char *)&counts + which_count_offset);
    unsigned long was = *(unsigned long *)((char *)&before + which_count_offset);
    if (decision == ECHO_NO_ANSWER && moved != was + 1) {
        fprintf(stderr, "  %s: its own counter did not move by exactly one\n", what);
        ok = false;
    }

    /* ⚠ Every other counter must have stayed still. */
    size_t fields = sizeof counts / sizeof(unsigned long);
    for (size_t i = 0; i < fields; i++) {
        if (i * sizeof(unsigned long) == which_count_offset && decision == ECHO_NO_ANSWER) {
            continue;
        }
        unsigned long now = ((unsigned long *)&counts)[i];
        if (now != ((unsigned long *)&before)[i]) {
            fprintf(stderr, "  %s: counter %zu moved as well, to %lu\n", what, i, now);
            ok = false;
        }
    }

    if (decision == ECHO_NO_ANSWER) {
        if (outcome.reply_bytes != 0) {
            fprintf(stderr, "  %s: a reply was built for something we declined\n", what);
            ok = false;
        }
        for (size_t i = 0; i < sizeof reply; i++) {
            if (reply[i] != 0xaa) {
                fprintf(stderr, "  %s: octet %zu of the reply buffer was written into\n",
                        what, i);
                ok = false;
                break;
            }
        }
    }
    return ok;
}

#define COUNT_AT(field) offsetof(struct echo_counts, field)

/* ⚠ The one the whole milestone leans on the other way round: the kernel's own
 * echo request is answered, and ⚠ the reply is the kernel's own reply, octet for
 * octet, from the ICMP message onward. */
static bool case_the_kernels_echo_request_is_answered(void)
{
    struct datagram request;
    struct datagram kernels_reply;
    if (!load_the_request(&request) ||
        !load_the_datagram_of("icmp-echo-reply-98.hex", &kernels_reply)) {
        return false;
    }

    struct echo_counts counts;
    memset(&counts, 0, sizeof counts);
    unsigned char reply[512];
    memset(reply, 0xaa, sizeof reply);
    struct echo_outcome outcome;
    echo_respond(request.octets, request.bytes, IPV4_TIME_TO_LIVE_WE_SEND, THEIR_MAC, OUR_MAC, OUR_IPV4, reply,
                 sizeof reply, &outcome, &counts);

    if (outcome.decision != ECHO_ANSWER) {
        fprintf(stderr, "  the kernel's echo request was declined, reason %d\n",
                (int)outcome.reason);
        return false;
    }

    bool ok = true;
    if (outcome.reply_bytes != ETHERNET_HEADER_BYTES + request.bytes) {
        fprintf(stderr, "  the reply is %zu octets and the frame that asked was %zu\n",
                outcome.reply_bytes, ETHERNET_HEADER_BYTES + request.bytes);
        return false;
    }

    /* The ethernet header we built. */
    if (memcmp(reply, THEIR_MAC, ETHERNET_ADDRESS_BYTES) != 0 ||
        memcmp(reply + ETHERNET_ADDRESS_BYTES, OUR_MAC, ETHERNET_ADDRESS_BYTES) != 0 ||
        read_16(reply + 12) != IPV4_ETHERNET_LENGTH_TYPE) {
        fputs("  the ethernet header of the reply is not ours to theirs under 0x0800\n",
              stderr);
        ok = false;
    }

    /* ⚠ The ICMP message, against the kernel's own answer to this very request.
     * ⚠ Everything from octet 20 of the datagram onward. */
    const unsigned char *ours = reply + ETHERNET_HEADER_BYTES + IPV4_FIXED_HEADER_BYTES;
    const unsigned char *theirs = kernels_reply.octets + IPV4_FIXED_HEADER_BYTES;
    size_t message_bytes = request.bytes - IPV4_FIXED_HEADER_BYTES;
    for (size_t i = 0; i < message_bytes; i++) {
        if (ours[i] != theirs[i]) {
            fprintf(stderr, "  ICMP octet %zu: the kernel put %02x and we put %02x\n", i,
                    theirs[i], ours[i]);
            ok = false;
        }
    }

    /* The internet header we built. ⚠ The owner's three values, and the two
     * addresses the other way round from the request. */
    const unsigned char *header = reply + ETHERNET_HEADER_BYTES;
    struct ipv4_header read_back;
    enum ipv4_parse answer =
        ipv4_parse_header(header, outcome.reply_bytes - ETHERNET_HEADER_BYTES, &read_back);
    if (answer != IPV4_PARSE_OK) {
        /* ⚠ Our own parser accepting it also says the header checksum agrees,
         * because it is checked before anything else is judged. */
        fprintf(stderr, "  the internet header we built came back as %d\n", (int)answer);
        return false;
    }
    if (read_back.time_to_live != IPV4_TIME_TO_LIVE_WE_SEND ||
        read_back.identification != IPV4_IDENTIFICATION_WE_SEND ||
        read_back.flags != 0 || read_back.fragment_offset != 0 ||
        read_back.protocol != IPV4_PROTOCOL_ICMP) {
        fprintf(stderr, "  the header we built holds ttl %u, id %u, flags %u, "
                        "offset %u, protocol %u\n",
                read_back.time_to_live, read_back.identification, read_back.flags,
                read_back.fragment_offset, read_back.protocol);
        ok = false;
    }
    if (memcmp(read_back.source_address, OUR_IPV4, IPV4_ADDRESS_BYTES) != 0 ||
        memcmp(read_back.destination_address, request.octets + AT_SOURCE_ADDRESS,
               IPV4_ADDRESS_BYTES) != 0) {
        fputs("  the reply's addresses are not ours to the sender's\n", stderr);
        ok = false;
    }

    /* ⚠ Not counted here: nothing has been sent. ⚠ The caller counts what the
     * wire took (the same division arp_respond uses). */
    if (counts.answered != 0) {
        fputs("  it counted an answer that has not left yet\n", stderr);
        ok = false;
    }
    return ok;
}

/* ⚠ AC 2, and the reason `ping` alone is not enough. ⚠ Every octet of the ICMP
 * message in turn, so this cannot pass by catching one lucky position. */
static bool case_an_icmp_checksum_that_does_not_agree_is_not_answered_and_is_counted(void)
{
    struct datagram intact;
    if (!load_the_request(&intact)) {
        return false;
    }
    bool ok = true;
    for (size_t i = IPV4_FIXED_HEADER_BYTES; i < intact.bytes; i++) {
        struct datagram d = intact;
        d.octets[i] = (unsigned char)(d.octets[i] ^ 0xff);
        char what[80];
        snprintf(what, sizeof what, "ICMP octet %zu flipped",
                 i - IPV4_FIXED_HEADER_BYTES);
        if (!answered(what, &d, ECHO_NO_ANSWER, ECHO_REASON_ICMP_CHECKSUM_DISAGREES,
                      COUNT_AT(icmp_checksum_disagrees))) {
            ok = false;
        }
    }
    return ok;
}

/* ⚠ Every reason, one at a time, and ⚠ each moves only its own count. */
static bool case_each_reason_moves_only_its_own_count(void)
{
    bool ok = true;
    struct datagram d;

    /* The internet header, four ways. */
    if (!load_the_request(&d)) {
        return false;
    }
    d.bytes = IPV4_FIXED_HEADER_BYTES - 1;
    if (!answered("a truncated internet header", &d, ECHO_NO_ANSWER,
                  ECHO_REASON_INTERNET_HEADER_MALFORMED,
                  COUNT_AT(internet_header_malformed))) {
        ok = false;
    }

    if (!load_the_request(&d)) {
        return false;
    }
    d.octets[AT_VERSION_AND_LENGTH] = (unsigned char)((6 << 4) | 5);
    repair_the_header_checksum(&d);
    if (!answered("a version we do not read", &d, ECHO_NO_ANSWER,
                  ECHO_REASON_INTERNET_HEADER_NOT_HANDLED,
                  COUNT_AT(internet_header_not_handled))) {
        ok = false;
    }

    if (!load_the_request(&d)) {
        return false;
    }
    d.octets[AT_HEADER_CHECKSUM] = (unsigned char)(d.octets[AT_HEADER_CHECKSUM] ^ 0xff);
    if (!answered("an internet header checksum that disagrees", &d, ECHO_NO_ANSWER,
                  ECHO_REASON_INTERNET_HEADER_CHECKSUM_DISAGREES,
                  COUNT_AT(internet_header_checksum_disagrees))) {
        ok = false;
    }

    if (!load_the_request(&d)) {
        return false;
    }
    write_16(d.octets + AT_FLAGS_AND_OFFSET, (unsigned)IPV4_FLAG_MORE_FRAGMENTS << 13);
    repair_the_header_checksum(&d);
    if (!answered("a fragment", &d, ECHO_NO_ANSWER, ECHO_REASON_FRAGMENT,
                  COUNT_AT(fragment))) {
        ok = false;
    }

    /* Addressed to somebody else. */
    if (!load_the_request(&d)) {
        return false;
    }
    d.octets[AT_DESTINATION_ADDRESS + 3] = 9;
    repair_the_header_checksum(&d);
    if (!answered("addressed to somebody else", &d, ECHO_NO_ANSWER,
                  ECHO_REASON_NOT_FOR_US, COUNT_AT(not_for_us))) {
        ok = false;
    }

    /* A protocol we do not act on. */
    if (!load_the_request(&d)) {
        return false;
    }
    d.octets[AT_PROTOCOL] = 17;
    repair_the_header_checksum(&d);
    if (!answered("protocol 17", &d, ECHO_NO_ANSWER, ECHO_REASON_PROTOCOL_NOT_HANDLED,
                  COUNT_AT(protocol_not_handled))) {
        ok = false;
    }

    /* The ICMP message, three ways. ⚠ Total Length is moved with the message, so
     * these are datagrams that hold what they say they hold. */
    if (!load_the_request(&d)) {
        return false;
    }
    d.octets[IPV4_FIXED_HEADER_BYTES + 1] = 7; /* the code, which an echo's is 0 */
    write_16(d.octets + AT_TOTAL_LENGTH, (unsigned)d.bytes);
    repair_the_header_checksum(&d);
    {
        size_t message_bytes = d.bytes - IPV4_FIXED_HEADER_BYTES;
        write_16(d.octets + IPV4_FIXED_HEADER_BYTES + 2,
                 internet_checksum_with_field_cleared(
                     d.octets + IPV4_FIXED_HEADER_BYTES, message_bytes, 2));
    }
    if (!answered("an ICMP code that is not 0", &d, ECHO_NO_ANSWER,
                  ECHO_REASON_ICMP_MALFORMED, COUNT_AT(icmp_malformed))) {
        ok = false;
    }

    if (!load_the_request(&d)) {
        return false;
    }
    d.octets[IPV4_FIXED_HEADER_BYTES] = 3; /* a type we do not act on */
    {
        size_t message_bytes = d.bytes - IPV4_FIXED_HEADER_BYTES;
        write_16(d.octets + IPV4_FIXED_HEADER_BYTES + 2, 0);
        write_16(d.octets + IPV4_FIXED_HEADER_BYTES + 2,
                 internet_checksum_with_field_cleared(
                     d.octets + IPV4_FIXED_HEADER_BYTES, message_bytes, 2));
    }
    repair_the_header_checksum(&d);
    if (!answered("an ICMP type we do not act on", &d, ECHO_NO_ANSWER,
                  ECHO_REASON_ICMP_TYPE_NOT_HANDLED, COUNT_AT(icmp_type_not_handled))) {
        ok = false;
    }

    if (!load_the_request(&d)) {
        return false;
    }
    d.octets[d.bytes - 1] = (unsigned char)(d.octets[d.bytes - 1] ^ 0xff);
    if (!answered("an ICMP checksum that disagrees", &d, ECHO_NO_ANSWER,
                  ECHO_REASON_ICMP_CHECKSUM_DISAGREES,
                  COUNT_AT(icmp_checksum_disagrees))) {
        ok = false;
    }
    return ok;
}

/* ⚠ Ours, not the sender's, and counted rather than dropped in silence. */
static bool case_a_reply_we_could_not_build_is_counted_as_ours(void)
{
    struct datagram request;
    if (!load_the_request(&request)) {
        return false;
    }
    bool ok = true;
    size_t needed = ETHERNET_HEADER_BYTES + request.bytes;

    for (size_t room = 0; room < needed; room++) {
        struct echo_counts counts;
        memset(&counts, 0, sizeof counts);
        unsigned char reply[512];
        memset(reply, 0xaa, sizeof reply);
        struct echo_outcome outcome;
        echo_respond(request.octets, request.bytes, IPV4_TIME_TO_LIVE_WE_SEND, THEIR_MAC, OUR_MAC, OUR_IPV4, reply,
                     room, &outcome, &counts);

        if (outcome.decision != ECHO_NO_ANSWER ||
            outcome.reason != ECHO_REASON_WE_COULD_NOT_BUILD_THE_REPLY ||
            counts.we_could_not_build_the_reply != 1) {
            fprintf(stderr, "  %zu octets of room: decision %d reason %d, counted %lu\n",
                    room, (int)outcome.decision, (int)outcome.reason,
                    counts.we_could_not_build_the_reply);
            ok = false;
            break;
        }
    }

    /* ⚠ The other half: exactly enough room answers, or the loop above would
     * pass for a responder that never answered anything. */
    struct echo_counts counts;
    memset(&counts, 0, sizeof counts);
    unsigned char reply[512];
    struct echo_outcome outcome;
    echo_respond(request.octets, request.bytes, IPV4_TIME_TO_LIVE_WE_SEND, THEIR_MAC, OUR_MAC, OUR_IPV4, reply,
                 needed, &outcome, &counts);
    if (outcome.decision != ECHO_ANSWER || outcome.reply_bytes != needed) {
        fprintf(stderr, "  exactly %zu octets of room was declined, reason %d\n", needed,
                (int)outcome.reason);
        ok = false;
    }
    return ok;
}

/* ⚠ How far the ICMP message runs comes from Total Length, not from how many
 * octets arrived. ⚠ A frame padded up to the wire's minimum must answer exactly
 * as it would without the padding, or the padding lands inside the checksum. */
static bool case_padding_after_the_datagram_is_not_part_of_the_message(void)
{
    struct datagram plain;
    if (!load_the_request(&plain)) {
        return false;
    }

    struct echo_counts counts;
    memset(&counts, 0, sizeof counts);
    unsigned char without[512];
    struct echo_outcome outcome;
    echo_respond(plain.octets, plain.bytes, IPV4_TIME_TO_LIVE_WE_SEND, THEIR_MAC, OUR_MAC, OUR_IPV4, without,
                 sizeof without, &outcome, &counts);
    if (outcome.decision != ECHO_ANSWER) {
        fputs("  the unpadded request was declined\n", stderr);
        return false;
    }
    size_t without_bytes = outcome.reply_bytes;

    struct datagram padded = plain;
    for (size_t i = 0; i < 26; i++) {
        padded.octets[padded.bytes + i] = 0x5a;
    }
    padded.bytes += 26;

    unsigned char with[512];
    struct echo_outcome padded_outcome;
    echo_respond(padded.octets, padded.bytes, IPV4_TIME_TO_LIVE_WE_SEND, THEIR_MAC, OUR_MAC, OUR_IPV4, with,
                 sizeof with, &padded_outcome, &counts);
    if (padded_outcome.decision != ECHO_ANSWER) {
        fprintf(stderr, "  the padded request was declined, reason %d\n",
                (int)padded_outcome.reason);
        return false;
    }
    if (padded_outcome.reply_bytes != without_bytes ||
        memcmp(with, without, without_bytes) != 0) {
        fputs("  the padding changed the reply\n", stderr);
        return false;
    }
    return true;
}

/* ⚠ Answering in place: the reply written over the very frame that asked. */
static bool case_the_reply_may_be_built_over_the_request(void)
{
    struct datagram request;
    if (!load_the_request(&request)) {
        return false;
    }

    struct echo_counts counts;
    memset(&counts, 0, sizeof counts);
    unsigned char apart[512];
    struct echo_outcome outcome;
    echo_respond(request.octets, request.bytes, IPV4_TIME_TO_LIVE_WE_SEND, THEIR_MAC, OUR_MAC, OUR_IPV4, apart,
                 sizeof apart, &outcome, &counts);
    if (outcome.decision != ECHO_ANSWER) {
        fputs("  the request was declined when built apart\n", stderr);
        return false;
    }
    size_t apart_bytes = outcome.reply_bytes;

    /* ⚠ A whole frame, with the datagram where it really sits inside one. */
    unsigned char frame[512];
    memset(frame, 0, sizeof frame);
    memcpy(frame + ETHERNET_HEADER_BYTES, request.octets, request.bytes);

    struct echo_outcome in_place;
    echo_respond(frame + ETHERNET_HEADER_BYTES, request.bytes, IPV4_TIME_TO_LIVE_WE_SEND, THEIR_MAC, OUR_MAC,
                 OUR_IPV4, frame, sizeof frame, &in_place, &counts);
    if (in_place.decision != ECHO_ANSWER) {
        fprintf(stderr, "  the request was declined when built over itself, reason %d\n",
                (int)in_place.reason);
        return false;
    }
    if (in_place.reply_bytes != apart_bytes || memcmp(frame, apart, apart_bytes) != 0) {
        fputs("  building over the request gave different octets from building apart\n",
              stderr);
        return false;
    }
    return true;
}

static const struct test_case cases[] = {
    { "the_kernels_echo_request_is_answered", case_the_kernels_echo_request_is_answered },
    { "an_icmp_checksum_that_does_not_agree_is_not_answered_and_is_counted",
      case_an_icmp_checksum_that_does_not_agree_is_not_answered_and_is_counted },
    { "each_reason_moves_only_its_own_count", case_each_reason_moves_only_its_own_count },
    { "a_reply_we_could_not_build_is_counted_as_ours",
      case_a_reply_we_could_not_build_is_counted_as_ours },
    { "padding_after_the_datagram_is_not_part_of_the_message",
      case_padding_after_the_datagram_is_not_part_of_the_message },
    { "the_reply_may_be_built_over_the_request",
      case_the_reply_may_be_built_over_the_request },
};

int main(int argc, char **argv)
{
    return check_main("echo-responder", cases, sizeof cases / sizeof cases[0], argc, argv);
}
