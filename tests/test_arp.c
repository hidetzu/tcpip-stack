/* Static-tier check of the ARP Parse layer.
 *
 * ⚠ No TAP device, no namespace, no clock, no elevated capability. It hands
 * octets to the parser and reads back what it made of them.
 *
 * ⚠ Running cases and reading fixtures is `tests/check.h`.
 *
 * ⚠ Two ways of pinning the parser down, on purpose:
 *   - against the captured fixture, with the expected octets read out of the
 *     file rather than typed in here a second time (`CLAUDE.md` §3)
 *   - against packets built here, where each field is written from octets that
 *     are separate from the value expected of them, ⚠ so byte order and offset
 *     are asserted rather than restated from the implementation */
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "arp.h"
#include "check.h"
#include "ethernet.h"
#include "tap.h"

/* ---- building a packet to hand over -------------------------------------- */

/* Four addresses that are told apart at a glance, so a parser that read one of
 * them from another's place is caught. */
static const unsigned char SENDER_HARDWARE[6] = {0x02,0x11,0x11,0x11,0x11,0x11};
static const unsigned char SENDER_PROTOCOL[4] = {10,0,0,21};
static const unsigned char TARGET_HARDWARE[6] = {0x02,0x22,0x22,0x22,0x22,0x22};
static const unsigned char TARGET_PROTOCOL[4] = {10,0,0,22};

#define BUILT_BYTES (ARP_FIXED_BYTES + 2 * (6 + 4))

/* Writes a well-formed packet, then lets the caller spoil one field. */
static void build(unsigned char *payload, unsigned hardware_space_high,
                  unsigned hardware_space_low, unsigned protocol_space_high,
                  unsigned protocol_space_low, unsigned hardware_length,
                  unsigned protocol_length, unsigned opcode_high, unsigned opcode_low)
{
    memset(payload, 0, BUILT_BYTES);
    payload[0] = (unsigned char)hardware_space_high;
    payload[1] = (unsigned char)hardware_space_low;
    payload[2] = (unsigned char)protocol_space_high;
    payload[3] = (unsigned char)protocol_space_low;
    payload[4] = (unsigned char)hardware_length;
    payload[5] = (unsigned char)protocol_length;
    payload[6] = (unsigned char)opcode_high;
    payload[7] = (unsigned char)opcode_low;
    memcpy(payload + 8, SENDER_HARDWARE, 6);
    memcpy(payload + 14, SENDER_PROTOCOL, 4);
    memcpy(payload + 18, TARGET_HARDWARE, 6);
    memcpy(payload + 24, TARGET_PROTOCOL, 4);
}

/* An ethernet-and-IPv4 request, which every case below starts from. */
static void build_a_request(unsigned char *payload)
{
    build(payload, 0x00, 0x01, 0x08, 0x00, 6, 4, 0x00, 0x01);
}

static bool answered(const char *what, const unsigned char *payload, size_t bytes,
                     enum arp_parse expected)
{
    struct arp_packet packet;
    enum arp_parse answer = arp_parse_packet(payload, bytes, &packet);
    if (answer != expected) {
        fprintf(stderr, "  %s: expected answer %d, got %d\n", what, (int)expected,
                (int)answer);
        return false;
    }
    return true;
}

/* ---- the cases ---------------------------------------------------------- */

/* ⚠ The expected values are read back out of the fixture, never typed in here
 * (`CLAUDE.md` §3). ⚠ The offset the payload starts at comes from the layer
 * that owns the ethernet header, not from a 14 written a second time. */
static bool case_the_captured_arp_request_parses_to_what_the_file_holds(void)
{
    unsigned char frame[TAP_FRAME_BUFFER_BYTES];
    long bytes = check_load_fixture("arp-request-42.hex", frame, sizeof frame);
    if (bytes < 0) {
        return false;
    }
    if (bytes <= ETHERNET_HEADER_BYTES) {
        fprintf(stderr, "  the fixture is %ld octets, too short to hold a payload\n", bytes);
        return false;
    }
    const unsigned char *payload = frame + ETHERNET_HEADER_BYTES;
    size_t payload_bytes = (size_t)bytes - ETHERNET_HEADER_BYTES;

    struct arp_packet packet;
    enum arp_parse answer = arp_parse_packet(payload, payload_bytes, &packet);

    bool ok = true;
    if (answer != ARP_PARSE_OK) {
        fprintf(stderr, "  the captured ARP request was not accepted: answer %d\n", (int)answer);
        return false;
    }
    if (packet.opcode != ARP_OPCODE_REQUEST) {
        fprintf(stderr, "  the captured packet is a request; its opcode read as %u\n",
                packet.opcode);
        ok = false;
    }
    struct { const char *what; const unsigned char *ours; const unsigned char *file; size_t bytes; }
    fields[] = {
        { "ar$sha", packet.sender_hardware_address, payload + 8, 6 },
        { "ar$spa", packet.sender_protocol_address, payload + 14, 4 },
        { "ar$tha", packet.target_hardware_address, payload + 18, 6 },
        { "ar$tpa", packet.target_protocol_address, payload + 24, 4 },
    };
    for (size_t i = 0; i < sizeof fields / sizeof fields[0]; i++) {
        if (memcmp(fields[i].ours, fields[i].file, fields[i].bytes) != 0) {
            fprintf(stderr, "  %s is not the octets the fixture holds at that place\n",
                    fields[i].what);
            ok = false;
        }
    }
    if (packet.hardware_address_space != ARP_HARDWARE_ADDRESS_SPACE_ETHERNET ||
        packet.protocol_address_space != ARP_PROTOCOL_ADDRESS_SPACE_IPV4 ||
        packet.hardware_address_length != 6 || packet.protocol_address_length != 4) {
        fprintf(stderr, "  the fixed fields did not read as the fixture holds them\n");
        ok = false;
    }
    return ok;
}

/* ⚠ Malformed: fewer octets than the fixed fields need. */
static bool case_a_payload_shorter_than_the_fixed_fields_is_malformed(void)
{
    unsigned char payload[BUILT_BYTES];
    build_a_request(payload);

    bool ok = true;
    for (size_t bytes = 0; bytes < ARP_FIXED_BYTES; bytes++) {
        char what[64];
        snprintf(what, sizeof what, "%zu octets", bytes);
        ok = answered(what, payload, bytes, ARP_PARSE_MALFORMED) && ok;
    }
    /* ⚠ The other half. A check that only says "too short is refused" stays
     * green when everything is refused (`verify` §5). */
    ok = answered("a whole request", payload, BUILT_BYTES, ARP_PARSE_OK) && ok;
    return ok;
}

/* ⚠ Malformed: the lengths the packet declares need more octets than arrived.
 * ⚠ ar$hln and ar$pln are the sender's assertion, not a fact. */
static bool case_a_payload_shorter_than_the_lengths_it_declares_is_malformed(void)
{
    unsigned char payload[BUILT_BYTES];
    build_a_request(payload);

    bool ok = true;
    for (size_t bytes = ARP_FIXED_BYTES; bytes < BUILT_BYTES; bytes++) {
        char what[64];
        snprintf(what, sizeof what, "6 and 4 declared, %zu octets present", bytes);
        ok = answered(what, payload, bytes, ARP_PARSE_MALFORMED) && ok;
    }
    return ok;
}

/* ⚠ Well-formed and unsupported. The sender is fine; we cannot place it. */
static bool case_address_spaces_we_do_not_handle_are_said_so(void)
{
    unsigned char payload[BUILT_BYTES];
    bool ok = true;

    build(payload, 0x00, 0x06, 0x08, 0x00, 6, 4, 0x00, 0x01);
    ok = answered("ar$hrd that is not ethernet", payload, BUILT_BYTES,
                  ARP_PARSE_ADDRESS_SPACES_NOT_HANDLED) && ok;

    build(payload, 0x00, 0x01, 0x86, 0xdd, 6, 4, 0x00, 0x01);
    ok = answered("ar$pro that is not IPv4", payload, BUILT_BYTES,
                  ARP_PARSE_ADDRESS_SPACES_NOT_HANDLED) && ok;

    /* Lengths that fit in what arrived, so this is not truncation. */
    build(payload, 0x00, 0x01, 0x08, 0x00, 4, 4, 0x00, 0x01);
    ok = answered("ar$hln that is not 6", payload, BUILT_BYTES,
                  ARP_PARSE_ADDRESS_SPACES_NOT_HANDLED) && ok;

    build(payload, 0x00, 0x01, 0x08, 0x00, 6, 2, 0x00, 0x01);
    ok = answered("ar$pln that is not 4", payload, BUILT_BYTES,
                  ARP_PARSE_ADDRESS_SPACES_NOT_HANDLED) && ok;
    return ok;
}

/* ⚠ Owner Decision 1: an opcode we do not handle is its own outcome. */
static bool case_an_opcode_we_do_not_handle_is_its_own_outcome(void)
{
    unsigned char payload[BUILT_BYTES];
    bool ok = true;

    const unsigned opcodes[] = { 0x0000, 0x0003, 0x00ff, 0xffff };
    for (size_t i = 0; i < sizeof opcodes / sizeof opcodes[0]; i++) {
        char what[64];
        snprintf(what, sizeof what, "opcode 0x%04x", opcodes[i]);
        build(payload, 0x00, 0x01, 0x08, 0x00, 6, 4, opcodes[i] >> 8, opcodes[i] & 0xff);
        ok = answered(what, payload, BUILT_BYTES, ARP_PARSE_OPCODE_NOT_HANDLED) && ok;

        /* ⚠ AC 4: asserted to be neither of the other two, not merely non-zero. */
        struct arp_packet packet;
        enum arp_parse answer = arp_parse_packet(payload, BUILT_BYTES, &packet);
        if (answer == ARP_PARSE_MALFORMED || answer == ARP_PARSE_ADDRESS_SPACES_NOT_HANDLED) {
            fprintf(stderr, "  %s was folded into one of the other two answers\n", what);
            ok = false;
        }
        /* ⚠ The fixed fields are still handed back: the packet was read fine. */
        if (packet.opcode != opcodes[i]) {
            fprintf(stderr, "  %s: the opcode was not handed back, got 0x%04x\n", what,
                    packet.opcode);
            ok = false;
        }
    }

    /* ⚠ The other half: the two opcodes we do handle are accepted. */
    build(payload, 0x00, 0x01, 0x08, 0x00, 6, 4, 0x00, 0x01);
    ok = answered("ares_op$REQUEST", payload, BUILT_BYTES, ARP_PARSE_OK) && ok;
    build(payload, 0x00, 0x01, 0x08, 0x00, 6, 4, 0x00, 0x02);
    ok = answered("ares_op$REPLY", payload, BUILT_BYTES, ARP_PARSE_OK) && ok;
    return ok;
}

/* ⚠ Both truncated and unsupported at once. The order the parser decides in is
 * observable, so it is pinned rather than left to drift: a packet that does not
 * contain what it says it contains is malformed, whether or not those lengths
 * are ones we place. */
static bool case_a_packet_that_is_both_truncated_and_unsupported_is_malformed(void)
{
    unsigned char payload[BUILT_BYTES];
    build(payload, 0x00, 0x06, 0x86, 0xdd, 0xff, 0xff, 0x00, 0x63);
    return answered("hostile lengths in a short packet", payload, BUILT_BYTES,
                    ARP_PARSE_MALFORMED);
}

/* ⚠ Four addresses, four places. A parser that read one from another's offset
 * would pass a check that only looked at one of them. */
static bool case_the_four_addresses_are_read_from_their_own_places(void)
{
    unsigned char payload[BUILT_BYTES];
    build_a_request(payload);

    struct arp_packet packet;
    if (arp_parse_packet(payload, BUILT_BYTES, &packet) != ARP_PARSE_OK) {
        fprintf(stderr, "  a well-formed request was not accepted\n");
        return false;
    }
    bool ok = true;
    if (memcmp(packet.sender_hardware_address, SENDER_HARDWARE, 6) != 0) {
        fprintf(stderr, "  ar$sha did not come back as it was put in\n"); ok = false;
    }
    if (memcmp(packet.sender_protocol_address, SENDER_PROTOCOL, 4) != 0) {
        fprintf(stderr, "  ar$spa did not come back as it was put in\n"); ok = false;
    }
    if (memcmp(packet.target_hardware_address, TARGET_HARDWARE, 6) != 0) {
        fprintf(stderr, "  ar$tha did not come back as it was put in\n"); ok = false;
    }
    if (memcmp(packet.target_protocol_address, TARGET_PROTOCOL, 4) != 0) {
        fprintf(stderr, "  ar$tpa did not come back as it was put in\n"); ok = false;
    }
    return ok;
}

/* ⚠ Three reasons, three values. Two sharing a value would make a count of one
 * indistinguishable from a count of the other (`CLAUDE.md` §1). */
static bool case_the_reasons_a_packet_is_not_accepted_are_three_distinct_values(void)
{
    const enum arp_parse reasons[] = {
        ARP_PARSE_MALFORMED,
        ARP_PARSE_ADDRESS_SPACES_NOT_HANDLED,
        ARP_PARSE_OPCODE_NOT_HANDLED,
    };
    const size_t count = sizeof reasons / sizeof reasons[0];

    bool ok = true;
    for (size_t i = 0; i < count; i++) {
        if (reasons[i] == ARP_PARSE_OK) {
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


/* ---- building a reply ---------------------------------------------------- */

/* ⚠ The strongest check here. The kernel built a reply for us and it is in
 * tests/fixtures/arp-reply-42.hex. ⚠ Feed our builder the values the kernel
 * answered with, and what comes out must be the kernel's own octets, all 42.
 *
 * ⚠ That is what a captured reply buys: a hand-written expectation and a
 * hand-written implementation agree with each other by construction, and this
 * one was not written by us (`.claude/rules/layers.md`, question 3). */
static bool case_the_captured_reply_is_rebuilt_octet_for_octet(void)
{
    unsigned char captured[TAP_FRAME_BUFFER_BYTES];
    long captured_bytes = check_load_fixture("arp-reply-42.hex", captured, sizeof captured);
    if (captured_bytes < 0) {
        return false;
    }
    if (captured_bytes != ARP_REPLY_FRAME_BYTES) {
        fprintf(stderr, "  the captured reply is %d octets, this one is %ld\n",
                ARP_REPLY_FRAME_BYTES, captured_bytes);
        return false;
    }

    /* What the kernel answered with, read back out of its own reply. ⚠ Not
     * typed in here: the hardware address is whatever it picked that run. */
    struct arp_packet parsed;
    if (arp_parse_packet(captured + ETHERNET_HEADER_BYTES,
                         (size_t)captured_bytes - ETHERNET_HEADER_BYTES,
                         &parsed) != ARP_PARSE_OK) {
        fprintf(stderr, "  the captured reply did not parse\n");
        return false;
    }
    if (parsed.opcode != ARP_OPCODE_REPLY) {
        fprintf(stderr, "  the captured frame is a reply; its ar$op read as %u\n", parsed.opcode);
        return false;
    }

    /* ⚠ The request that would have produced it: the kernel's reply names the
     * requester in ar$tha and ar$tpa, so those are the request's ar$sha/ar$spa. */
    struct arp_packet request;
    memset(&request, 0, sizeof request);
    memcpy(request.sender_hardware_address, parsed.target_hardware_address,
           ARP_HARDWARE_ADDRESS_BYTES);
    memcpy(request.sender_protocol_address, parsed.target_protocol_address,
           ARP_PROTOCOL_ADDRESS_BYTES);

    unsigned char ours[ARP_REPLY_FRAME_BYTES];
    size_t built = 0;
    if (arp_build_reply(&request, parsed.sender_hardware_address,
                        parsed.sender_protocol_address, ours, sizeof ours,
                        &built) != ARP_BUILD_OK) {
        fprintf(stderr, "  a reply into a buffer of exactly the right size was refused\n");
        return false;
    }
    if (built != (size_t)captured_bytes) {
        fprintf(stderr, "  built %zu octets, the kernel built %ld\n", built, captured_bytes);
        return false;
    }
    if (memcmp(ours, captured, (size_t)captured_bytes) != 0) {
        fprintf(stderr, "  our octets are not the kernel's. octet by octet:\n");
        for (long i = 0; i < captured_bytes; i++) {
            if (ours[i] != captured[i]) {
                fprintf(stderr, "    %02ld: ours %02x, the kernel's %02x\n", i, ours[i],
                        captured[i]);
            }
        }
        return false;
    }
    return true;
}

/* ⚠ The reply goes back to whoever asked, and every field it borrows is taken
 * from the request rather than from anywhere else. */
static bool case_the_reply_goes_to_the_requester(void)
{
    unsigned char payload[BUILT_BYTES];
    build_a_request(payload);
    struct arp_packet request;
    if (arp_parse_packet(payload, sizeof payload, &request) != ARP_PARSE_OK) {
        fprintf(stderr, "  the built request did not parse\n");
        return false;
    }

    static const unsigned char our_mac[6] = {0x02,0xaa,0xaa,0xaa,0xaa,0xaa};
    static const unsigned char our_ipv4[4] = {10,0,0,99};

    unsigned char frame[ARP_REPLY_FRAME_BYTES];
    size_t built = 0;
    if (arp_build_reply(&request, our_mac, our_ipv4, frame, sizeof frame, &built)
        != ARP_BUILD_OK) {
        fprintf(stderr, "  building the reply was refused\n");
        return false;
    }

    const unsigned char *packet = frame + ETHERNET_HEADER_BYTES;
    bool ok = true;
    struct { const char *what; const unsigned char *got; const unsigned char *want; size_t n; }
    fields[] = {
        { "the ethernet destination", frame, SENDER_HARDWARE, 6 },
        { "the ethernet source", frame + 6, our_mac, 6 },
        { "ar$sha", packet + 8, our_mac, 6 },
        { "ar$spa", packet + 14, our_ipv4, 4 },
        { "ar$tha", packet + 18, SENDER_HARDWARE, 6 },
        { "ar$tpa", packet + 24, SENDER_PROTOCOL, 4 },
    };
    for (size_t i = 0; i < sizeof fields / sizeof fields[0]; i++) {
        if (memcmp(fields[i].got, fields[i].want, fields[i].n) != 0) {
            fprintf(stderr, "  %s is not what it should be\n", fields[i].what);
            ok = false;
        }
    }
    unsigned length_type = ((unsigned)frame[12] << 8) | frame[13];
    if (length_type != ARP_ETHERNET_LENGTH_TYPE) {
        fprintf(stderr, "  the length/type is 0x%04x\n", length_type);
        ok = false;
    }
    unsigned opcode = ((unsigned)packet[6] << 8) | packet[7];
    if (opcode != ARP_OPCODE_REPLY) {
        fprintf(stderr, "  ar$op is %u, not a reply\n", opcode);
        ok = false;
    }
    /* ⚠ The other half: the request's own target address is NOT what we answer
     * with. A builder that echoed the request back would pass everything above
     * that only looked at the borrowed fields. */
    if (memcmp(packet + 14, request.target_protocol_address, 4) == 0) {
        fprintf(stderr, "  ar$spa is the request's ar$tpa, not the address we were given\n");
        ok = false;
    }
    return ok;
}

/* ⚠ A buffer that cannot hold the whole reply is refused, never truncated.
 * ⚠ Half a frame on the wire is worse than none. */
static bool case_a_buffer_too_small_is_refused_rather_than_truncated(void)
{
    unsigned char payload[BUILT_BYTES];
    build_a_request(payload);
    struct arp_packet request;
    arp_parse_packet(payload, sizeof payload, &request);

    static const unsigned char our_mac[6] = {0x02,0xaa,0xaa,0xaa,0xaa,0xaa};
    static const unsigned char our_ipv4[4] = {10,0,0,99};

    bool ok = true;
    for (size_t room = 0; room < ARP_REPLY_FRAME_BYTES; room++) {
        unsigned char frame[ARP_REPLY_FRAME_BYTES];
        memset(frame, 0xee, sizeof frame);
        size_t built = 12345;
        if (arp_build_reply(&request, our_mac, our_ipv4, frame, room, &built)
            != ARP_BUILD_BUFFER_TOO_SMALL) {
            fprintf(stderr, "  %zu octets of room should not be enough\n", room);
            ok = false;
            continue;
        }
        /* ⚠ Nothing was written. Not one octet of a frame that will not be whole. */
        for (size_t i = 0; i < sizeof frame; i++) {
            if (frame[i] != 0xee) {
                fprintf(stderr, "  %zu octets of room: the buffer was written to anyway\n", room);
                ok = false;
                break;
            }
        }
    }
    /* ⚠ The other half. A builder that refused everything would pass the loop. */
    unsigned char frame[ARP_REPLY_FRAME_BYTES];
    size_t built = 0;
    if (arp_build_reply(&request, our_mac, our_ipv4, frame, sizeof frame, &built)
        != ARP_BUILD_OK) {
        fprintf(stderr, "  exactly enough room was refused\n");
        ok = false;
    }
    return ok;
}

/* ---- running them ------------------------------------------------------- */

static const struct test_case cases[] = {
    { "the_captured_arp_request_parses_to_what_the_file_holds",
      case_the_captured_arp_request_parses_to_what_the_file_holds },
    { "a_payload_shorter_than_the_fixed_fields_is_malformed",
      case_a_payload_shorter_than_the_fixed_fields_is_malformed },
    { "a_payload_shorter_than_the_lengths_it_declares_is_malformed",
      case_a_payload_shorter_than_the_lengths_it_declares_is_malformed },
    { "address_spaces_we_do_not_handle_are_said_so",
      case_address_spaces_we_do_not_handle_are_said_so },
    { "an_opcode_we_do_not_handle_is_its_own_outcome",
      case_an_opcode_we_do_not_handle_is_its_own_outcome },
    { "a_packet_that_is_both_truncated_and_unsupported_is_malformed",
      case_a_packet_that_is_both_truncated_and_unsupported_is_malformed },
    { "the_four_addresses_are_read_from_their_own_places",
      case_the_four_addresses_are_read_from_their_own_places },
    { "the_reasons_a_packet_is_not_accepted_are_three_distinct_values",
      case_the_reasons_a_packet_is_not_accepted_are_three_distinct_values },
    { "the_captured_reply_is_rebuilt_octet_for_octet",
      case_the_captured_reply_is_rebuilt_octet_for_octet },
    { "the_reply_goes_to_the_requester", case_the_reply_goes_to_the_requester },
    { "a_buffer_too_small_is_refused_rather_than_truncated",
      case_a_buffer_too_small_is_refused_rather_than_truncated },
};

#define CASE_COUNT (sizeof cases / sizeof cases[0])

int main(int argc, char **argv)
{
    return check_main("arp", cases, CASE_COUNT, argc, argv);
}
