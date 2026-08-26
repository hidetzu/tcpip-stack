/* Static-tier check of the State layer: what an arriving ARP packet means for
 * us, and what we did about it.
 *
 * ⚠ No TAP device, no namespace, no clock. ⚠ It asserts that the four reasons
 * stay four things, which is the whole reason they were kept apart
 * (hidetzu/tcpip-stack#19 Owner Decisions 2 and 4). */
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "arp_responder.h"
#include "check.h"

static const unsigned char OUR_MAC[6] = {0x02,0x00,0x00,0x00,0x00,0x02};
static const unsigned char OUR_IPV4[4] = {10,0,0,2};
static const unsigned char THEIR_MAC[6] = {0x02,0x11,0x11,0x11,0x11,0x11};
static const unsigned char THEIR_IPV4[4] = {10,0,0,1};

#define PAYLOAD_BYTES (ARP_FIXED_BYTES + 2 * (6 + 4))

static void build(unsigned char *p, unsigned hrd, unsigned pro, unsigned hln,
                  unsigned pln, unsigned op, const unsigned char *target_ipv4)
{
    memset(p, 0, PAYLOAD_BYTES);
    p[0] = (unsigned char)(hrd >> 8); p[1] = (unsigned char)(hrd & 0xff);
    p[2] = (unsigned char)(pro >> 8); p[3] = (unsigned char)(pro & 0xff);
    p[4] = (unsigned char)hln; p[5] = (unsigned char)pln;
    p[6] = (unsigned char)(op >> 8); p[7] = (unsigned char)(op & 0xff);
    memcpy(p + 8, THEIR_MAC, 6);
    memcpy(p + 14, THEIR_IPV4, 4);
    memcpy(p + 24, target_ipv4, 4);
}

static void a_request_for(unsigned char *p, const unsigned char *target_ipv4)
{
    build(p, 0x0001, 0x0800, 6, 4, ARP_OPCODE_REQUEST, target_ipv4);
}

/* Hands one payload over and reports what came back. */
static bool answered(const char *what, const unsigned char *payload, size_t bytes,
                     enum arp_decision decision, enum arp_reason reason,
                     unsigned long *which_count, struct arp_counts *counts)
{
    struct arp_outcome outcome;
    unsigned long before = *which_count;
    arp_respond(payload, bytes, OUR_MAC, OUR_IPV4, &outcome, counts);

    bool ok = true;
    if (outcome.decision != decision || outcome.reason != reason) {
        fprintf(stderr, "  %s: expected decision %d reason %d, got %d and %d\n", what,
                (int)decision, (int)reason, (int)outcome.decision, (int)outcome.reason);
        ok = false;
    }
    if (*which_count != before + 1) {
        fprintf(stderr, "  %s: its own counter did not move by exactly one\n", what);
        ok = false;
    }
    if (decision == ARP_NO_ANSWER && outcome.reply_bytes != 0) {
        fprintf(stderr, "  %s: a reply was built for something we declined\n", what);
        ok = false;
    }
    return ok;
}

/* ⚠ The four reasons are four things. ⚠ Each moves its own counter and no
 * other: folding any two would make a count of one indistinguishable from a
 * count of the other (Owner Decisions 2 and 4). */
static bool case_each_reason_moves_only_its_own_count(void)
{
    unsigned char p[PAYLOAD_BYTES];
    struct arp_counts counts = {0,0,0,0,0};
    bool ok = true;

    a_request_for(p, THEIR_IPV4);  /* asks for 10.0.0.1, which is not ours */
    ok = answered("not for us", p, sizeof p, ARP_NO_ANSWER, ARP_REASON_NOT_FOR_US,
                  &counts.not_for_us, &counts) && ok;

    a_request_for(p, OUR_IPV4);
    ok = answered("malformed", p, ARP_FIXED_BYTES - 1, ARP_NO_ANSWER, ARP_REASON_MALFORMED,
                  &counts.malformed, &counts) && ok;

    build(p, 0x0006, 0x0800, 6, 4, ARP_OPCODE_REQUEST, OUR_IPV4);
    ok = answered("an address space we cannot place", p, sizeof p, ARP_NO_ANSWER,
                  ARP_REASON_UNSUPPORTED_ADDRESS_SPACE, &counts.unsupported_address_space,
                  &counts) && ok;

    build(p, 0x0001, 0x0800, 6, 4, 0x0063, OUR_IPV4);
    ok = answered("an opcode nobody defines", p, sizeof p, ARP_NO_ANSWER,
                  ARP_REASON_UNHANDLED_OPCODE, &counts.unhandled_opcode, &counts) && ok;

    /* ⚠ A reply is well formed and placeable, and we do not act on one. ⚠ It is
     * an opcode we do not act on — never "not for us", which is about whose
     * address was asked for. */
    build(p, 0x0001, 0x0800, 6, 4, ARP_OPCODE_REPLY, OUR_IPV4);
    ok = answered("a reply arriving", p, sizeof p, ARP_NO_ANSWER,
                  ARP_REASON_UNHANDLED_OPCODE, &counts.unhandled_opcode, &counts) && ok;

    /* ⚠ Nothing was answered, and the answered counter proves it stayed still. */
    if (counts.answered != 0) {
        fprintf(stderr, "  something was counted as answered and nothing was\n");
        ok = false;
    }
    return ok;
}

/* ⚠ The other half. A responder that declined everything would pass the case
 * above (`verify` §5). */
static bool case_a_request_for_our_address_is_answered(void)
{
    unsigned char p[PAYLOAD_BYTES];
    a_request_for(p, OUR_IPV4);

    struct arp_counts counts = {0,0,0,0,0};
    struct arp_outcome outcome;
    arp_respond(p, sizeof p, OUR_MAC, OUR_IPV4, &outcome, &counts);

    bool ok = true;
    if (outcome.decision != ARP_ANSWER || outcome.reason != ARP_REASON_NONE) {
        fprintf(stderr, "  a request for our own address was not answered\n");
        return false;
    }
    if (outcome.reply_bytes != ARP_REPLY_FRAME_BYTES) {
        fprintf(stderr, "  the reply is %zu octets, not %d\n", outcome.reply_bytes,
                ARP_REPLY_FRAME_BYTES);
        ok = false;
    }
    /* ⚠ Deliberately not counted here: the reply exists, it has not left. The
     * program counts it once the wire has taken it (`CLAUDE.md` §1). */
    if (counts.answered != 0) {
        fprintf(stderr, "  a reply that has not been sent was counted as answered\n");
        ok = false;
    }
    if (memcmp(outcome.reply, THEIR_MAC, 6) != 0) {
        fprintf(stderr, "  the reply is not addressed back to whoever asked\n");
        ok = false;
    }
    return ok;
}

static const struct test_case cases[] = {
    { "each_reason_moves_only_its_own_count", case_each_reason_moves_only_its_own_count },
    { "a_request_for_our_address_is_answered", case_a_request_for_our_address_is_answered },
};

#define CASE_COUNT (sizeof cases / sizeof cases[0])

int main(int argc, char **argv)
{
    return check_main("arp-responder", cases, CASE_COUNT, argc, argv);
}
