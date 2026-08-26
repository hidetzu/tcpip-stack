/* Static-tier check of the Report layer.
 *
 * ⚠ No TAP device, no namespace, no clock, no elevated capability. It builds
 * the lines a human reads and compares them byte for byte with the wording the
 * owner approved (hidetzu/tcpip-stack#2).
 *
 * ⚠ Running cases and reading fixtures is `tests/check.h`, shared with the
 * other static-tier binaries. ⚠ Only what is asserted lives here.
 *
 * ⚠ Exact comparison is the point: it is how "the timeout message claims
 * nothing about what the other side sent" is asserted. Any sentence added to
 * that message breaks this check. */
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "arp_responder.h"
#include "check.h"
#include "report.h"
#include "tap.h"

/* ---- the harness ------------------------------------------------------- */

struct produced {
    char *text;
    size_t length;
    FILE *out;
};

/* ⚠ Takes the caller's struct. open_memstream keeps the addresses it is given
 * and writes through them when the stream is flushed or closed, so they must
 * belong to something that outlives the stream — returning a filled-in struct
 * by value hands it the address of a dead local (`.claude/rules/c.md`). */
static void produced_open(struct produced *produced)
{
    produced->text = NULL;
    produced->length = 0;
    produced->out = open_memstream(&produced->text, &produced->length);
    if (produced->out == NULL) {
        fprintf(stderr, "could not capture output: %s\n", strerror(errno));
        exit(1);
    }
}

static void produced_close(struct produced *produced)
{
    fclose(produced->out);
    free(produced->text);
    produced->text = NULL;
    produced->out = NULL;
}

static bool matches(const char *what, struct produced *produced, const char *expected)
{
    fflush(produced->out);
    if (produced->text != NULL && strcmp(produced->text, expected) == 0) {
        return true;
    }
    fprintf(stderr, "  %s\n  expected:\n---\n%s---\n  produced:\n---\n%s---\n", what,
            expected, produced->text == NULL ? "" : produced->text);
    return false;
}

/* ---- the cases --------------------------------------------------------- */

static bool case_frame_line(void)
{
    struct produced produced;
    produced_open(&produced);
    report_frame(produced.out, 1, 42, false);
    bool ok = matches("frame line", &produced, "frame 1  42 bytes\n");
    produced_close(&produced);
    return ok;
}

static bool case_frame_line_when_the_buffer_was_filled(void)
{
    struct produced produced;
    produced_open(&produced);
    report_frame(produced.out, 4, TAP_FRAME_BUFFER_BYTES, true);
    bool ok = matches("frame line, buffer filled", &produced,
                      "frame 4  2048 bytes (filled the buffer; it may have been longer)\n");
    produced_close(&produced);
    return ok;
}

static bool case_hex_of_the_captured_arp_request(void)
{
    unsigned char frame[TAP_FRAME_BUFFER_BYTES];
    long bytes = check_load_fixture("arp-request-42.hex", frame, sizeof frame);
    if (bytes < 0) {
        return false;
    }
    if (bytes != 42) {
        fprintf(stderr, "  the captured ARP request is 42 bytes, this one is %ld\n", bytes);
        return false;
    }

    struct produced produced;
    produced_open(&produced);
    report_frame_bytes(produced.out, frame, (size_t)bytes);
    bool ok = matches("hex of the captured ARP request", &produced,
                      "  0000  ff ff ff ff ff ff 9e 28  ea ff 03 06 08 06 00 01\n"
                      "  0010  08 00 06 04 00 01 9e 28  ea ff 03 06 0a 00 00 01\n"
                      "  0020  00 00 00 00 00 00 0a 00  00 02\n");
    produced_close(&produced);
    return ok;
}

static bool case_summary_counts_what_was_observed(void)
{
    struct produced produced;
    produced_open(&produced);
    report_summary(produced.out, 3, 0);
    bool ok = matches("summary, plural", &produced, "read 3 frames, 0 read errors\n");
    produced_close(&produced);

    produced_open(&produced);
    report_summary(produced.out, 1, 1);
    ok = matches("summary, singular", &produced, "read 1 frame, 1 read error\n") && ok;
    produced_close(&produced);
    return ok;
}

static bool case_timeout_claims_nothing_about_the_sender(void)
{
    struct produced produced;
    produced_open(&produced);
    report_timeout(produced.out, "tap0", 2000, 0);
    bool ok = matches("timeout with nothing read", &produced,
                      "listened on tap0 for 2000 ms and read 0 frames. "
                      "Nothing arrived here; that does not say whether anything was sent.\n");
    produced_close(&produced);

    produced_open(&produced);
    report_timeout(produced.out, "tap0", 2000, 3);
    ok = matches("timeout after some frames", &produced,
                 "listened on tap0 for 2000 ms after frame 3 and read no more. "
                 "That does not say whether anything more was sent.\n") && ok;
    produced_close(&produced);
    return ok;
}

static bool case_attach_failure_names_the_step_and_the_errno(void)
{
    struct tap_failure name_too_long = { TAP_STEP_NAME, 0 };
    struct produced produced;
    produced_open(&produced);
    report_attach_failure(produced.out, "a-name-that-is-far-too-long", &name_too_long);
    bool ok = matches("device name rejected", &produced,
                      "could not attach to \"a-name-that-is-far-too-long\": "
                      "a device name is 1 to 15 characters.\n");
    produced_close(&produced);

    struct tap_failure could_not_open = { TAP_STEP_OPEN, EACCES };
    produced_open(&produced);
    report_attach_failure(produced.out, "tap0", &could_not_open);
    ok = matches("/dev/net/tun could not be opened", &produced,
                 "could not attach to tap0: opening /dev/net/tun failed: "
                 "Permission denied\n") && ok;
    produced_close(&produced);

    struct tap_failure not_permitted = { TAP_STEP_ATTACH, EPERM };
    produced_open(&produced);
    report_attach_failure(produced.out, "tap0", &not_permitted);
    ok = matches("the kernel refused to create the device", &produced,
                 "could not attach to tap0: creating the device failed: "
                 "Operation not permitted\n"
                 "  Creating a TAP device needs CAP_NET_ADMIN in the namespace that owns "
                 "it. The checks here get it from unshare -Urn, without sudo.\n") && ok;
    produced_close(&produced);
    return ok;
}


/* ⚠ The wording the owner approved for the ARP result, compared byte for byte
 * (hidetzu/tcpip-stack#19 Owner Decision 5). ⚠ The reason is a sentence; the
 * internal name never reaches a terminal (`CLAUDE.md` §4). */
static bool case_the_arp_result_says_the_decision_and_the_reason(void)
{
    static const unsigned char ours[4] = {10,0,0,2};
    struct arp_outcome outcome;
    memset(&outcome, 0, sizeof outcome);
    outcome.request.sender_protocol_address[0] = 10;
    outcome.request.sender_protocol_address[3] = 1;
    outcome.request.target_protocol_address[0] = 10;
    outcome.request.target_protocol_address[3] = 9;

    struct produced produced;
    outcome.decision = ARP_ANSWER;
    outcome.reason = ARP_REASON_NONE;
    produced_open(&produced);
    report_arp_outcome(produced.out, &outcome, ours);
    bool ok = matches("answered", &produced,
                      "  answered it: 10.0.0.2 is ours, and 10.0.0.1 was told our "
                      "hardware address\n");
    produced_close(&produced);

    outcome.decision = ARP_NO_ANSWER;
    struct { enum arp_reason reason; const char *what; const char *line; } declined[] = {
        { ARP_REASON_NOT_FOR_US, "not for us",
          "  no answer: it asked for 10.0.0.9, which is not an address we answer for\n" },
        { ARP_REASON_MALFORMED, "malformed",
          "  no answer: the ARP packet holds fewer octets than it says it does\n" },
        { ARP_REASON_UNSUPPORTED_ADDRESS_SPACE, "an address space we cannot place",
          "  no answer: its hardware or protocol address space is not one we can place\n" },
        { ARP_REASON_UNHANDLED_OPCODE, "an opcode we do not act on",
          "  no answer: its opcode is not one we act on\n" },
    };
    for (size_t i = 0; i < sizeof declined / sizeof declined[0]; i++) {
        outcome.reason = declined[i].reason;
        produced_open(&produced);
        report_arp_outcome(produced.out, &outcome, ours);
        ok = matches(declined[i].what, &produced, declined[i].line) && ok;
        produced_close(&produced);
    }
    return ok;
}

/* ⚠ Each reason counted on its own. A single "declined" number would make a
 * packet we could not read look exactly like one not addressed to us. */
static bool case_the_arp_summary_counts_each_reason_on_its_own(void)
{
    struct arp_counts one = { 1, 1, 1, 1, 1 };
    struct produced produced;
    produced_open(&produced);
    report_arp_summary(produced.out, &one);
    bool ok = matches("one of each", &produced,
                      "answered 1 ARP request. 1 was not for us, 1 was malformed, "
                      "1 named an address space we cannot place, "
                      "1 had an opcode we do not act on\n");
    produced_close(&produced);

    struct arp_counts several = { 2, 0, 3, 0, 4 };
    produced_open(&produced);
    report_arp_summary(produced.out, &several);
    ok = matches("several", &produced,
                 "answered 2 ARP requests. 0 were not for us, 3 were malformed, "
                 "0 named an address space we cannot place, "
                 "4 had an opcode we do not act on\n") && ok;
    produced_close(&produced);
    return ok;
}

/* ---- running them ------------------------------------------------------ */

static const struct test_case cases[] = {
    { "frame_line", case_frame_line },
    { "frame_line_when_the_buffer_was_filled", case_frame_line_when_the_buffer_was_filled },
    { "hex_of_the_captured_arp_request", case_hex_of_the_captured_arp_request },
    { "summary_counts_what_was_observed", case_summary_counts_what_was_observed },
    { "timeout_claims_nothing_about_the_sender", case_timeout_claims_nothing_about_the_sender },
    { "attach_failure_names_the_step_and_the_errno",
      case_attach_failure_names_the_step_and_the_errno },
    { "the_arp_result_says_the_decision_and_the_reason",
      case_the_arp_result_says_the_decision_and_the_reason },
    { "the_arp_summary_counts_each_reason_on_its_own",
      case_the_arp_summary_counts_each_reason_on_its_own },
};

#define CASE_COUNT (sizeof cases / sizeof cases[0])

int main(int argc, char **argv)
{
    return check_main("report", cases, CASE_COUNT, argc, argv);
}
