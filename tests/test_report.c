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

/* ---- running them ------------------------------------------------------ */

static const struct test_case cases[] = {
    { "frame_line", case_frame_line },
    { "frame_line_when_the_buffer_was_filled", case_frame_line_when_the_buffer_was_filled },
    { "hex_of_the_captured_arp_request", case_hex_of_the_captured_arp_request },
    { "summary_counts_what_was_observed", case_summary_counts_what_was_observed },
    { "timeout_claims_nothing_about_the_sender", case_timeout_claims_nothing_about_the_sender },
    { "attach_failure_names_the_step_and_the_errno",
      case_attach_failure_names_the_step_and_the_errno },
};

#define CASE_COUNT (sizeof cases / sizeof cases[0])

int main(int argc, char **argv)
{
    return check_main("report", cases, CASE_COUNT, argc, argv);
}
