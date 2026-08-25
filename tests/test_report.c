/* Static-tier check of the Report layer.
 *
 * ⚠ No TAP device, no namespace, no clock, no elevated capability. It builds
 * the lines a human reads and compares them byte for byte with the wording the
 * owner approved (hidetzu/tcpip-stack#2).
 *
 * ⚠ Exact comparison is the point: it is how "the timeout message claims
 * nothing about what the other side sent" is asserted. Any sentence added to
 * that message breaks this check. */
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "report.h"
#include "tap.h"

#define FIXTURE_DIRECTORY_DEFAULT "tests/fixtures"

static const char *fixture_directory = FIXTURE_DIRECTORY_DEFAULT;

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

/* ---- loading the captured frame ---------------------------------------- */

/* Reads the hex fixture into a caller-supplied buffer. Lines starting with '#'
 * are provenance, not bytes. Returns the number of bytes, or -1. */
static long load_fixture(const char *name, unsigned char *into, size_t capacity)
{
    char path[512];
    if ((size_t)snprintf(path, sizeof path, "%s/%s", fixture_directory, name) >= sizeof path) {
        fprintf(stderr, "  the path to fixture %s does not fit\n", name);
        return -1;
    }
    FILE *file = fopen(path, "r");
    if (file == NULL) {
        fprintf(stderr, "  could not read fixture %s: %s\n", path, strerror(errno));
        return -1;
    }

    long bytes = 0;
    char line[256];
    while (fgets(line, sizeof line, file) != NULL) {
        if (line[0] == '#' || line[0] == '\n') {
            continue;
        }
        for (const char *at = line; *at != '\0';) {
            if (*at == ' ' || *at == '\n' || *at == '\t' || *at == '\r') {
                at++;
                continue;
            }
            unsigned value = 0;
            if (sscanf(at, "%2x", &value) != 1) {
                fprintf(stderr, "  fixture %s has something that is not a byte\n", path);
                fclose(file);
                return -1;
            }
            if ((size_t)bytes >= capacity) {
                fprintf(stderr, "  fixture %s is larger than the buffer for it\n", path);
                fclose(file);
                return -1;
            }
            into[bytes++] = (unsigned char)value;
            at += 2;
        }
    }
    fclose(file);
    return bytes;
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
    long bytes = load_fixture("arp-request-42.hex", frame, sizeof frame);
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

struct test_case {
    const char *name;
    bool (*run)(void);
};

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
    const char *only = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--count") == 0) {
            /* ⚠ Counts without running and without touching a fixture. */
            printf("report: %zu cases\n", CASE_COUNT);
            return 0;
        }
        if (strcmp(argv[i], "--list") == 0) {
            for (size_t c = 0; c < CASE_COUNT; c++) {
                printf("%s\n", cases[c].name);
            }
            return 0;
        }
        if (strcmp(argv[i], "--case") == 0 && i + 1 < argc) {
            only = argv[++i];
            continue;
        }
        if (strcmp(argv[i], "--fixtures") == 0 && i + 1 < argc) {
            fixture_directory = argv[++i];
            continue;
        }
        fprintf(stderr, "usage: %s [--case NAME] [--fixtures DIR] [--list] [--count]\n",
                argv[0]);
        return 2;
    }

    size_t selected = 0;
    for (size_t c = 0; c < CASE_COUNT; c++) {
        if (only == NULL || strcmp(only, cases[c].name) == 0) {
            selected++;
        }
    }
    if (selected == 0) {
        fprintf(stderr, "report: no case is named %s\n", only);
        return 2;
    }

    /* ⚠ The first line says which subset ran (`.claude/skills/verify` §1). */
    if (only == NULL) {
        printf("report: running %zu of %zu cases\n", selected, CASE_COUNT);
    } else {
        printf("report: running %zu of %zu cases (%s)\n", selected, CASE_COUNT, only);
    }

    size_t passed = 0;
    for (size_t c = 0; c < CASE_COUNT; c++) {
        if (only != NULL && strcmp(only, cases[c].name) != 0) {
            continue;
        }
        bool ok = cases[c].run();
        printf("  %-44s %s\n", cases[c].name, ok ? "ok" : "FAILED");
        if (ok) {
            passed++;
        }
    }

    printf("report: %zu of %zu cases passed\n", passed, selected);
    return passed == selected ? 0 : 1;
}
