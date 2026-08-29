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


/* ⚠ The same two-line shape ARP prints, for an IPv4 datagram
 * (hidetzu/tcpip-stack#35 Owner Decision 1). ⚠ Every one of the ten reasons has
 * a sentence, and ⚠ none of them prints an internal name. */
static bool case_an_echo_outcome_says_what_was_decided_and_why(void)
{
    static const uint8_t ours[4] = { 10, 0, 0, 2 };
    struct produced produced;
    bool ok = true;

    struct echo_outcome answered;
    memset(&answered, 0, sizeof answered);
    answered.decision = ECHO_ANSWER;
    answered.header.source_address[0] = 10;
    answered.header.source_address[3] = 1;
    answered.request.data_bytes = 56;
    produced_open(&produced);
    report_echo_outcome(produced.out, &answered, ours);
    ok = matches("answered", &produced,
                 "  answered it: 10.0.0.2 is ours, and 10.0.0.1 got its 56 octets back\n")
         && ok;
    produced_close(&produced);

    /* ⚠ One octet is not "1 octets". */
    answered.request.data_bytes = 1;
    produced_open(&produced);
    report_echo_outcome(produced.out, &answered, ours);
    ok = matches("answered, one octet", &produced,
                 "  answered it: 10.0.0.2 is ours, and 10.0.0.1 got its 1 octet back\n")
         && ok;
    produced_close(&produced);

    static const struct {
        enum echo_reason reason;
        const char *line;
    } declined[] = {
        { ECHO_REASON_NOT_FOR_US,
          "  no answer: it was addressed to 10.0.0.9, which is not an address we "
          "answer for\n" },
        { ECHO_REASON_INTERNET_HEADER_MALFORMED,
          "  no answer: its internet header does not hold what it says it holds\n" },
        { ECHO_REASON_INTERNET_HEADER_NOT_HANDLED,
          "  no answer: its internet header is one we do not read yet\n" },
        { ECHO_REASON_INTERNET_HEADER_CHECKSUM_DISAGREES,
          "  no answer: its internet header checksum does not agree with the octets "
          "that arrived\n" },
        { ECHO_REASON_FRAGMENT,
          "  no answer: it is a fragment, and nothing here puts fragments back "
          "together\n" },
        { ECHO_REASON_PROTOCOL_NOT_HANDLED,
          "  no answer: it carries protocol 17, which is not one we act on\n" },
        { ECHO_REASON_ICMP_MALFORMED,
          "  no answer: its ICMP message is shorter than one can be, or its code is "
          "not the 0 an echo message has\n" },
        { ECHO_REASON_ICMP_TYPE_NOT_HANDLED,
          "  no answer: its ICMP type is not one we act on\n" },
        { ECHO_REASON_ICMP_CHECKSUM_DISAGREES,
          "  no answer: its ICMP checksum does not agree with the octets that "
          "arrived\n" },
        /* ⚠ Ours, and it says so rather than pointing at the sender
         * (`CLAUDE.md` §4-1). */
        { ECHO_REASON_WE_COULD_NOT_BUILD_THE_REPLY,
          "  no answer: we could not build the reply. That is ours, not the "
          "sender's\n" },
    };

    for (size_t i = 0; i < sizeof declined / sizeof declined[0]; i++) {
        struct echo_outcome outcome;
        memset(&outcome, 0, sizeof outcome);
        outcome.decision = ECHO_NO_ANSWER;
        outcome.reason = declined[i].reason;
        outcome.header.destination_address[0] = 10;
        outcome.header.destination_address[3] = 9;
        outcome.header.protocol = 17;
        produced_open(&produced);
        report_echo_outcome(produced.out, &outcome, ours);
        char what[64];
        snprintf(what, sizeof what, "reason %d", (int)declined[i].reason);
        ok = matches(what, &produced, declined[i].line) && ok;
        produced_close(&produced);
    }
    return ok;
}

/* ⚠ Ten numbers, each on its own, and ⚠ printed even when every one is zero:
 * hiding a zero would make "none arrived" indistinguishable from "nobody
 * counted" (`CLAUDE.md` §1). */
static bool case_the_echo_summary_counts_every_reason_apart(void)
{
    struct produced produced;
    struct echo_counts none;
    memset(&none, 0, sizeof none);

    produced_open(&produced);
    report_echo_summary(produced.out, &none);
    bool ok = matches("nothing at all", &produced,
        "answered 0 echo requests. 0 were not for us, 0 carried a protocol we do not "
        "act on\n"
        "0 internet headers were malformed, 0 were ones we do not read yet, 0 had a "
        "checksum that does not agree, 0 were fragments\n"
        "0 ICMP messages were malformed, 0 had a type we do not act on, 0 had a "
        "checksum that does not agree\n"
        "0 replies could not be built, which would be ours and not the sender's\n");
    produced_close(&produced);

    struct echo_counts one = { 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1 };
    produced_open(&produced);
    report_echo_summary(produced.out, &one);
    ok = matches("one of each", &produced,
        "answered 1 echo request. 1 was not for us, 1 carried a protocol we do not "
        "act on\n"
        "1 internet header was malformed, 1 was one we do not read yet, 1 had a "
        "checksum that does not agree, 1 was a fragment\n"
        "1 ICMP message was malformed, 1 had a type we do not act on, 1 had a "
        "checksum that does not agree\n"
        "1 reply could not be built, which would be ours and not the sender's\n") && ok;
    produced_close(&produced);
    return ok;
}

/* ⚠ The wait reported an error on the fd instead of a frame, and there is no
 * errno — ppoll succeeded (hidetzu/tcpip-stack#8 Owner Decision 1). ⚠ Measured:
 * reusing the older sentence here prints "waiting for a frame failed: Success",
 * because strerror(0) is "Success". */
static bool case_the_device_going_away_names_no_errno(void)
{
    struct produced produced;
    produced_open(&produced);
    report_device_gone(produced.out, "tap0");
    bool ok = matches("the device stopped being usable", &produced,
                      "could not keep listening on tap0: the device stopped being usable.\n"
                      "  Waiting for a frame will not help. Nothing here can say why.\n");
    produced_close(&produced);
    return ok;
}

/* ⚠ A read that could not be made gets a line of its own. ⚠ This had no case at
 * all until hidetzu/tcpip-stack#8 — the behaviour was checked only through the
 * program, and that route is gone. */
static bool case_a_read_that_could_not_be_made_has_its_own_line(void)
{
    struct tap_failure could_not_read = { TAP_STEP_READ, EBADFD };
    struct produced produced;
    produced_open(&produced);
    report_read_failure(produced.out, 7, &could_not_read);
    bool ok = matches("a read that could not be made", &produced,
                      "frame 7  could not be read: File descriptor in bad state\n");
    produced_close(&produced);
    return ok;
}


/* ⚠ The value, never a name. A name would be a lie for a VLAN-tagged frame
 * (ADR 0003), and ⚠ `0x0800` -> IPv4 has never been taken from a standard here.
 * ⚠ Destination before source, matching the octets on the wire. */
static bool case_the_ethernet_header_line_shows_the_value_and_no_name(void)
{
    struct ethernet_header header;
    memcpy(header.destination, (unsigned char[]){0xff,0xff,0xff,0xff,0xff,0xff}, 6);
    memcpy(header.source, (unsigned char[]){0x7a,0x4b,0x98,0xd8,0xd7,0xbd}, 6);

    struct produced produced;
    struct { unsigned value; const char *line; } shown[] = {
        { 0x0806, "  ff:ff:ff:ff:ff:ff <- 7a:4b:98:d8:d7:bd, length/type 0x0806\n" },
        { 0x0800, "  ff:ff:ff:ff:ff:ff <- 7a:4b:98:d8:d7:bd, length/type 0x0800\n" },
        { 0x86dd, "  ff:ff:ff:ff:ff:ff <- 7a:4b:98:d8:d7:bd, length/type 0x86dd\n" },
        { 0x8100, "  ff:ff:ff:ff:ff:ff <- 7a:4b:98:d8:d7:bd, length/type 0x8100\n" },
    };
    bool ok = true;
    for (size_t i = 0; i < sizeof shown / sizeof shown[0]; i++) {
        header.length_type = (uint16_t)shown[i].value;
        produced_open(&produced);
        report_ethernet_header(produced.out, NULL, 60, ETHERNET_PARSE_OK, &header);
        char what[64];
        snprintf(what, sizeof what, "length/type 0x%04x", shown[i].value);
        ok = matches(what, &produced, shown[i].line) && ok;
        produced_close(&produced);
    }
    return ok;
}

/* ⚠ A header that could not be read shows no octets it never had. */
static bool case_a_header_that_could_not_be_read_shows_no_octets(void)
{
    struct ethernet_header header;
    memset(&header, 0xee, sizeof header);
    struct produced produced;
    produced_open(&produced);
    report_ethernet_header(produced.out, NULL, 9, ETHERNET_PARSE_SHORTER_THAN_THE_HEADER,
                           &header);
    bool ok = matches("too few octets", &produced,
                      "  not read: fewer octets arrived than an ethernet header needs\n");
    produced_close(&produced);
    return ok;
}

/* ⚠ The two answers that decline a frame whose header WAS read say what was
 * read and then why it stopped. ⚠ Neither calls the sender wrong: an IEEE 802.3
 * frame is well formed (`CLAUDE.md` §4-1). */
static bool case_the_two_declining_answers_each_say_why(void)
{
    struct ethernet_header header;
    memcpy(header.destination, (unsigned char[]){0x02,0,0,0,0,0x01}, 6);
    memcpy(header.source, (unsigned char[]){0x02,0,0,0,0,0x02}, 6);

    struct produced produced;
    header.length_type = 0x0026;
    produced_open(&produced);
    report_ethernet_header(produced.out, NULL, 60, ETHERNET_PARSE_LENGTH_NOT_A_TYPE, &header);
    bool ok = matches("an IEEE 802.3 Length", &produced,
                      "  02:00:00:00:00:01 <- 02:00:00:00:00:02, length/type 0x0026\n"
                      "  not read further: that is an IEEE 802.3 Length, not a Type\n");
    produced_close(&produced);

    header.length_type = 0x05dd;
    produced_open(&produced);
    report_ethernet_header(produced.out, NULL, 60, ETHERNET_PARSE_LENGTH_TYPE_UNDEFINED,
                           &header);
    ok = matches("a value the standard does not define", &produced,
                 "  02:00:00:00:00:01 <- 02:00:00:00:00:02, length/type 0x05dd\n"
                 "  not read further: the standard does not define that value\n") && ok;
    produced_close(&produced);
    return ok;
}

/* ⚠ The zeros are printed. Hiding one would make "none arrived" indistinguishable
 * from "nobody counted" (`CLAUDE.md` §1). */
static bool case_the_ethernet_summary_prints_its_zeros(void)
{
    struct ethernet_counts none = { 0, 0, 0 };
    struct produced produced;
    produced_open(&produced);
    report_ethernet_summary(produced.out, &none);
    bool ok = matches("nothing was declined", &produced,
                      "0 frames were malformed, 0 carried an IEEE 802.3 Length, "
                      "0 carried a length/type the standard does not define\n");
    produced_close(&produced);

    struct ethernet_counts some = { 1, 2, 3 };
    produced_open(&produced);
    report_ethernet_summary(produced.out, &some);
    ok = matches("one of the first, several of the others", &produced,
                 "1 frame was malformed, 2 carried an IEEE 802.3 Length, "
                 "3 carried a length/type the standard does not define\n") && ok;
    produced_close(&produced);
    return ok;
}

/* ---- running them ------------------------------------------------------ */

/* ⚠ The line that opens every run, and ⚠ it had no case at all until
 * hidetzu/tcpip-stack#50 — for the whole life of the program. */
/* ⚠ hidetzu/tcpip-stack#115. ⚠ Two lines and they are different answers:
 * ⚠ **what the device said, and that it could not be asked** (`CLAUDE.md` §1).
 *
 * ⚠ The failing line must never read as a measurement — ⚠ **it says the number
 * carried on with was chosen here.** */
static bool case_the_mtu_lines_say_which_it_was(void)
{
    struct produced produced;
    produced_open(&produced);
    report_mtu(produced.out, "tap0", 1500);
    bool ok = matches("what the device said", &produced,
        "tap0 carries frames of up to 1500 bytes\n");
    produced_close(&produced);

    /* ⚠ Not 1500: a second value, so a line printing a constant where the
     * argument belongs cannot pass (`verify` §5). */
    produced_open(&produced);
    report_mtu(produced.out, "tap9", 1400);
    ok = matches("a second device and a second size", &produced,
        "tap9 carries frames of up to 1400 bytes\n") && ok;
    produced_close(&produced);

    struct tap_failure could_not_ask = { TAP_STEP_MTU, ENODEV };
    produced_open(&produced);
    report_mtu_could_not_be_read(produced.out, "tap0", &could_not_ask, 1500);
    ok = matches("could not be asked", &produced,
        "could not ask tap0 how large a frame it carries: No such device\n"
        "  Carrying on with 1500 bytes, which is a value chosen here and not one "
        "this device reported.\n") && ok;
    produced_close(&produced);

    /* ⚠ The syscalls succeeded and the answer was not a size. ⚠ There is no
     * errno to name, and the line must not print `Success`. */
    struct tap_failure not_a_size = { TAP_STEP_MTU, 0 };
    produced_open(&produced);
    report_mtu_could_not_be_read(produced.out, "tap0", &not_a_size, 1500);
    ok = matches("no errno to name", &produced,
        "could not ask tap0 how large a frame it carries: the answer was not a size.\n"
        "  Carrying on with 1500 bytes, which is a value chosen here and not one "
        "this device reported.\n") && ok;
    produced_close(&produced);
    return ok;
}

/* ⚠ hidetzu/tcpip-stack#119. ⚠ Two refusals and they are opposite problems:
 * ⚠ **an MTU that leaves nothing, and one that leaves more than the field can
 * promise.** ⚠ The sentences say which, and ⚠ **each tells the reader what to
 * do about it** (`CLAUDE.md` §4-1). */
static bool case_no_window_says_which_way_it_failed(void)
{
    struct produced produced;
    produced_open(&produced);
    report_no_window(produced.out, "tap0", 40, false);
    bool ok = matches("nothing left", &produced,
        "tap0 carries frames of up to 40 bytes, which leaves no room for data "
        "after an internet header and a TCP header.\n"
        "  Nothing was read. Bring the device up with a larger MTU.\n");
    produced_close(&produced);

    produced_open(&produced);
    report_no_window(produced.out, "tap9", 70000, true);
    ok = matches("more than the field can promise", &produced,
        "tap9 carries frames of up to 70000 bytes, which leaves more room than "
        "the Window field can promise.\n"
        "  Nothing was read. Bring the device up with a smaller MTU.\n") && ok;
    produced_close(&produced);
    return ok;
}

static bool case_the_listening_line(void)
{
    struct produced produced;
    produced_open(&produced);
    report_listening(produced.out, "tap0");
    bool ok = matches("listening", &produced, "listening on tap0\n");
    produced_close(&produced);
    return ok;
}

/* ⚠ A wait that failed with an errno, told apart from one that came back
 * reporting an error on the fd — which has no errno and its own line
 * (`the_device_going_away_names_no_errno`). ⚠ Both existed; ⚠ only one had a
 * case. */
static bool case_a_wait_that_failed_names_its_errno(void)
{
    struct tap_failure could_not_wait = { TAP_STEP_WAIT, EBADF };
    struct produced produced;
    produced_open(&produced);
    report_wait_failure(produced.out, "tap0", &could_not_wait);
    bool ok = matches("the wait failed", &produced,
                      "could not keep listening on tap0: waiting for a frame failed: "
                      "Bad file descriptor\n");
    produced_close(&produced);
    return ok;
}

/* ⚠ What `--help` prints. ⚠ Not asserted byte for byte: it is long, it changes
 * whenever an option is added, and ⚠ **a case that pinned every word of it
 * would be a case about the text rather than about the contract**
 * (`.claude/rules/testing.md`: never pin down the current implementation's
 * steps).
 *
 * ⚠ What IS asserted is the contract: ⚠ **every option the program accepts is
 * named**, so an option can never be added without appearing here. ⚠ That is the
 * half that goes wrong in silence. */
static bool case_the_usage_names_every_option(void)
{
    struct produced produced;
    produced_open(&produced);
    report_usage(produced.out, "tcpip-stack");
    fflush(produced.out);

    static const char *const options[] = {
        "--dev", "--mac", "--ipv4", "--tcp-port", "--count", "--timeout", "--hex",
        "--help",
    };
    bool ok = true;
    for (size_t i = 0; i < sizeof options / sizeof options[0]; i++) {
        if (produced.text == NULL || strstr(produced.text, options[i]) == NULL) {
            fprintf(stderr, "  the usage does not name %s\n", options[i]);
            ok = false;
        }
    }
    /* ⚠ The other half: it says what the program is for, so this cannot pass
     * for a usage that is only a list of flags. */
    if (produced.text == NULL || strstr(produced.text, "tcpip-stack") == NULL) {
        fputs("  the usage does not name the program\n", stderr);
        ok = false;
    }
    produced_close(&produced);
    return ok;
}

/* ⚠ Why a segment never reached the state machine. ⚠ Two sentences, and ⚠ the
 * two must stay apart: a header we could not read is not one whose checksum
 * disagrees (`.claude/rules/c.md`). */
static bool case_a_segment_that_was_not_read_says_which_it_was(void)
{
    struct produced produced;
    bool ok = true;

    produced_open(&produced);
    report_tcp_not_read(produced.out, TCP_PARSE_MALFORMED);
    ok = matches("malformed", &produced,
                 "  no answer: its TCP header does not hold what it says it holds\n")
         && ok;
    produced_close(&produced);

    produced_open(&produced);
    report_tcp_not_read(produced.out, TCP_PARSE_CHECKSUM_DISAGREES);
    ok = matches("the checksum disagrees", &produced,
                 "  no answer: its TCP checksum does not agree with the octets that "
                 "arrived\n") && ok;
    produced_close(&produced);
    return ok;
}

static bool case_the_tcp_summary_keeps_its_two_numbers_apart(void)
{
    struct produced produced;
    struct tcp_counts none = { 0, 0 };
    produced_open(&produced);
    report_tcp_summary(produced.out, &none);
    bool ok = matches("nothing at all", &produced,
                      "0 TCP headers were malformed and 0 had a checksum that does not "
                      "agree\n");
    produced_close(&produced);

    struct tcp_counts one = { 1, 1 };
    produced_open(&produced);
    report_tcp_summary(produced.out, &one);
    ok = matches("one of each", &produced,
                 "1 TCP header was malformed and 1 had a checksum that does not "
                 "agree\n") && ok;
    produced_close(&produced);
    return ok;
}

/* ⚠ The wording hidetzu/tcpip-stack#43 Owner Decision 2 and #44 Owner Decision 4
 * approved — ⚠ **and which no case asserted until #50**, while
 * `docs/SPEC.md` §1 said one did.
 *
 * ⚠ Every branch that has its own sentence, including the two that are ours and
 * say so (`CLAUDE.md` §4-1). */
static bool case_a_handshake_outcome_says_what_moved_and_why(void)
{
    struct produced produced;
    struct handshake_outcome outcome;
    bool ok = true;

    /* The remote socket every line below names. */
    struct connection_id id;
    memset(&id, 0, sizeof id);
    id.local.address[0] = 10;
    id.local.address[3] = 2;
    id.local.port = 80;
    id.remote.address[0] = 10;
    id.remote.address[3] = 1;
    id.remote.port = 50568;

    static const struct { enum connection_state state; const char *line; } moved[] = {
        { CONNECTION_SYN_RECEIVED,
          "  10.0.0.1:50568 asked to open a connection; now waiting for it to\n"
          "    confirm (SYN-RECEIVED)\n" },
        { CONNECTION_ESTABLISHED,
          "  10.0.0.1:50568 confirmed it; the connection is open (ESTABLISHED)\n" },
        /* ⚠ What happened first, then what is missing and what closes it.
         * ⚠ Nothing here is the sender's fault: it closed properly, and ⚠ **not
         * answering is ours** (`CLAUDE.md` §4-1). */
        { CONNECTION_CLOSE_WAIT,
          "  10.0.0.1:50568 has closed its side; we read the FIN and have not answered\n"
          "    it yet (CLOSE-WAIT)\n" },
        { CONNECTION_LAST_ACK,
          "  10.0.0.1:50568 has closed its side; we read the FIN, closed ours in the same\n"
          "    segment, and are waiting for that to be acknowledged (LAST-ACK)\n" },
        { CONNECTION_CLOSED,
          "  10.0.0.1:50568 acknowledged our own close; the connection is finished and\n"
          "    the room it held is free again (CLOSED)\n" },
    };
    for (size_t i = 0; i < sizeof moved / sizeof moved[0]; i++) {
        memset(&outcome, 0, sizeof outcome);
        outcome.decision = HANDSHAKE_MOVED;
        outcome.state = moved[i].state;
        outcome.id = id;
        produced_open(&produced);
        report_handshake_outcome(produced.out, &outcome);
        char what[48];
        snprintf(what, sizeof what, "moved to state %d", (int)moved[i].state);
        ok = matches(what, &produced, moved[i].line) && ok;
        produced_close(&produced);
    }

    static const struct { enum handshake_reason reason; const char *line; } stayed[] = {
        { HANDSHAKE_REASON_ASKED_AGAIN,
          "  10.0.0.1:50568 asked again; nothing changed\n" },
        { HANDSHAKE_REASON_ACKNOWLEDGMENT_WE_ARE_NOT_WAITING_FOR,
          "  no answer: it acknowledged 3735928559, and we are waiting for "
          "3735928559 + 1\n" },
        { HANDSHAKE_REASON_NOT_EXPECTED_IN_THIS_STATE,
          "  no answer: nothing in this connection's state expects that\n" },
        { HANDSHAKE_REASON_NO_CONNECTION_HELD,
          "  no answer: nothing here is expecting a segment from 10.0.0.1:50568\n" },
        /* ⚠ Ours, and it says so. */
        { HANDSHAKE_REASON_THE_OTHER_SIDE_RESET_IT,
          "  10.0.0.1:50568 reset the connection; it is gone and the room it held is free\n"
          "    again (CLOSED)\n" },
        { HANDSHAKE_REASON_A_RESET_OUTSIDE_THE_WINDOW,
          "  no answer: that reset is not for a sequence number we are waiting\n"
          "    for, so nothing was done with it\n" },
        { HANDSHAKE_REASON_URGENT_AND_NOBODY_TO_TELL,
          "  no answer: that was marked urgent, and there is nobody here to\n"
          "    hand it to. That is ours, not the sender's\n" },
        { HANDSHAKE_REASON_ADDRESSED_TO_EVERYONE,
          "  no answer: that was addressed to a broadcast or multicast address,\n"
          "    and a connection is never made to one\n" },
        { HANDSHAKE_REASON_NO_ROOM,
          "  no answer: we are already holding a connection, and this build has\n"
          "    room for one. That is ours, not the sender's\n" },
        /* ⚠ Our timer fired — ⚠ **not them asking again**, which is what this
         * sentence said until hidetzu/tcpip-stack#59. */
        { HANDSHAKE_REASON_THE_ANSWER_WENT_OUT_AGAIN,
          "  10.0.0.1:50568 has not confirmed it; the answer went out again\n" },
        /* ⚠ Nobody confirmed it — ⚠ not the sender being wrong about anything
         * (`CLAUDE.md` §4-1). */
        { HANDSHAKE_REASON_NOBODY_CONFIRMED_IT,
          "  10.0.0.1:50568 never confirmed it; the connection was given up on\n" },
        { HANDSHAKE_REASON_WE_COULD_NOT_BUILD_THE_REPLY,
          "  no answer: we could not hand the reply to the device. That is ours,\n"
          "    not the sender's\n" },
        /* ⚠ Which of the two it was is not claimed, because ⚠ **this build does
         * not tell them apart** (hidetzu/tcpip-stack#64). */
        /* ⚠ Our timer fired — ⚠ **not them asking for anything.** */
        { HANDSHAKE_REASON_OUR_FIN_WENT_OUT_AGAIN,
          "  10.0.0.1:50568 has not acknowledged our close; it went out again\n" },
        /* ⚠ We stopped waiting, and ⚠ **it is not the same event as a handshake
         * nobody confirmed** (the sentence above it in this table). */
        { HANDSHAKE_REASON_NOBODY_ACKNOWLEDGED_OUR_FIN,
          "  10.0.0.1:50568 never acknowledged our close; we stopped waiting and freed the\n"
          "    room the connection held\n" },
        /* ⚠ Two sentences where there was one saying "either, or"
         * (hidetzu/tcpip-stack#76). */
        { HANDSHAKE_REASON_A_FIN_WE_HAVE_READ_ALREADY,
          "  no answer: we have read that FIN already and moved past it\n" },
        { HANDSHAKE_REASON_A_FIN_THAT_BEGINS_TOO_FAR_AHEAD,
          "  no answer: that FIN begins past what we are waiting for, and there\n"
          "    are octets before it we have not taken\n" },
        { HANDSHAKE_REASON_A_FIN_WE_CANNOT_PLACE,
          "  no answer: nothing here is holding the connection that FIN closes, so\n"
          "    its sequence number cannot be checked against anything\n" },
        { HANDSHAKE_REASON_DATA_WE_HAVE_TAKEN_ALREADY,
          "  no answer: we have taken every octet of that already\n" },
        { HANDSHAKE_REASON_DATA_THAT_BEGINS_TOO_FAR_AHEAD,
          "  no answer: that data begins past what we are waiting for, and there\n"
          "    are octets before it we have not seen\n" },
    };
    for (size_t i = 0; i < sizeof stayed / sizeof stayed[0]; i++) {
        memset(&outcome, 0, sizeof outcome);
        outcome.decision = HANDSHAKE_STAYED;
        outcome.reason = stayed[i].reason;
        outcome.id = id;
        outcome.acknowledgment_we_had = 3735928559u;
        outcome.acknowledgment_we_expected = 3735928560u;
        produced_open(&produced);
        report_handshake_outcome(produced.out, &outcome);
        char what[48];
        snprintf(what, sizeof what, "reason %d", (int)stayed[i].reason);
        ok = matches(what, &produced, stayed[i].line) && ok;
        produced_close(&produced);
    }

    /* ⚠ The one reason whose sentence carries a number, so it needs the field
     * set. ⚠ One and two, because ⚠ **the singular is where the wording of a
     * count usually breaks** and a table of one value never shows it. */
    static const struct { uint16_t octets; const char *line; } taken[] = {
        { 1, "  1 octet of data arrived; we took it, told the sender so, and\n"
             "    had nobody to give it to\n" },
        { 2, "  2 octets of data arrived; we took them, told the sender so, and\n"
             "    had nobody to give them to\n" },
    };
    for (size_t i = 0; i < sizeof taken / sizeof taken[0]; i++) {
        memset(&outcome, 0, sizeof outcome);
        outcome.decision = HANDSHAKE_STAYED;
        outcome.reason = HANDSHAKE_REASON_THE_DATA_WAS_TAKEN_AND_DISCARDED;
        outcome.id = id;
        outcome.octets_taken = taken[i].octets;
        produced_open(&produced);
        report_handshake_outcome(produced.out, &outcome);
        char what[48];
        snprintf(what, sizeof what, "%u octets taken", (unsigned)taken[i].octets);
        ok = matches(what, &produced, taken[i].line) && ok;
        produced_close(&produced);
    }

    /* ⚠ Data can ride the acknowledgment that opens the connection, and then
     * ⚠ **both lines are printed** — the transition and what became of the
     * octets. ⚠ A payload nobody mentioned reads exactly like one that never
     * arrived (`CLAUDE.md` §1). */
    memset(&outcome, 0, sizeof outcome);
    outcome.decision = HANDSHAKE_MOVED;
    outcome.state = CONNECTION_ESTABLISHED;
    outcome.id = id;
    outcome.octets_taken = 1;
    produced_open(&produced);
    report_handshake_outcome(produced.out, &outcome);
    ok = matches("established, carrying an octet", &produced,
        "  10.0.0.1:50568 confirmed it; the connection is open (ESTABLISHED)\n"
        "  1 octet of data arrived; we took it, told the sender so, and\n"
        "    had nobody to give it to\n") && ok;
    produced_close(&produced);

    /* ⚠ A FIN may ride data too, and ⚠ **then both lines are printed.** */
    memset(&outcome, 0, sizeof outcome);
    outcome.decision = HANDSHAKE_MOVED;
    outcome.state = CONNECTION_CLOSE_WAIT;
    outcome.id = id;
    outcome.octets_taken = 1;
    produced_open(&produced);
    report_handshake_outcome(produced.out, &outcome);
    ok = matches("closed, carrying an octet", &produced,
        "  10.0.0.1:50568 has closed its side; we read the FIN and have not answered\n"
        "    it yet (CLOSE-WAIT)\n"
        "  1 octet of data arrived; we took it, told the sender so, and\n"
        "    had nobody to give it to\n") && ok;
    produced_close(&produced);
    return ok;
}

/* ⚠ Every number on its own, and ⚠ printed even when every one is zero.
 *
 * ⚠ One of them is in octets and the rest are in segments, and ⚠ **the line
 * says which** (`CLAUDE.md` §6). */
static bool case_the_handshake_summary_counts_every_reason_apart(void)
{
    struct produced produced;
    struct handshake_counts none;
    memset(&none, 0, sizeof none);

    produced_open(&produced);
    report_handshake_summary(produced.out, &none);
    bool ok = matches("nothing at all", &produced,
        "0 connections were opened and 0 answered. 0 asked again\n"
        "0 reached open. 0 acknowledged a number we are not waiting for, 0 arrived "
        "for no connection we hold, 0 arrived where the connection's state did not "
        "expect them\n"
        "0 of our own closes left the device and 0 went out again because nobody "
        "had acknowledged them. 0 connections finished, and 0 were given up on with "
        "our close unacknowledged\n"
        "0 answers went out again because nobody had confirmed them\n"
        "0 connections were given up on after nobody confirmed them\n"
        "0 acknowledgments for data left the device, and 0 said where we are without "
        "accepting anything\n"
        "0 octets of data were taken and discarded. 0 segments carried data we had "
        "taken already, and 0 began past what we were waiting for\n"
        "the other side closed 0 connections. 0 FINs arrived that we had read "
        "already, 0 began past what we were waiting for, and 0 named a connection we "
        "hold nothing for\n"
        "the other side reset 0 connections and 0 resets named a sequence number we "
        "are not waiting for. 0 segments were marked urgent with nobody here to hand "
        "it to\n"
        "0 segments were addressed to a broadcast or multicast address, which a "
        "connection is never made to\n"
        "0 segments were from an address that can never send anything\n"
        "0 octets of ours went out again in 0 segments because nobody had "
        "acknowledged them\n"
        "0 octets of ours left in 0 segments, and 0 times there was no room in the "
        "window they advertised\n"
        "0 were refused for want of room and 0 answers never left the device, which "
        "are ours and not the sender's\n");
    produced_close(&produced);

    struct handshake_counts one;
    memset(&one, 0, sizeof one);
    one.opened = 1;
    one.established = 1;
    one.asked_again = 1;
    one.acknowledgment_we_are_not_waiting_for = 1;
    one.not_expected_in_this_state = 1;
    one.no_connection_held = 1;
    one.we_could_not_build_the_reply = 1;
    one.given_up_on = 1;
    one.answered_again = 1;
    one.answered = 1;
    one.room.refused_for_want_of_room = 1;
    one.addressed_to_everyone = 1;
    one.from_an_impossible_source = 1;
    one.data_segments_we_sent = 1;
    one.data_octets_we_sent = 1;
    one.their_window_had_no_room = 1;
    one.data_segments_we_sent_again = 1;
    one.data_octets_we_sent_again = 1;
    one.reset_by_the_other_side = 1;
    one.reset_outside_the_window = 1;
    one.urgent_and_nobody_to_tell = 1;
    one.data_acknowledged = 1;
    one.told_them_where_we_are = 1;
    one.octets_taken_and_discarded = 1;
    one.data_we_have_taken_already = 1;
    one.data_that_begins_too_far_ahead = 1;
    one.the_other_side_closed = 1;
    one.our_fin_left = 1;
    one.our_fin_went_out_again = 1;
    one.closed = 1;
    one.never_acknowledged_our_fin = 1;
    one.fin_we_have_read_already = 1;
    one.fin_that_begins_too_far_ahead = 1;
    one.fin_we_could_not_place = 1;

    produced_open(&produced);
    report_handshake_summary(produced.out, &one);
    ok = matches("one of each", &produced,
        "1 connection was opened and 1 answered. 1 asked again\n"
        "1 reached open. 1 acknowledged a number we are not waiting for, 1 arrived "
        "for no connection we hold, 1 arrived where the connection's state did not "
        "expect them\n"
        "1 of our own closes left the device and 1 went out again because nobody "
        "had acknowledged them. 1 connection finished, and 1 was given up on with "
        "our close unacknowledged\n"
        "1 answer went out again because nobody had confirmed it\n"
        "1 connection was given up on after nobody confirmed it\n"
        "1 acknowledgment for data left the device, and 1 said where we are without "
        "accepting anything\n"
        "1 octet of data was taken and discarded. 1 segment carried data we had "
        "taken already, and 1 began past what we were waiting for\n"
        "the other side closed 1 connection. 1 FIN arrived that we had read already, "
        "1 began past what we were waiting for, and 1 named a connection we hold "
        "nothing for\n"
        "the other side reset 1 connection and 1 reset named a sequence number we "
        "are not waiting for. 1 segment was marked urgent with nobody here to hand "
        "it to\n"
        "1 segment was addressed to a broadcast or multicast address, which a "
        "connection is never made to\n"
        "1 segment was from an address that can never send anything\n"
        "1 octet of ours went out again in 1 segment because nobody had "
        "acknowledged them\n"
        "1 octet of ours left in 1 segment, and 1 time there was no room in the "
        "window they advertised\n"
        "1 was refused for want of room and 1 answer never left the device, which "
        "are ours and not the sender's\n") && ok;
    produced_close(&produced);

    /* ⚠ The half the two blocks above cannot assert: ⚠ **every number is 0 in
     * one and 1 in the other, and 1 and 1 are symmetric** — so a line printing
     * one counter where another belongs passes both.
     *
     * ⚠ Measured: swapping the last two numbers of the FIN line left this case
     * green, ⚠ **which is the same defect `each_kind_of_frame_moves_its_own_counter`
     * had** (hidetzu/tcpip-stack#52). ⚠ Every number here is different, and
     * ⚠ they also carry the plural wording the block above cannot reach. */
    struct handshake_counts each;
    memset(&each, 0, sizeof each);
    each.opened = 2;
    each.answered = 3;
    each.asked_again = 4;
    each.established = 5;
    each.acknowledgment_we_are_not_waiting_for = 6;
    each.no_connection_held = 7;
    each.not_expected_in_this_state = 8;
    each.answered_again = 9;
    each.given_up_on = 10;
    each.our_fin_left = 18;
    each.our_fin_went_out_again = 19;
    each.closed = 20;
    each.never_acknowledged_our_fin = 21;
    each.data_acknowledged = 22;
    each.told_them_where_we_are = 25;
    each.octets_taken_and_discarded = 11;
    each.data_we_have_taken_already = 12;
    each.data_that_begins_too_far_ahead = 23;
    each.the_other_side_closed = 13;
    each.fin_we_have_read_already = 14;
    each.fin_that_begins_too_far_ahead = 24;
    each.fin_we_could_not_place = 15;
    each.room.refused_for_want_of_room = 16;
    each.addressed_to_everyone = 26;
    each.from_an_impossible_source = 30;
    each.data_segments_we_sent = 31;
    each.data_octets_we_sent = 32;
    each.their_window_had_no_room = 33;
    each.data_segments_we_sent_again = 34;
    each.data_octets_we_sent_again = 35;
    each.reset_by_the_other_side = 27;
    each.reset_outside_the_window = 28;
    each.urgent_and_nobody_to_tell = 29;
    each.we_could_not_build_the_reply = 17;

    produced_open(&produced);
    report_handshake_summary(produced.out, &each);
    ok = matches("no two numbers alike", &produced,
        "2 connections were opened and 3 answered. 4 asked again\n"
        "5 reached open. 6 acknowledged a number we are not waiting for, 7 arrived "
        "for no connection we hold, 8 arrived where the connection's state did not "
        "expect them\n"
        "18 of our own closes left the device and 19 went out again because nobody "
        "had acknowledged them. 20 connections finished, and 21 were given up on "
        "with our close unacknowledged\n"
        "9 answers went out again because nobody had confirmed them\n"
        "10 connections were given up on after nobody confirmed them\n"
        "22 acknowledgments for data left the device, and 25 said where we are "
        "without accepting anything\n"
        "11 octets of data were taken and discarded. 12 segments carried data we had "
        "taken already, and 23 began past what we were waiting for\n"
        "the other side closed 13 connections. 14 FINs arrived that we had read "
        "already, 24 began past what we were waiting for, and 15 named a connection "
        "we hold nothing for\n"
        "the other side reset 27 connections and 28 resets named a sequence number "
        "we are not waiting for. 29 segments were marked urgent with nobody here to "
        "hand it to\n"
        "26 segments were addressed to a broadcast or multicast address, which a "
        "connection is never made to\n"
        "30 segments were from an address that can never send anything\n"
        "35 octets of ours went out again in 34 segments because nobody had "
        "acknowledged them\n"
        "32 octets of ours left in 31 segments, and 33 times there was no room in "
        "the window they advertised\n"
        "16 were refused for want of room and 17 answers never left the device, "
        "which are ours and not the sender's\n") && ok;
    produced_close(&produced);
    return ok;
}

/* ⚠ The sentences hidetzu/tcpip-stack#51 moved out of `src/tcpip_stack.c`.
 * ⚠ **Word for word what they were** — the issue moved where they live and
 * decided nothing about what they say (hidetzu/tcpip-stack#2).
 *
 * ⚠ Every one of them, including the fallback, ⚠ **because a problem added
 * without a sentence is the thing that fallback exists for.** */
static bool case_every_option_problem_has_its_own_sentence(void)
{
    static const struct { enum option_problem problem; const char *line; } said[] = {
        { OPTION_HARDWARE_ADDRESS,
          "--mac takes six hexadecimal octets, as 02:00:00:00:00:02.\n" },
        { OPTION_PROTOCOL_ADDRESS,
          "--ipv4 takes four octets from 0 to 255, as 10.0.0.2.\n" },
        { OPTION_TCP_PORT, "--tcp-port takes a whole number from 1 to 65535.\n" },
        { OPTION_TIME_TO_LIVE,
          "--ttl takes a whole number from 1 to 255.\n" },
        { OPTION_COUNT, "--count takes a whole number of frames, 0 or more.\n" },
        { OPTION_TIMEOUT,
          "--timeout takes a whole number of milliseconds, 0 or more.\n" },
        { OPTION_HALF_AN_IDENTITY,
          "--mac and --ipv4 are given together or not at all.\n" },
        { OPTION_PORT_WITHOUT_IDENTITY,
          "--tcp-port needs --mac and --ipv4 as well: nothing can be answered "
          "without them.\n" },
        { OPTION_ARGUMENTS_BEYOND_THE_OPTIONS,
          "tcpip-stack takes no arguments beyond its options.\n" },
    };

    struct produced produced;
    bool ok = true;
    for (size_t i = 0; i < sizeof said / sizeof said[0]; i++) {
        produced_open(&produced);
        report_option_problem(produced.out, said[i].problem, "tcpip-stack");
        char what[48];
        snprintf(what, sizeof what, "problem %d", (int)said[i].problem);
        ok = matches(what, &produced, said[i].line) && ok;
        produced_close(&produced);
    }

    /* ⚠ The fallback, reached only by a value with no sentence. ⚠ It names the
     * program and says plainly that this build has no wording — ⚠ it does not
     * print the number (`CLAUDE.md` §4). */
    produced_open(&produced);
    report_option_problem(produced.out, (enum option_problem)99, "tcpip-stack");
    ok = matches("a problem with no sentence", &produced,
                 "tcpip-stack was asked for something it cannot do, and this build "
                 "has no wording for what.\n") && ok;
    produced_close(&produced);
    return ok;
}

/* ⚠ Written twice in `src/tcpip_stack.c` before #51, and ⚠ once now. */
static bool case_failing_to_arrange_a_clean_stop_names_its_errno(void)
{
    struct produced produced;
    produced_open(&produced);
    report_could_not_arrange_to_stop(produced.out, EINVAL);
    bool ok = matches("could not arrange to stop", &produced,
                      "could not arrange to stop cleanly on a signal: "
                      "Invalid argument\n");
    produced_close(&produced);
    return ok;
}

/* ⚠ The number is what was counted, and ⚠ the sentence claims nothing about
 * why (`CLAUDE.md` §1). */
static bool case_giving_up_on_reads_says_how_many(void)
{
    struct produced produced;
    produced_open(&produced);
    report_gave_up_on_reads(produced.out, 8);
    bool ok = matches("gave up on reads", &produced,
                      "gave up after 8 reads in a row that could not be made.\n");
    produced_close(&produced);

    /* ⚠ The other half: the number is the one it was handed, not a constant. */
    produced_open(&produced);
    report_gave_up_on_reads(produced.out, 1);
    ok = matches("gave up after one", &produced,
                 "gave up after 1 reads in a row that could not be made.\n") && ok;
    produced_close(&produced);
    return ok;
}

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
    { "an_echo_outcome_says_what_was_decided_and_why",
      case_an_echo_outcome_says_what_was_decided_and_why },
    { "the_echo_summary_counts_every_reason_apart",
      case_the_echo_summary_counts_every_reason_apart },
    { "the_listening_line", case_the_listening_line },
    { "no_window_says_which_way_it_failed", case_no_window_says_which_way_it_failed },
    { "the_mtu_lines_say_which_it_was", case_the_mtu_lines_say_which_it_was },
    { "every_option_problem_has_its_own_sentence",
      case_every_option_problem_has_its_own_sentence },
    { "failing_to_arrange_a_clean_stop_names_its_errno",
      case_failing_to_arrange_a_clean_stop_names_its_errno },
    { "giving_up_on_reads_says_how_many", case_giving_up_on_reads_says_how_many },
    { "a_wait_that_failed_names_its_errno", case_a_wait_that_failed_names_its_errno },
    { "the_usage_names_every_option", case_the_usage_names_every_option },
    { "a_segment_that_was_not_read_says_which_it_was",
      case_a_segment_that_was_not_read_says_which_it_was },
    { "the_tcp_summary_keeps_its_two_numbers_apart",
      case_the_tcp_summary_keeps_its_two_numbers_apart },
    { "a_handshake_outcome_says_what_moved_and_why",
      case_a_handshake_outcome_says_what_moved_and_why },
    { "the_handshake_summary_counts_every_reason_apart",
      case_the_handshake_summary_counts_every_reason_apart },
    { "the_device_going_away_names_no_errno", case_the_device_going_away_names_no_errno },
    { "a_read_that_could_not_be_made_has_its_own_line",
      case_a_read_that_could_not_be_made_has_its_own_line },
    { "the_ethernet_header_line_shows_the_value_and_no_name",
      case_the_ethernet_header_line_shows_the_value_and_no_name },
    { "a_header_that_could_not_be_read_shows_no_octets",
      case_a_header_that_could_not_be_read_shows_no_octets },
    { "the_two_declining_answers_each_say_why",
      case_the_two_declining_answers_each_say_why },
    { "the_ethernet_summary_prints_its_zeros",
      case_the_ethernet_summary_prints_its_zeros },
};

#define CASE_COUNT (sizeof cases / sizeof cases[0])

int main(int argc, char **argv)
{
    return check_main("report", cases, CASE_COUNT, argc, argv);
}
