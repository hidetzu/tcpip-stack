/* tcpip-stack — attach to a TAP device, read the frames that arrive, report them.
 *
 * ⚠ Given --mac and --ipv4 it also answers the ARP requests that ask for that
 * address, and sends the reply. ⚠ Without them it only reads
 * (hidetzu/tcpip-stack#19 Owner Decision 6).
 * ⚠ Nothing above ARP is interpreted, and nothing here writes a sentence — the
 * wording lives in report.c (`.claude/rules/layers.md`). */
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "arp_responder.h"
#include "echo_responder.h"
#include "handshake.h"
#include "moment.h"
#include "ethernet.h"
#include "report.h"
#include "tap.h"

/* ⚠ Each outcome leaves its own exit code, so a caller can tell them apart
 * without reading prose (hidetzu/tcpip-stack#2). */
enum exit_code {
    EXIT_READ_WHAT_WAS_ASKED = 0,
    EXIT_ASKED_FOR_SOMETHING_WE_CANNOT_DO = 1,
    EXIT_TIMER_RAN_OUT = 2,
    EXIT_COULD_NOT_USE_THE_DEVICE = 3
};

/* ⚠ A read that keeps failing must not spin. After this many failures in a row
 * with no frame in between, stop and say so.
 *
 * ⚠ No route to a failing read(2) is known today. The one that existed was the
 * gap hidetzu/tcpip-stack#8 closed — ppoll now says the device is gone instead
 * of saying READY on an error — and a replacement was searched for on
 * 2026-08-27 without success: with POLLIN set, six reads in six succeeded.
 *
 * ⚠ This guard stays anyway. ⚠ Not being able to reach a failure today is not a
 * proof that none exists, and a guard removed for that reason is a spin waiting
 * to happen (`CLAUDE.md` §1). */
#define CONSECUTIVE_READ_FAILURES_ALLOWED 8

#define DEFAULT_DEVICE_NAME "tap0"
#define COUNT_UNLIMITED (-1L)
#define TIMEOUT_NONE (-1)

static volatile sig_atomic_t stop_requested = 0;

static void request_stop(int signal_number)
{
    (void)signal_number;
    stop_requested = 1;
}

/* Deliberately without SA_RESTART: the wait must come back with EINTR so the
 * loop can notice the request and print its summary. */
static bool install_stop_handler(int signal_number)
{
    struct sigaction action;
    memset(&action, 0, sizeof action);
    action.sa_handler = request_stop;
    sigemptyset(&action.sa_mask);
    action.sa_flags = 0;
    return sigaction(signal_number, &action, NULL) == 0;
}

struct options {
    const char *device_name;
    long count;   /* COUNT_UNLIMITED, or how many frames to read */
    int timeout_ms;
    bool print_bytes;

    /* ⚠ The identity is given, never derived. The TAP device's own hardware
     * address is the kernel's end of the wire and is a different value on every
     * run (hidetzu/tcpip-stack#19 Owner Decision 1).
     * ⚠ Both or neither: half an identity is refused, not quietly ignored. */
    bool has_identity;
    uint8_t hardware_address[ARP_HARDWARE_ADDRESS_BYTES];
    uint8_t protocol_address[ARP_PROTOCOL_ADDRESS_BYTES];

    /* ⚠ The TCP port this stack answers for, or 0 for none.
     *
     * ⚠ hidetzu/tcpip-stack#35 Owner Decision 3 refused to add an option nobody
     * needed. ⚠ This is a different kind of thing: ⚠ **a TTL is how we answer;
     * a port is what we answer for** — the same kind as `--ipv4`. ⚠ Hard-coding
     * it would leave this as the one piece of "what we answer for" that is not
     * on the command line (hidetzu/tcpip-stack#44 Owner Decision 1). */
    uint16_t tcp_port;
};

/* Returns false when the text is not a number in [minimum, maximum]. */
static bool parse_bounded_long(const char *text, long minimum, long maximum, long *out)
{
    if (text == NULL || *text == '\0') {
        return false;
    }
    char *unparsed = NULL;
    errno = 0;
    long value = strtol(text, &unparsed, 10);
    if (errno != 0 || *unparsed != '\0' || value < minimum || value > maximum) {
        return false;
    }
    *out = value;
    return true;
}

/* Returns false when the text is not six hexadecimal octets separated by ':'. */
static bool parse_hardware_address(const char *text, uint8_t *into)
{
    unsigned octet[ARP_HARDWARE_ADDRESS_BYTES];
    char trailing = 0;
    int read = sscanf(text, "%2x:%2x:%2x:%2x:%2x:%2x%c", &octet[0], &octet[1], &octet[2],
                      &octet[3], &octet[4], &octet[5], &trailing);
    if (read != ARP_HARDWARE_ADDRESS_BYTES) {
        return false;
    }
    for (int i = 0; i < ARP_HARDWARE_ADDRESS_BYTES; i++) {
        if (octet[i] > 0xff) {
            return false;
        }
        into[i] = (uint8_t)octet[i];
    }
    return true;
}

/* Returns false when the text is not four decimal octets separated by '.'. */
static bool parse_protocol_address(const char *text, uint8_t *into)
{
    unsigned octet[ARP_PROTOCOL_ADDRESS_BYTES];
    char trailing = 0;
    int read = sscanf(text, "%u.%u.%u.%u%c", &octet[0], &octet[1], &octet[2], &octet[3],
                      &trailing);
    if (read != ARP_PROTOCOL_ADDRESS_BYTES) {
        return false;
    }
    for (int i = 0; i < ARP_PROTOCOL_ADDRESS_BYTES; i++) {
        if (octet[i] > 255) {
            return false;
        }
        into[i] = (uint8_t)octet[i];
    }
    return true;
}

int main(int argc, char **argv)
{
    struct options options = {
        .device_name = DEFAULT_DEVICE_NAME,
        .count = COUNT_UNLIMITED,
        .timeout_ms = TIMEOUT_NONE,
        .print_bytes = false,
    };

    static const struct option long_options[] = {
        { "dev", required_argument, NULL, 'd' },
        { "count", required_argument, NULL, 'c' },
        { "timeout", required_argument, NULL, 't' },
        { "mac", required_argument, NULL, 'm' },
        { "ipv4", required_argument, NULL, '4' },
        { "tcp-port", required_argument, NULL, 'p' },
        { "hex", no_argument, NULL, 'x' },
        { "help", no_argument, NULL, 'h' },
        { NULL, 0, NULL, 0 },
    };

    int option;
    bool given_hardware_address = false;
    bool given_protocol_address = false;

    while ((option = getopt_long(argc, argv, "d:c:t:m:4:p:xh", long_options, NULL)) != -1) {
        long value = 0;
        switch (option) {
        case 'm':
            if (!parse_hardware_address(optarg, options.hardware_address)) {
                report_option_problem(stderr, OPTION_HARDWARE_ADDRESS, argv[0]);
                return EXIT_ASKED_FOR_SOMETHING_WE_CANNOT_DO;
            }
            given_hardware_address = true;
            break;
        case '4':
            if (!parse_protocol_address(optarg, options.protocol_address)) {
                report_option_problem(stderr, OPTION_PROTOCOL_ADDRESS, argv[0]);
                return EXIT_ASKED_FOR_SOMETHING_WE_CANNOT_DO;
            }
            given_protocol_address = true;
            break;
        case 'p':
            if (!parse_bounded_long(optarg, 1, 65535, &value)) {
                report_option_problem(stderr, OPTION_TCP_PORT, argv[0]);
                return EXIT_ASKED_FOR_SOMETHING_WE_CANNOT_DO;
            }
            options.tcp_port = (uint16_t)value;
            break;
        case 'd':
            options.device_name = optarg;
            break;
        case 'c':
            if (!parse_bounded_long(optarg, 0, LONG_MAX, &value)) {
                report_option_problem(stderr, OPTION_COUNT, argv[0]);
                return EXIT_ASKED_FOR_SOMETHING_WE_CANNOT_DO;
            }
            options.count = value;
            break;
        case 't':
            if (!parse_bounded_long(optarg, 0, INT_MAX, &value)) {
                report_option_problem(stderr, OPTION_TIMEOUT, argv[0]);
                return EXIT_ASKED_FOR_SOMETHING_WE_CANNOT_DO;
            }
            options.timeout_ms = (int)value;
            break;
        case 'x':
            options.print_bytes = true;
            break;
        case 'h':
            report_usage(stdout, argv[0]);
            return EXIT_READ_WHAT_WAS_ASKED;
        default:
            report_usage(stderr, argv[0]);
            return EXIT_ASKED_FOR_SOMETHING_WE_CANNOT_DO;
        }
    }
    /* ⚠ Half an identity is refused rather than quietly ignored: a stack that
     * silently declined to answer would look exactly like one nobody asked
     * (Owner Decision 6). */
    if (given_hardware_address != given_protocol_address) {
        report_option_problem(stderr, OPTION_HALF_AN_IDENTITY, argv[0]);
        return EXIT_ASKED_FOR_SOMETHING_WE_CANNOT_DO;
    }
    options.has_identity = given_hardware_address;

    /* ⚠ A port with no identity answers nothing, and ⚠ saying so beats
     * accepting it and staying silent — a stack that quietly declined would look
     * exactly like one nobody asked (the shape Owner Decision 6 set). */
    if (options.tcp_port != 0 && !options.has_identity) {
        report_option_problem(stderr, OPTION_PORT_WITHOUT_IDENTITY, argv[0]);
        return EXIT_ASKED_FOR_SOMETHING_WE_CANNOT_DO;
    }

    if (optind != argc) {
        report_option_problem(stderr, OPTION_ARGUMENTS_BEYOND_THE_OPTIONS, argv[0]);
        return EXIT_ASKED_FOR_SOMETHING_WE_CANNOT_DO;
    }

    if (!install_stop_handler(SIGINT) || !install_stop_handler(SIGTERM)) {
        report_could_not_arrange_to_stop(stderr, errno);
        return EXIT_COULD_NOT_USE_THE_DEVICE;
    }

    /* ⚠ Blocked for the whole loop, and unblocked only inside the wait. That is
     * what makes a stop request arriving just before the wait interrupt it
     * rather than be lost (see tap.h). */
    sigset_t stop_signals;
    sigemptyset(&stop_signals);
    sigaddset(&stop_signals, SIGINT);
    sigaddset(&stop_signals, SIGTERM);

    sigset_t deliverable_while_waiting;
    if (sigprocmask(SIG_BLOCK, &stop_signals, &deliverable_while_waiting) != 0) {
        report_could_not_arrange_to_stop(stderr, errno);
        return EXIT_COULD_NOT_USE_THE_DEVICE;
    }

    struct tap_failure failure = { TAP_STEP_NONE, 0 };
    int device = tap_attach(options.device_name, &failure);
    if (device < 0) {
        report_attach_failure(stderr, options.device_name, &failure);
        return EXIT_COULD_NOT_USE_THE_DEVICE;
    }

    report_listening(stdout, options.device_name);
    fflush(stdout);

    /* ⚠ Owner of this buffer: main. It lives as long as the loop and nothing
     * that outlives the loop keeps a pointer into it. */
    uint8_t frame[TAP_FRAME_BUFFER_BYTES];
    unsigned long frames_read = 0;
    unsigned long read_errors = 0;
    struct arp_counts arp_counts = { 0, 0, 0, 0, 0 };
    struct echo_counts echo_counts;
    memset(&echo_counts, 0, sizeof echo_counts);
    struct handshake_counts handshake_counts;
    memset(&handshake_counts, 0, sizeof handshake_counts);
    struct connections connections;
    connections_forget_everything(&connections);
    struct tcp_counts tcp_counts = { 0, 0 };

    /* ⚠ When to give up reading, kept as a deadline rather than as a limit
     * handed to each wait.
     *
     * ⚠ Why: ⚠ **a timer of ours shortens the wait**, and a per-wait limit would
     * then be reset by our own timer firing — ⚠ `--timeout 1500` would stop
     * meaning "1500 ms without a frame" (hidetzu/tcpip-stack#58 Owner Decision
     * 1). ⚠ The deadline moves only when a frame arrives, so ⚠ **the number the
     * timeout line prints keeps meaning what it meant** (`CLAUDE.md` §6).
     *
     * ⚠ It starts running now: `--timeout` applied from the start before this
     * change too, and that does not move. */
    struct deadline give_up_reading = { false, { 0 } };
    if (options.timeout_ms >= 0) {
        give_up_reading.set = true;
        give_up_reading.at = moment_after(moment_now(), (uint64_t)options.timeout_ms);
    }
    struct ethernet_counts ethernet_counts = { 0, 0, 0 };
    unsigned int consecutive_read_failures = 0;
    int exit_code = EXIT_READ_WHAT_WAS_ASKED;

    while (options.count == COUNT_UNLIMITED || (long)frames_read < options.count) {
        if (stop_requested) {
            break;
        }

        /* ⚠ The nearer of the two deadlines, ⚠ **so a timer of ours ends the wait
         * as surely as a frame does.** ⚠ Neither set means wait without a
         * limit, which is what the program did before it had any timer. */
        struct deadline the_timer = { false, { 0 } };
        the_timer.set = handshake_next_moment(&connections, &the_timer.at);
        int wait_limit_ms =
            moment_wait_limit(moment_now(), give_up_reading, the_timer);

        enum tap_wait waited = tap_wait_readable(device, wait_limit_ms,
                                                 &deliverable_while_waiting, &failure);
        if (waited == TAP_WAIT_INTERRUPTED) {
            continue; /* the loop re-reads stop_requested at the top */
        }
        if (waited == TAP_WAIT_TIMEOUT) {
            /* ⚠ A wait that ran out is not one thing any more. ⚠ Asking what is
             * due now says which it was: ⚠ **our own timer, or nothing having
             * arrived.** ⚠ No new outcome was needed from the wait — the caller
             * knows what it asked for (hidetzu/tcpip-stack#58).
             *
             * ⚠ It cannot be mistaken: `moment_milliseconds_until` rounds up, so
             * a wait shortened for a timer ends at or after that moment
             * (`src/moment.h`). */
            struct handshake_outcome handshake;
            uint8_t again[TAP_FRAME_BUFFER_BYTES];
            enum handshake_due due =
                handshake_what_is_due(&connections, moment_now(),
                                      options.hardware_address, again, sizeof again,
                                      &handshake_counts, &handshake);
            if (due != HANDSHAKE_NOTHING_DUE || handshake.reason != HANDSHAKE_REASON_NONE) {
                report_handshake_outcome(stdout, &handshake);

                if (due == HANDSHAKE_ANSWER_AGAIN && handshake.reply_bytes != 0) {
                    ssize_t handed = tap_write_frame(device, again,
                                                     handshake.reply_bytes, &failure);
                    /* ⚠ Counted only once the wire took the whole answer, the
                     * same division everything else here uses (`CLAUDE.md` §1).
                     * ⚠ An answer that was built is not an answer that left. */
                    if (handed >= 0 && (size_t)handed == handshake.reply_bytes) {
                        /* ⚠ Which counter is the State layer's word, not a rule
                         * written here a second time (`CLAUDE.md` §3). */
                        if (handshake.reply == HANDSHAKE_REPLY_OUR_FIN) {
                            handshake_counts.our_fin_went_out_again++;
                        } else {
                            handshake_counts.answered_again++;
                        }
                    }
                }
                fflush(stdout);
                continue;
            }
            report_timeout(stderr, options.device_name, options.timeout_ms, frames_read);
            exit_code = EXIT_TIMER_RAN_OUT;
            break;
        }
        if (waited == TAP_WAIT_DEVICE_GONE) {
            report_device_gone(stderr, options.device_name);
            exit_code = EXIT_COULD_NOT_USE_THE_DEVICE;
            break;
        }
        if (waited == TAP_WAIT_FAILED) {
            report_wait_failure(stderr, options.device_name, &failure);
            exit_code = EXIT_COULD_NOT_USE_THE_DEVICE;
            break;
        }

        ssize_t bytes = tap_read_frame(device, frame, sizeof frame, &failure);
        if (bytes < 0) {
            read_errors++;
            consecutive_read_failures++;
            report_read_failure(stderr, frames_read + 1, &failure);
            if (consecutive_read_failures >= CONSECUTIVE_READ_FAILURES_ALLOWED) {
                report_gave_up_on_reads(stderr, consecutive_read_failures);
                exit_code = EXIT_COULD_NOT_USE_THE_DEVICE;
                break;
            }
            continue;
        }

        consecutive_read_failures = 0;
        frames_read++;
        /* ⚠ A frame arrived, so the deadline for giving up reading moves.
         * ⚠ **Only a frame moves it** — a timer of ours must not, or `--timeout`
         * would stop meaning what it says (Owner Decision 1). */
        if (options.timeout_ms >= 0) {
            give_up_reading.at = moment_after(moment_now(), (uint64_t)options.timeout_ms);
        }
        report_frame(stdout, frames_read, (size_t)bytes, (size_t)bytes == sizeof frame);
        /* ⚠ Every frame, always (hidetzu/tcpip-stack#10 Owner Decision 1). The
         * header was already read to spot ARP; ⚠ until now none of what it
         * found reached the page. */
        struct ethernet_header header;
        enum ethernet_parse header_answer =
            ethernet_parse_header(frame, (size_t)bytes, &header);
        report_ethernet_header(stdout, frame, (size_t)bytes, header_answer, &header);
        switch (header_answer) {
        case ETHERNET_PARSE_SHORTER_THAN_THE_HEADER:
            ethernet_counts.malformed++;
            break;
        case ETHERNET_PARSE_LENGTH_NOT_A_TYPE:
            ethernet_counts.ieee_802_3_length++;
            break;
        case ETHERNET_PARSE_LENGTH_TYPE_UNDEFINED:
            ethernet_counts.length_type_undefined++;
            break;
        case ETHERNET_PARSE_OK:
            break;
        }

        if (options.print_bytes) {
            report_frame_bytes(stdout, frame, (size_t)bytes);
        }

        /* ⚠ Only with an identity. Without one the program reads and answers
         * nothing, which is what it did before (Owner Decision 6). */
        if (options.has_identity) {
            if (header_answer == ETHERNET_PARSE_OK &&
                header.length_type == ARP_ETHERNET_LENGTH_TYPE) {
                struct arp_outcome outcome;
                arp_respond(frame + ETHERNET_HEADER_BYTES,
                            (size_t)bytes - ETHERNET_HEADER_BYTES,
                            options.hardware_address, options.protocol_address,
                            &outcome, &arp_counts);
                report_arp_outcome(stdout, &outcome, options.protocol_address);

                if (outcome.decision == ARP_ANSWER) {
                    ssize_t handed = tap_write_frame(device, outcome.reply,
                                                     outcome.reply_bytes, &failure);
                    /* ⚠ Counted only once the wire took the whole reply. A frame
                     * that did not leave is not a frame we answered with
                     * (`CLAUDE.md` §1). ⚠ A failure here is followed by the read
                     * failing too — the device is gone — and that path already
                     * counts and reports itself. */
                    if (handed >= 0 && (size_t)handed == outcome.reply_bytes) {
                        arp_counts.answered++;
                    }
                }
            } else if (header_answer == ETHERNET_PARSE_OK &&
                       header.length_type == IPV4_ETHERNET_LENGTH_TYPE) {
                /* ⚠ Read once here to see whose it is and what it carries.
                 * ⚠ `echo_respond` reads it again below — ⚠ that is the same
                 * function called twice, not a second implementation of the
                 * question (`CLAUDE.md` §3), and ⚠ it keeps every IPv4-level
                 * reason counted in one place.
                 *
                 * ⚠ Only a datagram that is FOR US and carries TCP is diverted.
                 * ⚠ One that is malformed, a fragment, or addressed elsewhere
                 * still reaches `echo_respond` and is counted there, so ⚠ those
                 * numbers keep meaning what they meant. */
                struct ipv4_header internet;
                bool for_us_over_tcp =
                    options.tcp_port != 0 &&
                    ipv4_parse_header(frame + ETHERNET_HEADER_BYTES,
                                      (size_t)bytes - ETHERNET_HEADER_BYTES,
                                      &internet) == IPV4_PARSE_OK &&
                    internet.protocol == IPV4_PROTOCOL_TCP &&
                    memcmp(internet.destination_address, options.protocol_address,
                           IPV4_ADDRESS_BYTES) == 0;

                if (for_us_over_tcp) {
                    size_t internet_header_bytes =
                        (size_t)internet.internet_header_length * IPV4_HEADER_LENGTH_UNIT;
                    const uint8_t *segment =
                        frame + ETHERNET_HEADER_BYTES + internet_header_bytes;
                    /* ⚠ Bounded by Total Length, never by what arrived: the
                     * pseudo-header's TCP Length comes from this and ⚠ padding
                     * would make the checksum disagree with nothing pointing at
                     * it (`src/tcp.h`). */
                    size_t segment_bytes =
                        (size_t)internet.total_length - internet_header_bytes;

                    struct tcp_header tcp;
                    enum tcp_parse read_segment =
                        tcp_parse_header(segment, segment_bytes,
                                         internet.source_address,
                                         internet.destination_address, &tcp);
                    if (read_segment != TCP_PARSE_OK) {
                        report_tcp_not_read(stdout, read_segment);
                        if (read_segment == TCP_PARSE_MALFORMED) {
                            tcp_counts.malformed++;
                        } else {
                            tcp_counts.checksum_disagrees++;
                        }
                    } else {
                        struct connection_id id;
                        memset(&id, 0, sizeof id);
                        memcpy(id.local.address, internet.destination_address,
                               CONNECTION_ADDRESS_BYTES);
                        id.local.port = tcp.destination_port;
                        memcpy(id.remote.address, internet.source_address,
                               CONNECTION_ADDRESS_BYTES);
                        id.remote.port = tcp.source_port;

                        uint8_t reply[TAP_FRAME_BUFFER_BYTES];
                        struct handshake_outcome handshake;
                        handshake_receive(&tcp, &id, options.tcp_port, moment_now(), header.source,
                                          options.hardware_address, &connections, reply,
                                          sizeof reply, &handshake_counts, &handshake);
                        report_handshake_outcome(stdout, &handshake);

                        if (handshake.reply_bytes != 0) {
                            ssize_t handed = tap_write_frame(device, reply,
                                                             handshake.reply_bytes,
                                                             &failure);
                            /* ⚠ Counted only once the wire took the whole
                             * answer, the same division ARP and ICMP use
                             * (`CLAUDE.md` §1). */
                            if (handed >= 0 &&
                                (size_t)handed == handshake.reply_bytes) {
                                /* ⚠ Which counter is the State layer's word,
                                 * not a rule written here a second time
                                 * (`CLAUDE.md` §3). */
                                switch (handshake.reply) {
                                case HANDSHAKE_REPLY_OUR_FIN:
                                    handshake_counts.our_fin_left++;
                                    break;
                                case HANDSHAKE_REPLY_THE_DATA_IS_ACKNOWLEDGED:
                                    handshake_counts.data_acknowledged++;
                                    break;
                                case HANDSHAKE_REPLY_WHERE_WE_ARE:
                                    handshake_counts.told_them_where_we_are++;
                                    break;
                                case HANDSHAKE_REPLY_THE_ANSWER:
                                case HANDSHAKE_REPLY_NONE:
                                    handshake_counts.answered++;
                                    break;
                                }
                            }
                        }
                    }
                    fflush(stdout);
                    continue;
                }

                struct echo_outcome echo;
                /* ⚠ A buffer of its own rather than the frame that arrived: the
                 * hex of a frame has already been printed by here, but ⚠ a
                 * reader comparing what came in with what went out must be able
                 * to, and overwriting the one with the other takes that away. */
                uint8_t reply[TAP_FRAME_BUFFER_BYTES];
                echo_respond(frame + ETHERNET_HEADER_BYTES,
                             (size_t)bytes - ETHERNET_HEADER_BYTES,
                             header.source, options.hardware_address,
                             options.protocol_address, reply, sizeof reply, &echo,
                             &echo_counts);
                report_echo_outcome(stdout, &echo, options.protocol_address);

                if (echo.decision == ECHO_ANSWER) {
                    ssize_t handed =
                        tap_write_frame(device, reply, echo.reply_bytes, &failure);
                    /* ⚠ Counted only once the wire took the whole reply, the
                     * same division ARP uses above (`CLAUDE.md` §1). */
                    if (handed >= 0 && (size_t)handed == echo.reply_bytes) {
                        echo_counts.answered++;
                    }
                }
            }
        }
        fflush(stdout);
    }

    report_summary(stdout, frames_read, read_errors);
    report_ethernet_summary(stdout, &ethernet_counts);
    if (options.has_identity) {
        report_arp_summary(stdout, &arp_counts);
        report_echo_summary(stdout, &echo_counts);
    }
    if (options.tcp_port != 0) {
        report_tcp_summary(stdout, &tcp_counts);
        report_handshake_summary(stdout, &handshake_counts);
    }
    tap_detach(device);
    return exit_code;
}
