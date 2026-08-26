/* tcpip-stack — attach to a TAP device, read the frames that arrive, report them.
 *
 * ⚠ Read only. Sending frames is not implemented yet (hidetzu/tcpip-stack#2).
 * ⚠ Nothing here interprets a byte of a frame. */
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
 * with no frame in between, stop and say so. */
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
        { "hex", no_argument, NULL, 'x' },
        { "help", no_argument, NULL, 'h' },
        { NULL, 0, NULL, 0 },
    };

    int option;
    while ((option = getopt_long(argc, argv, "d:c:t:xh", long_options, NULL)) != -1) {
        long value = 0;
        switch (option) {
        case 'd':
            options.device_name = optarg;
            break;
        case 'c':
            if (!parse_bounded_long(optarg, 0, LONG_MAX, &value)) {
                fprintf(stderr, "--count takes a whole number of frames, 0 or more.\n");
                return EXIT_ASKED_FOR_SOMETHING_WE_CANNOT_DO;
            }
            options.count = value;
            break;
        case 't':
            if (!parse_bounded_long(optarg, 0, INT_MAX, &value)) {
                fprintf(stderr, "--timeout takes a whole number of milliseconds, 0 or more.\n");
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
    if (optind != argc) {
        fprintf(stderr, "%s takes no arguments beyond its options.\n", argv[0]);
        return EXIT_ASKED_FOR_SOMETHING_WE_CANNOT_DO;
    }

    if (!install_stop_handler(SIGINT) || !install_stop_handler(SIGTERM)) {
        fprintf(stderr, "could not arrange to stop cleanly on a signal: %s\n",
                strerror(errno));
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
        fprintf(stderr, "could not arrange to stop cleanly on a signal: %s\n",
                strerror(errno));
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
    unsigned int consecutive_read_failures = 0;
    int exit_code = EXIT_READ_WHAT_WAS_ASKED;

    while (options.count == COUNT_UNLIMITED || (long)frames_read < options.count) {
        if (stop_requested) {
            break;
        }

        enum tap_wait waited = tap_wait_readable(device, options.timeout_ms,
                                                 &deliverable_while_waiting, &failure);
        if (waited == TAP_WAIT_INTERRUPTED) {
            continue; /* the loop re-reads stop_requested at the top */
        }
        if (waited == TAP_WAIT_TIMEOUT) {
            report_timeout(stderr, options.device_name, options.timeout_ms, frames_read);
            exit_code = EXIT_TIMER_RAN_OUT;
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
                fprintf(stderr, "gave up after %u reads in a row that could not be made.\n",
                        consecutive_read_failures);
                exit_code = EXIT_COULD_NOT_USE_THE_DEVICE;
                break;
            }
            continue;
        }

        consecutive_read_failures = 0;
        frames_read++;
        report_frame(stdout, frames_read, (size_t)bytes, (size_t)bytes == sizeof frame);
        if (options.print_bytes) {
            report_frame_bytes(stdout, frame, (size_t)bytes);
        }
        fflush(stdout);
    }

    report_summary(stdout, frames_read, read_errors);
    tap_detach(device);
    return exit_code;
}
