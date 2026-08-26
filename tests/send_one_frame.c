/* A real-tier driver: attaches to a TAP device and hands frames to it, so a
 * check can watch what the kernel's own counters do.
 *
 * ⚠ It lives in tests/ and never in src/. It is harness, not product
 * (`CLAUDE.md` §3: the stack does protocol, the harness does the environment),
 * and ⚠ nothing in the shipped binary calls it.
 *
 * ⚠ It waits for a line on stdin before writing, and for a second line after.
 * The device only exists while this program holds the fd (`docs/SPEC.md` §1), so
 * ⚠ the counters have to be read while it is still attached — closing first
 * takes the device away and there is nothing left to read. The two waits are
 * what let the case read them before and after, and ⚠ a fixed sleep in place of
 * either would be a guess about how long the other side takes.
 *
 * ⚠ It writes no sentence for a human to act on. What it prints is for the case
 * to read, and the exit code is what the case judges. ⚠ The errno is the
 * kernel's choice, so it is printed and never asserted
 * (`.claude/rules/testing.md`). */
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tap.h"

#define DEFAULT_FRAME_BYTES 60

int main(int argc, char **argv)
{
    const char *device_name = "tap0";
    long how_many = 1;
    long frame_bytes = DEFAULT_FRAME_BYTES;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--dev") == 0 && i + 1 < argc) {
            device_name = argv[++i];
        } else if (strcmp(argv[i], "--count") == 0 && i + 1 < argc) {
            how_many = strtol(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "--bytes") == 0 && i + 1 < argc) {
            frame_bytes = strtol(argv[++i], NULL, 10);
        } else {
            fprintf(stderr, "usage: %s [--dev NAME] [--count N] [--bytes M]\n", argv[0]);
            return 2;
        }
    }
    if (how_many < 0 || frame_bytes < 0 || frame_bytes > TAP_FRAME_BUFFER_BYTES) {
        fprintf(stderr, "count must be 0 or more and bytes at most %d\n",
                TAP_FRAME_BUFFER_BYTES);
        return 2;
    }

    struct tap_failure failure = { TAP_STEP_NONE, 0 };
    int device = tap_attach(device_name, &failure);
    if (device < 0) {
        fprintf(stderr, "could not attach to %s: errno %d\n", device_name, failure.errnum);
        return 3;
    }
    printf("attached to %s\n", device_name);
    fflush(stdout);

    /* ⚠ The case reads the counters and arranges the world while this waits. */
    int waited = getchar();
    (void)waited;

    /* ⚠ Owner of this buffer: main. Nothing outlives it holds a pointer in. */
    uint8_t frame[TAP_FRAME_BUFFER_BYTES];
    memset(frame, 0, sizeof frame);
    /* A destination, a source, and a length/type nothing here handles — so the
     * kernel receives it and has nothing to do with it. ⚠ That keeps "it
     * arrived" and "the kernel acted on it" apart. */
    static const uint8_t destination[6] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 };
    static const uint8_t source[6] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x02 };
    memcpy(frame, destination, sizeof destination);
    memcpy(frame + 6, source, sizeof source);
    frame[12] = 0x88;
    frame[13] = 0xb5;

    unsigned long handed_over = 0;
    unsigned long octets = 0;
    unsigned long could_not = 0;
    unsigned long short_writes = 0;
    unsigned long wrong_step = 0;

    for (long i = 0; i < how_many; i++) {
        ssize_t written = tap_write_frame(device, frame, (size_t)frame_bytes, &failure);
        if (written < 0) {
            could_not++;
            /* ⚠ The step is what lets a caller follow where it went wrong. It
             * is counted rather than printed, because an enum never reaches a
             * human (`CLAUDE.md` §4) — and because a count is what a check can
             * assert. */
            if (failure.step != TAP_STEP_WRITE) {
                wrong_step++;
            }
            printf("could not hand it over: errno %d\n", failure.errnum);
            continue;
        }
        /* ⚠ What came back is compared with what was asked for. No short write
         * has been observed on this fd (see src/tap.h), and ⚠ that is an
         * observation, so it is checked rather than trusted. */
        if ((size_t)written != (size_t)frame_bytes) {
            short_writes++;
        }
        handed_over++;
        octets += (unsigned long)written;
    }

    printf("handed over %lu frames, %lu octets, %lu could not be handed over, "
           "%lu short, %lu with the wrong step\n", handed_over, octets, could_not,
           short_writes, wrong_step);
    fflush(stdout);

    /* ⚠ Held open until the case has read the counters. Letting go here would
     * remove the device and leave nothing to count. */
    waited = getchar();
    (void)waited;

    tap_detach(device);
    return (could_not == 0 && short_writes == 0 && wrong_step == 0) ? 0 : 1;
}
