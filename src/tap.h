/* Wire — the octets that actually arrived, and nothing about what they mean.
 *
 * ⚠ Nothing in this file interprets a byte of a frame, and nothing in it writes
 * a word a human reads (`.claude/rules/layers.md`). A failure comes back as a
 * step and an errno; `report.h` is what turns that into a sentence. */
#ifndef TAP_H
#define TAP_H

#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/* The read buffer every caller supplies.
 *
 * ⚠ Why 2048: the checks build the device with the default MTU of 1500, so a
 * frame is at most 1518 bytes with an 802.1Q tag. 2048 leaves room above that.
 *
 * ⚠ Why the exact value matters: read(2) on a TAP fd hands back the truncated
 * bytes when the frame is longer than the buffer and discards the rest — it
 * does not fail and it does not say it truncated. So a read that returns
 * exactly the buffer size is a length we do not know, and it is reported as
 * such rather than as a measurement (`CLAUDE.md` §1). */
#define TAP_FRAME_BUFFER_BYTES 2048

/* The longest device name the kernel accepts, terminator excluded.
 *
 * ⚠ This is a second copy of the kernel's IFNAMSIZ, and the two are cross-checked
 * mechanically in tap.c so they cannot drift apart in silence (`CLAUDE.md` §3).
 * It exists so that Report can say what the limit is without pulling kernel
 * headers into the layer that writes prose (`.claude/rules/layers.md`). */
#define TAP_DEVICE_NAME_MAX 15

/* Which step failed. ⚠ An enum never reaches a human (`CLAUDE.md` §4). */
enum tap_step {
    TAP_STEP_NONE = 0,
    TAP_STEP_NAME,   /* the device name does not fit what the kernel accepts */
    TAP_STEP_OPEN,   /* open("/dev/net/tun") */
    TAP_STEP_ATTACH, /* ioctl(TUNSETIFF) */
    TAP_STEP_WAIT,   /* poll(2) */
    TAP_STEP_READ    /* read(2) */
};

struct tap_failure {
    enum tap_step step;
    int errnum; /* errno as it stood when the step failed, or 0 if it does not apply */
};

/* Create (or take over) a TAP device and attach to it.
 *
 * Returns the fd on success, or -1 with *failure filled in.
 * ⚠ Owner of the fd: the caller. It is released with tap_detach().
 * ⚠ The interface exists only while this fd is open — closing it removes it. */
int tap_attach(const char *device_name, struct tap_failure *failure);

void tap_detach(int fd);

enum tap_wait {
    TAP_WAIT_READY,       /* a frame can be read now */
    TAP_WAIT_TIMEOUT,     /* the time we agreed to wait ran out. ⚠ Not an answer */
    TAP_WAIT_INTERRUPTED, /* a signal arrived while waiting */
    TAP_WAIT_FAILED       /* *failure says which step and which errno */
};

/* Wait until a frame can be read. timeout_ms < 0 waits without a limit.
 *
 * `deliverable_while_waiting` is the signal mask that applies for exactly as
 * long as the wait lasts.
 *
 * ⚠ Why the caller has to supply one: with a signal merely handled, a stop
 * request that arrives between the caller testing its flag and this function
 * entering the wait is lost, and a wait with no limit then never returns. The
 * caller blocks those signals around the loop and hands the unblocked mask in
 * here, so they can only be delivered inside the wait, where they interrupt it
 * (`.claude/skills/change-review/SKILL.md` §4: reorder it, do not reason that
 * it is unlikely). */
enum tap_wait tap_wait_readable(int fd, int timeout_ms,
                                const sigset_t *deliverable_while_waiting,
                                struct tap_failure *failure);

/* Read one frame into a caller-supplied buffer.
 *
 * Returns the number of bytes placed in `buffer`, or -1 with *failure set.
 * ⚠ Bounds come from buffer_bytes — what was actually supplied — never from
 * anything a frame claims about itself (`.claude/rules/c.md`). */
ssize_t tap_read_frame(int fd, uint8_t *buffer, size_t buffer_bytes,
                       struct tap_failure *failure);

#endif /* TAP_H */
