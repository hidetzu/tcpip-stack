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

/* What to carry on with when the device could not be asked how large a frame it
 * carries.
 *
 * ⚠ **This is a value chosen here. It is not a measurement, and nothing prints
 * it as though it were** (`CLAUDE.md` §6, and `report_mtu_could_not_be_read`
 * says so on screen).
 *
 * ⚠ 1500 because that is what a tap comes up with when nothing sets it —
 * measured, `unshare -Urn`, 3 runs, every run 1500 — ⚠ **so it is the likeliest
 * right answer for a device we could not ask, and still only a guess.**
 *
 * ⚠ **Why carry on at all**: one auxiliary thing missing must not take the whole
 * stack down (`.claude/rules/c.md`), and ⚠ **the alternative was considered and
 * refused** (hidetzu/tcpip-stack#115 Owner Decision 1). */
#define TAP_FRAME_BYTES_WHEN_UNKNOWN 1500u

/* Which step failed. ⚠ An enum never reaches a human (`CLAUDE.md` §4). */
enum tap_step {
    TAP_STEP_NONE = 0,
    TAP_STEP_NAME,   /* the device name does not fit what the kernel accepts */
    TAP_STEP_OPEN,   /* open("/dev/net/tun") */
    TAP_STEP_ATTACH, /* ioctl(TUNSETIFF) */
    TAP_STEP_WAIT,   /* poll(2) */
    TAP_STEP_READ,   /* read(2) */
    TAP_STEP_WRITE,  /* write(2) */

    /* ⚠ Asking the device how large a frame it carries. ⚠ Two syscalls can
     * fail here and they are one step on purpose: ⚠ **a caller's next move
     * is the same either way** — the number could not be obtained. */
    TAP_STEP_MTU     /* socket(2) or ioctl(SIOCGIFMTU) */
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
    TAP_WAIT_FAILED,      /* *failure says which step and which errno */

    /* ⚠ The wait came back reporting an error on the fd rather than a frame.
     * ⚠ There is no errno: ppoll SUCCEEDED — it returned 1 — and POLLERR is not
     * an errno. ⚠ Nothing here can say why, and nothing pretends to
     * (hidetzu/tcpip-stack#8 Owner Decision 1).
     *
     * ⚠ Measured 2026-08-26, 30 of 30 iterations across 3 runs: `ip link del`
     * on the device gives revents = 0x0008, POLLERR alone, POLLIN clear.
     * ⚠ POLLHUP and POLLNVAL are folded in here provisionally — ⚠ neither has
     * ever been observed on this fd, and ⚠ not having observed a thing is not a
     * proof that it cannot happen (`CLAUDE.md` §1). */
    TAP_WAIT_DEVICE_GONE
};

/* Wait until a frame can be read. timeout_ms < 0 waits without a limit.
 *
 * `deliverable_while_waiting` is the signal mask that applies for exactly as
 * long as the wait lasts.
 *
 * ⚠ Why the caller has to supply one: with a signal merely handled, a stop
 * request that arrives between the caller testing its flag and this function
 * entering the wait is lost, and a wait with no limit then never returns. The
 * ⚠ What comes back is decided by `revents`, not by ppoll's return value. ⚠ A
 * non-zero return says something happened, not that a frame can be read: an
 * error on the fd counts as something (hidetzu/tcpip-stack#8).
 *
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

/* Hand one frame to the device.
 *
 * Returns the number of octets the kernel took, or -1 with *failure set.
 * ⚠ The frame is the caller's and is not kept.
 *
 * ⚠ What write(2) does on this fd, measured rather than assumed
 * (hidetzu/tcpip-stack#17 AC 4). Arch Linux, kernel 7.0.2-arch1-1, x86_64,
 * unshare -Urn as uid 1000, tap0 up with the default MTU of 1500, 2026-08-26:
 *
 *     0, 1, 13 octets     -1, EINVAL — ⚠ fewer than an ethernet header is
 *                         refused outright, not written in part
 *     14 .. 8192 octets   ⚠ exactly what was asked for, every size tried,
 *                         including 1515, 1518, 2048, 4096 and 8192, which are
 *                         above the MTU
 *
 * ⚠ No short write was observed at any size. ⚠ That is an observation and not a
 * proof that none can happen (`CLAUDE.md` §1) — so a caller must still compare
 * what came back with what it asked for, and this function does not pretend the
 * question is settled.
 *
 * ⚠ A frame that was not handed over is not a frame sent. The caller counts
 * what actually left, never what it intended to send
 * (`.claude/rules/c.md`: an uncounted drop is invisible). */
ssize_t tap_write_frame(int fd, const uint8_t *frame, size_t frame_bytes,
                        struct tap_failure *failure);

/* Ask the device how large a frame it carries.
 *
 * ⚠ **`ask`, not the other verb.** ⚠ Two reasons and both matter: ⚠ this is an
 * `ioctl` question and not a read of octets, ⚠ **and the spelling this function
 * first had was the shape of the name this program used to carry** —
 * `tests/static.sh` `the_old_program_name_is_gone` fired on it and ⚠ **it was
 * right to.** ⚠ **The check was not widened to let a second one through**
 * (`.claude/rules/testing.md`: never widen a check until it stops complaining),
 * ⚠ and ⚠ **it fired a second time on the comment that explained the first** —
 * ⚠ that case does not strip comments, ⚠ **and a check that reads prose about
 * itself is exactly what `CLAUDE.md` §5 warns of.**
 *
 * On success returns 0 and writes the MTU to *mtu. ⚠ On failure returns -1,
 * *mtu is untouched, and *failure says which syscall and which errno.
 *
 * ⚠ **"could not be obtained" is not "it is 1500"** (`CLAUDE.md` §1). ⚠ This
 * function never substitutes a value, and ⚠ **a caller that carries on with one
 * says so to the human** (hidetzu/tcpip-stack#115 Owner Decision 1).
 *
 * ⚠ **Why a second fd.** ⚠ Measured 2026-08-29, Arch Linux 7.0.2-arch1-1,
 * `unshare -Urn` as uid 1000, 3 runs, every run identical:
 *
 *     SIOCGIFMTU on the TUN fd                    ⚠ EINVAL
 *     SIOCGIFMTU on an AF_INET SOCK_DGRAM socket  ⚠ succeeds, unprivileged
 *
 * ⚠ **So there is no way to read the MTU without one**, and an `AF_INET` socket
 * in this layer is an owner decision, not a convenience
 * (hidetzu/tcpip-stack#115 Owner Decision 3).
 *
 * ⚠ **Owner of the socket: this function.** ⚠ It is opened, used and closed
 * before returning; ⚠ **nothing of it escapes** (`.claude/rules/c.md`).
 *
 * ⚠ **Setup time, never per packet** (`CLAUDE.md` §3). ⚠ `tests/static.sh`
 * `the_mtu_is_read_in_one_place` is what holds that.
 *
 * ⚠ **The failing path is not exercised by any check.** ⚠ **Measured, not
 * assumed**: deleting the whole `else` branch at the call site — so a failed
 * read would print the constant as though the device had reported it —
 * ⚠ **left every check green** (2026-08-29). ⚠ **That is the checks not
 * asserting it, and not a mutation with no effect** (`.claude/rules/testing.md`
 * asks which, and this is the first).
 *
 * ⚠ The SENTENCES are asserted — `tests/static.sh` `report_lines` →
 * `the_mtu_lines_say_which_it_was`, both shapes, and ⚠ **dropping the clause
 * that says the number was chosen here fails it.** ⚠ **What is not asserted is
 * that the branch is taken**: no harness here can make the read fail, because
 * the device exists by the time it is asked — the fd above created it — and
 * ⚠ **contriving a failure would be testing the contrivance.**
 *
 * ⚠ `docs/SPEC.md` §2 names the gap.
 *
 * ⚠ **What a tap will actually take**, measured under the conditions above,
 * 3 runs, every run identical — ⚠ **a property of a tap on this kernel and not
 * of TCP:**
 *
 *     smallest   68        ⚠ 46 and below are refused by the kernel
 *     largest    65521     ⚠ 65535 and above are refused
 */
int tap_ask_mtu(const char *device_name, unsigned int *mtu,
                 struct tap_failure *failure);

#endif /* TAP_H */
