#include "moment.h"

#include <limits.h>
#include <time.h>

#define NANOSECONDS_IN_A_MILLISECOND 1000000u
#define NANOSECONDS_IN_A_SECOND 1000000000u

/* ⚠ Half the space. A difference below this means `a` is at or after `b`; above
 * it, the other way round. ⚠ The same shape `src/handshake.c` uses for sequence
 * numbers, for the same reason. */
#define HALF_THE_SPACE 0x8000000000000000u

struct moment moment_now(void)
{
    /* ⚠ The last moment read, so a failure cannot hand back something earlier
     * than what a caller has already seen. ⚠ Not a cache: it is only ever
     * returned when the clock could not be read at all. */
    static struct moment last = { 0 };

    struct timespec read;
    if (clock_gettime(CLOCK_MONOTONIC, &read) != 0) {
        return last;
    }
    last.nanoseconds = (uint64_t)read.tv_sec * NANOSECONDS_IN_A_SECOND +
                       (uint64_t)read.tv_nsec;
    return last;
}

bool moment_is_at_or_after(struct moment a, struct moment b)
{
    /* ⚠ Unsigned subtraction is defined to wrap; ⚠ `(int64_t)(a - b) >= 0` is
     * signed overflow, which is not a comparison at all
     * (`.claude/rules/c.md`). */
    return (uint64_t)(a.nanoseconds - b.nanoseconds) < HALF_THE_SPACE;
}

struct moment moment_after_nanoseconds(struct moment from, uint64_t nanoseconds)
{
    struct moment later;
    later.nanoseconds = from.nanoseconds + nanoseconds;
    return later;
}

struct moment moment_after(struct moment from, uint64_t milliseconds)
{
    struct moment then;
    /* ⚠ Unsigned, so this is defined even when it wraps. ⚠ The comparison above
     * is what makes a wrapped moment still work. */
    then.nanoseconds =
        from.nanoseconds + milliseconds * (uint64_t)NANOSECONDS_IN_A_MILLISECOND;
    return then;
}

int moment_milliseconds_until(struct moment now, struct moment deadline)
{
    if (moment_is_at_or_after(now, deadline)) {
        /* ⚠ Already due. ⚠ 0 and not a negative number: `ppoll` reads a negative
         * limit as "wait for ever" (`src/tap.h`), which is the opposite of what
         * a past deadline means. */
        return 0;
    }

    uint64_t left = deadline.nanoseconds - now.nanoseconds;
    uint64_t milliseconds = left / NANOSECONDS_IN_A_MILLISECOND;
    /* ⚠ Rounded up, so a caller never wakes a moment before the deadline and
     * finds nothing due. */
    if (left % NANOSECONDS_IN_A_MILLISECOND != 0) {
        milliseconds++;
    }
    if (milliseconds > (uint64_t)INT_MAX) {
        return INT_MAX;
    }
    return (int)milliseconds;
}

int moment_wait_limit(struct moment now, struct deadline first, struct deadline second)
{
    if (!first.set && !second.set) {
        /* ⚠ Nothing to wake for. ⚠ -1 is `tap_wait_readable`'s "no limit", and
         * ⚠ it is what the program did before it had any timer at all. */
        return -1;
    }
    if (!first.set) {
        return moment_milliseconds_until(now, second.at);
    }
    if (!second.set) {
        return moment_milliseconds_until(now, first.at);
    }
    /* ⚠ The nearer of the two, ⚠ compared the way moments must be so it works
     * across the wrap. ⚠ Taking the further one would let a deadline pass
     * unnoticed. */
    struct moment nearer =
        moment_is_at_or_after(second.at, first.at) ? first.at : second.at;
    return moment_milliseconds_until(now, nearer);
}
