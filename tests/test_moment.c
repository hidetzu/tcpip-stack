/* Static-tier check of the one place this stack reads a clock.
 *
 * ⚠ No fd, no namespace, and ⚠ **almost no clock**: every case but one works on
 * moments made up here, ⚠ **which is the whole point of the type**
 * (hidetzu/tcpip-stack#56 Owner Decision 1).
 *
 * ⚠ The one case that does read the clock reads it twice and compares them.
 * ⚠ It asserts only what `man 2 clock_gettime` says — ⚠ **that it does not go
 * backwards** — and ⚠ **not that it moved**, because the document says two calls
 * may return the same value. */
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>

#include "check.h"
#include "moment.h"

static struct moment at(uint64_t nanoseconds)
{
    struct moment moment = { nanoseconds };
    return moment;
}

/* ⚠ The comparison, including where the count wraps. ⚠ A plain `a >= b` is
 * correct for centuries and then wrong once — this is that once. */
static bool case_a_moment_is_told_from_another_across_the_wrap(void)
{
    static const uint64_t last = UINT64_MAX;
    bool ok = true;

#define SAY(a_value, b_value, expected, what)                                     \
    do {                                                                          \
        bool got = moment_is_at_or_after(at(a_value), at(b_value));               \
        if (got != (expected)) {                                                  \
            fprintf(stderr, "  %s: got %d, it must be %d\n", what, (int)got,       \
                    (int)(expected));                                             \
            ok = false;                                                           \
        }                                                                         \
    } while (0)

    SAY(10, 10, true, "the same moment is at or after itself");
    SAY(11, 10, true, "one nanosecond later");
    SAY(10, 11, false, "one nanosecond earlier");

    /* ⚠ Across the wrap: 0 comes after UINT64_MAX, not before it. ⚠ A plain
     * comparison says the opposite of both of these. */
    SAY(0, last, true, "zero is after the last nanosecond there is");
    SAY(last, 0, false, "the last nanosecond is not after zero");
    SAY(5, last - 5, true, "five past the wrap is after ten before it");
    SAY(last - 5, 5, false, "ten before the wrap is not after five past it");
#undef SAY
    return ok;
}

/* ⚠ Adding a duration, including where it carries past the end. */
static bool case_a_moment_after_another_is_that_much_later(void)
{
    bool ok = true;
    if (moment_after(at(0), 1).nanoseconds != 1000000u) {
        fputs("  a millisecond is not a million nanoseconds\n", stderr);
        ok = false;
    }
    if (moment_after(at(7), 0).nanoseconds != 7) {
        fputs("  no milliseconds moved the moment\n", stderr);
        ok = false;
    }

    /* ⚠ Past the end, and ⚠ the comparison still says it is later. */
    struct moment near_the_end = at(UINT64_MAX - 1000u);
    struct moment past_it = moment_after(near_the_end, 1);
    if (past_it.nanoseconds >= near_the_end.nanoseconds) {
        fputs("  adding a millisecond near the end did not wrap, so this case "
              "asserts nothing about the wrap\n", stderr);
        ok = false;
    }
    if (!moment_is_at_or_after(past_it, near_the_end)) {
        fputs("  a moment past the wrap is not seen as later\n", stderr);
        ok = false;
    }
    return ok;
}

/* ⚠ What a caller about to wait is handed. ⚠ Never negative, because `ppoll`
 * reads a negative limit as "wait for ever" (`src/tap.h`). */
static bool case_the_time_until_a_deadline_is_never_negative(void)
{
    bool ok = true;

    static const struct { uint64_t now; uint64_t deadline; int expected;
                          const char *what; } asked[] = {
        { 0, 0, 0, "a deadline that is now" },
        { 10, 5, 0, "a deadline already past" },
        { 0, 1000000u, 1, "one millisecond away" },
        { 0, 1500000u, 2, "one and a half milliseconds, rounded up" },
        { 0, 1u, 1, "one nanosecond away, rounded up to a whole millisecond" },
        { 0, 2000000u, 2, "two milliseconds away" },
    };
    for (size_t i = 0; i < sizeof asked / sizeof asked[0]; i++) {
        int got = moment_milliseconds_until(at(asked[i].now), at(asked[i].deadline));
        if (got != asked[i].expected) {
            fprintf(stderr, "  %s: got %d, expected %d\n", asked[i].what, got,
                    asked[i].expected);
            ok = false;
        }
    }

    /* ⚠ Rounded UP, never down: a caller that woke a moment early would find
     * nothing due and wait again, ⚠ which is a busy loop rather than a wait. */
    if (moment_milliseconds_until(at(0), at(1u)) != 1) {
        fputs("  a deadline less than a millisecond away was rounded down to 0\n",
              stderr);
        ok = false;
    }

    /* ⚠ And it fits what tap_wait_readable takes, however far away it is. */
    if (moment_milliseconds_until(at(0), at(UINT64_MAX / 2)) != INT_MAX) {
        fputs("  a deadline further away than INT_MAX milliseconds was not capped\n",
              stderr);
        ok = false;
    }
    return ok;
}

/* ⚠ The only case that reads the clock, and ⚠ it asserts only what the
 * documentation says. */
static bool case_the_clock_does_not_go_backwards(void)
{
    struct moment first = moment_now();
    struct moment second = moment_now();

    if (!moment_is_at_or_after(second, first)) {
        fprintf(stderr, "  the clock went backwards: %llu then %llu\n",
                (unsigned long long)first.nanoseconds,
                (unsigned long long)second.nanoseconds);
        return false;
    }

    /* ⚠ NOT asserted: that it moved. ⚠ `man 2 clock_gettime`: "successive calls
     * may—depending on the architecture—return identical (not-increased) time
     * values." ⚠ A case requiring it to advance would be asserting something the
     * document says may not happen (`CLAUDE.md` §1).
     *
     * ⚠ What IS asserted is that it is not stuck at zero, which would mean the
     * call did nothing at all. */
    if (first.nanoseconds == 0 && second.nanoseconds == 0) {
        fputs("  the clock reads zero, so it was probably never read\n", stderr);
        return false;
    }
    return true;
}

static const struct test_case cases[] = {
    { "a_moment_is_told_from_another_across_the_wrap",
      case_a_moment_is_told_from_another_across_the_wrap },
    { "a_moment_after_another_is_that_much_later",
      case_a_moment_after_another_is_that_much_later },
    { "the_time_until_a_deadline_is_never_negative",
      case_the_time_until_a_deadline_is_never_negative },
    { "the_clock_does_not_go_backwards", case_the_clock_does_not_go_backwards },
};

int main(int argc, char **argv)
{
    return check_main("moment", cases, sizeof cases / sizeof cases[0], argc, argv);
}
