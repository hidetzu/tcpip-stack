/* A moment in time, and the one place this stack reads a clock.
 *
 * ⚠ Nothing else in `src/` reads the time, and ⚠ a check says so
 * (`tests/static.sh` `the_clock_is_read_in_one_place`).
 *
 * ⚠ Why that matters, and it is about the checks: ⚠ **the State layer is handed
 * a moment rather than reading one** (hidetzu/tcpip-stack#56 Owner Decision 1).
 * ⚠ Every State-layer check runs with no clock and no waiting today — `handshake`,
 * `connection_state`, `arp_responder`, `echo_responder` — and ⚠ **a State layer
 * that read a clock could not be checked that way.** ⚠ Its checks would wait in
 * real time, which is the least reproducible thing there is (`CLAUDE.md` §6), or
 * install a clock of their own, ⚠ **which is a second implementation of what
 * time is** (`CLAUDE.md` §3).
 *
 * ⚠ The clock is `CLOCK_MONOTONIC`, and ⚠ **only what the documentation says
 * about it is relied on** (`man 2 clock_gettime`, read 2026-08-28):
 *
 *   "A nonsettable system-wide clock that represents monotonic time since—as
 *    described by POSIX—'some unspecified point in the past'. ... is not
 *    affected by discontinuous jumps in the system time ..., but is affected by
 *    frequency adjustments.  This clock does not count time that the system is
 *    suspended.  All CLOCK_MONOTONIC variants guarantee that the time returned
 *    by consecutive calls will not go backwards, but successive calls
 *    may—depending on the architecture—return identical (not-increased) time
 *    values."
 *
 * ⚠ Three things follow, and ⚠ **nothing else is claimed** (ADR 0018):
 *
 *   ⚠ **It does not go backwards**, so nothing here guards against that. ⚠ A
 *     guard would be code nobody could say why they were reading.
 *   ⚠ **Two calls can give the same value.** ⚠ That is the document's word, not
 *     a worry — ⚠ anything deciding on elapsed time has to survive it.
 *   ⚠ **It does not count time the machine was suspended.** ⚠ The only other end
 *     this stack has is on the same machine, so ⚠ it was suspended too — ⚠ an
 *     observation about where this runs, ⚠ **not a claim about a distant peer.**
 */
#ifndef MOMENT_H
#define MOMENT_H

#include <stdbool.h>
#include <stdint.h>

/* ⚠ Nanoseconds since the unspecified point the documentation names — ⚠ **on
 * Linux, since the machine booted.** ⚠ The origin is not a date and ⚠ nothing
 * here turns it into one: two moments may be compared and subtracted, and that
 * is all they are for.
 *
 * ⚠ 64 bits of nanoseconds is about 584 years, so ⚠ **the wrap is not reachable
 * on a machine that has been up for less than that.** ⚠ The comparison below
 * survives it anyway, because writing it the other way is the defect that looks
 * correct for years (`.claude/rules/c.md`). */
struct moment {
    uint64_t nanoseconds;
};

/* Read the clock. ⚠ **The only place in `src/` that does.**
 *
 * ⚠ It cannot fail in a way a caller could do anything about: `CLOCK_MONOTONIC`
 * is required to exist, and ⚠ **a failure here would mean the machine has no
 * monotonic clock at all.** ⚠ If the call does fail, the moment returned is the
 * last one that was read, ⚠ **which cannot go backwards and cannot make
 * something due early** — and that is the whole guarantee callers get. */
struct moment moment_now(void);

/* ⚠ True when `a` is at or after `b`, ⚠ **across the wrap.**
 *
 * ⚠ Written with unsigned arithmetic, the same shape `src/handshake.c` uses for
 * sequence numbers: ⚠ **a plain `a >= b` is correct for centuries and then
 * wrong once.** ⚠ The signed-difference trick is undefined behaviour and is not
 * a comparison at all (`.claude/rules/c.md`).
 *
 * ⚠ Two moments more than about 292 years apart compare the other way round.
 * ⚠ Said rather than left to be found. */
bool moment_is_at_or_after(struct moment a, struct moment b);

/* The moment `milliseconds` after `from`. */
struct moment moment_after(struct moment from, uint64_t milliseconds);

/* How long until `deadline`, in milliseconds, for a caller about to wait.
 *
 * ⚠ Never negative: a deadline already past gives 0, ⚠ **because a negative
 * limit means "wait for ever" to `ppoll`** (`src/tap.h`) and ⚠ that is the
 * opposite of what a past deadline means.
 *
 * ⚠ Never more than `INT_MAX`, so it fits what `tap_wait_readable` takes. */
int moment_milliseconds_until(struct moment now, struct moment deadline);

#endif /* MOMENT_H */
