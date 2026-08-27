/* Static-tier check of where connection state lives.
 *
 * ⚠ No TAP device, no namespace, no clock, no fd — which is the point of the
 * shape ADR 0008 set and ADR 0015 followed (hidetzu/tcpip-stack#42 AC 3).
 *
 * ⚠ What it is really guarding is `.claude/skills/change-review/SKILL.md` §4:
 * ⚠ **state overwritten by a stale result reads, from outside, as something
 * that was observed.** ⚠ On a network that is the ordinary case — segments
 * arrive twice, arrive late, and arrive from someone else. */
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "check.h"
#include "connection.h"

static struct connection_id an_id(unsigned char local_last, unsigned local_port,
                                  unsigned char remote_last, unsigned remote_port)
{
    struct connection_id id;
    memset(&id, 0, sizeof id);
    id.local.address[0] = 10;
    id.local.address[3] = local_last;
    id.local.port = (uint16_t)local_port;
    id.remote.address[0] = 10;
    id.remote.address[3] = remote_last;
    id.remote.port = (uint16_t)remote_port;
    return id;
}

/* The one this milestone is built around: 10.0.0.2:80 answering 10.0.0.1:50568. */
static struct connection_id the_connection(void)
{
    return an_id(2, 80, 1, 50568);
}

/* ⚠ Nothing may be readable before anything was put there. */
static bool case_a_set_of_connections_starts_holding_nothing(void)
{
    struct connections connections;
    memset(&connections, 0xaa, sizeof connections);
    connections_forget_everything(&connections);

    struct connection_id id = the_connection();
    if (connections_find(&connections, &id) != NULL) {
        fputs("  a connection was found in a set that holds nothing\n", stderr);
        return false;
    }
    /* ⚠ The other half: something taken IS then found, or the case above would
     * pass for an implementation that never finds anything. */
    struct connection_counts counts;
    memset(&counts, 0, sizeof counts);
    struct transmission_control_block *taken = NULL;
    if (connections_take(&connections, &id, &counts, &taken) != CONNECTION_TAKEN ||
        taken == NULL) {
        fputs("  the first connection could not be taken\n", stderr);
        return false;
    }
    if (connections_find(&connections, &id) != taken) {
        fputs("  what was taken is not what is found\n", stderr);
        return false;
    }
    return true;
}

/* ⚠ RFC 793: "A connection is fully specified by the pair of sockets at the
 * ends." ⚠ Two connections that differ in ANY one field of that pair are
 * different connections — ⚠ and none of it is position or arrival order. */
static bool case_a_connection_is_told_apart_by_both_of_its_sockets(void)
{
    struct connections connections;
    connections_forget_everything(&connections);
    struct connection_counts counts;
    memset(&counts, 0, sizeof counts);

    struct connection_id held = the_connection();
    struct transmission_control_block *taken = NULL;
    if (connections_take(&connections, &held, &counts, &taken) != CONNECTION_TAKEN) {
        fputs("  the connection could not be taken\n", stderr);
        return false;
    }

    /* ⚠ One field different at a time, and every one of the four. */
    static const struct { unsigned char ll; unsigned lp; unsigned char rl; unsigned rp;
                          const char *what; } others[] = {
        { 9, 80, 1, 50568, "a different local address" },
        { 2, 81, 1, 50568, "a different local port" },
        { 2, 80, 9, 50568, "a different remote address" },
        { 2, 80, 1, 50569, "a different remote port" },
    };

    bool ok = true;
    for (size_t i = 0; i < sizeof others / sizeof others[0]; i++) {
        struct connection_id other =
            an_id(others[i].ll, others[i].lp, others[i].rl, others[i].rp);
        if (connections_find(&connections, &other) != NULL) {
            fprintf(stderr, "  %s was found as the one we hold\n", others[i].what);
            ok = false;
        }
    }

    /* ⚠ The other half: the one that matches in all four IS found, so the loop
     * above cannot pass for an implementation that never matches anything. */
    struct connection_id same = the_connection();
    if (connections_find(&connections, &same) != taken) {
        fputs("  the connection we hold was not found by an equal id\n", stderr);
        ok = false;
    }
    return ok;
}

/* ⚠ The kernel retransmits its SYN — 7 times in one measured `connect()`,
 * 2026-08-28 — so ⚠ taking the same connection twice is the ordinary case.
 * ⚠ It must hand back the block that already holds it, not a second one and not
 * a refusal. */
static bool case_taking_a_connection_we_already_hold_is_not_a_second_one(void)
{
    struct connections connections;
    connections_forget_everything(&connections);
    struct connection_counts counts;
    memset(&counts, 0, sizeof counts);

    struct connection_id id = the_connection();
    struct transmission_control_block *first = NULL;
    struct transmission_control_block *again = NULL;
    if (connections_take(&connections, &id, &counts, &first) != CONNECTION_TAKEN) {
        fputs("  the first take was refused\n", stderr);
        return false;
    }
    for (int i = 0; i < 7; i++) {
        if (connections_take(&connections, &id, &counts, &again) != CONNECTION_TAKEN) {
            fprintf(stderr, "  retransmission %d was refused\n", i + 1);
            return false;
        }
        if (again != first) {
            fprintf(stderr, "  retransmission %d got a different block\n", i + 1);
            return false;
        }
    }
    if (counts.refused_for_want_of_room != 0) {
        fprintf(stderr, "  retransmissions were counted as refusals: %lu\n",
                counts.refused_for_want_of_room);
        return false;
    }
    return true;
}

/* ⚠ There is room for one, and ⚠ the one that does not fit is counted rather
 * than dropped in silence (hidetzu/tcpip-stack#42 Owner Decision 1). */
static bool case_a_connection_that_does_not_fit_is_refused_and_counted(void)
{
    struct connections connections;
    connections_forget_everything(&connections);
    struct connection_counts counts;
    memset(&counts, 0, sizeof counts);

    /* Fill it, whatever CONNECTIONS_AT_ONCE happens to be. */
    for (size_t i = 0; i < CONNECTIONS_AT_ONCE; i++) {
        struct connection_id id = an_id(2, 80, 1, (unsigned)(50000 + i));
        struct transmission_control_block *taken = NULL;
        if (connections_take(&connections, &id, &counts, &taken) != CONNECTION_TAKEN) {
            fprintf(stderr, "  connection %zu of %d could not be taken\n", i + 1,
                    CONNECTIONS_AT_ONCE);
            return false;
        }
    }
    if (counts.refused_for_want_of_room != 0) {
        fputs("  filling the set counted a refusal\n", stderr);
        return false;
    }

    bool ok = true;
    for (unsigned extra = 0; extra < 3; extra++) {
        struct connection_id id = an_id(2, 80, 1, 60000 + extra);
        struct transmission_control_block *taken = &connections.block[0];
        if (connections_take(&connections, &id, &counts, &taken) != CONNECTION_NO_ROOM) {
            fprintf(stderr, "  a connection past the %d there is room for was taken\n",
                    CONNECTIONS_AT_ONCE);
            ok = false;
        }
        /* ⚠ Nothing handed back for something that was refused: a caller must
         * not be able to write into a block it was not given. */
        if (taken != NULL) {
            fputs("  a block was handed back for a refused connection\n", stderr);
            ok = false;
        }
        if (counts.refused_for_want_of_room != extra + 1) {
            fprintf(stderr, "  refusal %u counted %lu\n", extra + 1,
                    counts.refused_for_want_of_room);
            ok = false;
        }
        /* ⚠ And the refused one is not now findable. */
        if (connections_find(&connections, &id) != NULL) {
            fputs("  a refused connection can be found\n", stderr);
            ok = false;
        }
    }
    return ok;
}

/* ⚠ The one `change-review` §4 is about. ⚠ A block given back and taken again
 * must not hand the next connection what the last one left — ⚠ that is stale
 * state read as current, and from outside it looks like something observed. */
static bool case_a_block_taken_again_holds_nothing_of_the_last_one(void)
{
    struct connections connections;
    connections_forget_everything(&connections);
    struct connection_counts counts;
    memset(&counts, 0, sizeof counts);

    struct connection_id first = the_connection();
    struct transmission_control_block *block = NULL;
    if (connections_take(&connections, &first, &counts, &block) != CONNECTION_TAKEN) {
        fputs("  the first connection could not be taken\n", stderr);
        return false;
    }
    connections_release(&connections, block);

    /* ⚠ Gone, and ⚠ gone by its own identity rather than by the set being
     * empty. */
    if (connections_find(&connections, &first) != NULL) {
        fputs("  a released connection can still be found\n", stderr);
        return false;
    }

    struct connection_id second = an_id(2, 80, 1, 50569);
    struct transmission_control_block *again = NULL;
    if (connections_take(&connections, &second, &counts, &again) != CONNECTION_TAKEN) {
        fputs("  a connection could not be taken after a release\n", stderr);
        return false;
    }

    bool ok = true;
    /* ⚠ It holds the new identity and not a trace of the old one. */
    if (memcmp(&again->id, &second, sizeof second) != 0) {
        fputs("  the block taken again does not hold the new connection's id\n", stderr);
        ok = false;
    }
    if (connections_find(&connections, &first) != NULL) {
        fputs("  the old connection is findable through the block taken again\n", stderr);
        ok = false;
    }
    if (counts.refused_for_want_of_room != 0) {
        fputs("  taking after a release was counted as a refusal\n", stderr);
        ok = false;
    }
    return ok;
}

/* ⚠ Releasing nothing is not a crash, and releasing twice is not either. ⚠ Both
 * are what a caller that lost track will do, and ⚠ neither may leave the set
 * holding something. */
static bool case_releasing_nothing_and_releasing_twice_are_both_safe(void)
{
    struct connections connections;
    connections_forget_everything(&connections);
    struct connection_counts counts;
    memset(&counts, 0, sizeof counts);

    connections_release(&connections, NULL);

    struct connection_id id = the_connection();
    struct transmission_control_block *block = NULL;
    if (connections_take(&connections, &id, &counts, &block) != CONNECTION_TAKEN) {
        fputs("  the connection could not be taken\n", stderr);
        return false;
    }
    connections_release(&connections, block);
    connections_release(&connections, block);

    if (connections_find(&connections, &id) != NULL) {
        fputs("  releasing twice left the connection findable\n", stderr);
        return false;
    }
    /* ⚠ The other half: the room really did come back. */
    struct transmission_control_block *taken = NULL;
    if (connections_take(&connections, &id, &counts, &taken) != CONNECTION_TAKEN) {
        fputs("  the room did not come back after releasing\n", stderr);
        return false;
    }
    return true;
}

static const struct test_case cases[] = {
    { "a_set_of_connections_starts_holding_nothing",
      case_a_set_of_connections_starts_holding_nothing },
    { "a_connection_is_told_apart_by_both_of_its_sockets",
      case_a_connection_is_told_apart_by_both_of_its_sockets },
    { "taking_a_connection_we_already_hold_is_not_a_second_one",
      case_taking_a_connection_we_already_hold_is_not_a_second_one },
    { "a_connection_that_does_not_fit_is_refused_and_counted",
      case_a_connection_that_does_not_fit_is_refused_and_counted },
    { "a_block_taken_again_holds_nothing_of_the_last_one",
      case_a_block_taken_again_holds_nothing_of_the_last_one },
    { "releasing_nothing_and_releasing_twice_are_both_safe",
      case_releasing_nothing_and_releasing_twice_are_both_safe },
};

int main(int argc, char **argv)
{
    return check_main("connection", cases, sizeof cases / sizeof cases[0], argc, argv);
}
