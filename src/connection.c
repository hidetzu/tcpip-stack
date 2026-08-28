#include "connection.h"

#include <string.h>

static bool same_socket(const struct socket *a, const struct socket *b)
{
    return a->port == b->port &&
           memcmp(a->address, b->address, CONNECTION_ADDRESS_BYTES) == 0;
}

/* ⚠ "A connection is fully specified by the pair of sockets at the ends."
 * ⚠ Both, every time: a connection that differs only in the remote port is a
 * different connection. */
static bool same_connection(const struct connection_id *a, const struct connection_id *b)
{
    return same_socket(&a->local, &b->local) && same_socket(&a->remote, &b->remote);
}

void connections_forget_everything(struct connections *connections)
{
    memset(connections, 0, sizeof *connections);
}

struct transmission_control_block *connections_find(struct connections *connections,
                                                    const struct connection_id *id)
{
    for (size_t i = 0; i < CONNECTIONS_AT_ONCE; i++) {
        struct transmission_control_block *block = &connections->block[i];
        if (block->in_use && same_connection(&block->id, id)) {
            return block;
        }
    }
    return NULL;
}

enum connection_take connections_take(struct connections *connections,
                                      const struct connection_id *id,
                                      struct connection_counts *counts,
                                      struct transmission_control_block **taken)
{
    /* ⚠ Already held is not a second connection. ⚠ The kernel retransmits its
     * SYN, so this is the ordinary case and not a rare one. */
    struct transmission_control_block *held = connections_find(connections, id);
    if (held != NULL) {
        *taken = held;
        return CONNECTION_TAKEN;
    }

    for (size_t i = 0; i < CONNECTIONS_AT_ONCE; i++) {
        struct transmission_control_block *block = &connections->block[i];
        if (block->in_use) {
            continue;
        }
        /* ⚠ Cleared before it is filled, so nothing a previous connection left
         * can be read as this one's.
         *
         * ⚠ Provable since hidetzu/tcpip-stack#43 gave a block a state and four
         * sequence numbers to leak. ⚠ **As a pair with the one in
         * `connections_release`**: removing either alone changes nothing,
         * because the other still clears the block; ⚠ **removing both fails
         * `a_block_taken_again_holds_none_of_the_last_connections_numbers`**,
         * which then reads the last connection's `iss` and `irs`.
         *
         * ⚠ When #42 wrote this line there was nothing that could survive, and
         * ⚠ the comment here said so rather than claiming it was asserted
         * (`CLAUDE.md` §1). ⚠ It stopped being true with #43 and changed with
         * it. */
        memset(block, 0, sizeof *block);
        block->in_use = true;
        block->id = *id;
        *taken = block;
        return CONNECTION_TAKEN;
    }

    /* ⚠ Counted, and the caller is told nothing was taken. ⚠ A refusal nobody
     * counted is invisible, and an invisible refusal looks exactly like a
     * segment that never arrived (`.claude/rules/c.md`). */
    *taken = NULL;
    counts->refused_for_want_of_room++;
    return CONNECTION_NO_ROOM;
}

void connections_release(struct connections *connections,
                         struct transmission_control_block *block)
{
    (void)connections;
    if (block == NULL) {
        return;
    }
    /* ⚠ Cleared on the way out as well as on the way in. ⚠ Either alone would
     * do; both means a block is never readable between the two, whichever end a
     * future reader looks at.
     *
     * ⚠ Provable since hidetzu/tcpip-stack#43, ⚠ **as a pair with the one in
     * `connections_take`** — see the note there. ⚠ Removing this one alone still
     * changes nothing, and that is what "either alone would do" means. */
    memset(block, 0, sizeof *block);
}
