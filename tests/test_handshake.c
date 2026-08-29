/* Static-tier check of the transitions from LISTEN to ESTABLISHED.
 *
 * ⚠ No TAP device, no namespace, no clock, no fd — the shape ADR 0008 set,
 * ADR 0015 kept, and ⚠ what makes every rule below assertable at all.
 *
 * ⚠ Two things this file exists to stop, and they are different:
 *   ⚠ **establishing on any acknowledgment at all** — which the ping milestone's
 *     lesson says would look correct end to end (`CLAUDE.md` §1)
 *   ⚠ **a comparison written with `<`** on a sequence space that wraps, which is
 *     correct for years and then wrong once. */
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "check.h"
#include "handshake.h"
#include "moment.h"

static const unsigned char THEIR_MAC[6] = { 0x02, 0x11, 0x11, 0x11, 0x11, 0x11 };
static const unsigned char OUR_MAC[6] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x02 };

#define OUR_PORT 80
#define THEIR_PORT 50568
#define THEIR_ISN 0x831b6b20u

static struct connection_id the_connection(void)
{
    struct connection_id id;
    memset(&id, 0, sizeof id);
    id.local.address[0] = 10;
    id.local.address[3] = 2;
    id.local.port = OUR_PORT;
    id.remote.address[0] = 10;
    id.remote.address[3] = 1;
    id.remote.port = THEIR_PORT;
    return id;
}

static struct tcp_header a_segment(unsigned control_bits, uint32_t sequence_number,
                                   uint32_t acknowledgment_number)
{
    struct tcp_header header;
    memset(&header, 0, sizeof header);
    header.source_port = THEIR_PORT;
    header.destination_port = OUR_PORT;
    header.sequence_number = sequence_number;
    header.acknowledgment_number = acknowledgment_number;
    header.control_bits = (uint8_t)control_bits;
    header.data_offset = TCP_HEADER_LENGTH_MINIMUM;
    header.data_begins_at = TCP_FIXED_HEADER_BYTES;
    return header;
}

/* ⚠ A segment carrying `data_bytes` octets of data. ⚠ The octets themselves are
 * never given: ⚠ **this layer is handed a header that was already read**, and
 * ⚠ how many there are is the only thing it may act on (`src/tcp.h`). */
static struct tcp_header carrying(struct tcp_header header, size_t data_bytes)
{
    header.data_bytes = data_bytes;
    return header;
}

/* ⚠ A moment made up here. ⚠ Every case works on these, ⚠ **which is what
 * handing "now" in buys** (ADR 0018): no clock, no waiting. */
static struct moment at(uint64_t milliseconds)
{
    struct moment moment = { milliseconds * 1000000u };
    return moment;
}

struct world {
    struct connections connections;
    struct handshake_counts counts;
    /* ⚠ What this world thinks the time is. ⚠ A case moves it by assigning. */
    struct moment now;
    /* ⚠ Plainly large enough for the answer, so a case is never about the
     * buffer unless it says it is. */
    unsigned char reply[256];
};

static void a_world(struct world *world)
{
    connections_forget_everything(&world->connections);
    memset(&world->counts, 0, sizeof world->counts);
    memset(world->reply, 0xaa, sizeof world->reply);
    world->now = at(0);
}

static struct handshake_outcome receive(struct world *world,
                                        const struct tcp_header *header)
{
    struct connection_id id = the_connection();
    struct handshake_outcome outcome;
    handshake_receive(header, &id, OUR_PORT, world->now, IPV4_TIME_TO_LIVE_WE_SEND, THEIR_MAC, OUR_MAC, &world->connections,
                      world->reply, sizeof world->reply, &world->counts, &outcome);
    return outcome;
}

/* Opens a connection and hands back what we chose to answer with. */
static bool open_one(struct world *world, uint32_t their_isn,
                     struct transmission_control_block **held)
{
    struct tcp_header syn = a_segment(TCP_CONTROL_SYN, their_isn, 0);
    struct handshake_outcome outcome = receive(world, &syn);
    if (outcome.decision != HANDSHAKE_MOVED ||
        outcome.state != CONNECTION_SYN_RECEIVED) {
        fprintf(stderr, "  a SYN did not open a connection: decision %d state %d\n",
                (int)outcome.decision, (int)outcome.state);
        return false;
    }
    struct connection_id id = the_connection();
    *held = connections_find(&world->connections, &id);
    return *held != NULL;
}

/* ⚠ RFC 793 for the LISTEN state, quoted: "Set RCV.NXT to SEG.SEQ+1, IRS is set
 * to SEG.SEQ ... SND.NXT is set to ISS+1 and SND.UNA to ISS.  The connection
 * state should be changed to SYN-RECEIVED." ⚠ Every number, asserted. */
static bool case_a_syn_opens_a_connection_and_sets_every_number(void)
{
    struct world world;
    a_world(&world);
    /* ⚠ Opened at a moment that is not zero, ⚠ **because since
     * hidetzu/tcpip-stack#98 the initial send sequence number IS the clock**,
     * and at moment 0 it would be 0 — ⚠ **which the half below rejects, on
     * purpose.** ⚠ A real clock is nanoseconds since boot and is never 0;
     * ⚠ **this case says so rather than leaving the 0 to look like a rule.** */
    world.now = at(1234567u);
    struct transmission_control_block *held = NULL;
    if (!open_one(&world, THEIR_ISN, &held)) {
        return false;
    }

    bool ok = true;
#define SAME(field, expected)                                                    \
    do {                                                                         \
        if (held->field != (expected)) {                                         \
            fprintf(stderr, "  %s is 0x%08lx, the document says 0x%08lx\n",       \
                    #field, (unsigned long)held->field, (unsigned long)(expected)); \
            ok = false;                                                          \
        }                                                                        \
    } while (0)
    SAME(irs, THEIR_ISN);
    SAME(rcv_nxt, THEIR_ISN + 1u);
    /* ⚠ The number is what the clock said when the connection was taken —
     * asserted against the function and not against a literal, so ⚠ **it
     * follows the rate if that changes** (hidetzu/tcpip-stack#98,
     * `.claude/rules/testing.md`). */
    SAME(iss, handshake_initial_send_sequence(world.now));
    SAME(snd_una, handshake_initial_send_sequence(world.now));
    SAME(snd_nxt, handshake_initial_send_sequence(world.now) + 1u);
#undef SAME
    if (held->state != CONNECTION_SYN_RECEIVED) {
        fputs("  the state is not SYN-RECEIVED\n", stderr);
        ok = false;
    }
    if (world.counts.opened != 1) {
        fprintf(stderr, "  opening was counted %lu times\n", world.counts.opened);
        ok = false;
    }

    /* ⚠ The other half: a block nobody filled in is all zeroes, so ⚠ the numbers
     * above have to be non-zero for the case to mean anything
     * (hidetzu/tcpip-stack#43 Owner Decision 1's reason for not choosing 0). */
    if (held->iss == 0 || held->irs == 0) {
        fputs("  the numbers chosen are indistinguishable from an unfilled block\n",
              stderr);
        ok = false;
    }
    return ok;
}

/* ⚠ The one the ping milestone's lesson demands. ⚠ RFC 793: "If SND.UNA =<
 * SEG.ACK =< SND.NXT then enter ESTABLISHED state". ⚠ It is a window, and
 * ⚠ **both ends of it are acceptable** — writing `== iss + 1` would be stricter
 * than the document. */
static bool case_only_an_acknowledgment_in_the_window_establishes(void)
{
    bool ok = true;

    /* Inside: ISS and ISS+1, both. */
    static const uint32_t inside[] = { 0, 1 };
    for (size_t i = 0; i < sizeof inside / sizeof inside[0]; i++) {
        struct world world;
        a_world(&world);
        struct transmission_control_block *held = NULL;
        if (!open_one(&world, THEIR_ISN, &held)) {
            return false;
        }
        struct tcp_header ack = a_segment(TCP_CONTROL_ACK, THEIR_ISN + 1u,
                                          handshake_initial_send_sequence(at(0)) + inside[i]);
        struct handshake_outcome outcome = receive(&world, &ack);
        if (outcome.decision != HANDSHAKE_MOVED ||
            outcome.state != CONNECTION_ESTABLISHED) {
            fprintf(stderr, "  an acknowledgment of iss+%lu did not establish\n",
                    (unsigned long)inside[i]);
            ok = false;
        }
        if (world.counts.established != 1) {
            fputs("  establishing was not counted exactly once\n", stderr);
            ok = false;
        }
    }

    /* ⚠ Outside, on both sides, and ⚠ far away. ⚠ Without this the case above
     * passes for a machine that establishes on any acknowledgment at all. */
    static const uint32_t outside[] = { 0xffffffffu, 2, 3, 0x10000u, 0x80000000u };
    for (size_t i = 0; i < sizeof outside / sizeof outside[0]; i++) {
        struct world world;
        a_world(&world);
        struct transmission_control_block *held = NULL;
        if (!open_one(&world, THEIR_ISN, &held)) {
            return false;
        }
        uint32_t wrong = handshake_initial_send_sequence(at(0)) + outside[i];
        struct tcp_header ack = a_segment(TCP_CONTROL_ACK, THEIR_ISN + 1u, wrong);
        struct handshake_outcome outcome = receive(&world, &ack);
        if (outcome.decision != HANDSHAKE_STAYED ||
            outcome.reason != HANDSHAKE_REASON_ACKNOWLEDGMENT_WE_ARE_NOT_WAITING_FOR) {
            fprintf(stderr, "  an acknowledgment of iss%+ld established: decision %d "
                            "reason %d\n",
                    (long)(int32_t)outside[i], (int)outcome.decision,
                    (int)outcome.reason);
            ok = false;
        }
        if (world.counts.acknowledgment_we_are_not_waiting_for != 1 ||
            world.counts.established != 0) {
            fputs("  a wrong acknowledgment was not counted on its own\n", stderr);
            ok = false;
        }
        if (held->state != CONNECTION_SYN_RECEIVED) {
            fputs("  a wrong acknowledgment moved the state anyway\n", stderr);
            ok = false;
        }
        /* ⚠ The numbers the sentence a human reads will need. */
        if (outcome.acknowledgment_we_had != wrong ||
            outcome.acknowledgment_we_expected != handshake_initial_send_sequence(at(0)) + 1u) {
            fputs("  the outcome does not carry the two numbers to report\n", stderr);
            ok = false;
        }
    }
    return ok;
}

/* ⚠ The wrap. ⚠ A comparison written with `<` is correct for years and then
 * wrong once — this is that once, and ⚠ it is asserted rather than reasoned
 * about. */
static bool case_the_window_still_works_where_the_sequence_space_wraps(void)
{
    bool ok = true;

    /* ⚠ Their SYN carries the last number there is, so `rcv_nxt` wraps to 0. */
    struct world world;
    a_world(&world);
    struct transmission_control_block *held = NULL;
    if (!open_one(&world, 0xffffffffu, &held)) {
        return false;
    }
    if (held->rcv_nxt != 0) {
        fprintf(stderr, "  rcv_nxt after a SYN of 0xffffffff is 0x%08lx, not 0\n",
                (unsigned long)held->rcv_nxt);
        ok = false;
    }

    /* ⚠ And our own window straddling the wrap: with `iss` at the last number,
     * `snd_nxt` is 0, so ⚠ **an acknowledgment of 0 must be accepted while one
     * of 1 must not.** ⚠ A plain `snd_una <= ack && ack <= snd_nxt` accepts
     * neither. */
    static const struct { uint32_t iss; uint32_t ack; bool establishes; const char *what; }
    around_the_wrap[] = {
        { 0xffffffffu, 0xffffffffu, true,  "iss at the last number, acknowledging it" },
        { 0xffffffffu, 0x00000000u, true,  "iss at the last number, acknowledging 0" },
        { 0xffffffffu, 0x00000001u, false, "iss at the last number, acknowledging 1" },
        { 0xfffffffeu, 0xffffffffu, true,  "one below, acknowledging the last number" },
        { 0xfffffffeu, 0x00000000u, false, "one below, acknowledging 0" },
    };

    for (size_t i = 0; i < sizeof around_the_wrap / sizeof around_the_wrap[0]; i++) {
        struct connections connections;
        connections_forget_everything(&connections);
        struct handshake_counts counts;
        memset(&counts, 0, sizeof counts);
        struct connection_id id = the_connection();

        /* ⚠ The chosen ISS is a constant, so the window is placed by hand here.
         * ⚠ That is the only way to reach the wrap without a clock. */
        struct transmission_control_block *block = NULL;
        if (connections_take(&connections, &id, &counts.room, &block) !=
            CONNECTION_TAKEN) {
            fputs("  a connection could not be taken\n", stderr);
            return false;
        }
        block->state = CONNECTION_SYN_RECEIVED;
        block->irs = THEIR_ISN;
        block->rcv_nxt = THEIR_ISN + 1u;
        block->iss = around_the_wrap[i].iss;
        block->snd_una = around_the_wrap[i].iss;
        block->snd_nxt = around_the_wrap[i].iss + 1u;

        struct tcp_header ack =
            a_segment(TCP_CONTROL_ACK, THEIR_ISN + 1u, around_the_wrap[i].ack);
        unsigned char reply[256];
        struct handshake_outcome outcome;
        handshake_receive(&ack, &id, OUR_PORT, at(0), IPV4_TIME_TO_LIVE_WE_SEND, THEIR_MAC, OUR_MAC, &connections, reply,
                          sizeof reply, &counts, &outcome);

        bool established = outcome.decision == HANDSHAKE_MOVED &&
                           outcome.state == CONNECTION_ESTABLISHED;
        if (established != around_the_wrap[i].establishes) {
            fprintf(stderr, "  %s: established=%d, it must be %d\n",
                    around_the_wrap[i].what, (int)established,
                    (int)around_the_wrap[i].establishes);
            ok = false;
        }
    }
    return ok;
}

/* ⚠ The Linux kernel retransmits its SYN — 7 times in one measured `connect()`,
 * 2026-08-28 — so this is the ordinary case. ⚠ Nothing may be re-chosen: a peer
 * that did get our first answer must not be told a different number. */
static bool case_a_retransmitted_syn_changes_nothing(void)
{
    struct world world;
    a_world(&world);
    struct transmission_control_block *held = NULL;
    if (!open_one(&world, THEIR_ISN, &held)) {
        return false;
    }
    struct transmission_control_block before = *held;

    bool ok = true;
    for (int i = 0; i < 7; i++) {
        struct tcp_header again = a_segment(TCP_CONTROL_SYN, THEIR_ISN, 0);
        struct handshake_outcome outcome = receive(&world, &again);
        if (outcome.decision != HANDSHAKE_STAYED ||
            outcome.reason != HANDSHAKE_REASON_ASKED_AGAIN) {
            fprintf(stderr, "  retransmission %d: decision %d reason %d\n", i + 1,
                    (int)outcome.decision, (int)outcome.reason);
            ok = false;
        }
        if (memcmp(held, &before, sizeof before) != 0) {
            fprintf(stderr, "  retransmission %d changed what we hold\n", i + 1);
            ok = false;
            break;
        }
    }
    if (world.counts.asked_again != 7 || world.counts.opened != 1) {
        fprintf(stderr, "  counted %lu asked-again and %lu opened\n",
                world.counts.asked_again, world.counts.opened);
        ok = false;
    }
    /* ⚠ And a retransmission is not an error: it moved none of the counters that
     * mean something went wrong. */
    if (world.counts.not_expected_in_this_state != 0 ||
        world.counts.acknowledgment_we_are_not_waiting_for != 0) {
        fputs("  a retransmission was counted as something being wrong\n", stderr);
        ok = false;
    }
    return ok;
}

/* ⚠ The answer RFC 793 describes, octet for octet:
 *   "<SEQ=ISS><ACK=RCV.NXT><CTL=SYN,ACK>"
 *
 * ⚠ And it is read back with our own parser, which ⚠ **checks the checksum
 * before anything else** (hidetzu/tcpip-stack#41) — so ⚠ an answer that parses
 * at all is one whose checksum agrees, without computing it a second way. */
static bool case_the_answer_is_the_one_the_document_describes(void)
{
    struct world world;
    a_world(&world);
    struct transmission_control_block *held = NULL;
    if (!open_one(&world, THEIR_ISN, &held)) {
        return false;
    }
    struct handshake_outcome outcome;
    {
        /* Re-run so the outcome is to hand; `open_one` threw its away. */
        a_world(&world);
        struct tcp_header syn = a_segment(TCP_CONTROL_SYN, THEIR_ISN, 0);
        outcome = receive(&world, &syn);
        struct connection_id id = the_connection();
        held = connections_find(&world.connections, &id);
    }
    if (outcome.decision != HANDSHAKE_MOVED || held == NULL) {
        fputs("  the SYN did not open a connection\n", stderr);
        return false;
    }

    bool ok = true;
    size_t expected = ETHERNET_HEADER_BYTES + IPV4_FIXED_HEADER_BYTES +
                      TCP_FIXED_HEADER_BYTES;
    if (outcome.reply_bytes != expected) {
        fprintf(stderr, "  the answer is %zu octets and a bare SYN-ACK is %zu\n",
                outcome.reply_bytes, expected);
        return false;
    }

    /* The ethernet header. */
    if (memcmp(world.reply, THEIR_MAC, ETHERNET_ADDRESS_BYTES) != 0 ||
        memcmp(world.reply + ETHERNET_ADDRESS_BYTES, OUR_MAC, ETHERNET_ADDRESS_BYTES)
            != 0) {
        fputs("  the answer's ethernet header is not ours to theirs\n", stderr);
        ok = false;
    }

    /* The internet header, read back by our own parser. */
    const unsigned char *datagram = world.reply + ETHERNET_HEADER_BYTES;
    struct ipv4_header internet;
    enum ipv4_parse read_back =
        ipv4_parse_header(datagram, outcome.reply_bytes - ETHERNET_HEADER_BYTES,
                          &internet);
    if (read_back != IPV4_PARSE_OK) {
        fprintf(stderr, "  the internet header we built came back as %d\n",
                (int)read_back);
        return false;
    }
    struct connection_id id = the_connection();
    if (internet.protocol != IPV4_PROTOCOL_TCP ||
        memcmp(internet.source_address, id.local.address, IPV4_ADDRESS_BYTES) != 0 ||
        memcmp(internet.destination_address, id.remote.address, IPV4_ADDRESS_BYTES)
            != 0) {
        fputs("  the answer's internet header is not ours to theirs under TCP\n",
              stderr);
        ok = false;
    }

    /* ⚠ The segment, read back by `tcp_parse_header` — which judges the checksum
     * first, so reaching OK is what says the checksum agrees. ⚠ The addresses go
     * in the other way round, because this is a segment WE sent. */
    struct tcp_header answer;
    enum tcp_parse parsed =
        tcp_parse_header(datagram + IPV4_FIXED_HEADER_BYTES,
                         (size_t)internet.total_length - IPV4_FIXED_HEADER_BYTES,
                         id.local.address, id.remote.address, &answer);
    if (parsed != TCP_PARSE_OK) {
        fprintf(stderr, "  the segment we built came back as %d "
                        "(2 would mean its own checksum disagrees)\n", (int)parsed);
        return false;
    }

    if (answer.control_bits != (TCP_CONTROL_SYN | TCP_CONTROL_ACK)) {
        fprintf(stderr, "  the answer's control bits are 0x%02x, not SYN|ACK\n",
                answer.control_bits);
        ok = false;
    }
    if (answer.sequence_number != held->iss) {
        fputs("  the answer's sequence number is not the ISS\n", stderr);
        ok = false;
    }
    if (answer.acknowledgment_number != held->rcv_nxt) {
        fputs("  the answer does not acknowledge RCV.NXT\n", stderr);
        ok = false;
    }
    /* ⚠ And the number reported for it is the same one, so ⚠ **a caller told
     * what we would acknowledge is told what actually goes out**
     * (hidetzu/tcpip-stack#65). */
    if (outcome.we_would_acknowledge != held->rcv_nxt) {
        fprintf(stderr, "  we would acknowledge %lu and the answer carries %lu\n",
                (unsigned long)outcome.we_would_acknowledge,
                (unsigned long)held->rcv_nxt);
        ok = false;
    }
    if (answer.source_port != OUR_PORT || answer.destination_port != THEIR_PORT) {
        fputs("  the answer's ports are not ours to theirs\n", stderr);
        ok = false;
    }
    /* ⚠ hidetzu/tcpip-stack#64 Owner Decision 1: the window we promise.
     * ⚠ Asserted against the constant AND against 0, because ⚠ **0 was the
     * value before #64 and a window of 0 makes a FIN impossible** — measured,
     * `src/handshake.h`. ⚠ Comparing only with the constant would pass if both
     * moved back to 0 together. */
    if (answer.window != HANDSHAKE_WINDOW || answer.window == 0) {
        fprintf(stderr, "  the answer advertises a window of %u, not %u\n",
                answer.window, (unsigned)HANDSHAKE_WINDOW);
        ok = false;
    }
    /* ⚠ Owner Decision 2: no options at all. */
    if (answer.data_offset != TCP_HEADER_LENGTH_MINIMUM) {
        fprintf(stderr, "  the answer carries %u octets of options\n",
                (answer.data_offset - TCP_HEADER_LENGTH_MINIMUM) * 4);
        ok = false;
    }
    return ok;
}

/* ⚠ Nothing is answered for anything but a SYN that opened a connection.
 * ⚠ RFC 793 §3.9 asks for a reset in two of these and an ack in the third;
 * ⚠ **none is sent**, and `docs/SPEC.md` §2 names all three. */
static bool case_nothing_is_answered_except_a_syn_that_opened_one(void)
{
    bool ok = true;
    static const struct { unsigned control; uint32_t seq; uint32_t ack; bool open_first;
                          const char *what; } quiet[] = {
        { TCP_CONTROL_ACK, THEIR_ISN, 1, false, "an acknowledgment with nothing held" },
        { TCP_CONTROL_SYN, THEIR_ISN, 0, true,  "a retransmitted SYN" },
        { TCP_CONTROL_ACK, THEIR_ISN + 1u, 0x0badf00du, true,
          "an acknowledgment outside the window" },
        { 0, THEIR_ISN + 1u, 0, true, "a segment with no control bits" },
    };

    for (size_t i = 0; i < sizeof quiet / sizeof quiet[0]; i++) {
        struct world world;
        a_world(&world);
        if (quiet[i].open_first) {
            struct transmission_control_block *held = NULL;
            if (!open_one(&world, THEIR_ISN, &held)) {
                return false;
            }
            memset(world.reply, 0xaa, sizeof world.reply);
        }
        struct tcp_header header =
            a_segment(quiet[i].control, quiet[i].seq, quiet[i].ack);
        struct handshake_outcome outcome = receive(&world, &header);

        if (outcome.reply_bytes != 0) {
            fprintf(stderr, "  %s: %zu octets were built to send\n", quiet[i].what,
                    outcome.reply_bytes);
            ok = false;
        }
        for (size_t j = 0; j < sizeof world.reply; j++) {
            if (world.reply[j] != 0xaa) {
                fprintf(stderr, "  %s: octet %zu of the reply buffer was written into\n",
                        quiet[i].what, j);
                ok = false;
                break;
            }
        }
    }

    /* ⚠ The other half: a SYN that opens one IS answered, or the loop above
     * would pass for a stack that never answered anything. */
    struct world world;
    a_world(&world);
    struct tcp_header syn = a_segment(TCP_CONTROL_SYN, THEIR_ISN, 0);
    struct handshake_outcome outcome = receive(&world, &syn);
    if (outcome.reply_bytes == 0) {
        fputs("  a SYN that opened a connection was not answered\n", stderr);
        ok = false;
    }
    return ok;
}

/* ⚠ Ours, not the sender's, ⚠ counted, and ⚠ the connection is given back so the
 * next SYN is not refused for want of room by one nothing will ever answer. */
static bool case_an_answer_that_would_not_fit_is_counted_as_ours(void)
{
    struct world world;
    a_world(&world);
    size_t needed =
        ETHERNET_HEADER_BYTES + IPV4_FIXED_HEADER_BYTES + TCP_FIXED_HEADER_BYTES;

    bool ok = true;
    for (size_t room = 0; room < needed; room++) {
        struct connections connections;
        connections_forget_everything(&connections);
        struct handshake_counts counts;
        memset(&counts, 0, sizeof counts);
        unsigned char reply[256];
        memset(reply, 0xaa, sizeof reply);

        struct connection_id id = the_connection();
        struct tcp_header syn = a_segment(TCP_CONTROL_SYN, THEIR_ISN, 0);
        struct handshake_outcome outcome;
        handshake_receive(&syn, &id, OUR_PORT, at(0), IPV4_TIME_TO_LIVE_WE_SEND, THEIR_MAC, OUR_MAC, &connections, reply,
                          room, &counts, &outcome);

        if (outcome.decision != HANDSHAKE_STAYED ||
            outcome.reason != HANDSHAKE_REASON_WE_COULD_NOT_BUILD_THE_REPLY ||
            counts.we_could_not_build_the_reply != 1 || counts.opened != 0) {
            fprintf(stderr, "  %zu octets of room: decision %d reason %d, counted %lu\n",
                    room, (int)outcome.decision, (int)outcome.reason,
                    counts.we_could_not_build_the_reply);
            ok = false;
            break;
        }
        if (outcome.reply_bytes != 0) {
            fprintf(stderr, "  %zu octets of room: it says it built %zu\n", room,
                    outcome.reply_bytes);
            ok = false;
            break;
        }
        /* ⚠ The block came back, so a later SYN is not refused for want of room
         * by a connection nothing will ever answer. */
        if (connections_find(&connections, &id) != NULL) {
            fprintf(stderr, "  %zu octets of room: the connection was kept\n", room);
            ok = false;
            break;
        }
    }

    /* ⚠ The other half: exactly enough room answers. */
    struct connections connections;
    connections_forget_everything(&connections);
    struct handshake_counts counts;
    memset(&counts, 0, sizeof counts);
    unsigned char reply[256];
    struct connection_id id = the_connection();
    struct tcp_header syn = a_segment(TCP_CONTROL_SYN, THEIR_ISN, 0);
    struct handshake_outcome outcome;
    handshake_receive(&syn, &id, OUR_PORT, at(0), IPV4_TIME_TO_LIVE_WE_SEND, THEIR_MAC, OUR_MAC, &connections, reply,
                      needed, &counts, &outcome);
    if (outcome.decision != HANDSHAKE_MOVED || outcome.reply_bytes != needed) {
        fprintf(stderr, "  exactly %zu octets of room was declined, reason %d\n", needed,
                (int)outcome.reason);
        ok = false;
    }
    return ok;
}

/* Opens one and confirms it, so a case can start from ESTABLISHED. */
static bool open_and_confirm(struct world *world,
                             struct transmission_control_block **held)
{
    if (!open_one(world, THEIR_ISN, held)) {
        return false;
    }
    struct tcp_header ack = a_segment(TCP_CONTROL_ACK, THEIR_ISN + 1u, (*held)->iss + 1u);
    struct handshake_outcome outcome = receive(world, &ack);
    if (outcome.decision != HANDSHAKE_MOVED ||
        outcome.state != CONNECTION_ESTABLISHED) {
        fputs("  the connection did not reach ESTABLISHED\n", stderr);
        return false;
    }
    return true;
}

/* ⚠ hidetzu/tcpip-stack#64 Owner Decision 2: taken, discarded, ⚠ and counted.
 *
 * ⚠ What this exists to stop is the payload going by uncounted: ⚠ **an octet
 * nobody counted is indistinguishable from one that never arrived**
 * (`.claude/rules/c.md`). */
static bool case_data_on_an_open_connection_is_taken_and_discarded(void)
{
    struct world world;
    a_world(&world);
    struct transmission_control_block *held = NULL;
    if (!open_and_confirm(&world, &held)) {
        return false;
    }
    uint32_t was = held->rcv_nxt;

    bool ok = true;
    struct tcp_header data =
        carrying(a_segment(TCP_CONTROL_ACK, was, held->iss + 1u), 1);
    struct handshake_outcome outcome = receive(&world, &data);

    if (outcome.reason != HANDSHAKE_REASON_THE_DATA_WAS_TAKEN_AND_DISCARDED) {
        fprintf(stderr, "  one octet of data came back as reason %d\n",
                (int)outcome.reason);
        ok = false;
    }
    if (outcome.octets_taken != 1 || world.counts.octets_taken_and_discarded != 1) {
        fprintf(stderr, "  %u octets reported and %lu counted, for one octet sent\n",
                (unsigned)outcome.octets_taken,
                world.counts.octets_taken_and_discarded);
        ok = false;
    }
    /* ⚠ RCV.NXT advanced, which is what taking delivery MEANS. ⚠ Without this
     * the count could move while nothing was actually accepted. */
    if (held->rcv_nxt != was + 1u) {
        fprintf(stderr, "  RCV.NXT is %lu and one octet was taken from %lu\n",
                (unsigned long)held->rcv_nxt, (unsigned long)was);
        ok = false;
    }
    /* ⚠ Not folded in with a segment the state did not expect
     * (hidetzu/tcpip-stack#64 AC 2). */
    if (world.counts.not_expected_in_this_state != 0 ||
        world.counts.data_we_have_taken_already != 0 ||
        world.counts.data_that_begins_too_far_ahead != 0) {
        fputs("  data on an open connection moved somebody else's counter\n", stderr);
        ok = false;
    }
    /* ⚠ And it is acknowledged. ⚠ Until hidetzu/tcpip-stack#74 this asserted
     * that nothing was built — ⚠ **the promise was kept in taking and not in
     * telling**, and this is the telling. */
    if (outcome.reply_bytes == 0 ||
        outcome.reply != HANDSHAKE_REPLY_THE_DATA_IS_ACKNOWLEDGED) {
        fprintf(stderr, "  %zu octets were built for data, of kind %d\n",
                outcome.reply_bytes, (int)outcome.reply);
        ok = false;
    }
    return ok;
}

/* ⚠ RFC 793's seventh step, verbatim: "When the TCP takes responsibility for
 * delivering the data to the user it must also acknowledge the receipt of the
 * data ... Send an acknowledgment of the form:
 * <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>".
 *
 * ⚠ Every field of it, read back by our own parser — ⚠ **reaching OK is what
 * says the checksum agrees.** */
static bool case_the_acknowledgment_for_data_is_the_one_the_document_describes(void)
{
    struct world world;
    a_world(&world);
    struct transmission_control_block *held = NULL;
    if (!open_and_confirm(&world, &held)) {
        return false;
    }
    uint32_t the_octet_sits_at = held->rcv_nxt;
    uint32_t snd_nxt_before = held->snd_nxt;

    bool ok = true;
    struct tcp_header data =
        carrying(a_segment(TCP_CONTROL_ACK, the_octet_sits_at, held->iss + 1u), 1);
    struct handshake_outcome outcome = receive(&world, &data);

    size_t expected = ETHERNET_HEADER_BYTES + IPV4_FIXED_HEADER_BYTES +
                      TCP_FIXED_HEADER_BYTES;
    if (outcome.reply_bytes != expected) {
        fprintf(stderr, "  the acknowledgment is %zu octets and a bare ACK is %zu\n",
                outcome.reply_bytes, expected);
        return false;
    }

    const unsigned char *datagram = world.reply + ETHERNET_HEADER_BYTES;
    struct ipv4_header internet;
    if (ipv4_parse_header(datagram, outcome.reply_bytes - ETHERNET_HEADER_BYTES,
                          &internet) != IPV4_PARSE_OK) {
        fputs("  the internet header of the acknowledgment did not read back\n", stderr);
        return false;
    }
    struct connection_id id = the_connection();
    struct tcp_header ours;
    enum tcp_parse parsed =
        tcp_parse_header(datagram + IPV4_FIXED_HEADER_BYTES,
                         (size_t)internet.total_length - IPV4_FIXED_HEADER_BYTES,
                         id.local.address, id.remote.address, &ours);
    if (parsed != TCP_PARSE_OK) {
        fprintf(stderr, "  the segment we built came back as %d "
                        "(2 would mean its own checksum disagrees)\n", (int)parsed);
        return false;
    }

    /* ⚠ ACK alone: ⚠ **no SYN and no FIN.** ⚠ A build that reused either of the
     * other two segments unchanged would carry one. */
    if (ours.control_bits != TCP_CONTROL_ACK) {
        fprintf(stderr, "  the acknowledgment carries control bits 0x%02x, not ACK\n",
                ours.control_bits);
        ok = false;
    }
    /* ⚠ It acknowledges past the octet by exactly one, ⚠ **asserted against the
     * octet's own sequence number** and not against whatever RCV.NXT is. */
    if (ours.acknowledgment_number != the_octet_sits_at + 1u) {
        fprintf(stderr, "  it acknowledges %lu, and the octet sat at %lu\n",
                (unsigned long)ours.acknowledgment_number,
                (unsigned long)the_octet_sits_at);
        ok = false;
    }
    /* ⚠ And the number reported for it is the same one, so ⚠ **a caller told
     * what we would acknowledge is told what actually went out.** */
    if (outcome.we_would_acknowledge != ours.acknowledgment_number) {
        fprintf(stderr, "  we report acknowledging %lu and the segment carries %lu\n",
                (unsigned long)outcome.we_would_acknowledge,
                (unsigned long)ours.acknowledgment_number);
        ok = false;
    }
    /* ⚠ RFC 793's glossary: an ACK is "A control bit (acknowledge) occupying no
     * sequence space". ⚠ So `SND.NXT` is carried and ⚠ **not moved** — a build
     * that consumed one would break every later segment's numbering. */
    if (ours.sequence_number != snd_nxt_before || held->snd_nxt != snd_nxt_before) {
        fprintf(stderr, "  it sits at %lu and SND.NXT went from %lu to %lu\n",
                (unsigned long)ours.sequence_number, (unsigned long)snd_nxt_before,
                (unsigned long)held->snd_nxt);
        ok = false;
    }
    if (ours.window != HANDSHAKE_WINDOW || ours.data_offset != TCP_HEADER_LENGTH_MINIMUM) {
        fprintf(stderr, "  it carries a window of %u and %u octets of options\n",
                ours.window, (ours.data_offset - TCP_HEADER_LENGTH_MINIMUM) * 4);
        ok = false;
    }
    if (ours.source_port != OUR_PORT || ours.destination_port != THEIR_PORT) {
        fputs("  the acknowledgment's ports are not ours to theirs\n", stderr);
        ok = false;
    }
    if (memcmp(world.reply, THEIR_MAC, ETHERNET_ADDRESS_BYTES) != 0 ||
        memcmp(world.reply + ETHERNET_ADDRESS_BYTES, OUR_MAC, ETHERNET_ADDRESS_BYTES) != 0) {
        fputs("  its ethernet header is not ours to theirs\n", stderr);
        ok = false;
    }
    return ok;
}

/* ⚠ **Data the window did not cover is never acknowledged AS TAKEN**, so the
 * change cannot pass for a stack that claims everything that arrives.
 *
 * ⚠ Until hidetzu/tcpip-stack#80 this asserted that nothing was built at all.
 * ⚠ **Something is built now** — the acknowledgment the document describes for
 * an unacceptable segment — ⚠ **and the case's real subject is unchanged: we do
 * not pretend to have taken it.** ⚠ `RCV.NXT` does not move
 * and the segment is not the one that accepts data. */
static bool case_nothing_is_acknowledged_for_data_the_window_did_not_cover(void)
{
    bool ok = true;

    /* ⚠ Behind us: taken already. */
    {
        struct world world;
        a_world(&world);
        struct transmission_control_block *held = NULL;
        if (!open_and_confirm(&world, &held)) {
            return false;
        }
        struct tcp_header first =
            carrying(a_segment(TCP_CONTROL_ACK, held->rcv_nxt, held->iss + 1u), 1);
        (void)receive(&world, &first);
        uint32_t was = held->rcv_nxt;
        struct handshake_outcome again = receive(&world, &first);
        if (again.reply != HANDSHAKE_REPLY_WHERE_WE_ARE || held->rcv_nxt != was ||
            again.octets_taken != 0) {
            fprintf(stderr, "  an octet taken already drew a reply of kind %d and "
                            "moved RCV.NXT by %lu\n",
                    (int)again.reply, (unsigned long)(held->rcv_nxt - was));
            ok = false;
        }
    }

    /* ⚠ Past the window: it begins beyond what we asked for. */
    {
        struct world world;
        a_world(&world);
        struct transmission_control_block *held = NULL;
        if (!open_and_confirm(&world, &held)) {
            return false;
        }
        uint32_t was = held->rcv_nxt;
        struct tcp_header ahead =
            carrying(a_segment(TCP_CONTROL_ACK, was + 4096u, held->iss + 1u), 1);
        struct handshake_outcome outcome = receive(&world, &ahead);
        if (outcome.reply != HANDSHAKE_REPLY_WHERE_WE_ARE || held->rcv_nxt != was ||
            outcome.octets_taken != 0) {
            fprintf(stderr, "  data past the window drew a reply of kind %d and moved "
                            "RCV.NXT by %lu\n",
                    (int)outcome.reply, (unsigned long)(held->rcv_nxt - was));
            ok = false;
        }
    }

    /* ⚠ The other half: the same connection, an octet the window DOES cover,
     * ⚠ **is acknowledged** — so this case is about which data and not about
     * data at all. */
    {
        struct world world;
        a_world(&world);
        struct transmission_control_block *held = NULL;
        if (!open_and_confirm(&world, &held)) {
            return false;
        }
        struct tcp_header good =
            carrying(a_segment(TCP_CONTROL_ACK, held->rcv_nxt, held->iss + 1u), 1);
        struct handshake_outcome outcome = receive(&world, &good);
        if (outcome.reply != HANDSHAKE_REPLY_THE_DATA_IS_ACKNOWLEDGED) {
            fprintf(stderr, "  an octet inside the window was not acknowledged: kind %d\n",
                    (int)outcome.reply);
            ok = false;
        }
    }
    return ok;
}

/* ⚠ hidetzu/tcpip-stack#80. ⚠ **A segment we refuse draws an acknowledgment**,
 * and ⚠ **it says where we are without accepting anything.**
 *
 * ⚠ Verbatim, RFC 9293 §3.10.7.4: "If an incoming segment is not acceptable, an
 * acknowledgment should be sent in reply ... <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>."
 * ⚠ **Lowercase "should", so not a BCP 14 requirement** (§2) — ⚠ the grounds for
 * doing it are the measurement in `tests/foreign.sh`
 * `a_peer_whose_acknowledgment_was_lost_recovers`, not the sentence."
 *
 * ⚠ All four ways to be refused, and ⚠ **the numbers are asserted, not just the
 * fact that something came back.** */
static bool case_a_segment_we_refuse_draws_an_acknowledgment(void)
{
    static const struct { const char *what; bool a_fin; bool ahead; } ways[] = {
        { "data we have taken already", false, false },
        { "data that begins too far ahead", false, true },
        { "a FIN we have read already", true, false },
        { "a FIN that begins too far ahead", true, true },
    };

    bool ok = true;
    for (size_t i = 0; i < sizeof ways / sizeof ways[0]; i++) {
        struct world world;
        a_world(&world);
        struct transmission_control_block *held = NULL;
        if (!open_and_confirm(&world, &held)) {
            return false;
        }
        /* ⚠ Two octets taken first, so ⚠ **`RCV.NXT` is somewhere a wrong
         * acknowledgment could not reach by accident.** */
        struct tcp_header some =
            carrying(a_segment(TCP_CONTROL_ACK, held->rcv_nxt, held->iss + 1u), 2);
        if (receive(&world, &some).octets_taken != 2) {
            fputs("  the first two octets were not taken\n", stderr);
            return false;
        }
        uint32_t where_we_are = held->rcv_nxt;
        uint32_t snd_nxt_before = held->snd_nxt;

        uint32_t sits_at = ways[i].ahead ? where_we_are + 500u : where_we_are - 2u;
        unsigned bits = TCP_CONTROL_ACK | (ways[i].a_fin ? TCP_CONTROL_FIN : 0u);
        struct tcp_header refused =
            carrying(a_segment(bits, sits_at, held->iss + 1u), ways[i].a_fin ? 0 : 2);
        struct handshake_outcome outcome = receive(&world, &refused);

        if (outcome.reply != HANDSHAKE_REPLY_WHERE_WE_ARE || outcome.reply_bytes == 0) {
            fprintf(stderr, "  %s drew a reply of kind %d\n", ways[i].what,
                    (int)outcome.reply);
            ok = false;
            continue;
        }
        /* ⚠ It accepted nothing: `RCV.NXT` where it was, `SND.NXT` where it was
         * — ⚠ **an ACK occupies no sequence space.** */
        if (held->rcv_nxt != where_we_are || held->snd_nxt != snd_nxt_before ||
            outcome.octets_taken != 0 || outcome.the_fin_was_read) {
            fprintf(stderr, "  %s moved something: RCV.NXT %lu of %lu, SND.NXT %lu\n",
                    ways[i].what, (unsigned long)held->rcv_nxt,
                    (unsigned long)where_we_are, (unsigned long)held->snd_nxt);
            ok = false;
            continue;
        }

        const unsigned char *datagram = world.reply + ETHERNET_HEADER_BYTES;
        struct ipv4_header internet;
        struct connection_id id = the_connection();
        struct tcp_header ours;
        if (ipv4_parse_header(datagram, outcome.reply_bytes - ETHERNET_HEADER_BYTES,
                              &internet) != IPV4_PARSE_OK ||
            tcp_parse_header(datagram + IPV4_FIXED_HEADER_BYTES,
                             (size_t)internet.total_length - IPV4_FIXED_HEADER_BYTES,
                             id.local.address, id.remote.address, &ours) != TCP_PARSE_OK) {
            fprintf(stderr, "  what we built for %s did not read back\n", ways[i].what);
            ok = false;
            continue;
        }
        /* ⚠ `<SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>`, every field of it. */
        if (ours.control_bits != TCP_CONTROL_ACK ||
            ours.sequence_number != snd_nxt_before ||
            ours.acknowledgment_number != where_we_are) {
            fprintf(stderr, "  for %s we sent bits 0x%02x seq %lu ack %lu, and SND.NXT "
                            "is %lu with RCV.NXT %lu\n",
                    ways[i].what, ours.control_bits,
                    (unsigned long)ours.sequence_number,
                    (unsigned long)ours.acknowledgment_number,
                    (unsigned long)snd_nxt_before, (unsigned long)where_we_are);
            ok = false;
        }
    }
    return ok;
}

/* ⚠ AC 4. ⚠ **Nothing draws one that should not.** ⚠ Without this, "we answer a
 * refused segment" would pass for a stack that answers everything. */
static bool case_only_a_refused_data_segment_or_fin_draws_one(void)
{
    bool ok = true;

    /* ⚠ A segment carrying no data and no FIN: ⚠ **nothing the sequence check
     * ever looked at**, so nothing to say where we are about. */
    {
        struct world world;
        a_world(&world);
        struct transmission_control_block *held = NULL;
        if (!open_and_confirm(&world, &held)) {
            return false;
        }
        struct tcp_header bare = a_segment(TCP_CONTROL_ACK, held->rcv_nxt, held->iss + 1u);
        struct handshake_outcome outcome = receive(&world, &bare);
        if (outcome.reply != HANDSHAKE_REPLY_NONE || outcome.reply_bytes != 0) {
            fprintf(stderr, "  a bare acknowledgment drew a reply of kind %d\n",
                    (int)outcome.reply);
            ok = false;
        }
    }

    /* ⚠ A connection we hold nothing for. ⚠ RFC 793: "Do not process the FIN if
     * the state is CLOSED, LISTEN or SYN-SENT since the SEG.SEQ cannot be
     * validated" — ⚠ **and an acknowledgment carrying RCV.NXT would need one to
     * carry.** */
    {
        struct world world;
        a_world(&world);
        struct tcp_header fin =
            a_segment(TCP_CONTROL_FIN | TCP_CONTROL_ACK, THEIR_ISN, 1);
        struct handshake_outcome outcome = receive(&world, &fin);
        if (outcome.reply != HANDSHAKE_REPLY_NONE || outcome.reply_bytes != 0) {
            fprintf(stderr, "  a FIN with nothing held drew a reply of kind %d\n",
                    (int)outcome.reply);
            ok = false;
        }
    }

    /* ⚠ The other half: ⚠ **a refused segment on a connection we do hold still
     * draws one**, so this case is about which and not about refusing to
     * answer at all. */
    {
        struct world world;
        a_world(&world);
        struct transmission_control_block *held = NULL;
        if (!open_and_confirm(&world, &held)) {
            return false;
        }
        struct tcp_header ahead =
            carrying(a_segment(TCP_CONTROL_ACK, held->rcv_nxt + 9u, held->iss + 1u), 1);
        if (receive(&world, &ahead).reply != HANDSHAKE_REPLY_WHERE_WE_ARE) {
            fputs("  a refused segment on a held connection drew nothing\n", stderr);
            ok = false;
        }
    }
    return ok;
}

/* ⚠ Ours, not the sender's: the acknowledgment could not be built into the
 * buffer we were given.
 *
 * ⚠ **The octets stay taken and `RCV.NXT` stays moved.** ⚠ Giving them back is
 * not possible — ⚠ they were discarded — so ⚠ **pretending they never arrived
 * would be the lie**, and the failure is reported as ours instead. */
static bool case_an_acknowledgment_that_would_not_fit_is_counted_as_ours(void)
{
    struct world world;
    a_world(&world);
    struct transmission_control_block *held = NULL;
    if (!open_and_confirm(&world, &held)) {
        return false;
    }
    uint32_t was = held->rcv_nxt;

    bool ok = true;
    unsigned char no_room[ETHERNET_HEADER_BYTES + IPV4_FIXED_HEADER_BYTES];
    struct connection_id id = the_connection();
    struct tcp_header data =
        carrying(a_segment(TCP_CONTROL_ACK, was, held->iss + 1u), 1);
    struct handshake_outcome outcome;
    handshake_receive(&data, &id, OUR_PORT, at(0), IPV4_TIME_TO_LIVE_WE_SEND, THEIR_MAC, OUR_MAC, &world.connections,
                      no_room, sizeof no_room, &world.counts, &outcome);

    if (outcome.reason != HANDSHAKE_REASON_WE_COULD_NOT_BUILD_THE_REPLY ||
        world.counts.we_could_not_build_the_reply != 1) {
        fprintf(stderr, "  an acknowledgment that would not fit came back as reason %d\n",
                (int)outcome.reason);
        ok = false;
    }
    if (outcome.reply_bytes != 0 || outcome.reply != HANDSHAKE_REPLY_NONE) {
        fprintf(stderr, "  %zu octets were reported for one that would not fit\n",
                outcome.reply_bytes);
        ok = false;
    }
    /* ⚠ The octet was taken all the same, and it is counted. */
    if (outcome.octets_taken != 1 || world.counts.octets_taken_and_discarded != 1 ||
        held->rcv_nxt != was + 1u) {
        fprintf(stderr, "  the octet was un-taken: %u reported, RCV.NXT %lu from %lu\n",
                (unsigned)outcome.octets_taken, (unsigned long)held->rcv_nxt,
                (unsigned long)was);
        ok = false;
    }
    return ok;
}

/* ⚠ Data none of which the window covers, both ways it can happen. */
static bool case_data_outside_the_window_is_refused_and_nothing_moves(void)
{
    bool ok = true;

    /* ⚠ Behind us: every octet has been taken already. */
    {
        struct world world;
        a_world(&world);
        struct transmission_control_block *held = NULL;
        if (!open_and_confirm(&world, &held)) {
            return false;
        }
        struct tcp_header first =
            carrying(a_segment(TCP_CONTROL_ACK, held->rcv_nxt, held->iss + 1u), 1);
        (void)receive(&world, &first);
        uint32_t was = held->rcv_nxt;

        struct handshake_outcome outcome = receive(&world, &first);
        /* ⚠ Its own answer since hidetzu/tcpip-stack#76: ⚠ **we have had it**,
         * not "either we have had it or it is ahead". */
        if (outcome.reason != HANDSHAKE_REASON_DATA_WE_HAVE_TAKEN_ALREADY ||
            world.counts.data_we_have_taken_already != 1 ||
            world.counts.data_that_begins_too_far_ahead != 0) {
            fprintf(stderr, "  the same octet again came back as reason %d\n",
                    (int)outcome.reason);
            ok = false;
        }
        if (outcome.octets_taken != 0 || held->rcv_nxt != was ||
            world.counts.octets_taken_and_discarded != 1) {
            fprintf(stderr, "  the same octet was taken twice: %lu counted\n",
                    world.counts.octets_taken_and_discarded);
            ok = false;
        }
    }

    /* ⚠ Past the window: it begins beyond what we asked for. ⚠ RFC 793 would
     * hold it for later; ⚠ **nothing here holds anything** (`docs/SPEC.md` §2). */
    {
        struct world world;
        a_world(&world);
        struct transmission_control_block *held = NULL;
        if (!open_and_confirm(&world, &held)) {
            return false;
        }
        uint32_t was = held->rcv_nxt;
        struct tcp_header ahead =
            carrying(a_segment(TCP_CONTROL_ACK, was + 4096u, held->iss + 1u), 1);
        struct handshake_outcome outcome = receive(&world, &ahead);
        /* ⚠ The other answer, and ⚠ **the two do not share a counter.** */
        if (outcome.reason != HANDSHAKE_REASON_DATA_THAT_BEGINS_TOO_FAR_AHEAD ||
            world.counts.data_that_begins_too_far_ahead != 1 ||
            world.counts.data_we_have_taken_already != 0 ||
            outcome.octets_taken != 0 || held->rcv_nxt != was ||
            world.counts.octets_taken_and_discarded != 0) {
            fprintf(stderr, "  data beginning past the window came back as reason %d, "
                            "%lu already-had and %lu too-far-ahead\n",
                    (int)outcome.reason, world.counts.data_we_have_taken_already,
                    world.counts.data_that_begins_too_far_ahead);
            ok = false;
        }
    }
    return ok;
}

/* ⚠ A segment longer than the window is trimmed, not refused and not swallowed
 * whole. ⚠ RFC 793: "if the segment contains data that begins outside the
 * window, that data is trimmed."
 *
 * ⚠ This is what stops the window being a number that means nothing:
 * ⚠ **a segment carrying more than we asked for must move RCV.NXT by exactly
 * what we asked for.**
 *
 * ⚠ **A peer that honours our window does not send such a segment** — measured
 * 2026-08-29, it sends what the window allows and waits (`tests/foreign.sh`
 * `the_peers_send_queue_drains_once_we_acknowledge`). ⚠ The case stays, and it
 * is not weaker for it: ⚠ **it tests the contract, not one peer's habits**
 * (`.claude/rules/testing.md`), and ⚠ **a peer that sends past what we asked
 * for is exactly the hostile input the trimming exists for.** */
static bool case_a_segment_longer_than_the_window_is_taken_a_window_at_a_time(void)
{
    struct world world;
    a_world(&world);
    struct transmission_control_block *held = NULL;
    if (!open_and_confirm(&world, &held)) {
        return false;
    }
    uint32_t began_at = held->rcv_nxt;

    bool ok = true;
    /* ⚠ Two windows' worth and a bit, ⚠ **written from the constant** so this
     * follows the number rather than pinning a value of its own. */
    size_t too_much = (size_t)HANDSHAKE_WINDOW * 2u + 7u;
    struct tcp_header oversized =
        carrying(a_segment(TCP_CONTROL_ACK, began_at, held->iss + 1u), too_much);

    /* ⚠ The same segment arriving three times: ⚠ **a window's worth each time**
     * until what is left is smaller than the window. */
    for (unsigned arrival = 1; arrival <= 2; arrival++) {
        struct handshake_outcome outcome = receive(&world, &oversized);
        if (outcome.octets_taken != HANDSHAKE_WINDOW) {
            fprintf(stderr, "  arrival %u of %zu octets took %u, not %u\n",
                    arrival, too_much, (unsigned)outcome.octets_taken,
                    (unsigned)HANDSHAKE_WINDOW);
            ok = false;
        }
        if (held->rcv_nxt != began_at + arrival * HANDSHAKE_WINDOW) {
            fprintf(stderr, "  after arrival %u RCV.NXT had moved by %lu\n", arrival,
                    (unsigned long)(held->rcv_nxt - began_at));
            ok = false;
        }
    }
    /* ⚠ The tail: fewer octets left than the window, ⚠ **so all of them go** —
     * a build that always took exactly the window would take too many. */
    struct handshake_outcome tail = receive(&world, &oversized);
    if (tail.octets_taken != 7 || held->rcv_nxt != began_at + too_much) {
        fprintf(stderr, "  the tail took %u octets and RCV.NXT moved by %lu of %zu\n",
                (unsigned)tail.octets_taken, (unsigned long)(held->rcv_nxt - began_at),
                too_much);
        ok = false;
    }
    if (world.counts.octets_taken_and_discarded != too_much) {
        fprintf(stderr, "  %lu octets were counted for %zu sent three times\n",
                world.counts.octets_taken_and_discarded, too_much);
        ok = false;
    }
    /* ⚠ A fourth arrival is entirely behind us now. */
    struct handshake_outcome again = receive(&world, &oversized);
    if (again.reason != HANDSHAKE_REASON_DATA_WE_HAVE_TAKEN_ALREADY ||
        world.counts.octets_taken_and_discarded != too_much) {
        fprintf(stderr, "  a fourth arrival took more: reason %d, %lu counted\n",
                (int)again.reason, world.counts.octets_taken_and_discarded);
        ok = false;
    }
    return ok;
}

/* ⚠ The acknowledgment that opens the connection may carry data. ⚠ The
 * transition is what is reported, and ⚠ **the octets are still counted** —
 * otherwise a payload would vanish exactly where nobody looks. */
static bool case_data_riding_the_acknowledgment_that_opens_it_is_counted(void)
{
    struct world world;
    a_world(&world);
    struct transmission_control_block *held = NULL;
    if (!open_one(&world, THEIR_ISN, &held)) {
        return false;
    }
    uint32_t was = held->rcv_nxt;

    bool ok = true;
    struct tcp_header ack =
        carrying(a_segment(TCP_CONTROL_ACK, was, held->iss + 1u), 1);
    struct handshake_outcome outcome = receive(&world, &ack);

    if (outcome.decision != HANDSHAKE_MOVED ||
        outcome.state != CONNECTION_ESTABLISHED ||
        world.counts.established != 1) {
        fprintf(stderr, "  an acknowledgment carrying data did not open it: state %d\n",
                (int)outcome.state);
        ok = false;
    }
    if (outcome.octets_taken != 1 || world.counts.octets_taken_and_discarded != 1 ||
        held->rcv_nxt != was + 1u) {
        fprintf(stderr, "  the octet it carried was not taken: %u reported, %lu counted\n",
                (unsigned)outcome.octets_taken,
                world.counts.octets_taken_and_discarded);
        ok = false;
    }
    return ok;
}

/* ⚠ A segment carrying no data and no FIN is still nothing this state has a
 * rule for. ⚠ Without this, opening the window could quietly swallow one.
 *
 * ⚠ Until hidetzu/tcpip-stack#65 this fed a FIN, ⚠ **because a FIN was then
 * nothing this state had a rule for either.** ⚠ It has one now, and the case
 * feeds a bare acknowledgment instead — ⚠ **the assertion did not weaken, its
 * subject moved.** */
static bool case_a_segment_carrying_no_data_is_still_not_expected(void)
{
    struct world world;
    a_world(&world);
    struct transmission_control_block *held = NULL;
    if (!open_and_confirm(&world, &held)) {
        return false;
    }
    uint32_t was = held->rcv_nxt;

    bool ok = true;
    struct tcp_header bare = a_segment(TCP_CONTROL_ACK, was, held->iss + 1u);
    struct handshake_outcome outcome = receive(&world, &bare);
    if (outcome.reason != HANDSHAKE_REASON_NOT_EXPECTED_IN_THIS_STATE ||
        world.counts.not_expected_in_this_state != 1) {
        fprintf(stderr, "  a bare acknowledgment came back as reason %d\n",
                (int)outcome.reason);
        ok = false;
    }
    if (outcome.octets_taken != 0 || held->rcv_nxt != was ||
        world.counts.octets_taken_and_discarded != 0) {
        fputs("  a segment carrying nothing moved RCV.NXT or the octet count\n", stderr);
        ok = false;
    }
    return ok;
}

/* ⚠ RFC 793's eighth step, for ESTABLISHED: "Enter the CLOSE-WAIT state", after
 * "advance RCV.NXT over the FIN".
 *
 * ⚠ Both halves asserted: ⚠ **the state's name, and the number we would
 * acknowledge** — off by one there is the error that still looks like it
 * works.
 *
 * ⚠ Until hidetzu/tcpip-stack#66 this ended in `CLOSE-WAIT` and asserted that
 * nothing was built. ⚠ **It ends in `LAST-ACK` now and a segment IS built**,
 * because ADR 0022 made the FIN's arrival the CLOSE — ⚠ so the same pass goes
 * on to RFC 793's CLOSE Call. ⚠ **The assertions did not weaken; the state
 * machine moved on.** */
static bool case_a_fin_moves_the_connection_to_close_wait(void)
{
    struct world world;
    a_world(&world);
    struct transmission_control_block *held = NULL;
    if (!open_and_confirm(&world, &held)) {
        return false;
    }
    uint32_t the_fins_sequence_number = held->rcv_nxt;

    bool ok = true;
    struct tcp_header fin =
        a_segment(TCP_CONTROL_FIN | TCP_CONTROL_ACK, the_fins_sequence_number,
                  held->iss + 1u);
    struct handshake_outcome outcome = receive(&world, &fin);

    if (outcome.decision != HANDSHAKE_MOVED ||
        outcome.state != CONNECTION_LAST_ACK ||
        held->state != CONNECTION_LAST_ACK) {
        fprintf(stderr, "  a FIN left the connection in state %d\n",
                (int)outcome.state);
        ok = false;
    }
    if (!outcome.the_fin_was_read || world.counts.the_other_side_closed != 1) {
        fprintf(stderr, "  the FIN was not counted: read %d, counted %lu\n",
                (int)outcome.the_fin_was_read, world.counts.the_other_side_closed);
        ok = false;
    }
    /* ⚠ RFC 793's glossary: a FIN is "A control bit (finis) occupying one
     * sequence number". ⚠ Exactly one, and ⚠ **asserted against the FIN's own
     * sequence number rather than against whatever RCV.NXT happens to be**, so
     * a helper that moved it twice would show. */
    if (held->rcv_nxt != the_fins_sequence_number + 1u ||
        outcome.we_would_acknowledge != the_fins_sequence_number + 1u) {
        fprintf(stderr, "  RCV.NXT is %lu and we would acknowledge %lu, for a FIN at %lu\n",
                (unsigned long)held->rcv_nxt,
                (unsigned long)outcome.we_would_acknowledge,
                (unsigned long)the_fins_sequence_number);
        ok = false;
    }
    /* ⚠ And a segment was built for it, and it is ours and not the answer. */
    if (outcome.reply_bytes == 0 || outcome.reply != HANDSHAKE_REPLY_OUR_FIN) {
        fprintf(stderr, "  %zu octets were built for a FIN, of kind %d\n",
                outcome.reply_bytes, (int)outcome.reply);
        ok = false;
    }
    return ok;
}

/* ⚠ RFC 793: "the FIN is considered to occur after the last actual data octet
 * in a segment in which it occurs."
 *
 * ⚠ So a FIN riding one octet sits one past that octet, and ⚠ **RCV.NXT ends
 * two past where the segment began.** ⚠ This is the off-by-one AC 2 names. */
static bool case_a_fin_sits_after_the_data_it_rides_with(void)
{
    struct world world;
    a_world(&world);
    struct transmission_control_block *held = NULL;
    if (!open_and_confirm(&world, &held)) {
        return false;
    }
    uint32_t began_at = held->rcv_nxt;

    bool ok = true;
    struct tcp_header fin_with_data =
        carrying(a_segment(TCP_CONTROL_FIN | TCP_CONTROL_ACK, began_at, held->iss + 1u), 1);
    struct handshake_outcome outcome = receive(&world, &fin_with_data);

    if (outcome.state != CONNECTION_LAST_ACK || !outcome.the_fin_was_read) {
        fprintf(stderr, "  a FIN riding one octet left state %d\n", (int)outcome.state);
        ok = false;
    }
    if (outcome.octets_taken != 1 || world.counts.octets_taken_and_discarded != 1) {
        fprintf(stderr, "  the octet it rode with was not taken: %u\n",
                (unsigned)outcome.octets_taken);
        ok = false;
    }
    /* ⚠ One for the octet and one for the FIN. ⚠ A build that read the FIN
     * before the data would land one short here. */
    if (held->rcv_nxt != began_at + 2u ||
        outcome.we_would_acknowledge != began_at + 2u) {
        fprintf(stderr, "  RCV.NXT moved by %lu for one octet and a FIN\n",
                (unsigned long)(held->rcv_nxt - began_at));
        ok = false;
    }

    /* ⚠ The other half: a FIN riding MORE octets than the window covers is not
     * read, because ⚠ **it sits past what we asked for** — and reading it would
     * acknowledge data we never took.
     *
     * ⚠ Written from the constant, ⚠ **so this follows the window rather than
     * pinning a length of its own.** */
    struct world second;
    a_world(&second);
    struct transmission_control_block *other = NULL;
    if (!open_and_confirm(&second, &other)) {
        return false;
    }
    uint32_t from = other->rcv_nxt;
    size_t past_it = (size_t)HANDSHAKE_WINDOW + 2u;
    struct tcp_header fin_with_more =
        carrying(a_segment(TCP_CONTROL_FIN | TCP_CONTROL_ACK, from, other->iss + 1u),
                 past_it);
    struct handshake_outcome refused = receive(&second, &fin_with_more);
    /* ⚠ **Too far ahead**, not "already read": the data before it was trimmed
     * away, so the FIN sits past what we took (hidetzu/tcpip-stack#76). */
    if (refused.reason != HANDSHAKE_REASON_A_FIN_THAT_BEGINS_TOO_FAR_AHEAD ||
        refused.the_fin_was_read || other->state != CONNECTION_ESTABLISHED) {
        fprintf(stderr, "  a FIN riding %zu octets came back as reason %d, state %d\n",
                past_it, (int)refused.reason, (int)other->state);
        ok = false;
    }
    /* ⚠ The octets the window did cover were still taken. */
    if (other->rcv_nxt != from + HANDSHAKE_WINDOW) {
        fprintf(stderr, "  RCV.NXT moved by %lu when %u octets fit\n",
                (unsigned long)(other->rcv_nxt - from), (unsigned)HANDSHAKE_WINDOW);
        ok = false;
    }
    return ok;
}

/* ⚠ The measured case, and it is the common one: ⚠ **nothing acknowledges the
 * FIN, so the peer sends it again.** ⚠ Five times in one `close()`, measured
 * 2026-08-29.
 *
 * ⚠ RCV.NXT has moved over the first one, so every later copy is behind the
 * window. ⚠ Counted apart, and ⚠ **the connection does not close twice.** */
static bool case_a_fin_we_have_already_read_is_not_read_again(void)
{
    struct world world;
    a_world(&world);
    struct transmission_control_block *held = NULL;
    if (!open_and_confirm(&world, &held)) {
        return false;
    }

    bool ok = true;
    struct tcp_header fin =
        a_segment(TCP_CONTROL_FIN | TCP_CONTROL_ACK, held->rcv_nxt, held->iss + 1u);
    (void)receive(&world, &fin);
    uint32_t after_the_first = held->rcv_nxt;

    for (unsigned again = 1; again <= 4; again++) {
        struct handshake_outcome outcome = receive(&world, &fin);
        if (outcome.reason != HANDSHAKE_REASON_A_FIN_WE_HAVE_READ_ALREADY) {
            fprintf(stderr, "  retransmission %u came back as reason %d\n", again,
                    (int)outcome.reason);
            ok = false;
        }
        if (outcome.the_fin_was_read) {
            fprintf(stderr, "  retransmission %u was read as a new FIN\n", again);
            ok = false;
        }
    }
    if (world.counts.the_other_side_closed != 1 ||
        world.counts.fin_we_have_read_already != 4 ||
        world.counts.fin_that_begins_too_far_ahead != 0) {
        fprintf(stderr, "  one FIN and four copies were counted %lu and %lu\n",
                world.counts.the_other_side_closed,
                world.counts.fin_we_have_read_already);
        ok = false;
    }
    if (held->rcv_nxt != after_the_first || held->state != CONNECTION_LAST_ACK) {
        fputs("  a retransmitted FIN moved RCV.NXT again\n", stderr);
        ok = false;
    }
    /* ⚠ And nothing else moved: not the reason a state has no rule for a
     * segment, and not the count of connections that reached open. */
    if (world.counts.not_expected_in_this_state != 0 || world.counts.established != 1) {
        fputs("  a retransmitted FIN moved somebody else's counter\n", stderr);
        ok = false;
    }
    return ok;
}

/* ⚠ RFC 793: "Do not process the FIN if the state is CLOSED, LISTEN or SYN-SENT
 * since the SEG.SEQ cannot be validated; drop the segment and return."
 *
 * ⚠ Holding nothing is our LISTEN. ⚠ Counted apart from every other stray
 * segment, because ⚠ **the document gives it its own reason.** */
static bool case_a_fin_naming_no_connection_we_hold_is_its_own_outcome(void)
{
    struct world world;
    a_world(&world);

    bool ok = true;
    struct tcp_header fin =
        a_segment(TCP_CONTROL_FIN | TCP_CONTROL_ACK, THEIR_ISN, 1);
    struct handshake_outcome outcome = receive(&world, &fin);

    if (outcome.reason != HANDSHAKE_REASON_A_FIN_WE_CANNOT_PLACE ||
        world.counts.fin_we_could_not_place != 1) {
        fprintf(stderr, "  a FIN with nothing held came back as reason %d\n",
                (int)outcome.reason);
        ok = false;
    }
    /* ⚠ Not folded in with an acknowledgment arriving for no connection we
     * hold, and ⚠ **not counted as a connection closing.** */
    if (world.counts.no_connection_held != 0 ||
        world.counts.the_other_side_closed != 0) {
        fputs("  a FIN with nothing held moved somebody else's counter\n", stderr);
        ok = false;
    }
    /* ⚠ The other half: a bare acknowledgment with nothing held still lands on
     * its own reason, so this is about the FIN and not about the branch. */
    struct world second;
    a_world(&second);
    struct tcp_header ack = a_segment(TCP_CONTROL_ACK, THEIR_ISN, 1);
    struct handshake_outcome other = receive(&second, &ack);
    if (other.reason != HANDSHAKE_REASON_NO_CONNECTION_HELD ||
        second.counts.no_connection_held != 1) {
        fprintf(stderr, "  an acknowledgment with nothing held came back as reason %d\n",
                (int)other.reason);
        ok = false;
    }
    return ok;
}

/* ⚠ RFC 793: "if the ACK bit is off drop the segment and return" — the fifth
 * step, ⚠ **before the FIN is ever looked at.**
 *
 * ⚠ So a FIN with no acknowledgment closes nothing. ⚠ That is the document's
 * rule and not ours, and ⚠ **without this the two could not be told apart.** */
static bool case_a_fin_with_no_acknowledgment_closes_nothing(void)
{
    struct world world;
    a_world(&world);
    struct transmission_control_block *held = NULL;
    if (!open_and_confirm(&world, &held)) {
        return false;
    }
    uint32_t was = held->rcv_nxt;

    bool ok = true;
    struct tcp_header fin = a_segment(TCP_CONTROL_FIN, was, 0);
    struct handshake_outcome outcome = receive(&world, &fin);
    if (outcome.reason != HANDSHAKE_REASON_NOT_EXPECTED_IN_THIS_STATE ||
        outcome.the_fin_was_read || held->state != CONNECTION_ESTABLISHED ||
        held->rcv_nxt != was || world.counts.the_other_side_closed != 0) {
        fprintf(stderr, "  a FIN with no acknowledgment came back as reason %d, state %d\n",
                (int)outcome.reason, (int)held->state);
        ok = false;
    }
    return ok;
}

/* ⚠ RFC 793 for SYN-RECEIVED: "If SND.UNA =< SEG.ACK =< SND.NXT then enter
 * ESTABLISHED state and continue processing" — ⚠ **and the FIN check is one of
 * the steps that continue.**
 *
 * ⚠ So one segment can open a connection and close it. ⚠ Never observed here —
 * the Linux kernel sends its acknowledgment and its FIN apart — ⚠ **but the
 * document says it, and a reason cannot say two things, so both counters
 * move.** */
static bool case_one_segment_can_open_a_connection_and_close_it(void)
{
    struct world world;
    a_world(&world);
    struct transmission_control_block *held = NULL;
    if (!open_one(&world, THEIR_ISN, &held)) {
        return false;
    }
    uint32_t the_fins_sequence_number = held->rcv_nxt;

    bool ok = true;
    struct tcp_header both =
        a_segment(TCP_CONTROL_FIN | TCP_CONTROL_ACK, the_fins_sequence_number,
                  held->iss + 1u);
    struct handshake_outcome outcome = receive(&world, &both);

    if (outcome.decision != HANDSHAKE_MOVED ||
        outcome.state != CONNECTION_LAST_ACK) {
        fprintf(stderr, "  one segment carrying both left state %d\n",
                (int)outcome.state);
        ok = false;
    }
    /* ⚠ Both, and ⚠ **neither instead of the other**: a connection did reach
     * open, and a side did close. */
    if (world.counts.established != 1 || world.counts.the_other_side_closed != 1) {
        fprintf(stderr, "  reached open %lu, closed %lu\n", world.counts.established,
                world.counts.the_other_side_closed);
        ok = false;
    }
    if (held->rcv_nxt != the_fins_sequence_number + 1u) {
        fprintf(stderr, "  RCV.NXT is %lu for a FIN at %lu\n",
                (unsigned long)held->rcv_nxt,
                (unsigned long)the_fins_sequence_number);
        ok = false;
    }
    return ok;
}

/* ⚠ AC 4, the same shape hidetzu/tcpip-stack#43 asserted for the acknowledgment
 * window: ⚠ **the arithmetic must hold where the 32-bit space wraps.**
 *
 * ⚠ A plain `<` would be correct for years and then wrong once, here. */
static bool case_a_fin_is_read_where_the_sequence_space_wraps(void)
{
    struct world world;
    a_world(&world);
    /* ⚠ Their SYN carries 0xffffffff, so RCV.NXT is 0 and the FIN sits at 0 —
     * ⚠ **the wrap falls between the SYN and the FIN.** */
    struct transmission_control_block *held = NULL;
    if (!open_one(&world, 0xffffffffu, &held)) {
        return false;
    }
    struct tcp_header ack = a_segment(TCP_CONTROL_ACK, 0u, held->iss + 1u);
    if (receive(&world, &ack).state != CONNECTION_ESTABLISHED) {
        fputs("  the connection did not reach ESTABLISHED at the wrap\n", stderr);
        return false;
    }

    bool ok = true;
    if (held->rcv_nxt != 0u) {
        fprintf(stderr, "  RCV.NXT is %lu after a SYN at 0xffffffff\n",
                (unsigned long)held->rcv_nxt);
        ok = false;
    }
    struct tcp_header fin = a_segment(TCP_CONTROL_FIN | TCP_CONTROL_ACK, 0u,
                                      held->iss + 1u);
    struct handshake_outcome outcome = receive(&world, &fin);
    if (outcome.state != CONNECTION_LAST_ACK || !outcome.the_fin_was_read ||
        held->rcv_nxt != 1u) {
        fprintf(stderr, "  a FIN at 0 across the wrap: state %d, RCV.NXT %lu\n",
                (int)outcome.state, (unsigned long)held->rcv_nxt);
        ok = false;
    }

    /* ⚠ The other half: ⚠ **the FIN we already read, at 0xffffffff, is behind us
     * across the wrap** and must not be read again. */
    struct tcp_header behind = a_segment(TCP_CONTROL_FIN | TCP_CONTROL_ACK,
                                         0xffffffffu, held->iss + 1u);
    struct handshake_outcome refused = receive(&world, &behind);
    if (refused.reason != HANDSHAKE_REASON_A_FIN_WE_HAVE_READ_ALREADY ||
        refused.the_fin_was_read || held->rcv_nxt != 1u) {
        fprintf(stderr, "  a FIN at 0xffffffff was read again: reason %d, RCV.NXT %lu\n",
                (int)refused.reason, (unsigned long)held->rcv_nxt);
        ok = false;
    }

    /* ⚠ `RCV.NXT` sitting at 0xffffffff, with the FIN exactly on it.
     *
     * ⚠ This half was written for a window comparison that ⚠ **no longer
     * exists**: until hidetzu/tcpip-stack#75 the FIN was accepted anywhere
     * inside the window, and ⚠ **with `RCV.NXT` at 0xffffffff the window's far
     * edge wraps to 0**, which a plain `far <= where` got wrong.
     *
     * ⚠ **The test is equality now** — a FIN is read only where everything
     * before it was taken — and ⚠ **equality has no wrap to get wrong.**
     * ⚠ The case stays because ⚠ **it is still the only one that puts `RCV.NXT`
     * at the last number in the space**, and a build that added arithmetic back
     * would show here first. */
    struct world at_the_edge;
    a_world(&at_the_edge);
    struct transmission_control_block *edge = NULL;
    if (!open_one(&at_the_edge, 0xfffffffeu, &edge)) {
        return false;
    }
    struct tcp_header confirm =
        a_segment(TCP_CONTROL_ACK, 0xffffffffu, edge->iss + 1u);
    if (receive(&at_the_edge, &confirm).state != CONNECTION_ESTABLISHED ||
        edge->rcv_nxt != 0xffffffffu) {
        fprintf(stderr, "  RCV.NXT is %lu after a SYN at 0xfffffffe\n",
                (unsigned long)edge->rcv_nxt);
        return false;
    }
    struct tcp_header on_the_edge =
        a_segment(TCP_CONTROL_FIN | TCP_CONTROL_ACK, 0xffffffffu, edge->iss + 1u);
    struct handshake_outcome read_it = receive(&at_the_edge, &on_the_edge);
    if (read_it.state != CONNECTION_LAST_ACK || !read_it.the_fin_was_read ||
        edge->rcv_nxt != 0u) {
        fprintf(stderr, "  a FIN at RCV.NXT with the window's far edge wrapped to 0: "
                        "state %d, RCV.NXT %lu\n",
                (int)read_it.state, (unsigned long)edge->rcv_nxt);
        ok = false;
    }
    return ok;
}

/* Opens one, confirms it, and has the other side close. */
static bool open_confirm_and_be_closed(struct world *world,
                                       struct transmission_control_block **held,
                                       uint32_t *the_fins_sequence_number)
{
    if (!open_and_confirm(world, held)) {
        return false;
    }
    *the_fins_sequence_number = (*held)->rcv_nxt;
    struct tcp_header fin =
        a_segment(TCP_CONTROL_FIN | TCP_CONTROL_ACK, *the_fins_sequence_number,
                  (*held)->iss + 1u);
    struct handshake_outcome outcome = receive(world, &fin);
    if (outcome.state != CONNECTION_LAST_ACK || outcome.reply_bytes == 0) {
        fprintf(stderr, "  the FIN did not reach LAST-ACK: state %d, %zu octets\n",
                (int)outcome.state, outcome.reply_bytes);
        return false;
    }
    return true;
}

/* ⚠ What our own close carries, read back by our own parser — ⚠ **reaching OK
 * is what says the checksum agrees.**
 *
 * ⚠ RFC 793 for the CLOSE Call in CLOSE-WAIT: "send a FIN segment, enter
 * LAST-ACK state" — ⚠ `LAST-ACK` and not `CLOSING`, which is RFC 1122
 * §4.2.2.20 (a) correcting a known error and RFC 9293 §3.10.4 carrying the
 * correction (ADR 0022).
 *
 * ⚠ **One segment, carrying both their acknowledgment and our FIN.** ⚠ Measured
 * 2026-08-29: that is what the Linux kernel sends when its application closes
 * the moment the peer's FIN arrives (ADR 0023). */
static bool case_our_close_is_the_segment_the_document_describes(void)
{
    struct world world;
    a_world(&world);
    struct transmission_control_block *held = NULL;
    uint32_t their_fin = 0;
    if (!open_confirm_and_be_closed(&world, &held, &their_fin)) {
        return false;
    }
    struct handshake_outcome outcome;
    {
        /* Re-run so the outcome is to hand. */
        a_world(&world);
        if (!open_and_confirm(&world, &held)) {
            return false;
        }
        their_fin = held->rcv_nxt;
        struct tcp_header fin =
            a_segment(TCP_CONTROL_FIN | TCP_CONTROL_ACK, their_fin, held->iss + 1u);
        outcome = receive(&world, &fin);
    }

    bool ok = true;
    size_t expected = ETHERNET_HEADER_BYTES + IPV4_FIXED_HEADER_BYTES +
                      TCP_FIXED_HEADER_BYTES;
    if (outcome.reply_bytes != expected) {
        fprintf(stderr, "  our close is %zu octets and a bare FIN-ACK is %zu\n",
                outcome.reply_bytes, expected);
        return false;
    }

    const unsigned char *datagram = world.reply + ETHERNET_HEADER_BYTES;
    struct ipv4_header internet;
    if (ipv4_parse_header(datagram, outcome.reply_bytes - ETHERNET_HEADER_BYTES,
                          &internet) != IPV4_PARSE_OK) {
        fputs("  the internet header of our close did not read back\n", stderr);
        return false;
    }
    struct connection_id id = the_connection();
    struct tcp_header ours;
    enum tcp_parse parsed =
        tcp_parse_header(datagram + IPV4_FIXED_HEADER_BYTES,
                         (size_t)internet.total_length - IPV4_FIXED_HEADER_BYTES,
                         id.local.address, id.remote.address, &ours);
    if (parsed != TCP_PARSE_OK) {
        fprintf(stderr, "  the segment we built came back as %d "
                        "(2 would mean its own checksum disagrees)\n", (int)parsed);
        return false;
    }

    /* ⚠ FIN and ACK together, ⚠ **and no SYN**: a build that reused the answer
     * unchanged would carry one. */
    if (ours.control_bits != (TCP_CONTROL_FIN | TCP_CONTROL_ACK)) {
        fprintf(stderr, "  our close carries control bits 0x%02x, not FIN|ACK\n",
                ours.control_bits);
        ok = false;
    }
    /* ⚠ Our FIN occupies the sequence number after our SYN. ⚠ `SND.NXT` was
     * advanced over it, so it sits one below — ⚠ **asserted against `iss` and
     * not against `snd_nxt`**, so a build reading the wrong end shows. */
    if (ours.sequence_number != held->iss + 1u) {
        fprintf(stderr, "  our close sits at %lu and our SYN was at %lu\n",
                (unsigned long)ours.sequence_number, (unsigned long)held->iss);
        ok = false;
    }
    /* ⚠ AC 2: it acknowledges past their FIN, ⚠ **asserted against the FIN's own
     * sequence number.** ⚠ Off by one here is the error that still looks like it
     * works. */
    if (ours.acknowledgment_number != their_fin + 1u) {
        fprintf(stderr, "  our close acknowledges %lu, and their FIN was at %lu\n",
                (unsigned long)ours.acknowledgment_number, (unsigned long)their_fin);
        ok = false;
    }
    if (ours.source_port != OUR_PORT || ours.destination_port != THEIR_PORT) {
        fputs("  our close's ports are not ours to theirs\n", stderr);
        ok = false;
    }
    if (ours.window != HANDSHAKE_WINDOW || ours.data_offset != TCP_HEADER_LENGTH_MINIMUM) {
        fprintf(stderr, "  our close carries a window of %u and %u octets of options\n",
                ours.window, (ours.data_offset - TCP_HEADER_LENGTH_MINIMUM) * 4);
        ok = false;
    }
    /* ⚠ And it goes back to the hardware address the frame that closed came
     * from. */
    if (memcmp(world.reply, THEIR_MAC, ETHERNET_ADDRESS_BYTES) != 0 ||
        memcmp(world.reply + ETHERNET_ADDRESS_BYTES, OUR_MAC, ETHERNET_ADDRESS_BYTES) != 0) {
        fputs("  our close's ethernet header is not ours to theirs\n", stderr);
        ok = false;
    }
    return ok;
}

/* Reads the window out of whatever segment we last built. */
static bool the_window_of_what_we_built(const struct world *world, size_t reply_bytes,
                                        uint16_t *window)
{
    const unsigned char *datagram = world->reply + ETHERNET_HEADER_BYTES;
    struct ipv4_header internet;
    if (ipv4_parse_header(datagram, reply_bytes - ETHERNET_HEADER_BYTES,
                          &internet) != IPV4_PARSE_OK) {
        return false;
    }
    struct connection_id id = the_connection();
    struct tcp_header ours;
    if (tcp_parse_header(datagram + IPV4_FIXED_HEADER_BYTES,
                         (size_t)internet.total_length - IPV4_FIXED_HEADER_BYTES,
                         id.local.address, id.remote.address, &ours) != TCP_PARSE_OK) {
        return false;
    }
    *window = ours.window;
    return true;
}

/* ⚠ hidetzu/tcpip-stack#75 AC 1: ⚠ **the same number in every segment we
 * build**, read out of each rather than checked one at a time.
 *
 * ⚠ The cases that assert each segment's fields already compare its window with
 * the constant. ⚠ **That would still pass if a second constant appeared** and
 * one shape used it — ⚠ this compares the segments with each other.
 *
 * ⚠ **It read three of the four shapes until hidetzu/tcpip-stack#102**, and
 * ⚠ **the fourth was added at #80 without this case following.** ⚠ That is the
 * mistake `CLAUDE.md` §9's first row names: ⚠ **run the case and read whether it
 * covers every clause**, rather than trusting its name.
 *
 * ⚠ **It is the grounds for `MUST-39` now** (`docs/conformance.md`): the
 * receiver's SWS avoidance algorithm governs window updates, and ⚠ **a window
 * that is the same in every segment we build sends none.** ⚠ **So this case has
 * to cover every segment we build, or that argument is about three of four.** */
static bool case_every_segment_we_build_carries_the_same_window(void)
{
    struct world world;
    a_world(&world);
    struct transmission_control_block *held = NULL;

    bool ok = true;
    uint16_t in_the_answer = 0, in_the_acknowledgment = 0, in_our_close = 0;

    struct tcp_header syn = a_segment(TCP_CONTROL_SYN, THEIR_ISN, 0);
    struct handshake_outcome opened = receive(&world, &syn);
    struct connection_id id = the_connection();
    held = connections_find(&world.connections, &id);
    if (held == NULL || opened.reply_bytes == 0 ||
        !the_window_of_what_we_built(&world, opened.reply_bytes, &in_the_answer)) {
        fputs("  the answer was not built or did not read back\n", stderr);
        return false;
    }

    struct tcp_header confirm =
        a_segment(TCP_CONTROL_ACK, THEIR_ISN + 1u, held->iss + 1u);
    if (receive(&world, &confirm).state != CONNECTION_ESTABLISHED) {
        fputs("  the connection did not reach ESTABLISHED\n", stderr);
        return false;
    }

    struct tcp_header data =
        carrying(a_segment(TCP_CONTROL_ACK, held->rcv_nxt, held->iss + 1u), 1);
    struct handshake_outcome took = receive(&world, &data);
    if (took.reply_bytes == 0 ||
        !the_window_of_what_we_built(&world, took.reply_bytes, &in_the_acknowledgment)) {
        fputs("  the acknowledgment was not built or did not read back\n", stderr);
        return false;
    }

    /* ⚠ The fourth shape, and ⚠ **the one this case did not read until
     * hidetzu/tcpip-stack#102**: an acknowledgment for a segment we refuse. */
    uint16_t in_where_we_are = 0;
    struct tcp_header duplicate =
        carrying(a_segment(TCP_CONTROL_ACK, held->rcv_nxt - 1u, held->iss + 1u), 1);
    struct handshake_outcome refused = receive(&world, &duplicate);
    if (refused.reply != HANDSHAKE_REPLY_WHERE_WE_ARE ||
        !the_window_of_what_we_built(&world, refused.reply_bytes, &in_where_we_are)) {
        fprintf(stderr, "  the acknowledgment for a refused segment was of kind %d\n",
                (int)refused.reply);
        return false;
    }

    struct tcp_header fin =
        a_segment(TCP_CONTROL_FIN | TCP_CONTROL_ACK, held->rcv_nxt, held->iss + 1u);
    struct handshake_outcome closed = receive(&world, &fin);
    if (closed.reply_bytes == 0 ||
        !the_window_of_what_we_built(&world, closed.reply_bytes, &in_our_close)) {
        fputs("  our close was not built or did not read back\n", stderr);
        return false;
    }

    if (in_the_answer != in_the_acknowledgment || in_the_answer != in_our_close ||
        in_the_answer != in_where_we_are) {
        fprintf(stderr, "  the answer says %u, the acknowledgment %u, where-we-are %u "
                        "and our close %u\n",
                in_the_answer, in_the_acknowledgment, in_where_we_are, in_our_close);
        ok = false;
    }
    /* ⚠ And the other half: ⚠ **it is the number we chose**, not merely the
     * same wrong number three times. */
    if (in_the_answer != HANDSHAKE_WINDOW) {
        fprintf(stderr, "  all four say %u and the window is %u\n", in_the_answer,
                (unsigned)HANDSHAKE_WINDOW);
        ok = false;
    }
    return ok;
}

/* ⚠ hidetzu/tcpip-stack#75 AC 2, the side the trimming case does not cover:
 * ⚠ **a segment carrying the window exactly, or less, is taken whole.**
 *
 * ⚠ Without this, a build that always took one octet would pass every check
 * that only feeds oversized segments. */
static bool case_a_segment_the_window_covers_is_taken_whole(void)
{
    bool ok = true;
    static const size_t sizes[] = { 1, 2, 100, (size_t)HANDSHAKE_WINDOW - 1u,
                                    (size_t)HANDSHAKE_WINDOW };

    for (size_t i = 0; i < sizeof sizes / sizeof sizes[0]; i++) {
        struct world world;
        a_world(&world);
        struct transmission_control_block *held = NULL;
        if (!open_and_confirm(&world, &held)) {
            return false;
        }
        uint32_t was = held->rcv_nxt;
        struct tcp_header data =
            carrying(a_segment(TCP_CONTROL_ACK, was, held->iss + 1u), sizes[i]);
        struct handshake_outcome outcome = receive(&world, &data);

        if (outcome.octets_taken != sizes[i] ||
            world.counts.octets_taken_and_discarded != sizes[i] ||
            held->rcv_nxt != was + (uint32_t)sizes[i]) {
            fprintf(stderr, "  %zu octets arrived, %u were taken and RCV.NXT moved %lu\n",
                    sizes[i], (unsigned)outcome.octets_taken,
                    (unsigned long)(held->rcv_nxt - was));
            ok = false;
        }
        /* ⚠ And one acknowledgment for the segment, ⚠ **not one per octet** —
         * the two numbers are in different units. */
        if (outcome.reply != HANDSHAKE_REPLY_THE_DATA_IS_ACKNOWLEDGED) {
            fprintf(stderr, "  %zu octets drew a reply of kind %d\n", sizes[i],
                    (int)outcome.reply);
            ok = false;
        }
    }
    return ok;
}

/* ⚠ hidetzu/tcpip-stack#76 AC 3 and AC 4 together.
 *
 * ⚠ **"Behind us" and "ahead of us" are exactly the pair a plain comparison
 * gets wrong**, and ⚠ **nothing else in this file puts `RCV.NXT` where the two
 * readings disagree.** ⚠ Measured: with `>` in place of the unsigned reading,
 * every other case here still passed.
 *
 * ⚠ And the totals: ⚠ **what was one counter is two that sum to it.** */
static bool case_a_duplicate_and_a_segment_ahead_are_told_apart_at_the_wrap(void)
{
    bool ok = true;

    /* ⚠ `RCV.NXT` just past the wrap, and a duplicate ending just before it.
     * ⚠ A plain `RCV.NXT > where it ends` reads 5 > 0xfffffffe as false and
     * would call this one ahead of us. */
    {
        struct world world;
        a_world(&world);
        struct transmission_control_block *held = NULL;
        if (!open_one(&world, 0xfffffff9u, &held)) {
            return false;
        }
        struct tcp_header confirm =
            a_segment(TCP_CONTROL_ACK, 0xfffffffau, held->iss + 1u);
        if (receive(&world, &confirm).state != CONNECTION_ESTABLISHED) {
            fputs("  the connection did not reach ESTABLISHED at the wrap\n", stderr);
            return false;
        }
        /* Five octets across the wrap: 0xfffffffa .. 0xfffffffe, so RCV.NXT
         * becomes 0xffffffff. */
        struct tcp_header first =
            carrying(a_segment(TCP_CONTROL_ACK, 0xfffffffau, held->iss + 1u), 5);
        if (receive(&world, &first).octets_taken != 5 ||
            held->rcv_nxt != 0xffffffffu) {
            fprintf(stderr, "  RCV.NXT is %lu after five octets from 0xfffffffa\n",
                    (unsigned long)held->rcv_nxt);
            return false;
        }
        /* Six more, so RCV.NXT crosses zero and lands at 5. */
        struct tcp_header across =
            carrying(a_segment(TCP_CONTROL_ACK, 0xffffffffu, held->iss + 1u), 6);
        if (receive(&world, &across).octets_taken != 6 || held->rcv_nxt != 5u) {
            fprintf(stderr, "  RCV.NXT is %lu after six more across the wrap\n",
                    (unsigned long)held->rcv_nxt);
            return false;
        }

        struct handshake_outcome duplicate = receive(&world, &first);
        if (duplicate.reason != HANDSHAKE_REASON_DATA_WE_HAVE_TAKEN_ALREADY ||
            world.counts.data_we_have_taken_already != 1 ||
            world.counts.data_that_begins_too_far_ahead != 0) {
            fprintf(stderr, "  a duplicate ending at 0xfffffffe with RCV.NXT at 5 came "
                            "back as reason %d\n", (int)duplicate.reason);
            ok = false;
        }
    }

    /* ⚠ `RCV.NXT` just before the wrap, and a segment beginning just after it.
     * ⚠ A plain comparison reads 0xfffffffa > 5 as true and would call this one
     * something we have had. */
    {
        struct world world;
        a_world(&world);
        struct transmission_control_block *held = NULL;
        if (!open_one(&world, 0xfffffff9u, &held)) {
            return false;
        }
        struct tcp_header confirm =
            a_segment(TCP_CONTROL_ACK, 0xfffffffau, held->iss + 1u);
        if (receive(&world, &confirm).state != CONNECTION_ESTABLISHED ||
            held->rcv_nxt != 0xfffffffau) {
            fputs("  the connection did not reach ESTABLISHED before the wrap\n", stderr);
            return false;
        }
        struct tcp_header ahead =
            carrying(a_segment(TCP_CONTROL_ACK, 5u, held->iss + 1u), 3);
        struct handshake_outcome outcome = receive(&world, &ahead);
        if (outcome.reason != HANDSHAKE_REASON_DATA_THAT_BEGINS_TOO_FAR_AHEAD ||
            world.counts.data_that_begins_too_far_ahead != 1 ||
            world.counts.data_we_have_taken_already != 0 ||
            held->rcv_nxt != 0xfffffffau) {
            fprintf(stderr, "  a segment at 5 with RCV.NXT at 0xfffffffa came back as "
                            "reason %d\n", (int)outcome.reason);
            ok = false;
        }
    }

    /* ⚠ AC 4: ⚠ **the two sum to what the one number used to be.** ⚠ Three
     * duplicates and two ahead, in one connection, counted 3 and 2. */
    {
        struct world world;
        a_world(&world);
        struct transmission_control_block *held = NULL;
        if (!open_and_confirm(&world, &held)) {
            return false;
        }
        uint32_t was = held->rcv_nxt;
        struct tcp_header took =
            carrying(a_segment(TCP_CONTROL_ACK, was, held->iss + 1u), 2);
        if (receive(&world, &took).octets_taken != 2) {
            fputs("  the first two octets were not taken\n", stderr);
            return false;
        }
        struct tcp_header ahead =
            carrying(a_segment(TCP_CONTROL_ACK, was + 50u, held->iss + 1u), 2);
        for (unsigned i = 0; i < 3; i++) {
            (void)receive(&world, &took);
        }
        for (unsigned i = 0; i < 2; i++) {
            (void)receive(&world, &ahead);
        }
        if (world.counts.data_we_have_taken_already != 3 ||
            world.counts.data_that_begins_too_far_ahead != 2) {
            fprintf(stderr, "  three duplicates and two ahead were counted %lu and %lu\n",
                    world.counts.data_we_have_taken_already,
                    world.counts.data_that_begins_too_far_ahead);
            ok = false;
        }
        /* ⚠ And nothing else moved: the octets taken are still just the two. */
        if (world.counts.octets_taken_and_discarded != 2) {
            fprintf(stderr, "  %lu octets were taken, not 2\n",
                    world.counts.octets_taken_and_discarded);
            ok = false;
        }
    }
    return ok;
}

/* ⚠ hidetzu/tcpip-stack#103. ⚠ **The `Time to Live` we send with is the
 * caller's**, not a constant reachable from nothing.
 *
 * ⚠ RFC 9293 `MUST-49`: "The TTL value used to send TCP segments MUST be
 * configurable."
 *
 * ⚠ **Asserted at a value that is not the default**, ⚠ **or the check could not
 * tell a setting from a constant** — and at the default too, so ⚠ **a build that
 * ignored the parameter and a build that ignored the default both show.** */
static bool case_the_time_to_live_we_send_with_is_the_callers(void)
{
    static const uint8_t values[] = { 1u, 42u, IPV4_TIME_TO_LIVE_WE_SEND, 255u };
    bool ok = true;

    for (size_t i = 0; i < sizeof values / sizeof values[0]; i++) {
        struct world world;
        a_world(&world);
        struct connection_id id = the_connection();
        struct tcp_header syn = a_segment(TCP_CONTROL_SYN, THEIR_ISN, 0);
        struct handshake_outcome outcome;
        handshake_receive(&syn, &id, OUR_PORT, at(0), values[i], THEIR_MAC, OUR_MAC,
                          &world.connections, world.reply, sizeof world.reply,
                          &world.counts, &outcome);
        if (outcome.reply_bytes == 0) {
            fprintf(stderr, "  nothing was built at a time to live of %u\n", values[i]);
            ok = false;
            continue;
        }
        struct ipv4_header internet;
        if (ipv4_parse_header(world.reply + ETHERNET_HEADER_BYTES,
                              outcome.reply_bytes - ETHERNET_HEADER_BYTES,
                              &internet) != IPV4_PARSE_OK) {
            fprintf(stderr, "  the header built at %u did not read back\n", values[i]);
            ok = false;
            continue;
        }
        if (internet.time_to_live != values[i]) {
            fprintf(stderr, "  asked for a time to live of %u and the datagram carries %u\n",
                    values[i], internet.time_to_live);
            ok = false;
        }
    }
    return ok;
}

/* ⚠ hidetzu/tcpip-stack#112. ⚠ RFC 9293 `MUST-63`, §3.9.2.3: "An incoming SYN
 * with an invalid source address MUST be ignored either by TCP or by the IP
 * layer ... (see Section 3.2.1.3)."
 *
 * ⚠ **The mirror of the case below, and deliberately shaped the same**: what is
 * refused, ⚠ **that an ordinary source is still answered**, and ⚠ **that the
 * form we cannot recognise is still answered.**
 *
 * ⚠ **Met in part, never met** (hidetzu/tcpip-stack#112 Owner Decision 2). */
static bool case_a_syn_from_an_impossible_source_is_refused(void)
{
    static const struct { unsigned char address[4]; const char *what; } from[] = {
        { { 0, 0, 0, 0 }, "RFC 1122 §3.2.1.3 (a), { 0, 0 }" },
        { { 0, 1, 2, 3 }, "§3.2.1.3 (b), { 0, <host> }" },
        { { 127, 0, 0, 1 }, "§3.2.1.3 (g), the loopback address" },
        { { 127, 255, 255, 254 }, "§3.2.1.3 (g) at the top of 127/8" },
        { { 255, 255, 255, 255 }, "§3.2.1.3 (c), the limited broadcast" },
        { { 224, 0, 0, 1 }, "multicast at the bottom of the range" },
        { { 239, 255, 255, 255 }, "multicast at the top of it" },
    };

    bool ok = true;
    for (size_t i = 0; i < sizeof from / sizeof from[0]; i++) {
        struct world world;
        a_world(&world);
        struct connection_id id = the_connection();
        memcpy(id.remote.address, from[i].address, CONNECTION_ADDRESS_BYTES);
        struct tcp_header syn = a_segment(TCP_CONTROL_SYN, THEIR_ISN, 0);
        struct handshake_outcome outcome;
        handshake_receive(&syn, &id, OUR_PORT, at(0), IPV4_TIME_TO_LIVE_WE_SEND,
                          THEIR_MAC, OUR_MAC, &world.connections, world.reply,
                          sizeof world.reply, &world.counts, &outcome);

        if (outcome.reason != HANDSHAKE_REASON_FROM_AN_IMPOSSIBLE_SOURCE ||
            world.counts.from_an_impossible_source != 1) {
            fprintf(stderr, "  %s came back as reason %d\n", from[i].what,
                    (int)outcome.reason);
            ok = false;
        }
        /* ⚠ **No state and no reply.** ⚠ `MUST-63` says "ignored", and ⚠ a
         * connection taken and then dropped would not have been ignored. */
        if (outcome.reply_bytes != 0 || connections_find(&world.connections, &id) != NULL ||
            world.counts.opened != 0) {
            fprintf(stderr, "  %s left %zu octets built or a connection held\n",
                    from[i].what, outcome.reply_bytes);
            ok = false;
        }
        /* ⚠ Counted apart from the refusal for the DESTINATION. ⚠ **The two
         * lines in `handshake.c` read `id.local` and `id.remote`, and this is
         * what would notice them being swapped.** */
        if (world.counts.addressed_to_everyone != 0) {
            fprintf(stderr, "  %s moved the count for the destination instead\n",
                    from[i].what);
            ok = false;
        }
    }

    /* ⚠ The other half: ⚠ **an ordinary source is still answered**, or refusing
     * these would pass for a stack that refuses everything (`verify` §5). */
    {
        struct world world;
        a_world(&world);
        struct transmission_control_block *held = NULL;
        if (!open_one(&world, THEIR_ISN, &held)) {
            fputs("  an ordinary source was refused too\n", stderr);
            ok = false;
        } else if (world.counts.from_an_impossible_source != 0) {
            fputs("  an ordinary source was counted as an impossible one\n", stderr);
            ok = false;
        }
    }

    /* ⚠ The boundaries of every range above, ⚠ **each one octet outside it.**
     * ⚠ Refusing a range is only correct if it stops where the document stops:
     * ⚠ **`255.255.255.254` in particular, because §3.2.1.3 (c) is `{ -1, -1 }`
     * and not `255.<anything>`** — reading the first octet alone would refuse a
     * class E address the section never names. */
    {
        static const struct { unsigned char address[4]; const char *what; } still[] = {
            { { 1, 0, 0, 1 }, "1.0.0.1, one network above 0/8" },
            { { 126, 255, 255, 255 }, "126.255.255.255, just below 127/8" },
            { { 128, 0, 0, 1 }, "128.0.0.1, just above it" },
            { { 223, 255, 255, 255 }, "223.255.255.255, just below class D" },
            { { 240, 0, 0, 1 }, "240.0.0.1, just above class D" },
            { { 255, 255, 255, 254 }, "255.255.255.254, NOT the limited broadcast" },
        };
        for (size_t i = 0; i < sizeof still / sizeof still[0]; i++) {
            struct world world;
            a_world(&world);
            struct connection_id id = the_connection();
            memcpy(id.remote.address, still[i].address, CONNECTION_ADDRESS_BYTES);
            struct tcp_header syn = a_segment(TCP_CONTROL_SYN, THEIR_ISN, 0);
            struct handshake_outcome outcome;
            handshake_receive(&syn, &id, OUR_PORT, at(0), IPV4_TIME_TO_LIVE_WE_SEND,
                              THEIR_MAC, OUR_MAC, &world.connections, world.reply,
                              sizeof world.reply, &world.counts, &outcome);
            if (outcome.reason == HANDSHAKE_REASON_FROM_AN_IMPOSSIBLE_SOURCE ||
                world.counts.from_an_impossible_source != 0 ||
                outcome.reply_bytes == 0) {
                fprintf(stderr, "  %s was refused, and no document says to\n",
                        still[i].what);
                ok = false;
            }
        }
    }

    /* ⚠ And the part that is NOT met, pinned so it cannot be claimed by
     * accident: ⚠ **a directed broadcast source is answered**, because it cannot
     * be told from a host address without a netmask. ⚠ **The same gap `MUST-57`
     * has, and this fails if it ever closes silently.** */
    {
        struct world world;
        a_world(&world);
        struct connection_id id = the_connection();
        id.remote.address[3] = 255;
        struct tcp_header syn = a_segment(TCP_CONTROL_SYN, THEIR_ISN, 0);
        struct handshake_outcome outcome;
        handshake_receive(&syn, &id, OUR_PORT, at(0), IPV4_TIME_TO_LIVE_WE_SEND,
                          THEIR_MAC, OUR_MAC, &world.connections, world.reply,
                          sizeof world.reply, &world.counts, &outcome);
        if (outcome.reason == HANDSHAKE_REASON_FROM_AN_IMPOSSIBLE_SOURCE) {
            fputs("  a directed broadcast source was refused, which this build "
                  "cannot do without a netmask — say so and update "
                  "docs/conformance.md\n", stderr);
            ok = false;
        }
    }
    return ok;
}

/* ⚠ hidetzu/tcpip-stack#99. ⚠ RFC 9293 `MUST-57`: "A TCP implementation MUST
 * silently discard an incoming SYN segment that is addressed to a broadcast or
 * multicast address ... This prevents connection state and replies from being
 * erroneously generated."
 *
 * ⚠ **Met in part, and the part is asserted here.** ⚠ A directed broadcast
 * cannot be told from a host address without a netmask, ⚠ **and nothing here has
 * one** — `docs/conformance.md` says which part is met. */
static bool case_a_segment_addressed_to_everyone_is_refused(void)
{
    static const struct { unsigned char address[4]; const char *what; } to[] = {
        { { 255, 255, 255, 255 }, "the limited broadcast" },
        { { 224, 0, 0, 1 }, "a multicast address at the bottom of the range" },
        { { 239, 255, 255, 255 }, "a multicast address at the top of it" },
    };

    bool ok = true;
    for (size_t i = 0; i < sizeof to / sizeof to[0]; i++) {
        struct world world;
        a_world(&world);
        struct connection_id id = the_connection();
        memcpy(id.local.address, to[i].address, CONNECTION_ADDRESS_BYTES);
        struct tcp_header syn = a_segment(TCP_CONTROL_SYN, THEIR_ISN, 0);
        struct handshake_outcome outcome;
        handshake_receive(&syn, &id, OUR_PORT, at(0), IPV4_TIME_TO_LIVE_WE_SEND,
                          THEIR_MAC, OUR_MAC, &world.connections, world.reply,
                          sizeof world.reply, &world.counts, &outcome);

        if (outcome.reason != HANDSHAKE_REASON_ADDRESSED_TO_EVERYONE ||
            world.counts.addressed_to_everyone != 1) {
            fprintf(stderr, "  %s came back as reason %d\n", to[i].what,
                    (int)outcome.reason);
            ok = false;
        }
        /* ⚠ **No state and no reply** — the two things the document's reason
         * names. */
        if (outcome.reply_bytes != 0 || connections_find(&world.connections, &id) != NULL ||
            world.counts.opened != 0) {
            fprintf(stderr, "  %s left %zu octets built or a connection held\n",
                    to[i].what, outcome.reply_bytes);
            ok = false;
        }
    }

    /* ⚠ The other half: ⚠ **an ordinary address is still answered**, or
     * refusing these would pass for a stack that refuses everything. */
    {
        struct world world;
        a_world(&world);
        struct transmission_control_block *held = NULL;
        if (!open_one(&world, THEIR_ISN, &held)) {
            fputs("  an ordinary address was refused too\n", stderr);
            ok = false;
        } else if (world.counts.addressed_to_everyone != 0) {
            fputs("  an ordinary address was counted as a broadcast\n", stderr);
            ok = false;
        }
    }

    /* ⚠ And the part that is NOT met, pinned so it cannot be claimed by
     * accident: ⚠ **a directed broadcast is answered**, because it cannot be
     * told from a host address here. ⚠ **This case fails if that ever changes
     * silently** — the change would have to say so. */
    {
        struct world world;
        a_world(&world);
        struct connection_id id = the_connection();
        id.local.address[3] = 255;
        struct tcp_header syn = a_segment(TCP_CONTROL_SYN, THEIR_ISN, 0);
        struct handshake_outcome outcome;
        handshake_receive(&syn, &id, OUR_PORT, at(0), IPV4_TIME_TO_LIVE_WE_SEND,
                          THEIR_MAC, OUR_MAC, &world.connections, world.reply,
                          sizeof world.reply, &world.counts, &outcome);
        if (outcome.reason == HANDSHAKE_REASON_ADDRESSED_TO_EVERYONE) {
            fputs("  a directed broadcast was refused, which this build cannot do "
                  "without a netmask — say so and update docs/conformance.md\n", stderr);
            ok = false;
        }
    }
    return ok;
}

/* ⚠ hidetzu/tcpip-stack#101. ⚠ RFC 9293 `MUST-66`: "A TCP receiver MUST process
 * the RST and URG fields of all incoming segments, even when the receive window
 * is zero."
 *
 * ⚠ §3.10.7.4 for the synchronised states: "If the RST bit is set ... Enter the
 * CLOSED state, delete the TCB, and return." ⚠ For `SYN-RECEIVED` on a passive
 * `OPEN`: "return this connection to LISTEN state ... The user need not be
 * informed." ⚠ **Holding nothing is our LISTEN**, so both come to the same
 * thing. */
static bool case_a_reset_ends_the_connection(void)
{
    bool ok = true;
    static const enum { WHILE_OPENING, WHILE_OPEN } when[] = { WHILE_OPENING, WHILE_OPEN };

    for (size_t i = 0; i < sizeof when / sizeof when[0]; i++) {
        struct world world;
        a_world(&world);
        struct transmission_control_block *held = NULL;
        if (when[i] == WHILE_OPENING) {
            if (!open_one(&world, THEIR_ISN, &held)) {
                return false;
            }
        } else if (!open_and_confirm(&world, &held)) {
            return false;
        }
        uint32_t at_the_edge = held->rcv_nxt;

        struct tcp_header reset = a_segment(TCP_CONTROL_RST, at_the_edge, 0);
        struct handshake_outcome outcome = receive(&world, &reset);

        if (outcome.reason != HANDSHAKE_REASON_THE_OTHER_SIDE_RESET_IT ||
            outcome.state != CONNECTION_CLOSED ||
            world.counts.reset_by_the_other_side != 1) {
            fprintf(stderr, "  a reset in state %d came back as reason %d\n",
                    (int)when[i], (int)outcome.reason);
            ok = false;
        }
        /* ⚠ **The block is gone**, which is what "delete the TCB" means here. */
        struct connection_id id = the_connection();
        if (connections_find(&world.connections, &id) != NULL) {
            fputs("  the connection was still held after a reset\n", stderr);
            ok = false;
        }
        /* ⚠ Nothing is sent for it. */
        if (outcome.reply_bytes != 0) {
            fprintf(stderr, "  %zu octets were built in answer to a reset\n",
                    outcome.reply_bytes);
            ok = false;
        }
        /* ⚠ And a later `SYN` opens one, so the room really is free. */
        struct tcp_header again = a_segment(TCP_CONTROL_SYN, THEIR_ISN + 500u, 0);
        if (receive(&world, &again).state != CONNECTION_SYN_RECEIVED) {
            fputs("  a later SYN was refused after a reset\n", stderr);
            ok = false;
        }
    }
    return ok;
}

/* ⚠ The other half, and it is the document's own exception: ⚠ **a `RST` the
 * window does not cover is dropped and draws nothing.**
 *
 * ⚠ RFC 9293 §3.10.7.4's first step: an unacceptable segment draws an
 * acknowledgment ⚠ **"(unless the RST bit is set, if so drop the segment and
 * return)"** — ⚠ so this is the one refusal that stays silent. */
static bool case_a_reset_outside_the_window_changes_nothing(void)
{
    struct world world;
    a_world(&world);
    struct transmission_control_block *held = NULL;
    if (!open_and_confirm(&world, &held)) {
        return false;
    }
    uint32_t was = held->rcv_nxt;

    bool ok = true;
    static const uint32_t away[] = { 1u, 5000u };
    for (size_t i = 0; i < sizeof away / sizeof away[0]; i++) {
        uint32_t sits_at = i == 0 ? was - away[i] : was + away[i];
        struct tcp_header reset = a_segment(TCP_CONTROL_RST, sits_at, 0);
        struct handshake_outcome outcome = receive(&world, &reset);
        if (outcome.reason != HANDSHAKE_REASON_A_RESET_OUTSIDE_THE_WINDOW) {
            fprintf(stderr, "  a reset at %lu with RCV.NXT %lu came back as reason %d\n",
                    (unsigned long)sits_at, (unsigned long)was, (int)outcome.reason);
            ok = false;
        }
        /* ⚠ **Nothing sent** — unlike refused data or a refused FIN. */
        if (outcome.reply_bytes != 0 || outcome.reply != HANDSHAKE_REPLY_NONE) {
            fprintf(stderr, "  %zu octets were built for a reset outside the window\n",
                    outcome.reply_bytes);
            ok = false;
        }
    }
    /* ⚠ And the connection is untouched. */
    struct connection_id id = the_connection();
    if (connections_find(&world.connections, &id) == NULL ||
        held->state != CONNECTION_ESTABLISHED || held->rcv_nxt != was ||
        world.counts.reset_by_the_other_side != 0 ||
        world.counts.reset_outside_the_window != 2) {
        fprintf(stderr, "  the connection moved: state %d, reset %lu, outside %lu\n",
                (int)held->state, world.counts.reset_by_the_other_side,
                world.counts.reset_outside_the_window);
        ok = false;
    }
    return ok;
}

/* ⚠ A segment marked urgent. ⚠ **The pointer is read and there is nobody to
 * hand it to** (ADR 0022), and ⚠ **it is counted and said** rather than passing
 * as ordinary. */
static bool case_an_urgent_segment_is_counted_and_said(void)
{
    struct world world;
    a_world(&world);
    struct transmission_control_block *held = NULL;
    if (!open_and_confirm(&world, &held)) {
        return false;
    }

    bool ok = true;
    struct tcp_header urgent =
        a_segment(TCP_CONTROL_URG | TCP_CONTROL_ACK, held->rcv_nxt, held->iss + 1u);
    struct handshake_outcome outcome = receive(&world, &urgent);
    if (outcome.reason != HANDSHAKE_REASON_URGENT_AND_NOBODY_TO_TELL ||
        world.counts.urgent_and_nobody_to_tell != 1 ||
        world.counts.not_expected_in_this_state != 0) {
        fprintf(stderr, "  a segment marked urgent came back as reason %d\n",
                (int)outcome.reason);
        ok = false;
    }

    /* ⚠ The other half: ⚠ **`URG` beside data does not stop the data being
     * taken** — this reason is reached only when nothing else was. */
    struct tcp_header with_data =
        carrying(a_segment(TCP_CONTROL_URG | TCP_CONTROL_ACK, held->rcv_nxt,
                           held->iss + 1u), 2);
    struct handshake_outcome took = receive(&world, &with_data);
    if (took.octets_taken != 2 || world.counts.urgent_and_nobody_to_tell != 1) {
        fprintf(stderr, "  urgent data was not taken: %u octets, urgent counted %lu\n",
                (unsigned)took.octets_taken, world.counts.urgent_and_nobody_to_tell);
        ok = false;
    }
    return ok;
}

/* ⚠ hidetzu/tcpip-stack#98. ⚠ RFC 9293 `MUST-8`: "A TCP implementation MUST use
 * the above type of 'clock' for clock-driven selection of initial sequence
 * numbers", the clock being "a 32-bit counter that typically increments at least
 * once every roughly 4 microseconds".
 *
 * ⚠ **With no clock and no waiting**, which is what ADR 0018 bought: the moment
 * is handed in. */
static bool case_the_initial_sequence_number_follows_the_clock(void)
{
    bool ok = true;

    /* ⚠ It moves at the rate the document names. ⚠ Asserted against the step
     * rather than against 4000, so ⚠ **the case follows the constant.** */
    uint64_t step = HANDSHAKE_INITIAL_SEQUENCE_STEP_NANOSECONDS;
    if (handshake_initial_send_sequence(at(0)) !=
            handshake_initial_send_sequence(at(0)) ||
        handshake_initial_send_sequence(at(0)) + 1u !=
            handshake_initial_send_sequence(at(0)) + 1u) {
        fputs("  the same moment gave two different numbers\n", stderr);
        ok = false;
    }
    {
        struct moment early = { 1000000u };
        struct moment later = { 1000000u + step };
        if (handshake_initial_send_sequence(later) !=
            handshake_initial_send_sequence(early) + 1u) {
            fprintf(stderr, "  one step of %lu ns moved the number by %lu, not 1\n",
                    (unsigned long)step,
                    (unsigned long)(handshake_initial_send_sequence(later) -
                                    handshake_initial_send_sequence(early)));
            ok = false;
        }
        /* ⚠ And a moment shorter than a step does NOT move it — ⚠ **or the
         * "at least once every roughly 4 microseconds" would be a coincidence
         * of the arithmetic.** */
        struct moment barely = { 1000000u + step - 1u };
        if (handshake_initial_send_sequence(barely) !=
            handshake_initial_send_sequence(early)) {
            fputs("  a moment shorter than one step moved the number\n", stderr);
            ok = false;
        }
    }

    /* ⚠ **Two connections taken at different moments get different numbers**,
     * ⚠ with the denominator: one second apart, and one second is 250000 steps
     * of 4 microseconds. */
    {
        struct world world;
        a_world(&world);
        /* ⚠ `at()` takes milliseconds; ⚠ **this needs nanoseconds**, because a
         * step is 4 microseconds. */
        struct moment first_moment = { 5000u };
        struct moment a_second_later = { 5000u + 1000u * 1000u * 1000u };
        world.now = first_moment;
        struct transmission_control_block *first = NULL;
        if (!open_one(&world, THEIR_ISN, &first)) {
            return false;
        }
        uint32_t taken_early = first->iss;
        struct tcp_header reset = a_segment(TCP_CONTROL_RST, first->rcv_nxt, 0);
        (void)receive(&world, &reset);

        world.now = a_second_later;
        struct transmission_control_block *second = NULL;
        if (!open_one(&world, THEIR_ISN, &second)) {
            return false;
        }
        uint32_t apart = second->iss - taken_early;
        if (apart != (uint32_t)(1000u * 1000u * 1000u / step)) {
            fprintf(stderr, "  a second apart moved the number by %lu, and a second "
                            "is %lu steps\n",
                    (unsigned long)apart, (unsigned long)(1000000000u / step));
            ok = false;
        }
    }

    /* ⚠ ADR 0016's rule, and ⚠ **the one this change was most likely to
     * break**: a retransmitted `SYN` is answered with the same number, ⚠ **even
     * though the clock has moved.** */
    {
        struct world world;
        a_world(&world);
        struct moment when = { 7000u };
        world.now = when;
        struct transmission_control_block *held = NULL;
        if (!open_one(&world, THEIR_ISN, &held)) {
            return false;
        }
        uint32_t chosen = held->iss;

        /* ⚠ A minute later, so ⚠ **the clock has moved fifteen million steps.** */
        struct moment a_minute_later = { 7000u + 60ull * 1000u * 1000u * 1000u };
        world.now = a_minute_later;
        struct tcp_header again = a_segment(TCP_CONTROL_SYN, THEIR_ISN, 0);
        struct handshake_outcome outcome = receive(&world, &again);
        if (outcome.reason != HANDSHAKE_REASON_ASKED_AGAIN || held->iss != chosen) {
            fprintf(stderr, "  a minute later the number was re-chosen: 0x%08lx from "
                            "0x%08lx\n", (unsigned long)held->iss,
                    (unsigned long)chosen);
            ok = false;
        }
    }
    return ok;
}

/* ⚠ AC 5. ⚠ **Nothing is sent for a connection that has not seen a FIN**, so
 * this change cannot pass for a stack that sends on everything. */
static bool case_nothing_is_sent_for_a_connection_that_has_not_seen_a_fin(void)
{
    bool ok = true;

    /* An open connection, and a bare acknowledgment on it. */
    {
        struct world world;
        a_world(&world);
        struct transmission_control_block *held = NULL;
        if (!open_and_confirm(&world, &held)) {
            return false;
        }
        struct tcp_header bare = a_segment(TCP_CONTROL_ACK, held->rcv_nxt, held->iss + 1u);
        struct handshake_outcome outcome = receive(&world, &bare);
        if (outcome.reply_bytes != 0 || outcome.reply != HANDSHAKE_REPLY_NONE) {
            fprintf(stderr, "  %zu octets were built for a bare acknowledgment\n",
                    outcome.reply_bytes);
            ok = false;
        }
    }

    /* Data on an open connection. ⚠ Since hidetzu/tcpip-stack#74 this DOES
     * produce a segment — ⚠ **an acknowledgment, and never our close.** ⚠ The
     * case's subject is unchanged: nothing closes without a FIN. */
    {
        struct world world;
        a_world(&world);
        struct transmission_control_block *held = NULL;
        if (!open_and_confirm(&world, &held)) {
            return false;
        }
        struct tcp_header data =
            carrying(a_segment(TCP_CONTROL_ACK, held->rcv_nxt, held->iss + 1u), 1);
        struct handshake_outcome outcome = receive(&world, &data);
        if (outcome.reply == HANDSHAKE_REPLY_OUR_FIN ||
            held->state != CONNECTION_ESTABLISHED) {
            fprintf(stderr, "  data drew a reply of kind %d and left state %d\n",
                    (int)outcome.reply, (int)held->state);
            ok = false;
        }
    }

    /* ⚠ And the timer, on a connection that reached open and was left alone:
     * ⚠ **nothing is due**, however far the clock is moved. */
    {
        struct world world;
        a_world(&world);
        struct transmission_control_block *held = NULL;
        if (!open_and_confirm(&world, &held)) {
            return false;
        }
        struct handshake_outcome outcome;
        enum handshake_due due =
            handshake_what_is_due(&world.connections,
                                  at(HANDSHAKE_GIVE_UP_AFTER_MILLISECONDS * 10), IPV4_TIME_TO_LIVE_WE_SEND, OUR_MAC,
                                  world.reply, sizeof world.reply, &world.counts, &outcome);
        if (due != HANDSHAKE_NOTHING_DUE || outcome.reply_bytes != 0) {
            fprintf(stderr, "  an open connection was due %d with %zu octets\n",
                    (int)due, outcome.reply_bytes);
            ok = false;
        }
    }
    return ok;
}

/* ⚠ AC 5 again, from the other side. ⚠ The schedule covers a connection that is
 * still opening AND one waiting for our close to be acknowledged — ⚠ **but what
 * goes out is not the same segment**, and answering a closed-down connection
 * with a SYN-ACK would be sending at something that has said goodbye. */
static bool case_what_goes_out_again_for_a_closing_connection_is_our_close(void)
{
    struct world world;
    a_world(&world);
    struct transmission_control_block *held = NULL;
    uint32_t their_fin = 0;
    if (!open_confirm_and_be_closed(&world, &held, &their_fin)) {
        return false;
    }
    /* ⚠ What went out first, kept so the copy can be compared with it. */
    unsigned char first[256];
    memcpy(first, world.reply, sizeof first);

    bool ok = true;
    struct handshake_outcome outcome;
    enum handshake_due due =
        handshake_what_is_due(&world.connections, at(HANDSHAKE_ANSWER_AGAIN_AFTER_MILLISECONDS), IPV4_TIME_TO_LIVE_WE_SEND,
                              OUR_MAC, world.reply, sizeof world.reply,
                              &world.counts, &outcome);
    if (due != HANDSHAKE_ANSWER_AGAIN ||
        outcome.reason != HANDSHAKE_REASON_OUR_FIN_WENT_OUT_AGAIN ||
        outcome.reply != HANDSHAKE_REPLY_OUR_FIN) {
        fprintf(stderr, "  a closing connection was due %d, reason %d, kind %d\n",
                (int)due, (int)outcome.reason, (int)outcome.reply);
        ok = false;
    }
    /* ⚠ RFC 793: "All segments preceding and including FIN will be retransmitted
     * until acknowledged." ⚠ **Retransmitted, so the same octets** — a copy
     * carrying a different sequence number is a different segment. */
    if (memcmp(first, world.reply, sizeof first) != 0) {
        fputs("  our close went out again with different octets\n", stderr);
        ok = false;
    }
    /* ⚠ And it is not counted as the answer going out again. */
    if (world.counts.answered_again != 0) {
        fputs("  our close was counted as the answer going out again\n", stderr);
        ok = false;
    }
    return ok;
}

/* ⚠ The timers for the closing run from when our close went out, ⚠ **not from
 * the handshake.**
 *
 * ⚠ RFC 793 makes reinitialising the timer part of sending. ⚠ The ones left over
 * from opening the connection may already have passed — ⚠ **and then a close
 * would be given up on before it had been waited for.**
 *
 * ⚠ Everything else in this file happens at moment 0, where the two are the
 * same number. ⚠ **Measured: with the restart removed, every other case here
 * still passed.** ⚠ This case is the only thing that holds it, and the FIN
 * arrives late on purpose. */
static bool case_the_closing_timers_run_from_when_our_close_went_out(void)
{
    struct world world;
    a_world(&world);
    struct transmission_control_block *held = NULL;
    if (!open_and_confirm(&world, &held)) {
        return false;
    }

    /* ⚠ Late enough that the handshake's own give-up moment is nearly here. */
    uint64_t closed_at = HANDSHAKE_GIVE_UP_AFTER_MILLISECONDS - 500u;
    world.now = at(closed_at);
    struct tcp_header fin =
        a_segment(TCP_CONTROL_FIN | TCP_CONTROL_ACK, held->rcv_nxt, held->iss + 1u);
    if (receive(&world, &fin).state != CONNECTION_LAST_ACK) {
        fputs("  the late FIN did not reach LAST-ACK\n", stderr);
        return false;
    }

    bool ok = true;
    struct handshake_outcome outcome;
#define DUE_AT(milliseconds)                                                       \
    handshake_what_is_due(&world.connections, at(milliseconds), IPV4_TIME_TO_LIVE_WE_SEND, OUR_MAC,           \
                          world.reply, sizeof world.reply, &world.counts, &outcome)

    /* ⚠ The handshake's give-up moment passes and ⚠ **nothing happens**: the
     * timers were restarted when our close went out. */
    if (DUE_AT(closed_at + HANDSHAKE_ANSWER_AGAIN_AFTER_MILLISECONDS - 1u) !=
        HANDSHAKE_NOTHING_DUE) {
        fprintf(stderr, "  something was due %d at %lu, before our close was owed one\n",
                (int)outcome.reason,
                (unsigned long)(closed_at + HANDSHAKE_ANSWER_AGAIN_AFTER_MILLISECONDS - 1u));
        ok = false;
    }
    if (DUE_AT(closed_at + HANDSHAKE_ANSWER_AGAIN_AFTER_MILLISECONDS) !=
            HANDSHAKE_ANSWER_AGAIN ||
        outcome.reason != HANDSHAKE_REASON_OUR_FIN_WENT_OUT_AGAIN) {
        fprintf(stderr, "  our close was not owed again a second after it went out: "
                        "reason %d\n", (int)outcome.reason);
        ok = false;
    }
    if (DUE_AT(closed_at + HANDSHAKE_GIVE_UP_AFTER_MILLISECONDS) != HANDSHAKE_GIVE_UP ||
        outcome.reason != HANDSHAKE_REASON_NOBODY_ACKNOWLEDGED_OUR_FIN) {
        fprintf(stderr, "  our close was not given up on three seconds after it went "
                        "out: reason %d\n", (int)outcome.reason);
        ok = false;
    }
#undef DUE_AT
    return ok;
}

/* ⚠ RFC 793 for LAST-ACK: "The only thing that can arrive in this state is an
 * acknowledgment of our FIN.  If our FIN is now acknowledged, delete the TCB,
 * enter the CLOSED state, and return."
 *
 * ⚠ AC 4: ⚠ **and the next SYN can then open one** — there is room for exactly
 * one (ADR 0015), so a connection that was not released would refuse it. */
static bool case_the_acknowledgment_of_our_close_finishes_the_connection(void)
{
    struct world world;
    a_world(&world);
    struct transmission_control_block *held = NULL;
    uint32_t their_fin = 0;
    if (!open_confirm_and_be_closed(&world, &held, &their_fin)) {
        return false;
    }
    uint32_t our_fin_is_acknowledged_by = held->iss + 2u;

    bool ok = true;
    struct tcp_header last =
        a_segment(TCP_CONTROL_ACK, their_fin + 1u, our_fin_is_acknowledged_by);
    struct handshake_outcome outcome = receive(&world, &last);

    if (outcome.decision != HANDSHAKE_MOVED || outcome.state != CONNECTION_CLOSED ||
        world.counts.closed != 1) {
        fprintf(stderr, "  the acknowledgment of our close left state %d, closed %lu\n",
                (int)outcome.state, world.counts.closed);
        ok = false;
    }
    if (outcome.reply_bytes != 0) {
        fprintf(stderr, "  %zu octets were built in answer to it\n", outcome.reply_bytes);
        ok = false;
    }
    /* ⚠ The block is back. ⚠ **This is the half that says "released" rather
     * than "reported as released".** */
    struct connection_id id = the_connection();
    if (connections_find(&world.connections, &id) != NULL) {
        fputs("  the connection is still held after it finished\n", stderr);
        ok = false;
    }
    /* ⚠ And a fresh SYN opens one, which is what the room being free MEANS. */
    struct tcp_header syn = a_segment(TCP_CONTROL_SYN, THEIR_ISN + 1000u, 0);
    struct handshake_outcome again = receive(&world, &syn);
    if (again.decision != HANDSHAKE_MOVED || again.state != CONNECTION_SYN_RECEIVED ||
        world.counts.room.refused_for_want_of_room != 0) {
        fprintf(stderr, "  a later SYN was refused: state %d, refused %lu\n",
                (int)again.state, world.counts.room.refused_for_want_of_room);
        ok = false;
    }
    return ok;
}

/* ⚠ The other half: an acknowledgment that does NOT cover our close finishes
 * nothing. ⚠ Without this, "it closed" would pass for a stack that closed on
 * any acknowledgment at all — ⚠ **the same lesson the handshake taught**
 * (`CLAUDE.md` §1). */
static bool case_an_acknowledgment_that_does_not_cover_our_close_finishes_nothing(void)
{
    struct world world;
    a_world(&world);
    struct transmission_control_block *held = NULL;
    uint32_t their_fin = 0;
    if (!open_confirm_and_be_closed(&world, &held, &their_fin)) {
        return false;
    }

    bool ok = true;
    /* ⚠ Acknowledges our SYN and not our FIN — ⚠ **one short**, which is what a
     * peer that never got the close would send. */
    struct tcp_header short_of_it =
        a_segment(TCP_CONTROL_ACK, their_fin + 1u, held->iss + 1u);
    struct handshake_outcome outcome = receive(&world, &short_of_it);

    if (outcome.reason != HANDSHAKE_REASON_ACKNOWLEDGMENT_WE_ARE_NOT_WAITING_FOR ||
        world.counts.closed != 0) {
        fprintf(stderr, "  an acknowledgment one short of our close: reason %d, "
                        "closed %lu\n", (int)outcome.reason, world.counts.closed);
        ok = false;
    }
    struct connection_id id = the_connection();
    if (connections_find(&world.connections, &id) == NULL ||
        held->state != CONNECTION_LAST_ACK) {
        fputs("  the connection was released on an acknowledgment that did not "
              "cover our close\n", stderr);
        ok = false;
    }
    /* ⚠ And the numbers reported for the sentence are the two that matter. */
    if (outcome.acknowledgment_we_had != held->iss + 1u ||
        outcome.acknowledgment_we_expected != held->iss + 2u) {
        fprintf(stderr, "  it acknowledged %lu and we report waiting for %lu\n",
                (unsigned long)outcome.acknowledgment_we_had,
                (unsigned long)outcome.acknowledgment_we_expected);
        ok = false;
    }
    return ok;
}

/* ⚠ Nobody acknowledging our close is not nobody confirming the handshake.
 * ⚠ **Two events, two reasons, two counters** — folding them together is the
 * defect hidetzu/tcpip-stack#59 had to undo. */
static bool case_nobody_acknowledging_our_close_is_its_own_ending(void)
{
    struct world world;
    a_world(&world);
    struct transmission_control_block *held = NULL;
    uint32_t their_fin = 0;
    if (!open_confirm_and_be_closed(&world, &held, &their_fin)) {
        return false;
    }

    bool ok = true;
    struct handshake_outcome outcome;
    enum handshake_due due =
        handshake_what_is_due(&world.connections,
                              at(HANDSHAKE_GIVE_UP_AFTER_MILLISECONDS), IPV4_TIME_TO_LIVE_WE_SEND, OUR_MAC,
                              world.reply, sizeof world.reply, &world.counts, &outcome);
    if (due != HANDSHAKE_GIVE_UP ||
        outcome.reason != HANDSHAKE_REASON_NOBODY_ACKNOWLEDGED_OUR_FIN) {
        fprintf(stderr, "  a close nobody acknowledged came back as %d, reason %d\n",
                (int)due, (int)outcome.reason);
        ok = false;
    }
    if (world.counts.never_acknowledged_our_fin != 1 || world.counts.given_up_on != 0) {
        fprintf(stderr, "  counted %lu unacknowledged closes and %lu given up on\n",
                world.counts.never_acknowledged_our_fin, world.counts.given_up_on);
        ok = false;
    }
    /* ⚠ Released, so the next SYN can open one. */
    struct connection_id id = the_connection();
    if (connections_find(&world.connections, &id) != NULL) {
        fputs("  the connection was not freed when we stopped waiting\n", stderr);
        ok = false;
    }

    /* ⚠ The other half, so this case is about which ending it was and not about
     * the timer: ⚠ **a handshake nobody confirms still lands on its own
     * reason.** */
    struct world opening;
    a_world(&opening);
    struct transmission_control_block *never_confirmed = NULL;
    if (!open_one(&opening, THEIR_ISN, &never_confirmed)) {
        return false;
    }
    struct handshake_outcome other;
    if (handshake_what_is_due(&opening.connections,
                              at(HANDSHAKE_GIVE_UP_AFTER_MILLISECONDS), IPV4_TIME_TO_LIVE_WE_SEND, OUR_MAC,
                              opening.reply, sizeof opening.reply, &opening.counts,
                              &other) != HANDSHAKE_GIVE_UP ||
        other.reason != HANDSHAKE_REASON_NOBODY_CONFIRMED_IT ||
        opening.counts.given_up_on != 1 ||
        opening.counts.never_acknowledged_our_fin != 0) {
        fprintf(stderr, "  a handshake nobody confirmed came back as reason %d\n",
                (int)other.reason);
        ok = false;
    }
    return ok;
}

/* ⚠ Ours, not the sender's: the close could not be built into the buffer we
 * were given. ⚠ **The connection is not claimed to have closed**, and
 * ⚠ **the block is not given back** — their FIN was read and `RCV.NXT` moved,
 * so forgetting it would make the next copy of that FIN look like a new
 * connection. */
static bool case_a_close_that_would_not_fit_is_counted_as_ours(void)
{
    struct world world;
    a_world(&world);
    struct transmission_control_block *held = NULL;
    if (!open_and_confirm(&world, &held)) {
        return false;
    }
    uint32_t their_fin = held->rcv_nxt;
    uint32_t snd_nxt_before = held->snd_nxt;

    bool ok = true;
    unsigned char no_room[ETHERNET_HEADER_BYTES + IPV4_FIXED_HEADER_BYTES];
    struct connection_id id = the_connection();
    struct tcp_header fin =
        a_segment(TCP_CONTROL_FIN | TCP_CONTROL_ACK, their_fin, held->iss + 1u);
    struct handshake_outcome outcome;
    handshake_receive(&fin, &id, OUR_PORT, at(0), IPV4_TIME_TO_LIVE_WE_SEND, THEIR_MAC, OUR_MAC, &world.connections,
                      no_room, sizeof no_room, &world.counts, &outcome);

    if (outcome.reason != HANDSHAKE_REASON_WE_COULD_NOT_BUILD_THE_REPLY ||
        world.counts.we_could_not_build_the_reply != 1) {
        fprintf(stderr, "  a close that would not fit came back as reason %d\n",
                (int)outcome.reason);
        ok = false;
    }
    if (outcome.reply_bytes != 0 || outcome.reply != HANDSHAKE_REPLY_NONE) {
        fprintf(stderr, "  %zu octets were reported for a close that would not fit\n",
                outcome.reply_bytes);
        ok = false;
    }
    /* ⚠ CLOSE-WAIT and not LAST-ACK: ⚠ **we have not closed our side**, and
     * `SND.NXT` must not have moved over a FIN that never left. */
    if (held->state != CONNECTION_CLOSE_WAIT || outcome.state != CONNECTION_CLOSE_WAIT ||
        held->snd_nxt != snd_nxt_before) {
        fprintf(stderr, "  state %d and SND.NXT %lu, from %lu\n", (int)held->state,
                (unsigned long)held->snd_nxt, (unsigned long)snd_nxt_before);
        ok = false;
    }
    /* ⚠ Their FIN was still read, and the block is still held. */
    if (!outcome.the_fin_was_read || held->rcv_nxt != their_fin + 1u ||
        connections_find(&world.connections, &id) == NULL) {
        fputs("  their FIN was forgotten when our close could not be built\n", stderr);
        ok = false;
    }
    return ok;
}

/* ⚠ Every reason on its own, and ⚠ each moves only its own count. */
static bool case_each_reason_moves_only_its_own_count(void)
{
    bool ok = true;

    /* ⚠ RFC 793: "Any acknowledgment is bad if it arrives on a connection still
     * in the LISTEN state." */
    {
        struct world world;
        a_world(&world);
        struct tcp_header ack = a_segment(TCP_CONTROL_ACK, THEIR_ISN, 1);
        struct handshake_outcome outcome = receive(&world, &ack);
        if (outcome.reason != HANDSHAKE_REASON_NO_CONNECTION_HELD ||
            world.counts.no_connection_held != 1 || world.counts.opened != 0) {
            fputs("  an acknowledgment with nothing held was not counted on its own\n",
                  stderr);
            ok = false;
        }
    }

    /* A SYN carrying an ACK does not open one either. */
    {
        struct world world;
        a_world(&world);
        struct tcp_header both =
            a_segment(TCP_CONTROL_SYN | TCP_CONTROL_ACK, THEIR_ISN, 1);
        struct handshake_outcome outcome = receive(&world, &both);
        if (outcome.reason != HANDSHAKE_REASON_NO_CONNECTION_HELD) {
            fputs("  a SYN carrying an ACK opened a connection\n", stderr);
            ok = false;
        }
    }

    /* Something we hold, in a state with no rule for it here. */
    {
        struct world world;
        a_world(&world);
        struct transmission_control_block *held = NULL;
        if (!open_one(&world, THEIR_ISN, &held)) {
            return false;
        }
        struct tcp_header bare = a_segment(0, THEIR_ISN + 1u, 0);
        struct handshake_outcome outcome = receive(&world, &bare);
        if (outcome.reason != HANDSHAKE_REASON_NOT_EXPECTED_IN_THIS_STATE ||
            world.counts.not_expected_in_this_state != 1) {
            fprintf(stderr, "  a segment with no control bits: reason %d\n",
                    (int)outcome.reason);
            ok = false;
        }
    }

    /* ⚠ Ours, not the sender's: the one block is already in use by somebody
     * else. */
    {
        struct connections connections;
        connections_forget_everything(&connections);
        struct handshake_counts counts;
        memset(&counts, 0, sizeof counts);

        struct connection_id other = the_connection();
        other.remote.port = THEIR_PORT + 1;
        struct transmission_control_block *taken = NULL;
        if (connections_take(&connections, &other, &counts.room, &taken) !=
            CONNECTION_TAKEN) {
            fputs("  the first connection could not be taken\n", stderr);
            return false;
        }

        struct connection_id id = the_connection();
        struct tcp_header syn = a_segment(TCP_CONTROL_SYN, THEIR_ISN, 0);
        unsigned char reply[256];
        struct handshake_outcome outcome;
        handshake_receive(&syn, &id, OUR_PORT, at(0), IPV4_TIME_TO_LIVE_WE_SEND, THEIR_MAC, OUR_MAC, &connections, reply,
                          sizeof reply, &counts, &outcome);
        if (outcome.reason != HANDSHAKE_REASON_NO_ROOM ||
            counts.room.refused_for_want_of_room != 1 || counts.opened != 0) {
            fprintf(stderr, "  a SYN with no room: reason %d, counted %lu\n",
                    (int)outcome.reason, counts.room.refused_for_want_of_room);
            ok = false;
        }
    }

    /* ⚠ A segment for a local port we do not answer for. */
    {
        struct connections connections;
        connections_forget_everything(&connections);
        struct handshake_counts counts;
        memset(&counts, 0, sizeof counts);
        struct connection_id id = the_connection();
        struct tcp_header syn = a_segment(TCP_CONTROL_SYN, THEIR_ISN, 0);
        unsigned char reply[256];
        struct handshake_outcome outcome;
        handshake_receive(&syn, &id, OUR_PORT + 1, at(0), IPV4_TIME_TO_LIVE_WE_SEND, THEIR_MAC, OUR_MAC, &connections,
                          reply, sizeof reply, &counts, &outcome);
        if (outcome.reason != HANDSHAKE_REASON_NO_CONNECTION_HELD ||
            counts.opened != 0) {
            fputs("  a SYN for a port we do not listen on opened a connection\n",
                  stderr);
            ok = false;
        }
    }
    return ok;
}

/* ⚠ The half hidetzu/tcpip-stack#42 could not prove: a block given back and
 * taken again must not hand the next connection what the last one left.
 * ⚠ Now that a block holds a state and four sequence numbers, ⚠ **there is
 * finally something that could leak.** */
static bool case_a_block_taken_again_holds_none_of_the_last_connections_numbers(void)
{
    struct connections connections;
    connections_forget_everything(&connections);
    struct handshake_counts counts;
    memset(&counts, 0, sizeof counts);

    struct connection_id first = the_connection();
    struct tcp_header syn = a_segment(TCP_CONTROL_SYN, THEIR_ISN, 0);
    unsigned char reply[256];
    struct handshake_outcome outcome;
    handshake_receive(&syn, &first, OUR_PORT, at(0), IPV4_TIME_TO_LIVE_WE_SEND, THEIR_MAC, OUR_MAC, &connections, reply,
                      sizeof reply, &counts, &outcome);

    struct transmission_control_block *block = connections_find(&connections, &first);
    if (block == NULL || block->state != CONNECTION_SYN_RECEIVED) {
        fputs("  the first connection did not reach SYN-RECEIVED\n", stderr);
        return false;
    }
    block->state = CONNECTION_ESTABLISHED;
    connections_release(&connections, block);

    struct connection_id second = the_connection();
    second.remote.port = THEIR_PORT + 1;
    struct transmission_control_block *again = NULL;
    if (connections_take(&connections, &second, &counts.room, &again) !=
        CONNECTION_TAKEN) {
        fputs("  a connection could not be taken after a release\n", stderr);
        return false;
    }

    bool ok = true;
    if (again->state != CONNECTION_LISTEN) {
        fprintf(stderr, "  the block came back in state %d, not LISTEN\n",
                (int)again->state);
        ok = false;
    }
    if (again->iss != 0 || again->snd_una != 0 || again->snd_nxt != 0 ||
        again->irs != 0 || again->rcv_nxt != 0) {
        fprintf(stderr, "  the block came back holding the last connection's numbers: "
                        "iss 0x%08lx irs 0x%08lx\n",
                (unsigned long)again->iss, (unsigned long)again->irs);
        ok = false;
    }
    return ok;
}

/* ⚠ The schedule, asserted ⚠ **with no clock and no waiting** — which is what
 * hidetzu/tcpip-stack#56 bought and is the reason this case can exist at all.
 *
 * ⚠ RFC 793: "send the segment at the front of the retransmission queue again,
 * reinitialize the retransmission timer, and return." ⚠ So the interval is
 * measured from each send, ⚠ **not from when the connection opened.** */
static bool case_the_answer_is_due_a_second_after_each_send(void)
{
    struct world world;
    a_world(&world);
    struct transmission_control_block *held = NULL;
    if (!open_one(&world, THEIR_ISN, &held)) {
        return false;
    }
    struct handshake_outcome outcome;
    bool ok = true;

#define DUE_AT(milliseconds, expected, what)                                       \
    do {                                                                           \
        enum handshake_due got = handshake_what_is_due(&world.connections,          \
                                                       at(milliseconds),           \
                                                       IPV4_TIME_TO_LIVE_WE_SEND,  \
                                                       OUR_MAC,                    \
                                                       world.reply,                \
                                                       sizeof world.reply,         \
                                                       &world.counts, &outcome);   \
        if (got != (expected)) {                                                   \
            fprintf(stderr, "  %s: got %d, expected %d\n", what, (int)got,           \
                    (int)(expected));                                              \
            ok = false;                                                            \
        }                                                                          \
    } while (0)

    DUE_AT(0, HANDSHAKE_NOTHING_DUE, "the moment it opened");
    DUE_AT(999, HANDSHAKE_NOTHING_DUE, "one millisecond before the first second");
    DUE_AT(1000, HANDSHAKE_ANSWER_AGAIN, "exactly a second after it opened");
    /* ⚠ And now the timer has moved: nothing is due again until a second after
     * THAT, not a second after the connection opened. */
    DUE_AT(1001, HANDSHAKE_NOTHING_DUE, "just after answering again");
    DUE_AT(1999, HANDSHAKE_NOTHING_DUE, "one millisecond before the next second");
    DUE_AT(2000, HANDSHAKE_ANSWER_AGAIN, "a second after answering again");
    DUE_AT(2001, HANDSHAKE_NOTHING_DUE, "just after answering a second time");

    /* ⚠ Answering again is not counted here: a reply that was built is not a
     * reply that left (`CLAUDE.md` §1). */
    if (world.counts.given_up_on != 0) {
        fputs("  answering again was counted as giving up\n", stderr);
        ok = false;
    }
#undef DUE_AT
    return ok;
}

/* ⚠ RFC 793's USER TIMEOUT: "delete the TCB, enter the CLOSED state and
 * return." ⚠ Three seconds is ours and has no grounds in the document
 * (ADR 0019). */
static bool case_a_connection_nobody_confirms_is_given_up_on(void)
{
    struct world world;
    a_world(&world);
    struct transmission_control_block *held = NULL;
    if (!open_one(&world, THEIR_ISN, &held)) {
        return false;
    }
    struct handshake_outcome outcome;
    bool ok = true;

    /* ⚠ One millisecond before: still waiting, not given up on. */
    if (handshake_what_is_due(&world.connections, at(2999), IPV4_TIME_TO_LIVE_WE_SEND, OUR_MAC, world.reply,
                                          sizeof world.reply, &world.counts, &outcome)
        == HANDSHAKE_GIVE_UP) {
        fputs("  it was given up on a millisecond early\n", stderr);
        ok = false;
    }

    /* ⚠ Exactly at three seconds. ⚠ Both timers are due here, and ⚠ **giving up
     * wins** — the other order would send an answer nobody waits for. */
    if (handshake_what_is_due(&world.connections, at(3000), IPV4_TIME_TO_LIVE_WE_SEND, OUR_MAC, world.reply,
                                          sizeof world.reply, &world.counts, &outcome)
        != HANDSHAKE_GIVE_UP) {
        fputs("  it was not given up on at three seconds\n", stderr);
        return false;
    }
    if (outcome.reason != HANDSHAKE_REASON_NOBODY_CONFIRMED_IT ||
        world.counts.given_up_on != 1) {
        fprintf(stderr, "  giving up: reason %d, counted %lu\n", (int)outcome.reason,
                world.counts.given_up_on);
        ok = false;
    }
    /* ⚠ The connection was released, so ⚠ the next SYN can open one — there is
     * room for exactly one. */
    struct connection_id id = the_connection();
    if (connections_find(&world.connections, &id) != NULL) {
        fputs("  the connection was kept after being given up on\n", stderr);
        ok = false;
    }
    /* ⚠ And nothing is due any more. */
    if (handshake_what_is_due(&world.connections, at(9999), IPV4_TIME_TO_LIVE_WE_SEND, OUR_MAC, world.reply,
                                          sizeof world.reply, &world.counts, &outcome)
        != HANDSHAKE_NOTHING_DUE) {
        fputs("  something was still due after giving up\n", stderr);
        ok = false;
    }
    if (world.counts.given_up_on != 1) {
        fputs("  giving up was counted more than once\n", stderr);
        ok = false;
    }
    return ok;
}

/* ⚠ A connection that IS confirmed waits for nothing. ⚠ Without this, the
 * schedule would pass for one that answers again for ever. */
static bool case_a_confirmed_connection_is_due_nothing(void)
{
    struct world world;
    a_world(&world);
    struct transmission_control_block *held = NULL;
    if (!open_one(&world, THEIR_ISN, &held)) {
        return false;
    }
    struct tcp_header ack =
        a_segment(TCP_CONTROL_ACK, THEIR_ISN + 1u, handshake_initial_send_sequence(at(0)) + 1u);
    struct handshake_outcome outcome = receive(&world, &ack);
    if (outcome.state != CONNECTION_ESTABLISHED) {
        fputs("  the connection did not reach ESTABLISHED\n", stderr);
        return false;
    }

    bool ok = true;
    static const uint64_t much_later[] = { 1000, 2000, 3000, 60000 };
    for (size_t i = 0; i < sizeof much_later / sizeof much_later[0]; i++) {
        if (handshake_what_is_due(&world.connections, at(much_later[i]), IPV4_TIME_TO_LIVE_WE_SEND, OUR_MAC, world.reply,
                                  sizeof world.reply, &world.counts, &outcome) != HANDSHAKE_NOTHING_DUE) {
            fprintf(stderr, "  something was due %llu ms after it was confirmed\n",
                    (unsigned long long)much_later[i]);
            ok = false;
        }
    }
    if (world.counts.given_up_on != 0) {
        fputs("  a confirmed connection was given up on\n", stderr);
        ok = false;
    }
    /* ⚠ And nothing is waiting, so a caller has no deadline to wait for. */
    struct moment due;
    if (handshake_next_moment(&world.connections, &due)) {
        fputs("  a confirmed connection still names a moment to wait for\n", stderr);
        ok = false;
    }
    return ok;
}

/* ⚠ `man 2 clock_gettime`: "successive calls may ... return identical
 * (not-increased) time values." ⚠ **That is the document's word, and this is
 * what it must not do**: neither become due on every call, nor never again. */
static bool case_a_clock_that_does_not_move_neither_spins_nor_stops(void)
{
    struct world world;
    a_world(&world);
    struct transmission_control_block *held = NULL;
    if (!open_one(&world, THEIR_ISN, &held)) {
        return false;
    }
    struct handshake_outcome outcome;
    bool ok = true;

    /* ⚠ Due once at exactly a second. */
    if (handshake_what_is_due(&world.connections, at(1000), IPV4_TIME_TO_LIVE_WE_SEND, OUR_MAC, world.reply,
                                          sizeof world.reply, &world.counts, &outcome)
        != HANDSHAKE_ANSWER_AGAIN) {
        fputs("  nothing was due at a second\n", stderr);
        return false;
    }
    /* ⚠ And NOT due again at the same moment, however many times it is asked.
     * ⚠ A caller in a loop would otherwise send for ever without the clock
     * moving — a busy loop, not a wait. */
    for (int again = 0; again < 5; again++) {
        if (handshake_what_is_due(&world.connections, at(1000), IPV4_TIME_TO_LIVE_WE_SEND, OUR_MAC, world.reply,
                                          sizeof world.reply, &world.counts, &outcome)
            != HANDSHAKE_NOTHING_DUE) {
            fprintf(stderr, "  it was due again at the same moment, ask %d\n", again + 1);
            ok = false;
            break;
        }
    }
    /* ⚠ The other half: once the clock does move, it becomes due again. ⚠ Without
     * this the loop above would pass for a schedule that never fires twice. */
    if (handshake_what_is_due(&world.connections, at(2000), IPV4_TIME_TO_LIVE_WE_SEND, OUR_MAC, world.reply,
                                          sizeof world.reply, &world.counts, &outcome)
        != HANDSHAKE_ANSWER_AGAIN) {
        fputs("  it never became due again once the clock moved\n", stderr);
        ok = false;
    }
    return ok;
}

/* ⚠ What a caller about to wait is told. ⚠ The earlier of the two, and nothing
 * at all when nothing is waiting. */
static bool case_the_next_moment_is_the_earlier_of_the_two(void)
{
    struct world world;
    a_world(&world);
    struct moment due;

    /* ⚠ Nothing held: nothing to wait for. */
    if (handshake_next_moment(&world.connections, &due)) {
        fputs("  an empty set named a moment to wait for\n", stderr);
        return false;
    }

    struct transmission_control_block *held = NULL;
    if (!open_one(&world, THEIR_ISN, &held)) {
        return false;
    }
    bool ok = true;
    if (!handshake_next_moment(&world.connections, &due)) {
        fputs("  a waiting connection named no moment\n", stderr);
        return false;
    }
    /* ⚠ A second, not three: answering again comes first. */
    if (due.nanoseconds != at(1000).nanoseconds) {
        fprintf(stderr, "  the next moment is %llu ns, expected %llu\n",
                (unsigned long long)due.nanoseconds,
                (unsigned long long)at(1000).nanoseconds);
        ok = false;
    }

    /* ⚠ After the last answer, the give-up moment is the earlier one. */
    struct handshake_outcome outcome;
    handshake_what_is_due(&world.connections, at(2500), IPV4_TIME_TO_LIVE_WE_SEND, OUR_MAC, world.reply,
                                          sizeof world.reply, &world.counts, &outcome);
    if (!handshake_next_moment(&world.connections, &due)) {
        fputs("  it stopped naming a moment while still waiting\n", stderr);
        return false;
    }
    if (due.nanoseconds != at(3000).nanoseconds) {
        fprintf(stderr, "  after the last answer the next moment is %llu ns, "
                        "expected the give-up at %llu\n",
                (unsigned long long)due.nanoseconds,
                (unsigned long long)at(3000).nanoseconds);
        ok = false;
    }
    return ok;
}

/* ⚠ The answer that goes out again is ⚠ **the same answer**, octet for octet.
 * ⚠ Nothing is re-chosen — the reason hidetzu/tcpip-stack#43 asserted that a
 * retransmitted SYN changes nothing, ⚠ and the same reason in the other
 * direction: a peer that did get the first must not be told a different number.
 *
 * ⚠ And it is addressed from what the connection remembers, ⚠ **because a
 * retransmission has no arriving frame to read a hardware address from.** */
static bool case_the_answer_that_goes_out_again_is_the_same_answer(void)
{
    struct world world;
    a_world(&world);

    struct tcp_header syn = a_segment(TCP_CONTROL_SYN, THEIR_ISN, 0);
    struct handshake_outcome first = receive(&world, &syn);
    if (first.decision != HANDSHAKE_MOVED || first.reply_bytes == 0) {
        fputs("  the SYN was not answered\n", stderr);
        return false;
    }
    unsigned char as_first_sent[256];
    size_t first_bytes = first.reply_bytes;
    memcpy(as_first_sent, world.reply, first_bytes);

    bool ok = true;
    for (int again = 1; again <= 2; again++) {
        memset(world.reply, 0xaa, sizeof world.reply);
        struct handshake_outcome outcome;
        enum handshake_due due =
            handshake_what_is_due(&world.connections, at((uint64_t)again * 1000u),
                                  IPV4_TIME_TO_LIVE_WE_SEND, OUR_MAC, world.reply, sizeof world.reply,
                                  &world.counts, &outcome);
        if (due != HANDSHAKE_ANSWER_AGAIN) {
            fprintf(stderr, "  answer %d was not due\n", again);
            return false;
        }
        if (outcome.reason != HANDSHAKE_REASON_THE_ANSWER_WENT_OUT_AGAIN) {
            fprintf(stderr, "  answer %d came back with reason %d\n", again,
                    (int)outcome.reason);
            ok = false;
        }
        if (outcome.reply_bytes != first_bytes ||
            memcmp(world.reply, as_first_sent, first_bytes) != 0) {
            fprintf(stderr, "  answer %d is not the same octets as the first\n", again);
            ok = false;
        }
    }

    /* ⚠ Answering again is not counted here: ⚠ an answer that was built is not
     * an answer that left, and the caller counts what the wire took. */
    if (world.counts.answered_again != 0) {
        fputs("  answering again was counted before anything left\n", stderr);
        ok = false;
    }
    return ok;
}

/* ⚠ The two events that shared a reason until hidetzu/tcpip-stack#59, ⚠ **and
 * the sentence printed for one of them was false.**
 *
 * ⚠ A retransmitted SYN arriving is them asking again; ⚠ our timer firing is us
 * answering again. ⚠ **Different reasons, so the two can never be one number**
 * (`.claude/rules/c.md`). */
static bool case_them_asking_again_is_not_us_answering_again(void)
{
    struct world world;
    a_world(&world);
    struct transmission_control_block *held = NULL;
    if (!open_one(&world, THEIR_ISN, &held)) {
        return false;
    }

    bool ok = true;

    /* Them: a retransmitted SYN. */
    struct tcp_header again = a_segment(TCP_CONTROL_SYN, THEIR_ISN, 0);
    struct handshake_outcome theirs = receive(&world, &again);
    if (theirs.reason != HANDSHAKE_REASON_ASKED_AGAIN) {
        fprintf(stderr, "  a retransmitted SYN came back with reason %d\n",
                (int)theirs.reason);
        ok = false;
    }

    /* Us: the timer. */
    struct handshake_outcome ours;
    handshake_what_is_due(&world.connections, at(1000), IPV4_TIME_TO_LIVE_WE_SEND, OUR_MAC, world.reply,
                          sizeof world.reply, &world.counts, &ours);
    if (ours.reason != HANDSHAKE_REASON_THE_ANSWER_WENT_OUT_AGAIN) {
        fprintf(stderr, "  our own timer came back with reason %d\n", (int)ours.reason);
        ok = false;
    }

    /* ⚠ And the two reasons are not the same value, ⚠ **which is what stops one
     * number standing for both.** */
    if (theirs.reason == ours.reason) {
        fputs("  them asking again and us answering again share a reason\n", stderr);
        ok = false;
    }
    if (world.counts.asked_again != 1) {
        fprintf(stderr, "  they asked again %lu times, expected 1\n",
                world.counts.asked_again);
        ok = false;
    }
    return ok;
}

static const struct test_case cases[] = {
    { "a_syn_opens_a_connection_and_sets_every_number",
      case_a_syn_opens_a_connection_and_sets_every_number },
    { "only_an_acknowledgment_in_the_window_establishes",
      case_only_an_acknowledgment_in_the_window_establishes },
    { "the_window_still_works_where_the_sequence_space_wraps",
      case_the_window_still_works_where_the_sequence_space_wraps },
    { "a_retransmitted_syn_changes_nothing", case_a_retransmitted_syn_changes_nothing },
    { "the_answer_is_the_one_the_document_describes",
      case_the_answer_is_the_one_the_document_describes },
    { "nothing_is_answered_except_a_syn_that_opened_one",
      case_nothing_is_answered_except_a_syn_that_opened_one },
    { "an_answer_that_would_not_fit_is_counted_as_ours",
      case_an_answer_that_would_not_fit_is_counted_as_ours },
    { "each_reason_moves_only_its_own_count", case_each_reason_moves_only_its_own_count },
    { "data_on_an_open_connection_is_taken_and_discarded",
      case_data_on_an_open_connection_is_taken_and_discarded },
    { "the_acknowledgment_for_data_is_the_one_the_document_describes",
      case_the_acknowledgment_for_data_is_the_one_the_document_describes },
    { "nothing_is_acknowledged_for_data_the_window_did_not_cover",
      case_nothing_is_acknowledged_for_data_the_window_did_not_cover },
    { "a_segment_we_refuse_draws_an_acknowledgment",
      case_a_segment_we_refuse_draws_an_acknowledgment },
    { "only_a_refused_data_segment_or_fin_draws_one",
      case_only_a_refused_data_segment_or_fin_draws_one },
    { "an_acknowledgment_that_would_not_fit_is_counted_as_ours",
      case_an_acknowledgment_that_would_not_fit_is_counted_as_ours },
    { "data_outside_the_window_is_refused_and_nothing_moves",
      case_data_outside_the_window_is_refused_and_nothing_moves },
    { "a_segment_longer_than_the_window_is_taken_a_window_at_a_time",
      case_a_segment_longer_than_the_window_is_taken_a_window_at_a_time },
    { "data_riding_the_acknowledgment_that_opens_it_is_counted",
      case_data_riding_the_acknowledgment_that_opens_it_is_counted },
    { "a_segment_carrying_no_data_is_still_not_expected",
      case_a_segment_carrying_no_data_is_still_not_expected },
    { "a_fin_moves_the_connection_to_close_wait",
      case_a_fin_moves_the_connection_to_close_wait },
    { "a_fin_sits_after_the_data_it_rides_with",
      case_a_fin_sits_after_the_data_it_rides_with },
    { "a_fin_we_have_already_read_is_not_read_again",
      case_a_fin_we_have_already_read_is_not_read_again },
    { "a_fin_naming_no_connection_we_hold_is_its_own_outcome",
      case_a_fin_naming_no_connection_we_hold_is_its_own_outcome },
    { "a_fin_with_no_acknowledgment_closes_nothing",
      case_a_fin_with_no_acknowledgment_closes_nothing },
    { "one_segment_can_open_a_connection_and_close_it",
      case_one_segment_can_open_a_connection_and_close_it },
    { "a_fin_is_read_where_the_sequence_space_wraps",
      case_a_fin_is_read_where_the_sequence_space_wraps },
    { "our_close_is_the_segment_the_document_describes",
      case_our_close_is_the_segment_the_document_describes },
    { "every_segment_we_build_carries_the_same_window",
      case_every_segment_we_build_carries_the_same_window },
    { "a_segment_the_window_covers_is_taken_whole",
      case_a_segment_the_window_covers_is_taken_whole },
    { "a_duplicate_and_a_segment_ahead_are_told_apart_at_the_wrap",
      case_a_duplicate_and_a_segment_ahead_are_told_apart_at_the_wrap },
    { "the_time_to_live_we_send_with_is_the_callers",
      case_the_time_to_live_we_send_with_is_the_callers },
    { "the_initial_sequence_number_follows_the_clock",
      case_the_initial_sequence_number_follows_the_clock },
    { "a_reset_ends_the_connection", case_a_reset_ends_the_connection },
    { "a_reset_outside_the_window_changes_nothing",
      case_a_reset_outside_the_window_changes_nothing },
    { "an_urgent_segment_is_counted_and_said",
      case_an_urgent_segment_is_counted_and_said },
    { "a_segment_addressed_to_everyone_is_refused",
      case_a_segment_addressed_to_everyone_is_refused },
    { "a_syn_from_an_impossible_source_is_refused",
      case_a_syn_from_an_impossible_source_is_refused },
    { "nothing_is_sent_for_a_connection_that_has_not_seen_a_fin",
      case_nothing_is_sent_for_a_connection_that_has_not_seen_a_fin },
    { "what_goes_out_again_for_a_closing_connection_is_our_close",
      case_what_goes_out_again_for_a_closing_connection_is_our_close },
    { "the_closing_timers_run_from_when_our_close_went_out",
      case_the_closing_timers_run_from_when_our_close_went_out },
    { "the_acknowledgment_of_our_close_finishes_the_connection",
      case_the_acknowledgment_of_our_close_finishes_the_connection },
    { "an_acknowledgment_that_does_not_cover_our_close_finishes_nothing",
      case_an_acknowledgment_that_does_not_cover_our_close_finishes_nothing },
    { "nobody_acknowledging_our_close_is_its_own_ending",
      case_nobody_acknowledging_our_close_is_its_own_ending },
    { "a_close_that_would_not_fit_is_counted_as_ours",
      case_a_close_that_would_not_fit_is_counted_as_ours },
    { "the_answer_is_due_a_second_after_each_send",
      case_the_answer_is_due_a_second_after_each_send },
    { "a_connection_nobody_confirms_is_given_up_on",
      case_a_connection_nobody_confirms_is_given_up_on },
    { "a_confirmed_connection_is_due_nothing",
      case_a_confirmed_connection_is_due_nothing },
    { "a_clock_that_does_not_move_neither_spins_nor_stops",
      case_a_clock_that_does_not_move_neither_spins_nor_stops },
    { "the_next_moment_is_the_earlier_of_the_two",
      case_the_next_moment_is_the_earlier_of_the_two },
    { "the_answer_that_goes_out_again_is_the_same_answer",
      case_the_answer_that_goes_out_again_is_the_same_answer },
    { "them_asking_again_is_not_us_answering_again",
      case_them_asking_again_is_not_us_answering_again },
    { "a_block_taken_again_holds_none_of_the_last_connections_numbers",
      case_a_block_taken_again_holds_none_of_the_last_connections_numbers },
};

int main(int argc, char **argv)
{
    return check_main("handshake", cases, sizeof cases / sizeof cases[0], argc, argv);
}
