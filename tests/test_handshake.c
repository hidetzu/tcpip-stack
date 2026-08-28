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
    handshake_receive(header, &id, OUR_PORT, world->now, THEIR_MAC, OUR_MAC, &world->connections,
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
    SAME(iss, HANDSHAKE_INITIAL_SEND_SEQUENCE);
    SAME(snd_una, HANDSHAKE_INITIAL_SEND_SEQUENCE);
    SAME(snd_nxt, HANDSHAKE_INITIAL_SEND_SEQUENCE + 1u);
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
                                          HANDSHAKE_INITIAL_SEND_SEQUENCE + inside[i]);
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
        uint32_t wrong = HANDSHAKE_INITIAL_SEND_SEQUENCE + outside[i];
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
            outcome.acknowledgment_we_expected != HANDSHAKE_INITIAL_SEND_SEQUENCE + 1u) {
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
        handshake_receive(&ack, &id, OUR_PORT, at(0), THEIR_MAC, OUR_MAC, &connections, reply,
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
    if (answer.source_port != OUR_PORT || answer.destination_port != THEIR_PORT) {
        fputs("  the answer's ports are not ours to theirs\n", stderr);
        ok = false;
    }
    /* ⚠ Owner Decision 3: zero, because nothing here accepts data. */
    if (answer.window != 0) {
        fprintf(stderr, "  the answer advertises a window of %u\n", answer.window);
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
        handshake_receive(&syn, &id, OUR_PORT, at(0), THEIR_MAC, OUR_MAC, &connections, reply,
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
    handshake_receive(&syn, &id, OUR_PORT, at(0), THEIR_MAC, OUR_MAC, &connections, reply,
                      needed, &counts, &outcome);
    if (outcome.decision != HANDSHAKE_MOVED || outcome.reply_bytes != needed) {
        fprintf(stderr, "  exactly %zu octets of room was declined, reason %d\n", needed,
                (int)outcome.reason);
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
        handshake_receive(&syn, &id, OUR_PORT, at(0), THEIR_MAC, OUR_MAC, &connections, reply,
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
        handshake_receive(&syn, &id, OUR_PORT + 1, at(0), THEIR_MAC, OUR_MAC, &connections,
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
    handshake_receive(&syn, &first, OUR_PORT, at(0), THEIR_MAC, OUR_MAC, &connections, reply,
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
    if (handshake_what_is_due(&world.connections, at(2999), &world.counts, &outcome)
        == HANDSHAKE_GIVE_UP) {
        fputs("  it was given up on a millisecond early\n", stderr);
        ok = false;
    }

    /* ⚠ Exactly at three seconds. ⚠ Both timers are due here, and ⚠ **giving up
     * wins** — the other order would send an answer nobody waits for. */
    if (handshake_what_is_due(&world.connections, at(3000), &world.counts, &outcome)
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
    if (handshake_what_is_due(&world.connections, at(9999), &world.counts, &outcome)
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
        a_segment(TCP_CONTROL_ACK, THEIR_ISN + 1u, HANDSHAKE_INITIAL_SEND_SEQUENCE + 1u);
    struct handshake_outcome outcome = receive(&world, &ack);
    if (outcome.state != CONNECTION_ESTABLISHED) {
        fputs("  the connection did not reach ESTABLISHED\n", stderr);
        return false;
    }

    bool ok = true;
    static const uint64_t much_later[] = { 1000, 2000, 3000, 60000 };
    for (size_t i = 0; i < sizeof much_later / sizeof much_later[0]; i++) {
        if (handshake_what_is_due(&world.connections, at(much_later[i]), &world.counts,
                                  &outcome) != HANDSHAKE_NOTHING_DUE) {
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
    if (handshake_what_is_due(&world.connections, at(1000), &world.counts, &outcome)
        != HANDSHAKE_ANSWER_AGAIN) {
        fputs("  nothing was due at a second\n", stderr);
        return false;
    }
    /* ⚠ And NOT due again at the same moment, however many times it is asked.
     * ⚠ A caller in a loop would otherwise send for ever without the clock
     * moving — a busy loop, not a wait. */
    for (int again = 0; again < 5; again++) {
        if (handshake_what_is_due(&world.connections, at(1000), &world.counts, &outcome)
            != HANDSHAKE_NOTHING_DUE) {
            fprintf(stderr, "  it was due again at the same moment, ask %d\n", again + 1);
            ok = false;
            break;
        }
    }
    /* ⚠ The other half: once the clock does move, it becomes due again. ⚠ Without
     * this the loop above would pass for a schedule that never fires twice. */
    if (handshake_what_is_due(&world.connections, at(2000), &world.counts, &outcome)
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
    handshake_what_is_due(&world.connections, at(2500), &world.counts, &outcome);
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
    { "a_block_taken_again_holds_none_of_the_last_connections_numbers",
      case_a_block_taken_again_holds_none_of_the_last_connections_numbers },
};

int main(int argc, char **argv)
{
    return check_main("handshake", cases, sizeof cases / sizeof cases[0], argc, argv);
}
