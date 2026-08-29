/* Parse — an ICMP echo message, checked and in host terms, and the reply to it.
 *
 * ⚠ Nothing here writes a word a human reads, and nothing here decides whether
 * to answer (`.claude/rules/layers.md`). A message that is not accepted comes
 * back as a reason; `report.c` is the only place that becomes a sentence, and
 * hidetzu/tcpip-stack#35 is what decides.
 *
 * ⚠ Read and build live in one file so the offsets exist once (ADR 0007).
 *
 * ⚠ The names below are RFC 792's own, read on 2026-08-28 from rfc-editor.org
 * and cross-checked against the copy at datatracker.ietf.org. ⚠ Both agreed,
 * and this is what they say (ADR 0011):
 *
 *     Type: 8 for echo message; 0 for echo reply message.
 *     Code: 0
 *     Checksum: The checksum is the 16-bit ones's complement of the one's
 *       complement sum of the ICMP message starting with the ICMP Type.
 *     Identifier: If code = 0, an identifier to aid in matching echos and
 *       replies, may be zero.
 *     Sequence Number: If code = 0, a sequence number to aid in matching echos
 *       and replies, may be zero.
 *     Description: The data received in the echo message must be returned in
 *       the echo reply message.
 *
 *     To form an echo reply message, the source and destination addresses are
 *     simply reversed, the type code changed to 0, and the checksum recomputed.
 *
 * ⚠ RFC 792 uses no RFC 2119 keywords. ⚠ So nothing here or in any wording
 * built on it may say the RFC requires something (`CLAUDE.md` §1).
 *
 * ⚠ "the source and destination addresses are simply reversed" is about the
 * IPv4 addresses, which are not in this file. ⚠ What the document leaves for
 * an ICMP builder to do is the type and the checksum, and that is all this one
 * does. */
#ifndef ICMP_H
#define ICMP_H

#include <stddef.h>
#include <stdint.h>

/* Type, Code, Checksum, Identifier and Sequence Number, before Data begins.
 * ⚠ Counted off the diagram in RFC 792, not assumed. */
#define ICMP_FIXED_BYTES 8

/* ⚠ RFC 792's own values, quoted above: "8 for echo message; 0 for echo reply
 * message", and "Code: 0". */
#define ICMP_TYPE_ECHO 8u
#define ICMP_TYPE_ECHO_REPLY 0u
#define ICMP_CODE_ECHO 0u

/* RFC 792's error message types, ⚠ **read off its own diagrams**: Destination
 * Unreachable gives "Type: 3", Source Quench "4", Time Exceeded "11" and
 * Parameter Problem "12". */
/* The least an error message can carry back and still name anything.
 *
 * ⚠ RFC 792: "The internet header plus the first 64 bits of the original
 * datagram's data." ⚠ **An internet header with no options is twenty octets and
 * 64 bits is eight** — ⚠ **and the ports a match needs are inside those eight**:
 * "If a higher level protocol uses port numbers, they are assumed to be in the
 * first 64 data bits."
 *
 * ⚠ **Not `IPV4_FIXED_HEADER_BYTES + 8` written here**: `src/icmp.c` deliberately
 * knows nothing about what a datagram carries (ADR 0007), ⚠ **and pulling
 * `ipv4.h` in to reach one constant would give it that knowledge.** */
#define ICMP_CARRIED_LEAST_BYTES 28u

#define ICMP_TYPE_DESTINATION_UNREACHABLE 3u
#define ICMP_TYPE_SOURCE_QUENCH 4u
#define ICMP_TYPE_TIME_EXCEEDED 11u
#define ICMP_TYPE_PARAMETER_PROBLEM 12u

/* What an error means for a connection.
 *
 * ⚠ RFC 9293 §3.9.2.2 classifies them and ⚠ **this enum is that classification
 * and nothing more** — ⚠ what to DO about each is the State layer's
 * (`.claude/rules/layers.md`). */
enum icmp_error_class {
    /* ⚠ "TCP implementations MUST silently discard any received ICMP Source
     * Quench messages (MUST-55)." */
    ICMP_ERROR_SOURCE_QUENCH = 0,

    /* ⚠ "For IPv4 ICMP, these include: Destination Unreachable -- codes 0, 1, 5;
     * Time Exceeded -- codes 0, 1; and Parameter Problem." ⚠ "a TCP
     * implementation MUST NOT abort the connection (MUST-56)". */
    ICMP_ERROR_SOFT,

    /* ⚠ "For ICMP these include Destination Unreachable -- codes 2-4." ⚠ "These
     * are hard error conditions, so TCP implementations SHOULD abort the
     * connection (SHLD-26)." */
    ICMP_ERROR_HARD,

    /* ⚠ **The document classifies some codes and not others.** ⚠ Destination
     * Unreachable has sixteen codes and §3.9.2.2 names six; ⚠ Time Exceeded's
     * two are named and it has no others, ⚠ **but a sender may still put
     * something else there.**
     *
     * ⚠ **Silence in an RFC is not permission and it is not a class**
     * (`CLAUDE.md` §1). ⚠ So an unclassified error is its own answer:
     * ⚠ **counted, said, and the connection is left alone** — ⚠ which is the
     * safe direction and is said to be a choice rather than a reading. */
    ICMP_ERROR_NOT_CLASSIFIED
};

/* Which class this type and code fall in.
 *
 * ⚠ **Pure**: no fd, no clock, no packet. ⚠ It is handed two numbers the Parse
 * layer already validated. */
enum icmp_error_class icmp_class_of_error(uint8_t type, uint8_t code);

/* An error message, read into host terms.
 *
 * ⚠ **`carried` points into the caller's frame** and ⚠ **lives exactly as long
 * as that does** (`.claude/rules/c.md`). ⚠ It is the internet header of the
 * datagram that caused the error, followed by at least the first 64 bits of its
 * data — ⚠ RFC 792: "This data is used by the host to match the message to the
 * appropriate process." */
struct icmp_error {
    uint8_t type;
    uint8_t code;
    const uint8_t *carried;
    size_t carried_bytes;
};

/* Why an error message was not read. ⚠ An enum never reaches a human. */
enum icmp_error_parse {
    ICMP_ERROR_PARSE_OK = 0,

    /* ⚠ Fewer octets than the fixed fields need, ⚠ **or fewer carried back than
     * RFC 792 promises**: "The internet header plus the first 64 bits". ⚠ The
     * sender is wrong either way, ⚠ **and this is not the same as a Type we do
     * not act on.** */
    ICMP_ERROR_PARSE_MALFORMED,

    /* ⚠ Well formed and not an error message at all — an echo, a reply, or
     * anything else. ⚠ **The sender is fine.** */
    ICMP_ERROR_PARSE_NOT_AN_ERROR,

    /* ⚠ Its own answer, exactly as it is for an echo: ⚠ **something changed it,
     * or it was never right.** */
    ICMP_ERROR_PARSE_CHECKSUM_DISAGREES
};

/* Read an ICMP error message.
 *
 * ⚠ `message_bytes` is what was actually read, ⚠ **never what a header claims**
 * (`.claude/rules/c.md`). ⚠ Everything here is untrusted input, ⚠ **including
 * the internet header it quotes back at us.** */
enum icmp_error_parse icmp_parse_error(const uint8_t *message, size_t message_bytes,
                                       struct icmp_error *error);

/* Why a message was not accepted. ⚠ An enum never reaches a human
 * (`CLAUDE.md` §4). */
enum icmp_parse {
    ICMP_PARSE_OK = 0,

    /* ⚠ Malformed: the sender is wrong. ⚠ Two inputs land here — fewer octets
     * than the fixed fields need, and ⚠ a Code that is not 0 in an echo
     * message, which RFC 792 gives as `Code: 0`
     * (hidetzu/tcpip-stack#34 Owner Decision 1).
     *
     * ⚠ The document does not say to reject such a message. ⚠ That the sender
     * broke what it states is our reading, and ADR 0011 says so. */
    ICMP_PARSE_MALFORMED,

    /* ⚠ Its own answer, folded into neither of the others. The message is well
     * formed and its checksum agrees; ⚠ its Type is not one we act on — which
     * ⚠ includes an echo reply (hidetzu/tcpip-stack#34 Owner Decision 2).
     * ⚠ The sender is fine. */
    ICMP_PARSE_TYPE_NOT_HANDLED,

    /* ⚠ Its own answer. ⚠ A message whose checksum does not agree is not one we
     * may act on, and it is not the sender being wrong about the format —
     * ⚠ something changed it, or it was never right. */
    ICMP_PARSE_CHECKSUM_DISAGREES
};

struct icmp_echo {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint16_t identifier;
    uint16_t sequence_number;

    /* ⚠ Data is not copied. ⚠ Owner: the caller's buffer — this points into the
     * octets handed to `icmp_parse_echo`, and it lives exactly as long as they
     * do (`.claude/rules/c.md`). ⚠ A message of exactly the fixed fields leaves
     * `data_bytes` at 0, and `data` one past the last octet, which is a pointer
     * that may be held and never read.
     *
     * ⚠ Why not copied: RFC 792 puts no limit on how long Data is, and a fixed
     * array here would be a limit this file invented. */
    const uint8_t *data;
    size_t data_bytes;
};

/* Read one ICMP echo message.
 *
 * `message` is the octets that followed the internet header, and
 * `message_bytes` is ⚠ what was actually read, never what anything claims about
 * itself (`.claude/rules/c.md`). `echo` must not be NULL.
 *
 * ⚠ *echo is zeroed first, and the five fixed fields are filled whenever the 8
 * octets were there — including for the answers that decline the message,
 * because those fields were read perfectly well.
 *
 * ⚠ The order the answers are decided in, and why it is this order (ADR 0011):
 *
 *     fewer octets than the fixed fields   ⚠ nothing can be read at all
 *     the checksum does not agree          ⚠ before any field's content is
 *                                            judged: blaming the sender for
 *                                            octets that were corrupted in
 *                                            flight would be the wrong answer
 *     the Type is not 8                    ⚠ Code's meaning is given only for
 *                                            an echo message, so the Type has
 *                                            to be settled before it
 *     the Code is not 0                    malformed
 *     otherwise                            accepted */
enum icmp_parse icmp_parse_echo(const uint8_t *message, size_t message_bytes,
                                struct icmp_echo *echo);

/* Why a reply was not built. ⚠ An enum never reaches a human (`CLAUDE.md` §4). */
enum icmp_build {
    ICMP_BUILD_OK = 0,

    /* ⚠ The caller's buffer cannot hold the whole reply. ⚠ Refused, never
     * truncated: an echo reply missing the end of its Data is not the message
     * RFC 792 describes, and a caller told it succeeded would count a message
     * that was never whole (`.claude/rules/c.md`). */
    ICMP_BUILD_BUFFER_TOO_SMALL
};

/* Build the echo reply to `request`, into a caller-supplied buffer.
 *
 * `message_bytes` is what the buffer actually holds, and ⚠ not one octet is
 * written unless the whole reply fits. On OK, *reply_bytes is how much was
 * written.
 *
 * ⚠ What changes and what does not, and none of it is guessed:
 *
 *     Type             0        ⚠ "the type code changed to 0"
 *     Checksum         computed ⚠ "and the checksum recomputed", with the field
 *                               zero while it is computed, as the document says
 *     Code             carried across
 *     Identifier       carried across
 *     Sequence Number  carried across
 *     Data             carried across, octet for octet ⚠ "The data received in
 *                      the echo message must be returned in the echo reply"
 *
 * ⚠ `request->data` may overlap the buffer being written; the copy is done in a
 * way that allows it.
 *
 * ⚠ This decides nothing. Whether a request deserves an answer at all belongs
 * to whoever calls this (hidetzu/tcpip-stack#35). */
enum icmp_build icmp_build_echo_reply(const struct icmp_echo *request,
                                      uint8_t *message, size_t message_bytes,
                                      size_t *reply_bytes);

#endif /* ICMP_H */
