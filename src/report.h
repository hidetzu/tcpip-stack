/* Report — everything a human reads, and the only place any of it is written.
 *
 * ⚠ No decision is taken here and no byte of a frame is interpreted. This layer
 * is handed numbers and turns them into sentences (`.claude/rules/layers.md`).
 *
 * ⚠ The wording below is an owner decision (hidetzu/tcpip-stack#2). It is not
 * changed on our own judgement, and the checks assert it byte for byte. */
#ifndef REPORT_H
#define REPORT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "arp_responder.h"
#include "echo_responder.h"
#include "handshake.h"
#include "ethernet.h"
#include "tap.h"

void report_listening(FILE *out, const char *device_name);

/* What the device said when it was asked how large a frame it carries.
 *
 * ⚠ **Its own line, and the `listening on ...` line above is untouched.** ⚠ That
 * sentence is an owner decision (hidetzu/tcpip-stack#2) and the checks assert it
 * byte for byte; ⚠ **adding to it would change a decision this issue was not
 * given** (hidetzu/tcpip-stack#115).
 *
 * ⚠ **"bytes", not "MTU"**: the reader is told what it means, not what it is
 * called (`CLAUDE.md` §4). */
void report_mtu(FILE *out, const char *device_name, unsigned int mtu);

/* ⚠ No window can be promised for a device that carries frames of this size.
 *
 * ⚠ `too_large` tells the two apart: ⚠ **an MTU that leaves nothing after the
 * two headers, and one that leaves more than the sixteen bits RFC 793 gives the
 * field.** ⚠ They are opposite problems and the sentences say which
 * (`.claude/rules/layers.md`).
 *
 * ⚠ **Neither is reachable on a tap** — the kernel takes 68 .. 65521 — ⚠ **and
 * the line exists anyway**, because a refusal nobody can read is the same as a
 * silent one (`CLAUDE.md` §1). */
void report_no_window(FILE *out, const char *device_name, unsigned int mtu,
                      bool too_large);

/* ⚠ The device could not be asked, ⚠ **which is not the same as a small
 * device** (`CLAUDE.md` §1).
 *
 * ⚠ Says what happened, what was done instead, and ⚠ **that the number now in
 * use was chosen here rather than reported by the device** — ⚠ so nothing on
 * screen can be mistaken for a measurement (hidetzu/tcpip-stack#115 Owner
 * Decision 1: the stack carries on, and it says so).
 *
 * ⚠ `failure->errnum` is 0 when there was no errno to name — the syscalls
 * succeeded and the answer was not a size. ⚠ The line says that rather than
 * printing `Success`. */
void report_mtu_could_not_be_read(FILE *out, const char *device_name,
                                  const struct tap_failure *failure,
                                  unsigned int carrying_on_with);

/* `filled_buffer` is true when the read returned exactly as many bytes as the
 * buffer holds. ⚠ The length is then unknown, and the line says so rather than
 * printing it as if it were measured (`CLAUDE.md` §1). */
void report_frame(FILE *out, unsigned long frame_number, size_t bytes,
                  bool filled_buffer);

void report_frame_bytes(FILE *out, const uint8_t *frame, size_t bytes);

/* Counts of what the ethernet header turned out to be. ⚠ Each on its own: a
 * frame we could not read the header of is not a frame carrying a Length we do
 * not handle (`.claude/rules/c.md`). */
struct ethernet_counts {
    unsigned long malformed;
    unsigned long ieee_802_3_length;
    unsigned long length_type_undefined;
};

/* What the ethernet header of one frame holds, and how far it could be read.
 *
 * ⚠ Printed for every frame, always (hidetzu/tcpip-stack#10 Owner Decision 1).
 *
 * ⚠ The length/type is printed as the value it is and ⚠ never as a protocol
 * name: a name would be a lie for a VLAN-tagged frame (ADR 0003), and
 * ⚠ `0x0800` → IPv4 has never been taken from a standard in this repository.
 *
 * ⚠ Destination before source, matching the octets on the wire.
 *
 * ⚠ When the header could not be read, the line shows no octets that never
 * arrived. */
void report_ethernet_header(FILE *out, const uint8_t *frame, size_t bytes,
                            enum ethernet_parse answer,
                            const struct ethernet_header *header);

/* ⚠ Printed even when every count is zero. Hiding a zero would make "none
 * arrived" indistinguishable from "nobody counted" (`CLAUDE.md` §1). */
void report_ethernet_summary(FILE *out, const struct ethernet_counts *counts);

void report_read_failure(FILE *out, unsigned long frame_number,
                         const struct tap_failure *failure);

void report_summary(FILE *out, unsigned long frames_read, unsigned long read_errors);

/* ⚠ A timer running out is the absence of an answer, not an answer. The wording
 * says what we did and what reached us here, and claims nothing about what the
 * other side sent (`CLAUDE.md` §4-1). */
void report_timeout(FILE *out, const char *device_name, int timeout_ms,
                    unsigned long frames_read);

void report_attach_failure(FILE *out, const char *device_name,
                           const struct tap_failure *failure);

void report_wait_failure(FILE *out, const char *device_name,
                         const struct tap_failure *failure);

/* ⚠ The wait reported an error on the fd instead of a frame, and there is no
 * errno to name — ppoll succeeded (hidetzu/tcpip-stack#8 Owner Decision 1).
 *
 * ⚠ It says what the reader's next move is — waiting will not help — and
 * ⚠ claims no cause: POLLERR was only ever produced here by removing the
 * device, and nothing has measured that it cannot arise another way
 * (`CLAUDE.md` §1, §4-1). */
void report_device_gone(FILE *out, const char *device_name);

/* What was decided about one ARP packet, and why.
 *
 * ⚠ The decision and the reason are separate things and the line says both
 * (hidetzu/tcpip-stack#19 Owner Decision 2). ⚠ The reason is a sentence and
 * never the internal name: `unhandled-opcode` on a terminal is the `ERR_STATE_3`
 * `CLAUDE.md` §4 forbids.
 *
 * ⚠ Nothing here blames the sender for something that is ours: "its opcode is
 * not one we act on" is about us (`CLAUDE.md` §4-1). */
void report_arp_outcome(FILE *out, const struct arp_outcome *outcome,
                        const uint8_t *our_protocol_address);

/* ⚠ Each reason counted on its own, so a packet we could not read never looks
 * like one that was simply not addressed to us. */
void report_arp_summary(FILE *out, const struct arp_counts *counts);

/* What was decided about one IPv4 datagram, and why.
 *
 * ⚠ The same two-line shape ARP already prints, on purpose: a reader learns one
 * rule, not two (hidetzu/tcpip-stack#35 Owner Decision 1). ⚠ The decision and
 * the reason are separate things and the line says both.
 *
 * ⚠ Every reason is a sentence and never the internal name.
 *
 * ⚠ Nothing here blames the sender for something that is ours: "one we do not
 * read yet" and "we could not build the reply" are both about us, and they say
 * so (`CLAUDE.md` §4-1). */
void report_echo_outcome(FILE *out, const struct echo_outcome *outcome,
                         const uint8_t *our_protocol_address);

/* ⚠ Each reason counted on its own, so a datagram we could not read never looks
 * like one that was simply not addressed to us. ⚠ Printed even when every count
 * is zero (`CLAUDE.md` §1). */
void report_echo_summary(FILE *out, const struct echo_counts *counts);

/* Counts of segments the Parse layer would not hand on. ⚠ Each on its own: a
 * segment we could not read is not one whose checksum disagrees
 * (`.claude/rules/c.md`). */
struct tcp_counts {
    unsigned long malformed;
    unsigned long checksum_disagrees;
};

/* ⚠ Why a segment never reached the state machine. ⚠ Its own line, because the
 * reasons a segment is unreadable and the reasons a connection does not move
 * are different things (`.claude/rules/layers.md`). */
void report_tcp_not_read(FILE *out, enum tcp_parse answer);

void report_tcp_summary(FILE *out, const struct tcp_counts *counts);

/* What happened to one TCP segment, and why.
 *
 * ⚠ The same two-line shape ARP and ICMP already print
 * (hidetzu/tcpip-stack#43 Owner Decision 2, #44 Owner Decision 4).
 *
 * ⚠ The state names in brackets are RFC 793's own. ⚠ That is not the internal
 * name `CLAUDE.md` §4 forbids — ⚠ **it is the document's vocabulary, shown to a
 * reader on purpose.**
 *
 * ⚠ A transition gets a line of its own, not only the ends, ⚠ **so that where a
 * connection stopped leaves a trace.** ⚠ Until hidetzu/tcpip-stack#57 the reason
 * given here was that there was no clock and a half-finished handshake stopped
 * there for ever; ⚠ **there is a clock now and such a connection is given up
 * on** (ADR 0018, ADR 0019) — ⚠ the line is still printed, and the reason for it
 * is the trace, not the absence of a timer.
 *
 * ⚠ Every reason that is ours says so rather than pointing at the sender
 * (`CLAUDE.md` §4-1). ⚠ That includes the one for a `FIN` we have not answered:
 * ⚠ **the sender closed properly, and not answering is ours**
 * (hidetzu/tcpip-stack#65). */
void report_handshake_outcome(FILE *out, const struct handshake_outcome *outcome);

/* ⚠ Each reason counted on its own, and ⚠ printed even when every count is
 * zero. ⚠ `answered` moves only once the wire took the whole answer — a reply
 * that was built is not a reply that left. */
void report_handshake_summary(FILE *out, const struct handshake_counts *counts);

/* Which option was given something it cannot take, or which pair of them cannot
 * stand as given.
 *
 * ⚠ An enum reaching this layer is the point of the layer: ⚠ **it never reaches
 * a human** (`CLAUDE.md` §4). The same shape `report_attach_failure` uses for a
 * `tap_step`. */
enum option_problem {
    OPTION_HARDWARE_ADDRESS = 0,
    OPTION_PROTOCOL_ADDRESS,
    OPTION_TCP_PORT,
    OPTION_COUNT,
    OPTION_TIMEOUT,
    OPTION_TIME_TO_LIVE,
    OPTION_HALF_AN_IDENTITY,
    OPTION_PORT_WITHOUT_IDENTITY,
    OPTION_ARGUMENTS_BEYOND_THE_OPTIONS
};

/* ⚠ `program_name` is used by one of them and passed for all, so a caller never
 * has to know which. */
void report_option_problem(FILE *out, enum option_problem problem,
                           const char *program_name);

/* ⚠ Nothing here is the signal's fault, and the sentence does not say it is. */
void report_could_not_arrange_to_stop(FILE *out, int errnum);

/* ⚠ Reads that could not be made, one after another, until the program stopped
 * trying. ⚠ The number is what it counted, not a guess about why. */
void report_gave_up_on_reads(FILE *out, unsigned int consecutive_failures);

void report_usage(FILE *out, const char *program_name);

#endif /* REPORT_H */
