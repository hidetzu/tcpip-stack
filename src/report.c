#include "report.h"

#include <errno.h>
#include <string.h>

/* ⚠ 8 bytes, two spaces, 8 bytes — the shape the owner approved
 * (hidetzu/tcpip-stack#2). */
#define BYTES_PER_HEX_LINE 16
#define BYTES_PER_HEX_GROUP 8

static const char *plural(unsigned long count)
{
    return count == 1 ? "" : "s";
}

void report_listening(FILE *out, const char *device_name)
{
    fprintf(out, "listening on %s\n", device_name);
}

void report_mtu(FILE *out, const char *device_name, unsigned int mtu)
{
    fprintf(out, "%s carries frames of up to %u bytes\n", device_name, mtu);
}

void report_no_window(FILE *out, const char *device_name, unsigned int mtu,
                      bool too_large)
{
    if (too_large) {
        fprintf(out, "%s carries frames of up to %u bytes, which leaves more room "
                     "than the Window field can promise.\n", device_name, mtu);
        fprintf(out, "  Nothing was read. Bring the device up with a smaller MTU.\n");
        return;
    }
    fprintf(out, "%s carries frames of up to %u bytes, which leaves no room for "
                 "data after an internet header and a TCP header.\n", device_name, mtu);
    fprintf(out, "  Nothing was read. Bring the device up with a larger MTU.\n");
}

void report_mtu_could_not_be_read(FILE *out, const char *device_name,
                                  const struct tap_failure *failure,
                                  unsigned int carrying_on_with)
{
    /* ⚠ What happened, then what was done about it, then what it costs. ⚠ It
     * never prints the number as though it had been read (`CLAUDE.md` §1). */
    if (failure->errnum != 0) {
        fprintf(out, "could not ask %s how large a frame it carries: %s\n",
                device_name, strerror(failure->errnum));
    } else {
        fprintf(out, "could not ask %s how large a frame it carries: "
                     "the answer was not a size.\n", device_name);
    }
    fprintf(out, "  Carrying on with %u bytes, which is a value chosen here and "
                 "not one this device reported.\n", carrying_on_with);
}

void report_frame(FILE *out, unsigned long frame_number, size_t bytes,
                  bool filled_buffer)
{
    if (filled_buffer) {
        fprintf(out, "frame %lu  %zu bytes (filled the buffer; it may have been longer)\n",
                frame_number, bytes);
        return;
    }
    fprintf(out, "frame %lu  %zu bytes\n", frame_number, bytes);
}

void report_frame_bytes(FILE *out, const uint8_t *frame, size_t bytes)
{
    for (size_t offset = 0; offset < bytes; offset += BYTES_PER_HEX_LINE) {
        fprintf(out, "  %04zx", offset);
        for (size_t i = 0; i < BYTES_PER_HEX_LINE && offset + i < bytes; i++) {
            /* Two spaces open a group of eight, one space separates bytes
             * inside it. ⚠ A short last line ends after its last byte — no
             * padding, so nothing looks like a byte that was not read. */
            const char *separator = (i % BYTES_PER_HEX_GROUP == 0) ? "  " : " ";
            fprintf(out, "%s%02x", separator, frame[offset + i]);
        }
        fputc('\n', out);
    }
}

static void write_hardware_address(FILE *out, const uint8_t *address)
{
    fprintf(out, "%02x:%02x:%02x:%02x:%02x:%02x", address[0], address[1], address[2],
            address[3], address[4], address[5]);
}

void report_ethernet_header(FILE *out, const uint8_t *frame, size_t bytes,
                            enum ethernet_parse answer,
                            const struct ethernet_header *header)
{
    (void)frame;
    (void)bytes;

    if (answer == ETHERNET_PARSE_SHORTER_THAN_THE_HEADER) {
        /* ⚠ No addresses are shown: none arrived. */
        fputs("  not read: fewer octets arrived than an ethernet header needs\n", out);
        return;
    }

    fputs("  ", out);
    write_hardware_address(out, header->destination);
    fputs(" <- ", out);
    write_hardware_address(out, header->source);
    fprintf(out, ", length/type 0x%04x\n", header->length_type);

    switch (answer) {
    case ETHERNET_PARSE_LENGTH_NOT_A_TYPE:
        fputs("  not read further: that is an IEEE 802.3 Length, not a Type\n", out);
        return;
    case ETHERNET_PARSE_LENGTH_TYPE_UNDEFINED:
        fputs("  not read further: the standard does not define that value\n", out);
        return;
    case ETHERNET_PARSE_OK:
    case ETHERNET_PARSE_SHORTER_THAN_THE_HEADER:
        return;
    }
}

void report_ethernet_summary(FILE *out, const struct ethernet_counts *counts)
{
    fprintf(out,
            "%lu frame%s %s malformed, %lu carried an IEEE 802.3 Length, "
            "%lu carried a length/type the standard does not define\n",
            counts->malformed, plural(counts->malformed),
            counts->malformed == 1 ? "was" : "were",
            counts->ieee_802_3_length, counts->length_type_undefined);
}

void report_read_failure(FILE *out, unsigned long frame_number,
                         const struct tap_failure *failure)
{
    fprintf(out, "frame %lu  could not be read: %s\n", frame_number,
            strerror(failure->errnum));
}

void report_summary(FILE *out, unsigned long frames_read, unsigned long read_errors)
{
    fprintf(out, "read %lu frame%s, %lu read error%s\n", frames_read,
            plural(frames_read), read_errors, plural(read_errors));
}

void report_timeout(FILE *out, const char *device_name, int timeout_ms,
                    unsigned long frames_read)
{
    if (frames_read == 0) {
        fprintf(out,
                "listened on %s for %d ms and read 0 frames. Nothing arrived here; "
                "that does not say whether anything was sent.\n",
                device_name, timeout_ms);
        return;
    }
    fprintf(out,
            "listened on %s for %d ms after frame %lu and read no more. "
            "That does not say whether anything more was sent.\n",
            device_name, timeout_ms, frames_read);
}

void report_attach_failure(FILE *out, const char *device_name,
                           const struct tap_failure *failure)
{
    switch (failure->step) {
    case TAP_STEP_NAME:
        fprintf(out, "could not attach to \"%s\": a device name is 1 to %d characters.\n",
                device_name, TAP_DEVICE_NAME_MAX);
        return;
    case TAP_STEP_OPEN:
        fprintf(out, "could not attach to %s: opening /dev/net/tun failed: %s\n",
                device_name, strerror(failure->errnum));
        if (failure->errnum == ENOENT) {
            fprintf(out, "  The tun driver may not be loaded: modprobe tun.\n");
        }
        return;
    case TAP_STEP_ATTACH:
        fprintf(out, "could not attach to %s: creating the device failed: %s\n",
                device_name, strerror(failure->errnum));
        if (failure->errnum == EPERM) {
            fprintf(out,
                    "  Creating a TAP device needs CAP_NET_ADMIN in the namespace that "
                    "owns it. The checks here get it from unshare -Urn, without sudo.\n");
        }
        if (failure->errnum == EBUSY) {
            fprintf(out,
                    "  Something else is already attached to that device. "
                    "Choose another name with --dev.\n");
        }
        return;
    case TAP_STEP_NONE:
    case TAP_STEP_WAIT:
    case TAP_STEP_READ:
    case TAP_STEP_WRITE:
    case TAP_STEP_MTU:
        break;
    }
    /* ⚠ Reached only if a step is added above without a sentence for it. Say
     * that plainly rather than printing the number (`CLAUDE.md` §4). */
    fprintf(out, "could not attach to %s, and this build has no wording for why.\n",
            device_name);
}

void report_wait_failure(FILE *out, const char *device_name,
                         const struct tap_failure *failure)
{
    fprintf(out, "could not keep listening on %s: waiting for a frame failed: %s\n",
            device_name, strerror(failure->errnum));
}

/* ⚠ Written as four octets, not as a type: nothing here interprets a protocol
 * address, it only shows the one it was handed. */
static void write_protocol_address(FILE *out, const uint8_t *address)
{
    fprintf(out, "%u.%u.%u.%u", address[0], address[1], address[2], address[3]);
}

void report_arp_outcome(FILE *out, const struct arp_outcome *outcome,
                        const uint8_t *our_protocol_address)
{
    if (outcome->decision == ARP_ANSWER) {
        fputs("  answered it: ", out);
        write_protocol_address(out, our_protocol_address);
        fputs(" is ours, and ", out);
        write_protocol_address(out, outcome->request.sender_protocol_address);
        fputs(" was told our hardware address\n", out);
        return;
    }

    switch (outcome->reason) {
    case ARP_REASON_NOT_FOR_US:
        fputs("  no answer: it asked for ", out);
        write_protocol_address(out, outcome->request.target_protocol_address);
        fputs(", which is not an address we answer for\n", out);
        return;
    case ARP_REASON_MALFORMED:
        fputs("  no answer: the ARP packet holds fewer octets than it says it does\n", out);
        return;
    case ARP_REASON_UNSUPPORTED_ADDRESS_SPACE:
        fputs("  no answer: its hardware or protocol address space is not one we can place\n",
              out);
        return;
    case ARP_REASON_UNHANDLED_OPCODE:
        fputs("  no answer: its opcode is not one we act on\n", out);
        return;
    case ARP_REASON_NONE:
        break;
    }
    /* ⚠ Reached only if a reason is added without a sentence for it. Say that
     * plainly rather than printing the number (`CLAUDE.md` §4). */
    fputs("  no answer, and this build has no wording for why\n", out);
}

void report_arp_summary(FILE *out, const struct arp_counts *counts)
{
    fprintf(out,
            "answered %lu ARP request%s. %lu %s not for us, %lu %s malformed, "
            "%lu named an address space we cannot place, "
            "%lu had an opcode we do not act on\n",
            counts->answered, plural(counts->answered),
            counts->not_for_us, counts->not_for_us == 1 ? "was" : "were",
            counts->malformed, counts->malformed == 1 ? "was" : "were",
            counts->unsupported_address_space, counts->unhandled_opcode);
}

void report_device_gone(FILE *out, const char *device_name)
{
    fprintf(out,
            "could not keep listening on %s: the device stopped being usable.\n"
            "  Waiting for a frame will not help. Nothing here can say why.\n",
            device_name);
}

void report_echo_outcome(FILE *out, const struct echo_outcome *outcome,
                         const uint8_t *our_protocol_address)
{
    if (outcome->decision == ECHO_ANSWER) {
        fputs("  answered it: ", out);
        write_protocol_address(out, our_protocol_address);
        fputs(" is ours, and ", out);
        write_protocol_address(out, outcome->header.source_address);
        fprintf(out, " got its %zu octet%s back\n", outcome->request.data_bytes,
                outcome->request.data_bytes == 1 ? "" : "s");
        return;
    }

    switch (outcome->reason) {
    case ECHO_REASON_NOT_FOR_US:
        fputs("  no answer: it was addressed to ", out);
        write_protocol_address(out, outcome->header.destination_address);
        fputs(", which is not an address we answer for\n", out);
        return;
    case ECHO_REASON_INTERNET_HEADER_MALFORMED:
        fputs("  no answer: its internet header does not hold what it says it holds\n", out);
        return;
    case ECHO_REASON_INTERNET_HEADER_NOT_HANDLED:
        fputs("  no answer: its internet header is one we do not read yet\n", out);
        return;
    case ECHO_REASON_INTERNET_HEADER_CHECKSUM_DISAGREES:
        fputs("  no answer: its internet header checksum does not agree with the octets "
              "that arrived\n", out);
        return;
    case ECHO_REASON_FRAGMENT:
        fputs("  no answer: it is a fragment, and nothing here puts fragments back "
              "together\n", out);
        return;
    case ECHO_REASON_PROTOCOL_NOT_HANDLED:
        fprintf(out, "  no answer: it carries protocol %u, which is not one we act on\n",
                outcome->header.protocol);
        return;
    case ECHO_REASON_ICMP_MALFORMED:
        fputs("  no answer: its ICMP message is shorter than one can be, or its code is "
              "not the 0 an echo message has\n", out);
        return;
    case ECHO_REASON_ICMP_TYPE_NOT_HANDLED:
        fputs("  no answer: its ICMP type is not one we act on\n", out);
        return;
    case ECHO_REASON_ICMP_CHECKSUM_DISAGREES:
        fputs("  no answer: its ICMP checksum does not agree with the octets that "
              "arrived\n", out);
        return;
    case ECHO_REASON_WE_COULD_NOT_BUILD_THE_REPLY:
        /* ⚠ Ours, and it says so. ⚠ Reporting this as anything about the sender
         * would send the reader after the wrong thing (`CLAUDE.md` §4-1). */
        fputs("  no answer: we could not build the reply. That is ours, not the "
              "sender's\n", out);
        return;
    case ECHO_REASON_NONE:
        break;
    }
    /* ⚠ Reached only if a reason is added without a sentence for it. Say that
     * plainly rather than printing the number (`CLAUDE.md` §4). */
    fputs("  no answer, and this build has no wording for why\n", out);
}

void report_echo_summary(FILE *out, const struct echo_counts *counts)
{
    fprintf(out, "answered %lu echo request%s. %lu %s not for us, %lu carried a protocol "
                 "we do not act on\n",
            counts->answered, plural(counts->answered),
            counts->not_for_us, counts->not_for_us == 1 ? "was" : "were",
            counts->protocol_not_handled);
    fprintf(out, "%lu internet header%s malformed, %lu %s, "
                 "%lu had a checksum that does not agree, %lu %s\n",
            counts->internet_header_malformed,
            counts->internet_header_malformed == 1 ? " was" : "s were",
            counts->internet_header_not_handled,
            counts->internet_header_not_handled == 1 ? "was one we do not read yet"
                                                     : "were ones we do not read yet",
            counts->internet_header_checksum_disagrees,
            counts->fragment,
            counts->fragment == 1 ? "was a fragment" : "were fragments");
    fprintf(out, "%lu ICMP message%s malformed, %lu had a type we do not act on, "
                 "%lu had a checksum that does not agree\n",
            counts->icmp_malformed, counts->icmp_malformed == 1 ? " was" : "s were",
            counts->icmp_type_not_handled, counts->icmp_checksum_disagrees);
    fprintf(out, "%lu repl%s could not be built, which would be ours and not the "
                 "sender's\n",
            counts->we_could_not_build_the_reply,
            counts->we_could_not_build_the_reply == 1 ? "y" : "ies");
}

void report_tcp_not_read(FILE *out, enum tcp_parse answer)
{
    switch (answer) {
    case TCP_PARSE_MALFORMED:
        fputs("  no answer: its TCP header does not hold what it says it holds\n", out);
        return;
    case TCP_PARSE_CHECKSUM_DISAGREES:
        fputs("  no answer: its TCP checksum does not agree with the octets that "
              "arrived\n", out);
        return;
    case TCP_PARSE_OK:
        break;
    }
    /* ⚠ Reached only if an answer is added without a sentence for it. */
    fputs("  no answer, and this build has no wording for why\n", out);
}

void report_tcp_summary(FILE *out, const struct tcp_counts *counts)
{
    fprintf(out, "%lu TCP header%s malformed and %lu had a checksum that does not "
                 "agree\n",
            counts->malformed, counts->malformed == 1 ? " was" : "s were",
            counts->checksum_disagrees);
}

/* ⚠ A socket as RFC 793 describes it: "an internet address identifying the TCP
 * with a port identifier". */
static void write_socket(FILE *out, const struct socket *socket)
{
    write_protocol_address(out, socket->address);
    fprintf(out, ":%u", socket->port);
}

/* ⚠ What we did with the octets, in one place, because three lines print it.
 *
 * ⚠ It says what happened first (`CLAUDE.md` §4-1). ⚠ Nothing here is the
 * sender's fault: ⚠ **they sent what our own window invited**, and
 * ⚠ **having nobody to give it to is ours.**
 *
 * ⚠ Until hidetzu/tcpip-stack#74 this ended "The sender has not been told we
 * have it yet", ⚠ **which stopped being true when the acknowledgment started
 * going out.** ⚠ A stale sentence misleads harder than stale code
 * (`CLAUDE.md` §5). */
static void write_the_data_we_took(FILE *out, uint16_t octets_taken)
{
    fprintf(out, "  %u octet%s of data arrived; we took %s, told the sender so, and\n"
                 "    had nobody to give %s to\n",
            (unsigned)octets_taken, octets_taken == 1 ? "" : "s",
            octets_taken == 1 ? "it" : "them",
            octets_taken == 1 ? "it" : "them");
}

void report_handshake_outcome(FILE *out, const struct handshake_outcome *outcome)
{
    if (outcome->decision == HANDSHAKE_MOVED) {
        switch (outcome->state) {
        case CONNECTION_SYN_RECEIVED:
            fputs("  ", out);
            write_socket(out, &outcome->id.remote);
            fputs(" asked to open a connection; now waiting for it to\n"
                  "    confirm (SYN-RECEIVED)\n", out);
            return;
        case CONNECTION_ESTABLISHED:
            fputs("  ", out);
            write_socket(out, &outcome->id.remote);
            fputs(" confirmed it; the connection is open (ESTABLISHED)\n", out);
            /* ⚠ The acknowledgment that opened it may have carried data. ⚠ Its
             * own line rather than nothing: ⚠ **a payload nobody mentioned
             * reads exactly like one that never arrived** (`CLAUDE.md` §1). */
            if (outcome->octets_taken != 0) {
                write_the_data_we_took(out, outcome->octets_taken);
            }
            return;
        case CONNECTION_CLOSE_WAIT:
            fputs("  ", out);
            write_socket(out, &outcome->id.remote);
            /* ⚠ What happened first, then what is missing and what closes it
             * (`CLAUDE.md` §4-1). ⚠ Nothing here is the sender's fault: ⚠ **it
             * did the closing properly and we have not answered yet.** */
            fputs(" has closed its side; we read the FIN and have not answered\n"
                  "    it yet (CLOSE-WAIT)\n", out);
            if (outcome->octets_taken != 0) {
                write_the_data_we_took(out, outcome->octets_taken);
            }
            return;
        case CONNECTION_LAST_ACK:
            fputs("  ", out);
            write_socket(out, &outcome->id.remote);
            /* ⚠ What we did first, then what is still owed. ⚠ Nothing here is
             * the sender's fault (`CLAUDE.md` §4-1). */
            fputs(" has closed its side; we read the FIN, closed ours in the same\n"
                  "    segment, and are waiting for that to be acknowledged (LAST-ACK)\n",
                  out);
            if (outcome->octets_taken != 0) {
                write_the_data_we_took(out, outcome->octets_taken);
            }
            return;
        case CONNECTION_CLOSED:
            fputs("  ", out);
            write_socket(out, &outcome->id.remote);
            fputs(" acknowledged our own close; the connection is finished and\n"
                  "    the room it held is free again (CLOSED)\n", out);
            return;
        case CONNECTION_LISTEN:
            break;
        }
        /* ⚠ Reached only if a state is added without a sentence for it. */
        fputs("  something moved, and this build has no wording for it\n", out);
        return;
    }

    switch (outcome->reason) {
    case HANDSHAKE_REASON_ASKED_AGAIN:
        fputs("  ", out);
        write_socket(out, &outcome->id.remote);
        fputs(" asked again; nothing changed\n", out);
        return;
    case HANDSHAKE_REASON_ACKNOWLEDGMENT_WE_ARE_NOT_WAITING_FOR:
        fprintf(out, "  no answer: it acknowledged %lu, and we are waiting for %lu + 1\n",
                (unsigned long)outcome->acknowledgment_we_had,
                (unsigned long)(outcome->acknowledgment_we_expected - 1u));
        return;
    case HANDSHAKE_REASON_THE_DATA_WAS_TAKEN_AND_DISCARDED:
        write_the_data_we_took(out, outcome->octets_taken);
        return;
    case HANDSHAKE_REASON_A_FIN_WE_HAVE_READ_ALREADY:
        /* ⚠ The measured case: `RCV.NXT` moved over the first FIN, so every
         * copy of it that crosses our answer lands here. ⚠ Until
         * hidetzu/tcpip-stack#76 this and the line below were one sentence
         * saying "either, or" — ⚠ **which was honest about what the build knew,
         * and the build knows now.** */
        fputs("  no answer: we have read that FIN already and moved past it\n", out);
        return;
    case HANDSHAKE_REASON_A_FIN_THAT_BEGINS_TOO_FAR_AHEAD:
        fputs("  no answer: that FIN begins past what we are waiting for, and there\n"
              "    are octets before it we have not taken\n", out);
        return;
    case HANDSHAKE_REASON_A_FIN_WE_CANNOT_PLACE:
        fputs("  no answer: nothing here is holding the connection that FIN closes, so\n"
              "    its sequence number cannot be checked against anything\n", out);
        return;
    case HANDSHAKE_REASON_DATA_WE_HAVE_TAKEN_ALREADY:
        fputs("  no answer: we have taken every octet of that already\n", out);
        return;
    case HANDSHAKE_REASON_DATA_THAT_BEGINS_TOO_FAR_AHEAD:
        fputs("  no answer: that data begins past what we are waiting for, and there\n"
              "    are octets before it we have not seen\n", out);
        return;
    case HANDSHAKE_REASON_NOT_EXPECTED_IN_THIS_STATE:
        fputs("  no answer: nothing in this connection's state expects that\n", out);
        return;
    case HANDSHAKE_REASON_NO_CONNECTION_HELD:
        fputs("  no answer: nothing here is expecting a segment from ", out);
        write_socket(out, &outcome->id.remote);
        fputc('\n', out);
        return;
    case HANDSHAKE_REASON_THE_OTHER_SIDE_RESET_IT:
        fputs("  ", out);
        write_socket(out, &outcome->id.remote);
        /* ⚠ What happened, and what became of the connection. ⚠ Nothing here
         * calls it an error: ⚠ **a reset is a thing the other side is entitled
         * to do** (`CLAUDE.md` §4-1). */
        fputs(" reset the connection; it is gone and the room it held is free\n"
              "    again (CLOSED)\n", out);
        return;
    case HANDSHAKE_REASON_A_RESET_OUTSIDE_THE_WINDOW:
        /* ⚠ Nothing is sent for it, which is the document's own exception. */
        fputs("  no answer: that reset is not for a sequence number we are waiting\n"
              "    for, so nothing was done with it\n", out);
        return;
    case HANDSHAKE_REASON_URGENT_AND_NOBODY_TO_TELL:
        /* ⚠ Ours, and it says so: ⚠ **the sender marked it urgent properly and
         * we have nobody to pass that to.** */
        fputs("  no answer: that was marked urgent, and there is nobody here to\n"
              "    hand it to. That is ours, not the sender's\n", out);
        return;
    case HANDSHAKE_REASON_WE_SENT_WHAT_WE_WERE_ASKED_TO:
        fputs("  sent: data of ours, as much of it as one segment may carry\n", out);
        return;
    case HANDSHAKE_REASON_THEIR_WINDOW_HAD_NO_ROOM:
        /* ⚠ Ours to wait, not theirs to blame: ⚠ **they said what they can hold
         * and we are holding to it** (`CLAUDE.md` §4-1). */
        fputs("  nothing sent: there is data to send and the window they\n"
              "    advertised has no room for it yet\n", out);
        return;
    case HANDSHAKE_REASON_ADDRESSED_TO_EVERYONE:
        /* ⚠ Nothing here is the sender's fault in the usual sense, and the
         * sentence does not scold: ⚠ **it says what the address was and what we
         * did.** */
        fputs("  no answer: that was addressed to a broadcast or multicast address,\n"
              "    and a connection is never made to one\n", out);
        return;
    case HANDSHAKE_REASON_FROM_AN_IMPOSSIBLE_SOURCE:
        /* ⚠ This one IS the sender's, and the sentence may say so without
         * scolding: ⚠ **it names the address it used and what we did.**
         * ⚠ It does not say the sender forged it — ⚠ nothing here measured
         * that, and a misconfigured host looks the same from here
         * (`CLAUDE.md` §1). */
        fputs("  no answer: that claims to come from an address that can never\n"
              "    send anything, so nothing was taken from it\n", out);
        return;
    case HANDSHAKE_REASON_NO_ROOM:
        /* ⚠ Ours, and it says so (hidetzu/tcpip-stack#42 Owner Decision 1). */
        fputs("  no answer: we are already holding a connection, and this build has\n"
              "    room for one. That is ours, not the sender's\n", out);
        return;
    case HANDSHAKE_REASON_THE_ANSWER_WENT_OUT_AGAIN:
        /* ⚠ Nobody has confirmed it YET, and we answered again. ⚠ Not "they
         * asked again": ⚠ **our timer fired** (`CLAUDE.md` §4-1). */
        fputs("  ", out);
        write_socket(out, &outcome->id.remote);
        fputs(" has not confirmed it; the answer went out again\n", out);
        return;
    case HANDSHAKE_REASON_OUR_FIN_WENT_OUT_AGAIN:
        /* ⚠ Our timer fired, ⚠ **not them asking for anything** — the same
         * distinction hidetzu/tcpip-stack#59 had to make for the answer. */
        fputs("  ", out);
        write_socket(out, &outcome->id.remote);
        fputs(" has not acknowledged our close; it went out again\n", out);
        return;
    case HANDSHAKE_REASON_NOBODY_ACKNOWLEDGED_OUR_FIN:
        /* ⚠ We stopped waiting. ⚠ Not the sender being wrong about anything,
         * and ⚠ **not the same event as a handshake nobody confirmed.** */
        fputs("  ", out);
        write_socket(out, &outcome->id.remote);
        fputs(" never acknowledged our close; we stopped waiting and freed the\n"
              "    room the connection held\n", out);
        return;
    case HANDSHAKE_REASON_NOBODY_CONFIRMED_IT:
        /* ⚠ Nobody confirmed it. ⚠ Not "they did not answer" and not anything
         * about them being wrong — ⚠ we stopped waiting (`CLAUDE.md` §4-1). */
        fputs("  ", out);
        write_socket(out, &outcome->id.remote);
        fputs(" never confirmed it; the connection was given up on\n", out);
        return;
    case HANDSHAKE_REASON_WE_COULD_NOT_BUILD_THE_REPLY:
        fputs("  no answer: we could not hand the reply to the device. That is ours,\n"
              "    not the sender's\n", out);
        return;
    case HANDSHAKE_REASON_NONE:
        break;
    }
    /* ⚠ Reached only if a reason is added without a sentence for it. */
    fputs("  no answer, and this build has no wording for why\n", out);
}

void report_handshake_summary(FILE *out, const struct handshake_counts *counts)
{
    fprintf(out, "%lu connection%s opened and %lu answered. %lu asked again\n",
            counts->opened, counts->opened == 1 ? " was" : "s were",
            counts->answered, counts->asked_again);
    fprintf(out, "%lu reached open. %lu acknowledged a number we are not waiting for, "
                 "%lu arrived for no connection we hold, %lu arrived where the "
                 "connection's state did not expect them\n",
            counts->established, counts->acknowledgment_we_are_not_waiting_for,
            counts->no_connection_held, counts->not_expected_in_this_state);
    fprintf(out, "%lu of our own closes left the device and %lu went out again "
                 "because nobody had acknowledged them. %lu connection%s finished, "
                 "and %lu %s given up on with our close unacknowledged\n",
            counts->our_fin_left, counts->our_fin_went_out_again, counts->closed,
            counts->closed == 1 ? "" : "s", counts->never_acknowledged_our_fin,
            counts->never_acknowledged_our_fin == 1 ? "was" : "were");
    fprintf(out, "%lu answer%s went out again because nobody had confirmed %s\n",
            counts->answered_again, counts->answered_again == 1 ? "" : "s",
            counts->answered_again == 1 ? "it" : "them");
    fprintf(out, "%lu %s given up on after nobody confirmed %s\n",
            counts->given_up_on, counts->given_up_on == 1 ? "connection was" : "connections were",
            counts->given_up_on == 1 ? "it" : "them");
    /* ⚠ The first number here is octets and the second is segments. ⚠ Both say
     * which, on the line, because ⚠ **a number beside a number of a different
     * kind is read as the same kind** (`CLAUDE.md` §6). */
    fprintf(out, "%lu acknowledgment%s for data left the device, and %lu said where "
                 "we are without accepting anything\n",
            counts->data_acknowledged, counts->data_acknowledged == 1 ? "" : "s",
            counts->told_them_where_we_are);
    fprintf(out, "%lu octet%s of data %s taken and discarded. %lu segment%s carried "
                 "data we had taken already, and %lu began past what we were waiting "
                 "for\n",
            counts->octets_taken_and_discarded,
            counts->octets_taken_and_discarded == 1 ? "" : "s",
            counts->octets_taken_and_discarded == 1 ? "was" : "were",
            counts->data_we_have_taken_already,
            counts->data_we_have_taken_already == 1 ? "" : "s",
            counts->data_that_begins_too_far_ahead);
    fprintf(out, "the other side closed %lu connection%s. %lu FIN%s arrived that we had "
                 "read already, %lu began past what we were waiting for, and %lu named "
                 "a connection we hold nothing for\n",
            counts->the_other_side_closed,
            counts->the_other_side_closed == 1 ? "" : "s",
            counts->fin_we_have_read_already,
            counts->fin_we_have_read_already == 1 ? "" : "s",
            counts->fin_that_begins_too_far_ahead,
            counts->fin_we_could_not_place);
    fprintf(out, "the other side reset %lu connection%s and %lu reset%s named a sequence "
                 "number we are not waiting for. %lu segment%s marked urgent with "
                 "nobody here to hand it to\n",
            counts->reset_by_the_other_side,
            counts->reset_by_the_other_side == 1 ? "" : "s",
            counts->reset_outside_the_window,
            counts->reset_outside_the_window == 1 ? "" : "s",
            counts->urgent_and_nobody_to_tell,
            counts->urgent_and_nobody_to_tell == 1 ? " was" : "s were");
    fprintf(out, "%lu segment%s addressed to a broadcast or multicast address, which "
                 "a connection is never made to\n",
            counts->addressed_to_everyone,
            counts->addressed_to_everyone == 1 ? " was" : "s were");
    fprintf(out, "%lu segment%s from an address that can never send anything\n",
            counts->from_an_impossible_source,
            counts->from_an_impossible_source == 1 ? " was" : "s were");
    /* ⚠ Two numbers, ⚠ **because one alone cannot show segmentation**: 3000
     * octets in one segment and 3000 in three are the same octet count. */
    /* ⚠ Sent again, counted apart: ⚠ **octets sent twice are not octets
     * delivered twice.** */
    fprintf(out, "%lu octet%s of ours went out again in %lu segment%s because "
                 "nobody had acknowledged them\n",
            counts->data_octets_we_sent_again,
            counts->data_octets_we_sent_again == 1 ? "" : "s",
            counts->data_segments_we_sent_again,
            counts->data_segments_we_sent_again == 1 ? "" : "s");
    /* ⚠ Measured and refused, counted apart: ⚠ **a refused sample is not a
     * sample that never happened** (RFC 6298 §3, Karn's). */
    fprintf(out, "%lu round trip%s measured, and %lu %s not used because what "
                 "%s would have measured was sent more than once\n",
            counts->round_trips_we_measured,
            counts->round_trips_we_measured == 1 ? " was" : "s were",
            counts->round_trips_we_would_not_use,
            counts->round_trips_we_would_not_use == 1 ? "was" : "were",
            counts->round_trips_we_would_not_use == 1 ? "it" : "they");
    fprintf(out, "%lu octet%s of ours left in %lu segment%s, and %lu time%s there "
                 "was no room in the window they advertised\n",
            counts->data_octets_we_sent,
            counts->data_octets_we_sent == 1 ? "" : "s",
            counts->data_segments_we_sent,
            counts->data_segments_we_sent == 1 ? "" : "s",
            counts->their_window_had_no_room,
            counts->their_window_had_no_room == 1 ? "" : "s");
    fprintf(out, "%lu %s refused for want of room and %lu answer%s never left the "
                 "device, which are ours and not the sender's\n",
            counts->room.refused_for_want_of_room,
            counts->room.refused_for_want_of_room == 1 ? "was" : "were",
            counts->we_could_not_build_the_reply,
            counts->we_could_not_build_the_reply == 1 ? "" : "s");
}

void report_option_problem(FILE *out, enum option_problem problem,
                           const char *program_name)
{
    /* ⚠ Every sentence below is the one that was written in
     * src/tcpip_stack.c before hidetzu/tcpip-stack#51 moved it, ⚠ **word for
     * word.** ⚠ The issue moved where they live and ⚠ decided nothing about what
     * they say — that is the owner's (hidetzu/tcpip-stack#2). */
    switch (problem) {
    case OPTION_HARDWARE_ADDRESS:
        fputs("--mac takes six hexadecimal octets, as 02:00:00:00:00:02.\n", out);
        return;
    case OPTION_PROTOCOL_ADDRESS:
        fputs("--ipv4 takes four octets from 0 to 255, as 10.0.0.2.\n", out);
        return;
    case OPTION_TCP_PORT:
        fputs("--tcp-port takes a whole number from 1 to 65535.\n", out);
        return;
    case OPTION_SEND:
        fputs("--send takes a whole number of octets, 0 to 1048576.\n", out);
        return;
    case OPTION_TIME_TO_LIVE:
        fputs("--ttl takes a whole number from 1 to 255.\n", out);
        return;
    case OPTION_COUNT:
        fputs("--count takes a whole number of frames, 0 or more.\n", out);
        return;
    case OPTION_TIMEOUT:
        fputs("--timeout takes a whole number of milliseconds, 0 or more.\n", out);
        return;
    case OPTION_HALF_AN_IDENTITY:
        fputs("--mac and --ipv4 are given together or not at all.\n", out);
        return;
    case OPTION_PORT_WITHOUT_IDENTITY:
        fputs("--tcp-port needs --mac and --ipv4 as well: "
              "nothing can be answered without them.\n", out);
        return;
    case OPTION_ARGUMENTS_BEYOND_THE_OPTIONS:
        fprintf(out, "%s takes no arguments beyond its options.\n", program_name);
        return;
    }
    /* ⚠ Reached only if a problem is added above without a sentence for it. Say
     * that plainly rather than printing the number (`CLAUDE.md` §4). */
    fprintf(out, "%s was asked for something it cannot do, and this build has no "
                 "wording for what.\n", program_name);
}

void report_could_not_arrange_to_stop(FILE *out, int errnum)
{
    fprintf(out, "could not arrange to stop cleanly on a signal: %s\n",
            strerror(errnum));
}

void report_gave_up_on_reads(FILE *out, unsigned int consecutive_failures)
{
    fprintf(out, "gave up after %u reads in a row that could not be made.\n",
            consecutive_failures);
}

void report_usage(FILE *out, const char *program_name)
{
    fprintf(out,
            "%s reads the ethernet frames that arrive on a TAP device, and answers\n"
            "the ARP requests and ICMP echo requests among them that ask for the\n"
            "address it was given.\n"
            "\n"
            "  --dev NAME      device to create and attach to (default: tap0)\n"
            "  --mac ADDRESS   the hardware address to answer with, as 02:00:00:00:00:02\n"
            "  --ipv4 ADDRESS  the protocol address to answer for, as 10.0.0.2\n"
            "  --tcp-port N    a TCP port to answer connections on (needs --mac and --ipv4)\n"
            "  --ttl N         the Time to Live to send with (1 to 255, default 64)\n"
            "  --count N       stop after N frames (default: until interrupted)\n"
            "  --timeout MS    give up waiting after MS milliseconds (default: no limit)\n"
            "  --hex           print the bytes of each frame as well as its length\n"
            "  --help          this text\n"
            "\n"
            "Without --mac and --ipv4 it only reads.\n"
            "ARP and ICMP echo are what it answers so far.\n"
            "With --tcp-port it also answers a connection request on that port, as far\n"
            "as the connection being open. Data that arrives on it is acknowledged\n"
            "and then discarded, because there is nobody to give it to. When the\n"
            "other side closes, its FIN is acknowledged and this end closes in the\n"
            "same segment, and the connection is finished once that is acknowledged\n"
            "in return.\n"
            "The device exists only while this program holds it open.\n",
            program_name);
}
