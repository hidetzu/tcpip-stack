#include "arp.h"

#include <string.h>

#include "ethernet.h"

/* ⚠ Two places name the length of an ethernet address: this parser, because
 * ar$hln says 6 when ar$hrd is ethernet, and the layer that owns the ethernet
 * header. ⚠ This is the mechanical cross-check that stops them diverging
 * (`CLAUDE.md` §3, the same shape as tap.c's check against IFNAMSIZ). */
_Static_assert(ARP_HARDWARE_ADDRESS_BYTES == ETHERNET_ADDRESS_BYTES,
               "an ethernet hardware address is the same length in both parsers");

/* Where each fixed field sits, written as the layout rather than as numbers so
 * it cannot drift from ARP_FIXED_BYTES. */
#define HARDWARE_ADDRESS_SPACE_OFFSET 0
#define PROTOCOL_ADDRESS_SPACE_OFFSET 2
#define HARDWARE_ADDRESS_LENGTH_OFFSET 4
#define PROTOCOL_ADDRESS_LENGTH_OFFSET 5
#define OPCODE_OFFSET 6

/* ⚠ Network byte order, one octet at a time. ⚠ Never a struct overlaid on the
 * buffer and never a 16-bit load at an offset nothing aligned — the caller
 * chose where this buffer starts (`.claude/rules/c.md`). */
static uint16_t read_16(const uint8_t *at)
{
    return (uint16_t)(((uint16_t)at[0] << 8) | at[1]);
}

enum arp_parse arp_parse_packet(const uint8_t *payload, size_t payload_bytes,
                                struct arp_packet *packet)
{
    memset(packet, 0, sizeof *packet);

    /* ⚠ Checked against what was actually read, before a single octet is
     * touched. A zero-length payload lands here and `payload` is never
     * dereferenced. */
    if (payload_bytes < ARP_FIXED_BYTES) {
        return ARP_PARSE_MALFORMED;
    }

    packet->hardware_address_space = read_16(payload + HARDWARE_ADDRESS_SPACE_OFFSET);
    packet->protocol_address_space = read_16(payload + PROTOCOL_ADDRESS_SPACE_OFFSET);
    packet->hardware_address_length = payload[HARDWARE_ADDRESS_LENGTH_OFFSET];
    packet->protocol_address_length = payload[PROTOCOL_ADDRESS_LENGTH_OFFSET];
    packet->opcode = read_16(payload + OPCODE_OFFSET);

    /* ⚠ ar$hln and ar$pln are the sender's assertion about where the four
     * addresses sit. They are checked against what actually arrived before
     * either is used as an offset.
     *
     * ⚠ Why truncation is decided before support: a packet that does not
     * contain what it says it contains is malformed whether or not we would
     * have placed those lengths. ⚠ Deciding support first would report a
     * hostile length of 255 as "we do not handle that", which says the sender
     * is fine when the packet is short by 500 octets. */
    size_t addresses_need = 2u * ((size_t)packet->hardware_address_length +
                                  (size_t)packet->protocol_address_length);
    if (payload_bytes - ARP_FIXED_BYTES < addresses_need) {
        return ARP_PARSE_MALFORMED;
    }

    if (packet->hardware_address_space != ARP_HARDWARE_ADDRESS_SPACE_ETHERNET ||
        packet->protocol_address_space != ARP_PROTOCOL_ADDRESS_SPACE_IPV4 ||
        packet->hardware_address_length != ARP_HARDWARE_ADDRESS_BYTES ||
        packet->protocol_address_length != ARP_PROTOCOL_ADDRESS_BYTES) {
        return ARP_PARSE_ADDRESS_SPACES_NOT_HANDLED;
    }

    if (packet->opcode != ARP_OPCODE_REQUEST && packet->opcode != ARP_OPCODE_REPLY) {
        return ARP_PARSE_OPCODE_NOT_HANDLED;
    }

    const uint8_t *at = payload + ARP_FIXED_BYTES;
    memcpy(packet->sender_hardware_address, at, ARP_HARDWARE_ADDRESS_BYTES);
    at += ARP_HARDWARE_ADDRESS_BYTES;
    memcpy(packet->sender_protocol_address, at, ARP_PROTOCOL_ADDRESS_BYTES);
    at += ARP_PROTOCOL_ADDRESS_BYTES;
    memcpy(packet->target_hardware_address, at, ARP_HARDWARE_ADDRESS_BYTES);
    at += ARP_HARDWARE_ADDRESS_BYTES;
    memcpy(packet->target_protocol_address, at, ARP_PROTOCOL_ADDRESS_BYTES);

    return ARP_PARSE_OK;
}
