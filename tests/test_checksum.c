/* Static-tier check of the internet checksum.
 *
 * ⚠ The numbers it is held to were computed by the Linux kernel, not by us
 * (`.claude/rules/layers.md`, question 3). ⚠ A hand-written expectation and a
 * hand-written implementation agree by construction; ⚠ these two do not come
 * from us at all.
 *
 * ⚠ `CLAUDE.md` §1: a stack that answers a ping while computing the checksum
 * wrong still answers the ping. ⚠ That is what this file exists to stop. */
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "checksum.h"
#include "check.h"
#include "ethernet.h"

/* Where the IPv4 header sits inside the captured frame.
 *
 * ⚠ The start comes from the layer that owns the ethernet header. ⚠ The length
 * comes from the packet itself — the low half of its first octet, in units of
 * four — so ⚠ nothing here writes an IPv4 constant that `src/` does not have
 * yet, and nothing duplicates one it does (`CLAUDE.md` §3, ADR 0009).
 *
 * ⚠ This is the check reading for itself, deliberately. It never asks a parser
 * where anything is. */
#define IPV4_HEADER_LENGTH_UNITS 4
#define IPV4_CHECKSUM_AT 10
#define ICMP_CHECKSUM_AT 2

static long load_the_echo_request(unsigned char *into, size_t capacity)
{
    long bytes = check_load_fixture("icmp-echo-request-98.hex", into, capacity);
    if (bytes < 0) {
        return -1;
    }
    if (bytes != 98) {
        fprintf(stderr, "  the captured echo request is 98 octets, this one is %ld\n", bytes);
        return -1;
    }
    return bytes;
}

/* ⚠ The kernel put a number in the IPv4 header. Clearing the field and summing
 * must give that number back. */
static bool case_the_kernels_ipv4_header_checksum_is_reproduced(void)
{
    unsigned char frame[256];
    if (load_the_echo_request(frame, sizeof frame) < 0) {
        return false;
    }
    unsigned char *header = frame + ETHERNET_HEADER_BYTES;
    size_t header_bytes = (size_t)(header[0] & 0x0f) * IPV4_HEADER_LENGTH_UNITS;
    if (header_bytes < IPV4_CHECKSUM_AT + 2 || header_bytes > 60) {
        fprintf(stderr, "  the header says it is %zu octets, which cannot be right\n",
                header_bytes);
        return false;
    }

    unsigned carried = ((unsigned)header[IPV4_CHECKSUM_AT] << 8) |
                       header[IPV4_CHECKSUM_AT + 1];
    header[IPV4_CHECKSUM_AT] = 0;
    header[IPV4_CHECKSUM_AT + 1] = 0;
    unsigned ours = internet_checksum(header, header_bytes);

    if (ours != carried) {
        fprintf(stderr, "  the kernel put 0x%04x in the header and we compute 0x%04x\n",
                carried, ours);
        return false;
    }
    return true;
}

/* ⚠ And the other one, over different octets and a different length. */
static bool case_the_kernels_icmp_checksum_is_reproduced(void)
{
    unsigned char frame[256];
    long bytes = load_the_echo_request(frame, sizeof frame);
    if (bytes < 0) {
        return false;
    }
    unsigned char *header = frame + ETHERNET_HEADER_BYTES;
    size_t header_bytes = (size_t)(header[0] & 0x0f) * IPV4_HEADER_LENGTH_UNITS;
    unsigned char *icmp = header + header_bytes;
    size_t icmp_bytes = (size_t)bytes - ETHERNET_HEADER_BYTES - header_bytes;

    unsigned carried = ((unsigned)icmp[ICMP_CHECKSUM_AT] << 8) | icmp[ICMP_CHECKSUM_AT + 1];
    icmp[ICMP_CHECKSUM_AT] = 0;
    icmp[ICMP_CHECKSUM_AT + 1] = 0;
    unsigned ours = internet_checksum(icmp, icmp_bytes);

    if (ours != carried) {
        fprintf(stderr, "  the kernel put 0x%04x in the ICMP message (%zu octets) "
                        "and we compute 0x%04x\n", carried, icmp_bytes, ours);
        return false;
    }
    return true;
}

/* ⚠ The other half. A sum that returned the carried value no matter what would
 * pass both cases above. ⚠ Every octet position is flipped, one at a time, and
 * every one of them must change the answer (`verify` §5). */
static bool case_flipping_any_octet_changes_the_sum(void)
{
    unsigned char frame[256];
    if (load_the_echo_request(frame, sizeof frame) < 0) {
        return false;
    }
    unsigned char *header = frame + ETHERNET_HEADER_BYTES;
    size_t header_bytes = (size_t)(header[0] & 0x0f) * IPV4_HEADER_LENGTH_UNITS;
    header[IPV4_CHECKSUM_AT] = 0;
    header[IPV4_CHECKSUM_AT + 1] = 0;

    unsigned intact = internet_checksum(header, header_bytes);
    bool ok = true;
    for (size_t i = 0; i < header_bytes; i++) {
        unsigned char was = header[i];
        header[i] = (unsigned char)(was ^ 0xff);
        if (internet_checksum(header, header_bytes) == intact) {
            fprintf(stderr, "  flipping octet %zu did not change the sum\n", i);
            ok = false;
        }
        header[i] = was;
    }
    return ok;
}

/* ⚠ RFC 1071, read 2026-08-27: "[A,B] +' [C,D] +' ... +' [Z,0]". ⚠ The final
 * octet of an odd-length block is paired with a zero, so it is the high half of
 * the word. ⚠ Asserted by comparing against the same block with that zero
 * written out — which must give the same answer. */
static bool case_an_odd_length_pairs_the_last_octet_with_zero(void)
{
    static const unsigned char odd[] = { 0x12, 0x34, 0x56 };
    static const unsigned char padded[] = { 0x12, 0x34, 0x56, 0x00 };

    unsigned a = internet_checksum(odd, sizeof odd);
    unsigned b = internet_checksum(padded, sizeof padded);
    bool ok = true;
    if (a != b) {
        fprintf(stderr, "  odd gave 0x%04x and the same octets with a zero gave 0x%04x\n", a, b);
        ok = false;
    }
    /* ⚠ The other half: a trailing octet that is NOT zero must differ, or the
     * case above would pass for an implementation that dropped the last octet. */
    static const unsigned char other[] = { 0x12, 0x34, 0x56, 0x01 };
    if (internet_checksum(other, sizeof other) == a) {
        fprintf(stderr, "  a non-zero trailing octet made no difference\n");
        ok = false;
    }
    return ok;
}

/* ⚠ Decided here and asserted, not quoted: RFC 1071 was not read on this point.
 * The 1's complement of an empty sum is 0xffff. */
static bool case_no_octets_at_all(void)
{
    unsigned value = internet_checksum(NULL, 0);
    if (value != 0xffff) {
        fprintf(stderr, "  no octets gave 0x%04x, and this implementation says 0xffff\n", value);
        return false;
    }
    return true;
}

/* ⚠ A carry out of the top must be folded back in, and the fold can itself
 * carry. ⚠ An implementation that folded once would pass everything above. */
static bool case_a_carry_is_folded_back_and_folded_again(void)
{
    /* ⚠ Chosen so the fold itself carries, which is the only input that tells a
     * loop apart from a single fold:
     *
     *   0xffff + 0xffff + 0x0001 = 0x1ffff
     *   one fold   0xffff + 1 = 0x10000   -> ~ = 0xffff
     *   two folds  0x0000 + 1 = 0x00001   -> ~ = 0xfffe
     *
     * ⚠ An earlier version of this case used four 0xff octets. ⚠ It passed with
     * a single fold, because that input never needs a second one — the case was
     * named for something it did not check. */
    static const unsigned char carries[] = { 0xff, 0xff, 0xff, 0xff, 0x00, 0x01 };
    unsigned value = internet_checksum(carries, sizeof carries);
    if (value != 0xfffe) {
        fprintf(stderr, "  a sum whose fold carries gave 0x%04x, and folding until "
                        "nothing is left gives 0xfffe\n", value);
        return false;
    }
    return true;
}

/* ⚠ The field-cleared entry point must agree, octet for octet, with copying the
 * block and zeroing the field by hand — which is what every caller did before
 * it existed (hidetzu/tcpip-stack#34). ⚠ Checked over the captured frame's two
 * real checksums, at their two different offsets and lengths. */
static bool case_clearing_a_field_in_place_matches_clearing_a_copy(void)
{
    unsigned char frame[256];
    long bytes = load_the_echo_request(frame, sizeof frame);
    if (bytes < 0) {
        return false;
    }
    unsigned char *header = frame + ETHERNET_HEADER_BYTES;
    size_t header_bytes = (size_t)(header[0] & 0x0f) * IPV4_HEADER_LENGTH_UNITS;
    unsigned char *icmp = header + header_bytes;
    size_t icmp_bytes = (size_t)bytes - ETHERNET_HEADER_BYTES - header_bytes;

    struct { unsigned char *at; size_t count; size_t field; const char *what; } blocks[] = {
        { header, header_bytes, IPV4_CHECKSUM_AT, "the internet header" },
        { icmp, icmp_bytes, ICMP_CHECKSUM_AT, "the ICMP message" },
    };

    bool ok = true;
    for (size_t i = 0; i < sizeof blocks / sizeof blocks[0]; i++) {
        unsigned char copy[256];
        memcpy(copy, blocks[i].at, blocks[i].count);
        copy[blocks[i].field] = 0;
        copy[blocks[i].field + 1] = 0;

        unsigned by_copying = internet_checksum(copy, blocks[i].count);
        unsigned in_place = internet_checksum_with_field_cleared(
            blocks[i].at, blocks[i].count, blocks[i].field);
        if (by_copying != in_place) {
            fprintf(stderr, "  %s: clearing a copy gave 0x%04x, clearing in place gave 0x%04x\n",
                    blocks[i].what, by_copying, in_place);
            ok = false;
        }
        /* ⚠ The other half: it must also equal the number the kernel carried,
         * or the two could agree on the same wrong answer. */
        unsigned carried = ((unsigned)blocks[i].at[blocks[i].field] << 8) |
                           blocks[i].at[blocks[i].field + 1];
        if (in_place != carried) {
            fprintf(stderr, "  %s: the kernel carried 0x%04x and we compute 0x%04x\n",
                    blocks[i].what, carried, in_place);
            ok = false;
        }
        /* ⚠ And it must not have written into the caller's octets. */
        if (((unsigned)blocks[i].at[blocks[i].field] << 8 | blocks[i].at[blocks[i].field + 1]) !=
            carried) {
            fprintf(stderr, "  %s: the field was changed in the caller's buffer\n",
                    blocks[i].what);
            ok = false;
        }
    }
    return ok;
}

/* ⚠ Clearing nothing must be the plain sum. ⚠ Without this the two entry points
 * could diverge on every block that has no field to clear. */
static bool case_clearing_a_field_past_the_end_changes_nothing(void)
{
    static const unsigned char block[] = { 0x45, 0x00, 0x00, 0x54, 0xa3, 0x59 };
    unsigned plain = internet_checksum(block, sizeof block);
    unsigned past = internet_checksum_with_field_cleared(block, sizeof block, sizeof block);
    bool ok = true;
    if (plain != past) {
        fprintf(stderr, "  clearing past the end gave 0x%04x, the plain sum is 0x%04x\n",
                past, plain);
        ok = false;
    }
    /* ⚠ The other half: an offset that IS inside must change the answer, or the
     * case above would pass for an implementation that never clears anything. */
    if (internet_checksum_with_field_cleared(block, sizeof block, 2) == plain) {
        fputs("  clearing a field inside the block made no difference\n", stderr);
        ok = false;
    }
    return ok;
}

/* ⚠ Two blocks that are not next to each other must give what the same octets
 * joined would (hidetzu/tcpip-stack#41). ⚠ Split at every even offset of a real
 * block, so this cannot pass by working at one lucky boundary. */
static bool case_two_blocks_are_the_same_as_the_octets_joined(void)
{
    unsigned char frame[256];
    long bytes = load_the_echo_request(frame, sizeof frame);
    if (bytes < 0) {
        return false;
    }
    unsigned char *header = frame + ETHERNET_HEADER_BYTES;
    size_t header_bytes = (size_t)(header[0] & 0x0f) * IPV4_HEADER_LENGTH_UNITS;

    unsigned whole = internet_checksum_with_field_cleared(header, header_bytes,
                                                          IPV4_CHECKSUM_AT);
    bool ok = true;
    /* ⚠ Only even splits: the pad for an odd length belongs at the very end, and
     * checksum.h requires the first block to be even for exactly that reason. */
    for (size_t split = 0; split <= header_bytes; split += 2) {
        /* ⚠ The cleared field is an offset into the SECOND block, so a split
         * past it moves where it is; skip the splits that would cut the field
         * itself in half, which is not a thing any caller does. */
        if (split > IPV4_CHECKSUM_AT) {
            continue;
        }
        unsigned in_two = internet_checksum_of_two(header, split, header + split,
                                                   header_bytes - split,
                                                   IPV4_CHECKSUM_AT - split);
        if (in_two != whole) {
            fprintf(stderr, "  split at %zu gave 0x%04x, the whole gives 0x%04x\n",
                    split, in_two, whole);
            ok = false;
        }
    }

    /* ⚠ The other half: a prefix that is not part of the block must change the
     * answer, or the case above would pass for a function that ignored it. */
    static const unsigned char prefix[] = { 0x0a, 0x00, 0x00, 0x01 };
    if (internet_checksum_of_two(prefix, sizeof prefix, header, header_bytes,
                                 IPV4_CHECKSUM_AT) == whole) {
        fputs("  a four-octet prefix made no difference to the sum\n", stderr);
        ok = false;
    }
    return ok;
}

/* ⚠ No prefix at all is the plain sum. ⚠ Without this the two older entry points
 * could drift from the one they are now written in terms of. */
static bool case_no_prefix_is_the_plain_sum(void)
{
    static const unsigned char block[] = { 0x45, 0x00, 0x00, 0x54, 0xa3, 0x59, 0x40 };
    bool ok = true;

    if (internet_checksum_of_two(NULL, 0, block, sizeof block, sizeof block) !=
        internet_checksum(block, sizeof block)) {
        fputs("  no prefix did not give what internet_checksum gives\n", stderr);
        ok = false;
    }
    if (internet_checksum_of_two(NULL, 0, block, sizeof block, 2) !=
        internet_checksum_with_field_cleared(block, sizeof block, 2)) {
        fputs("  no prefix with a cleared field did not give what "
              "internet_checksum_with_field_cleared gives\n", stderr);
        ok = false;
    }
    /* ⚠ The other half: the block above has an odd length on purpose, so this
     * also says the pad still lands at the end when a prefix is asked for. */
    static const unsigned char nothing[1] = { 0 };
    if (internet_checksum_of_two(nothing, 0, block, sizeof block, sizeof block) !=
        internet_checksum(block, sizeof block)) {
        fputs("  a zero-length prefix that is not NULL behaved differently\n", stderr);
        ok = false;
    }
    return ok;
}

static const struct test_case cases[] = {
    { "the_kernels_ipv4_header_checksum_is_reproduced",
      case_the_kernels_ipv4_header_checksum_is_reproduced },
    { "the_kernels_icmp_checksum_is_reproduced", case_the_kernels_icmp_checksum_is_reproduced },
    { "flipping_any_octet_changes_the_sum", case_flipping_any_octet_changes_the_sum },
    { "an_odd_length_pairs_the_last_octet_with_zero",
      case_an_odd_length_pairs_the_last_octet_with_zero },
    { "no_octets_at_all", case_no_octets_at_all },
    { "a_carry_is_folded_back_and_folded_again",
      case_a_carry_is_folded_back_and_folded_again },
    { "clearing_a_field_in_place_matches_clearing_a_copy",
      case_clearing_a_field_in_place_matches_clearing_a_copy },
    { "clearing_a_field_past_the_end_changes_nothing",
      case_clearing_a_field_past_the_end_changes_nothing },
    { "two_blocks_are_the_same_as_the_octets_joined",
      case_two_blocks_are_the_same_as_the_octets_joined },
    { "no_prefix_is_the_plain_sum", case_no_prefix_is_the_plain_sum },
};

#define CASE_COUNT (sizeof cases / sizeof cases[0])

int main(int argc, char **argv)
{
    return check_main("checksum", cases, CASE_COUNT, argc, argv);
}
