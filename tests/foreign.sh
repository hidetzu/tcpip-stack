#!/bin/sh
# foreign — the other end of the conversation is the Linux kernel, which is not
# something we wrote (`.claude/rules/layers.md`, question 3).
#
# ⚠ Still nothing outside this machine: the namespace is private and the only
# other participant is the kernel's own stack.

set -u
cd "$(dirname -- "$0")/.." || exit 2
. tests/lib.sh

TCPIP_STACK=./build/tcpip-stack
MAKE=${MAKE:-make}

wait_for_interface() {
    i=0
    while [ "$i" -lt 60 ]; do
        if ip link show "$1" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.05
        i=$((i + 1))
    done
    return 1
}

# Turns the reported output back into one line per frame: "<length> <hex>".
#
# Turns the reported output back into one line per frame: "<length> <hex>".
#
# ⚠ This reads the bytes of a frame, and so does src/arp.c. ⚠ What used to be
# two implementations of the same question is now one: the offsets below are
# derived from the constants src/ uses, so ⚠ they cannot drift from the parser's
# (`CLAUDE.md` §3, hidetzu/tcpip-stack#11).
#
# ⚠ What is deliberately NOT shared is the reading itself. This case still cuts
# the octets out for itself and ⚠ never asks src/arp.c what the frame is. ⚠ That
# independence is what makes the foreign tier an answer to question 3
# (`.claude/rules/layers.md`): a check that used our parser to find the frame
# whose octets it verifies would be our parser agreeing with our parser.
#
# ⚠ So breaking src/arp.c must NOT break this case, and it does not — measured
# 2026-08-27: swapping ar$spa and ar$tpa left this passing and made 4 of 11
# static ARP cases fail. ⚠ The parser's correctness is the static tier's job.
frames_as_hex() {
    awk '
        /^frame [0-9]+  [0-9]+ bytes/ {
            if (seen > 0) print length_of_frame, hex
            seen++; length_of_frame = $3; hex = ""; next
        }
        /^  [0-9a-f][0-9a-f][0-9a-f][0-9a-f] / {
            line = $0
            sub(/^  [0-9a-f]+/, "", line)
            gsub(/ /, "", line)
            hex = hex line
        }
        END { if (seen > 0) print length_of_frame, hex }
    ' "$1"
}

# ⚠ The buffer size is read out of the header rather than written here a second
# time: if it changes, this check follows it instead of quietly stopping to
# exercise the path (`CLAUDE.md` §3).
read_buffer_bytes() {
    awk '/^#define TAP_FRAME_BUFFER_BYTES/ { print $3 }' src/tap.h
}

# Where a field sits in a frame, in octets, taken from the constants src/ uses.
#
# ⚠ One home for the layout. ⚠ Writing 12, 28 and 38 here a second time is how
# this file and the parser would silently diverge (`CLAUDE.md` §3).
constant() {  # header name
    awk -v n="$2" '$1 == "#define" && $2 == n { print $3 }' "$1"
}

# Turns an octet offset into the position of its first character in a hex string.
at_octet() {
    printf '%d' $(( $1 * 2 + 1 ))
}

# ⚠ read(2) on a TAP fd hands back a truncated frame and discards the rest — it
# does not fail and it does not say it truncated. So a read that returns exactly
# the buffer size is a length we do not know, and it has to be reported as that
# rather than as a measurement (`CLAUDE.md` §1).
#
# ⚠ The kernel is what produces the oversized frame: the MTU goes above the read
# buffer and it is given something large to send. Nothing is added to src/ to
# make this reachable.
inside_a_frame_larger_than_the_read_buffer_is_not_reported_as_a_known_length() {
    buffer_bytes=$(read_buffer_bytes)
    if [ -z "$buffer_bytes" ]; then
        note_failure "could not read TAP_FRAME_BUFFER_BYTES out of src/tap.h"
        return
    fi

    "$TCPIP_STACK" --dev tap0 --count 4 --timeout 3000 \
        >"$work/out.txt" 2>"$work/err.txt" &
    reader=$!

    if ! wait_for_interface tap0; then
        note_failure "tap0 never appeared while tcpip-stack was attached"
        kill "$reader" 2>/dev/null
        wait "$reader" 2>/dev/null
        return
    fi

    ip link set tap0 mtu $((buffer_bytes * 2))
    ip addr add 10.0.0.1/24 dev tap0
    ip link set tap0 up
    # Told where 10.0.0.2 is, so the kernel sends the echo request itself instead
    # of stopping at an ARP request nobody answers.
    ip neigh add 10.0.0.2 lladdr 02:00:00:00:00:02 dev tap0
    ping -c 2 -i 0.3 -W 1 -s $((buffer_bytes + 512)) 10.0.0.2 >/dev/null 2>&1 || true

    wait "$reader"
    reader_exit=$?
    if [ "$reader_exit" -ne 0 ] && [ "$reader_exit" -ne 2 ]; then
        note_failure "tcpip-stack stopped with exit code $reader_exit"
        sed 's/^/      /' "$work/err.txt" >&2
        return
    fi

    if ! grep -q "bytes (filled the buffer; it may have been longer)" "$work/out.txt"; then
        note_failure "no frame was reported as having filled the read buffer"
        printf '    what was read:\n' >&2
        sed 's/^/      /' "$work/out.txt" >&2
        return
    fi

    # ⚠ The other half. A check that only asks for the marker stays green if
    # every frame is marked (`verify` §5).
    if ! grep -q '^frame [0-9][0-9]*  [0-9][0-9]* bytes$' "$work/out.txt"; then
        note_failure "every frame was reported as having filled the buffer, which cannot be right"
        printf '    what was read:\n' >&2
        sed 's/^/      /' "$work/out.txt" >&2
    fi
}

inside_an_arp_request_the_kernel_generated_is_read_intact() {
    "$TCPIP_STACK" --dev tap0 --count 3 --timeout 3000 --hex \
        >"$work/out.txt" 2>"$work/err.txt" &
    reader=$!

    if ! wait_for_interface tap0; then
        note_failure "tap0 never appeared while tcpip-stack was attached"
        kill "$reader" 2>/dev/null
        wait "$reader" 2>/dev/null
        return
    fi

    # Give the kernel a reason to put an ARP request on the wire: an address on
    # tap0's subnet that nothing answers for (RFC 826).
    ip addr add 10.0.0.1/24 dev tap0
    ip link set tap0 up
    ping -c 2 -i 0.3 -W 1 10.0.0.2 >/dev/null 2>&1 || true

    # ⚠ The reader may finish by reading its three frames or by its timer running
    # out. Both are honest outcomes here, because how many frames the kernel
    # chooses to send is not ours to assert (`.claude/rules/testing.md`).
    wait "$reader"
    reader_exit=$?
    if [ "$reader_exit" -ne 0 ] && [ "$reader_exit" -ne 2 ]; then
        note_failure "tcpip-stack stopped with exit code $reader_exit"
        sed 's/^/      /' "$work/err.txt" >&2
        return
    fi

    # ⚠ Derived, never written here a second time (`CLAUDE.md` §3).
    address_octets=$(constant src/ethernet.h ETHERNET_ADDRESS_BYTES)
    header_octets=$(constant src/ethernet.h ETHERNET_HEADER_BYTES)
    fixed_octets=$(constant src/arp.h ARP_FIXED_BYTES)
    hardware_octets=$(constant src/arp.h ARP_HARDWARE_ADDRESS_BYTES)
    protocol_octets=$(constant src/arp.h ARP_PROTOCOL_ADDRESS_BYTES)
    for value in "$address_octets" "$header_octets" "$fixed_octets" \
        "$hardware_octets" "$protocol_octets"; do
        if [ -z "$value" ]; then
            note_failure "a constant could not be read out of src/, so the offsets are unknown"
            return
        fi
    done

    arp_frame_octets=$((header_octets + fixed_octets + 2 * (hardware_octets + protocol_octets)))
    ethertype_at=$(at_octet $((address_octets * 2)))
    spa_at=$(at_octet $((header_octets + fixed_octets + hardware_octets)))
    tpa_at=$(at_octet $((header_octets + fixed_octets + 2 * hardware_octets + protocol_octets)))

    found_arp_request=0
    lengths_disagreeing=0
    frames_as_hex "$work/out.txt" >"$work/frames.txt"
    while read -r frame_length hex; do
        [ -n "${hex:-}" ] || continue
        # ⚠ Every byte printed, and no byte that was not read.
        if [ "${#hex}" -ne $((frame_length * 2)) ]; then
            lengths_disagreeing=$((lengths_disagreeing + 1))
        fi
        [ "$frame_length" -eq "$arp_frame_octets" ] || continue
        ethertype=$(printf '%s' "$hex" | cut -c"$ethertype_at"-$((ethertype_at + 3)))
        sender_protocol_address=$(printf '%s' "$hex" | cut -c"$spa_at"-$((spa_at + 7)))
        target_protocol_address=$(printf '%s' "$hex" | cut -c"$tpa_at"-$((tpa_at + 7)))
        if [ "$ethertype" = "0806" ] &&
            [ "$sender_protocol_address" = "0a000001" ] &&
            [ "$target_protocol_address" = "0a000002" ]; then
            found_arp_request=1
        fi
    done <"$work/frames.txt"

    if [ "$lengths_disagreeing" -ne 0 ]; then
        note_failure "$lengths_disagreeing frame(s) printed a number of bytes that was not the length reported"
    fi

    # ⚠ Scanned, never positional: which frame arrives first is not stable
    # (measured 3 of 5 runs vs 2 of 5, hidetzu/tcpip-stack#2).
    if [ "$found_arp_request" -ne 1 ]; then
        note_failure "no ARP request for 10.0.0.2 from 10.0.0.1 was among the frames read"
        printf '    what was read:\n' >&2
        sed 's/^/      /' "$work/out.txt" >&2
    fi
}

# ⚠ The milestone's proof. The other end is the Linux kernel, and what says we
# answered is not our own output — it is ⚠ the kernel's neighbour table
# (`.claude/rules/layers.md`, question 3).
#
# ⚠ Both halves in one namespace: the address we answer for becomes resolved to
# OUR hardware address, and one we do not answer for stays unresolved. ⚠ A stack
# that answered everything would pass the first half alone (`verify` §5).
#
# ⚠ ping is not waited on and its verdict is not asserted here. ⚠ What this case
# is about is the neighbour table, and ⚠ whether the ping then succeeds is
# `ping_reports_no_loss_against_our_own_stack`'s question, not this one
# (`.claude/rules/testing.md`: assert our own correctness, one thing at a time).
#
# ⚠ The table is read while the program still holds the device. It is gone the
# moment that fd closes (`docs/SPEC.md` §1), and there is then nothing to read.
inside_the_kernel_believes_the_address_we_answered_for() {
    ours=10.0.0.2
    not_ours=10.0.0.9
    our_mac=02:00:00:00:00:02

    "$TCPIP_STACK" --dev tap0 --mac "$our_mac" --ipv4 "$ours" --timeout 4000 \
        >"$work/out.txt" 2>"$work/err.txt" &
    reader=$!

    if ! wait_for_interface tap0; then
        note_failure "tap0 never appeared while the stack was attached"
        kill "$reader" 2>/dev/null
        wait "$reader" 2>/dev/null
        return
    fi

    ip addr add 10.0.0.1/24 dev tap0
    ip link set tap0 up
    # ⚠ Give the kernel a reason to ask for each address.
    ping -c 2 -i 0.3 -W 1 "$ours" >/dev/null 2>&1 || true
    ping -c 1 -i 0.3 -W 1 "$not_ours" >/dev/null 2>&1 || true

    ip neigh show dev tap0 >"$work/neigh.txt"
    kill -INT "$reader" 2>/dev/null
    wait "$reader" 2>/dev/null

    # ⚠ The address that came back is asserted, not merely that the entry
    # stopped being INCOMPLETE. A stack that answered with somebody else's
    # hardware address would pass the weaker check.
    if ! grep -q "^$ours lladdr $our_mac " "$work/neigh.txt"; then
        note_failure "the kernel did not learn $our_mac for $ours"
        printf '    what the kernel believes:\n' >&2
        sed 's/^/      /' "$work/neigh.txt" >&2
        printf '    what the stack said:\n' >&2
        sed 's/^/      /' "$work/out.txt" >&2
        return
    fi

    # ⚠ The other half.
    if grep -q "^$not_ours lladdr " "$work/neigh.txt"; then
        note_failure "the kernel learned an address for $not_ours, which we do not answer for"
        sed 's/^/      /' "$work/neigh.txt" >&2
        return
    fi

    # ⚠ Declining is counted, so "we declined" can never be mistaken for
    # "nothing arrived" (`.claude/rules/c.md`).
    assert_file_contains "$work/out.txt" "1 was not for us" "declining is counted"
    assert_file_contains "$work/out.txt" \
        "no answer: it asked for $not_ours, which is not an address we answer for" \
        "declining says which address"

    printf '    the kernel believes: %s\n' "$(grep "^$ours" "$work/neigh.txt")"
}

# ⚠ The milestone's proof, and ⚠ the verdict is not ours: `ping` decides.
#
# ⚠ Why that is strong: the kernel checks the internet header checksum and the
# ICMP checksum before it accepts a reply, so ⚠ 0% loss is somebody else's
# arithmetic agreeing with ours (`.claude/rules/layers.md`, question 3).
#
# ⚠ Why it is not enough on its own: ⚠ a stack that never validated a checksum on
# the way in would answer this ping too (`CLAUDE.md` §1). ⚠ What stops that is
# `tests/static.sh` `echo_responder`, case
# `an_icmp_checksum_that_does_not_agree_is_not_answered_and_is_counted`
# (hidetzu/tcpip-stack#35 AC 2). ⚠ Neither check replaces the other.
#
# ⚠ This case reads no octet of any frame and asks no parser of ours anything
# (ADR 0009). ⚠ Breaking a parser must break the static tier, not this
# (measured — see the report on hidetzu/tcpip-stack#35).
#
# ⚠ LC_ALL=C so the sentence ping prints is the one being matched, whatever the
# machine's language is.
inside_ping_reports_no_loss_against_our_own_stack() {
    ours=10.0.0.2
    not_ours=10.0.0.9
    our_mac=02:00:00:00:00:02

    "$TCPIP_STACK" --dev tap0 --mac "$our_mac" --ipv4 "$ours" --timeout 5000 \
        >"$work/out.txt" 2>"$work/err.txt" &
    reader=$!

    if ! wait_for_interface tap0; then
        note_failure "tap0 never appeared while the stack was attached"
        kill "$reader" 2>/dev/null
        wait "$reader" 2>/dev/null
        return
    fi

    ip addr add 10.0.0.1/24 dev tap0
    ip link set tap0 up

    LC_ALL=C ping -c 3 -i 0.3 -W 1 "$ours" >"$work/ping.txt" 2>&1
    ping_exit=$?

    # ⚠ The other half, in the same run: an address we do not answer for must
    # still be lost. ⚠ Without it this case would pass on a machine where
    # something else was replying (`verify` §5).
    LC_ALL=C ping -c 1 -i 0.3 -W 1 "$not_ours" >"$work/ping-other.txt" 2>&1
    other_exit=$?

    kill -INT "$reader" 2>/dev/null
    wait "$reader" 2>/dev/null

    if [ "$ping_exit" -ne 0 ]; then
        note_failure "ping $ours exited $ping_exit"
        printf '    what ping said:\n' >&2
        sed 's/^/      /' "$work/ping.txt" >&2
        printf '    what the stack said:\n' >&2
        sed 's/^/      /' "$work/out.txt" >&2
        return
    fi
    # ⚠ ", 0% packet loss" and not "0% packet loss": the latter is inside
    # "100% packet loss" as well.
    if ! grep -q ", 0% packet loss" "$work/ping.txt"; then
        note_failure "ping $ours did not report 0% packet loss"
        sed 's/^/      /' "$work/ping.txt" >&2
        printf '    what the stack said:\n' >&2
        sed 's/^/      /' "$work/out.txt" >&2
        return
    fi

    if [ "$other_exit" -eq 0 ] || ! grep -q "100% packet loss" "$work/ping-other.txt"; then
        note_failure "ping $not_ours succeeded, and nothing here answers for that address"
        sed 's/^/      /' "$work/ping-other.txt" >&2
        return
    fi

    # ⚠ Answering is counted, and ⚠ counted only for what the wire took. ⚠ The
    # count is a number this stack printed, so it is a weaker statement than
    # ping's verdict above — it is here so that "we answered" can never be
    # mistaken for "nothing arrived" (`.claude/rules/c.md`).
    assert_file_contains "$work/out.txt" "answered 3 echo requests" \
        "answering is counted"
    assert_file_contains "$work/out.txt" "1 was not for us" \
        "a datagram for another address is counted apart"

    printf '    ping said: %s\n' "$(grep "packet loss" "$work/ping.txt")"
}

# ⚠ The milestone's proof, and ⚠ the verdict is not ours: `connect()` decides,
# and `ss` reports.
#
# ⚠ Why that is strong: the kernel checks the TCP checksum over a pseudo-header
# and the acknowledgment number before it completes a connection, so ⚠ ESTAB is
# somebody else's arithmetic agreeing with ours (`.claude/rules/layers.md`,
# question 3).
#
# ⚠ Why it is not enough on its own: ⚠ a stack that never validated a checksum on
# the way in would complete this handshake too (`CLAUDE.md` §1). ⚠ What stops
# that is `a_syn_whose_checksum_does_not_agree_is_not_answered` below, and
# `tests/static.sh` `handshake` (hidetzu/tcpip-stack#44 AC 2). ⚠ Neither replaces
# the other.
#
# ⚠ This case reads no octet of any frame and asks no parser of ours anything
# (ADR 0009). ⚠ It will still fail when a parser breaks, because it asserts end
# to end — ⚠ ADR 0012 already recorded that measurement and why it is correct.
#
# ⚠ The socket is held open by a live process while `ss` runs. ⚠ A shell's
# /dev/tcp closes the moment its subshell exits, and there would be nothing to
# report.
inside_the_kernel_opens_a_connection_to_us() {
    ours=10.0.0.2
    our_mac=02:00:00:00:00:02
    port=80

    "$TCPIP_STACK" --dev tap0 --mac "$our_mac" --ipv4 "$ours" --tcp-port "$port" \
        --timeout 6000 >"$work/out.txt" 2>"$work/err.txt" &
    reader=$!

    if ! wait_for_interface tap0; then
        note_failure "tap0 never appeared while the stack was attached"
        kill "$reader" 2>/dev/null
        wait "$reader" 2>/dev/null
        return
    fi

    ip addr add 10.0.0.1/24 dev tap0
    ip link set tap0 up

    # ⚠ python holds the socket while ss runs, and ⚠ prints only what it was
    # told by connect() and by ss — ⚠ nothing of ours is consulted.
    LC_ALL=C python3 -c '
import socket, subprocess, sys
s = socket.socket()
s.settimeout(5)
try:
    s.connect(("10.0.0.2", 80))
except Exception as why:
    print("connect failed:", why)
    sys.exit(1)
print("connect succeeded")
print(subprocess.run(["ss", "-tn"], capture_output=True, text=True).stdout, end="")
' >"$work/connect.txt" 2>&1
    connect_exit=$?

    # ⚠ The other half, in the same run: a port we do not answer for must not
    # open. ⚠ Without it this case would pass on a machine where something else
    # was answering.
    LC_ALL=C python3 -c '
import socket, sys
s = socket.socket()
s.settimeout(2)
try:
    s.connect(("10.0.0.2", 81))
except Exception:
    sys.exit(1)
sys.exit(0)
' >/dev/null 2>&1
    other_exit=$?

    kill -INT "$reader" 2>/dev/null
    wait "$reader" 2>/dev/null

    if [ "$connect_exit" -ne 0 ]; then
        note_failure "connect() to $ours:$port did not succeed"
        sed 's/^/      /' "$work/connect.txt" >&2
        printf '    what the stack said:\n' >&2
        sed 's/^/      /' "$work/out.txt" >&2
        return
    fi

    # ⚠ ss's own word, and ⚠ the peer is asserted rather than just the state: a
    # connection to something else on the machine would show ESTAB too.
    if ! grep -qE "^ESTAB .* $ours:$port *\$" "$work/connect.txt" &&
       ! grep -qE "ESTAB .*$ours:$port" "$work/connect.txt"; then
        note_failure "ss did not report a connection established to $ours:$port"
        sed 's/^/      /' "$work/connect.txt" >&2
        return
    fi

    if [ "$other_exit" -eq 0 ]; then
        note_failure "a connection opened on port 81, which nothing here answers for"
        return
    fi

    # ⚠ Answering is counted, and ⚠ counted only for what the wire took. ⚠ This
    # is a number our own stack printed, so it says less than ss's word above —
    # it is here so "we answered" can never be mistaken for "nothing arrived".
    assert_file_contains "$work/out.txt" "1 connection was opened and 1 answered" \
        "answering is counted once the wire took it"
    assert_file_contains "$work/out.txt" "1 reached open." \
        "reaching ESTABLISHED is counted"

    printf '    ss said: %s\n' "$(grep ESTAB "$work/connect.txt" | head -1)"
}

# ⚠ The half that stops the case above passing for a stack that never looked at
# a checksum (hidetzu/tcpip-stack#44 AC 2, and `CLAUDE.md` §1).
#
# ⚠ The segment is built here and handed to the kernel on a raw socket, so ⚠ the
# kernel routes it out tap0 and our stack reads it exactly as it reads anything
# else. ⚠ Why not write the frame onto the device directly: ⚠ **two processes
# cannot hold one TAP device**, which `tests/real.sh`
# `a_second_attach_to_the_same_device_is_refused` asserts.
#
# ⚠ Both halves are sent in one run: the same segment with the right checksum and
# with a wrong one. ⚠ Without the first, this case would pass for a stack that
# answered nothing at all.
inside_a_syn_whose_checksum_does_not_agree_is_not_answered() {
    ours=10.0.0.2
    our_mac=02:00:00:00:00:02

    "$TCPIP_STACK" --dev tap0 --mac "$our_mac" --ipv4 "$ours" --tcp-port 80 \
        --timeout 4000 >"$work/out.txt" 2>"$work/err.txt" &
    reader=$!

    if ! wait_for_interface tap0; then
        note_failure "tap0 never appeared while the stack was attached"
        kill "$reader" 2>/dev/null
        wait "$reader" 2>/dev/null
        return
    fi
    ip addr add 10.0.0.1/24 dev tap0
    ip link set tap0 up

    LC_ALL=C python3 -c '
import socket, struct

source = socket.inet_aton("10.0.0.1")
destination = socket.inet_aton("10.0.0.2")

def sum_of(octets):
    total = 0
    for i in range(0, len(octets) - 1, 2):
        total += (octets[i] << 8) | octets[i + 1]
    if len(octets) % 2:
        total += octets[-1] << 8
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff

def a_syn(port, right):
    segment = struct.pack("!HHIIBBHHH", port, 80, 1000, 0, 5 << 4, 0x02, 64240, 0, 0)
    pseudo = source + destination + bytes([0, 6, 0, len(segment)])
    checksum = sum_of(pseudo + segment)
    if not right:
        checksum ^= 0xffff
    return segment[:16] + struct.pack("!H", checksum) + segment[18:]

raw = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
raw.sendto(a_syn(41234, True), ("10.0.0.2", 0))
raw.sendto(a_syn(41235, False), ("10.0.0.2", 0))
' >"$work/sent.txt" 2>&1
    sent_exit=$?

    # ⚠ Give the reader time to see both before its timer runs out.
    sleep 1
    kill -INT "$reader" 2>/dev/null
    wait "$reader" 2>/dev/null

    if [ "$sent_exit" -ne 0 ]; then
        note_failure "the two segments could not be handed to the kernel"
        sed 's/^/      /' "$work/sent.txt" >&2
        return
    fi

    # ⚠ The wrong one: not answered, and counted apart.
    assert_file_contains "$work/out.txt" \
        "no answer: its TCP checksum does not agree with the octets that arrived" \
        "a segment whose checksum disagrees says so"
    assert_file_contains "$work/out.txt" \
        "0 TCP headers were malformed and 1 had a checksum that does not agree" \
        "a checksum that disagrees is counted apart"

    # ⚠ The right one: answered. ⚠ Without this the case would pass for a stack
    # that rejected every segment there is.
    assert_file_contains "$work/out.txt" "1 connection was opened and 1 answered" \
        "the same segment with the right checksum is answered"

    printf '    the stack said: %s\n' \
        "$(grep 'checksum does not agree' "$work/out.txt" | head -1 | sed 's/^ *//')"
}

in_namespace() {
    if ! unshare -Urn "$0" --inside "$1"; then
        current_case_ok=0
    fi
}

case_an_arp_request_the_kernel_generated_is_read_intact() {
    in_namespace an_arp_request_the_kernel_generated_is_read_intact
}
case_ping_reports_no_loss_against_our_own_stack() {
    in_namespace ping_reports_no_loss_against_our_own_stack
}
case_the_kernel_opens_a_connection_to_us() {
    in_namespace the_kernel_opens_a_connection_to_us
}
case_a_syn_whose_checksum_does_not_agree_is_not_answered() {
    in_namespace a_syn_whose_checksum_does_not_agree_is_not_answered
}
case_a_frame_larger_than_the_read_buffer_is_not_reported_as_a_known_length() {
    in_namespace a_frame_larger_than_the_read_buffer_is_not_reported_as_a_known_length
}
case_the_kernel_believes_the_address_we_answered_for() {
    in_namespace the_kernel_believes_the_address_we_answered_for
}

ALL_CASES="an_arp_request_the_kernel_generated_is_read_intact a_frame_larger_than_the_read_buffer_is_not_reported_as_a_known_length the_kernel_believes_the_address_we_answered_for ping_reports_no_loss_against_our_own_stack the_kernel_opens_a_connection_to_us a_syn_whose_checksum_does_not_agree_is_not_answered"

if [ "${1:-}" = "--inside" ]; then
    work=$(mktemp -d)
    trap 'rm -rf "$work"' EXIT
    current_case_ok=1
    "inside_$2"
    [ "$current_case_ok" -eq 1 ]
    exit $?
fi

# ⚠ --count and --list are answered before anything is built, so counting stays
# cheap (`.claude/skills/verify/SKILL.md` §1).
select_cases foreign "$ALL_CASES" "$@"

$MAKE -s build || exit 2

if ! unshare -Urn true 2>/dev/null; then
    printf 'foreign: the check environment could not be built here: unshare -Urn was refused.\n' >&2
    printf 'foreign: 0 cases ran. Nothing was checked, and nothing was disproved either.\n' >&2
    exit 2
fi

run_selected_cases
