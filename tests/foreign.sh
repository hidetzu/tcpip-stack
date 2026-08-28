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

# ⚠ hidetzu/tcpip-stack#64 AC 4, and ⚠ **the point of the whole change.**
#
# ⚠ Measured before the change, same conditions, 2026-08-29: with the answer's
# window at 0 the kernel's close() produced no FIN at all — five bare ACKs and
# nothing else — and ⚠ **with it at 1 the FIN arrives.** ⚠ So this case is what
# says the window is a number that does something, not a number that is written.
#
# ⚠ The issue named the real tier for this. ⚠ It cannot be real: ⚠ **the FIN is
# produced by the Linux kernel's own close()**, and who the other end is is what
# separates the tiers (`.claude/skills/verify/SKILL.md` §1). ⚠ A real-tier check
# would have had to craft the FIN itself, which would assert that we can send
# ourselves a FIN and nothing about the window.
#
# ⚠ The control bits are cut out of the hex here, by this file, ⚠ never by
# asking src/tcp.c what the segment is — the same independence
# `an_arp_request_the_kernel_generated_is_read_intact` keeps.
inside_a_fin_reaches_us_once_the_window_is_open() {
    ours=10.0.0.2
    our_mac=02:00:00:00:00:02
    port=80

    "$TCPIP_STACK" --dev tap0 --mac "$our_mac" --ipv4 "$ours" --tcp-port "$port" \
        --timeout 6000 --hex >"$work/out.txt" 2>"$work/err.txt" &
    reader=$!

    if ! wait_for_interface tap0; then
        note_failure "tap0 never appeared while the stack was attached"
        kill "$reader" 2>/dev/null
        wait "$reader" 2>/dev/null
        return
    fi

    # ⚠ IPv6 off, so the frames counted below are the ones this case is about.
    sysctl -qw net.ipv6.conf.tap0.disable_ipv6=1
    ip addr add 10.0.0.1/24 dev tap0
    ip link set tap0 up

    # ⚠ connect(), then close(). ⚠ Nothing of ours is consulted: the FIN is
    # whatever the kernel decides to send when the socket is closed.
    LC_ALL=C python3 -c '
import socket, sys, time
s = socket.socket()
s.settimeout(5)
try:
    s.connect(("10.0.0.2", 80))
except Exception as why:
    print("connect failed:", why)
    sys.exit(1)
print("connect succeeded")
s.close()
time.sleep(2)
' >"$work/close.txt" 2>&1
    connect_exit=$?

    kill -INT "$reader" 2>/dev/null
    wait "$reader" 2>/dev/null

    if [ "$connect_exit" -ne 0 ]; then
        note_failure "connect() to $ours:$port did not succeed, so nothing was closed"
        sed 's/^/      /' "$work/close.txt" >&2
        return
    fi

    # ⚠ Every offset and every bit comes from the constants src/ uses, ⚠ never
    # written here a second time (`CLAUDE.md` §3).
    ethernet_header=$(constant src/ethernet.h ETHERNET_HEADER_BYTES)
    ipv4_type=$(constant src/ipv4.h IPV4_ETHERNET_LENGTH_TYPE)
    tcp_number=$(constant src/tcp.h TCP_PROTOCOL_NUMBER)
    fin_bit=$(constant src/tcp.h TCP_CONTROL_FIN)
    syn_bit=$(constant src/tcp.h TCP_CONTROL_SYN)

    # ⚠ Counted apart: a check that called every segment a FIN would report the
    # SYN as one too, and ⚠ **bare acknowledgments are what arrived before this
    # change** (`verify` §5: never leave only the positive half).
    #
    # ⚠ python and not awk, because ⚠ `strtonum` and `and` are gawk's and
    # nothing else in this file needs them.
    LC_ALL=C frames_as_hex "$work/out.txt" | python3 -c '
import sys

def number(text):
    return int(text.rstrip("uU"), 0)

ethernet_header, ipv4_type, tcp_number, fin_bit, syn_bit = (
    number(argument) for argument in sys.argv[1:6])

syns = fins = others = 0
for line in sys.stdin:
    parts = line.split()
    if len(parts) != 2:
        continue
    octets = bytes.fromhex(parts[1])
    if len(octets) < ethernet_header + 20:
        continue
    if int.from_bytes(octets[ethernet_header - 2:ethernet_header], "big") != ipv4_type:
        continue
    internet_header = (octets[ethernet_header] & 0x0f) * 4
    if octets[ethernet_header + 9] != tcp_number:
        continue
    at = ethernet_header + internet_header
    if len(octets) < at + 20:
        continue
    bits = octets[at + 13]
    if bits & syn_bit:
        syns += 1
    elif bits & fin_bit:
        fins += 1
    else:
        others += 1
print(syns, fins, others)
' "$ethernet_header" "$ipv4_type" "$tcp_number" "$fin_bit" "$syn_bit" \
        >"$work/counted.txt"

    read -r syns fins others <"$work/counted.txt"

    if [ "$fins" -lt 1 ]; then
        note_failure "close() produced no FIN, so the window we advertise is not opening one"
        printf '    %s SYNs and %s other segments arrived\n' "$syns" "$others" >&2
        sed 's/^/      /' "$work/out.txt" | head -40 >&2
        return
    fi
    # ⚠ The other half: the bits are being read, not guessed. ⚠ The SYN and the
    # acknowledgment that opened the connection are neither of them FINs.
    if [ "$syns" -lt 1 ] || [ "$others" -lt 1 ]; then
        note_failure "no SYN or no plain acknowledgment was seen, so counting FINs proves nothing"
        printf '    %s SYNs, %s FINs, %s others\n' "$syns" "$fins" "$others" >&2
        return
    fi

    # ⚠ Our own stack's word, which says less than the octets above — it is here
    # so that a FIN arriving can never be mistaken for the connection never
    # having opened at all.
    assert_file_contains "$work/out.txt" "1 reached open." \
        "the connection reached ESTABLISHED before it was closed"
    # ⚠ hidetzu/tcpip-stack#65. ⚠ The octets above say a FIN arrived; ⚠ **this
    # says we read it** — and ⚠ the retransmissions are counted apart from it,
    # so one close never looks like several.
    assert_file_contains "$work/out.txt" "the other side closed 1 connection." \
        "the FIN the kernel sent moved the connection to CLOSE-WAIT"

    printf '    %s SYN, %s FIN and %s other segments arrived\n' "$syns" "$fins" "$others"
}

# ⚠ hidetzu/tcpip-stack#66 AC 1, 2 and 3, and ⚠ **none of them is our own
# output**: the segments are cut out of the wire by an `AF_PACKET` socket, and
# ⚠ **the verdict that we answered properly is the kernel's** — it stops
# retransmitting.
#
# ⚠ Measured before this change, same conditions, 2026-08-29: ⚠ **the kernel
# sent its FIN five times** because nothing acknowledged it. ⚠ One now.
#
# ⚠ Why `AF_PACKET` and not our own `--hex`: `--hex` prints what ARRIVED.
# ⚠ **What this case is about is what LEFT**, and a stack reporting its own
# sends would be our word for it (`.claude/rules/layers.md`, question 3).
inside_the_kernel_stops_retransmitting_once_we_close_back() {
    ours=10.0.0.2
    our_mac=02:00:00:00:00:02
    port=80

    "$TCPIP_STACK" --dev tap0 --mac "$our_mac" --ipv4 "$ours" --tcp-port "$port" \
        --timeout 5000 >"$work/out.txt" 2>"$work/err.txt" &
    reader=$!

    if ! wait_for_interface tap0; then
        note_failure "tap0 never appeared while the stack was attached"
        kill "$reader" 2>/dev/null
        wait "$reader" 2>/dev/null
        return
    fi
    sysctl -qw net.ipv6.conf.tap0.disable_ipv6=1
    ip addr add 10.0.0.1/24 dev tap0
    ip link set tap0 up

    ethernet_header=$(constant src/ethernet.h ETHERNET_HEADER_BYTES)
    ipv4_type=$(constant src/ipv4.h IPV4_ETHERNET_LENGTH_TYPE)
    tcp_number=$(constant src/tcp.h TCP_PROTOCOL_NUMBER)
    fin_bit=$(constant src/tcp.h TCP_CONTROL_FIN)
    ack_bit=$(constant src/tcp.h TCP_CONTROL_ACK)

    LC_ALL=C python3 -c '
import socket, subprocess, sys, threading, time

ethernet_header, ipv4_type, tcp_number, fin_bit, ack_bit = (
    int(argument.rstrip("uU"), 0) for argument in sys.argv[1:6])
OURS = bytes.fromhex(sys.argv[6].replace(":", ""))

# ⚠ ETH_P_ALL, or it receives nothing at all.
wire = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
wire.bind(("tap0", 0))
wire.settimeout(0.3)

seen = []
stop = threading.Event()

def watch():
    while not stop.is_set():
        try:
            frame = wire.recv(2048)
        except socket.timeout:
            continue
        except OSError:
            break
        if len(frame) < ethernet_header + 40:
            continue
        if int.from_bytes(frame[ethernet_header - 2:ethernet_header], "big") != ipv4_type:
            continue
        if frame[ethernet_header + 9] != tcp_number:
            continue
        internet = (frame[ethernet_header] & 0x0f) * 4
        at = ethernet_header + internet
        if len(frame) < at + 20:
            continue
        seen.append((frame[6:12] == OURS, frame[at + 13],
                     int.from_bytes(frame[at + 4:at + 8], "big"),
                     int.from_bytes(frame[at + 8:at + 12], "big")))

watcher = threading.Thread(target=watch)
watcher.start()

s = socket.socket()
s.settimeout(5)
try:
    s.connect(("10.0.0.2", 80))
except Exception as why:
    stop.set(); watcher.join()
    print("connect failed:", why); sys.exit(1)
s.close()
time.sleep(3.5)          # ⚠ past the whole retransmission schedule
after = subprocess.run(["ss", "-tan"], capture_output=True, text=True).stdout
stop.set(); watcher.join()

# ⚠ Theirs and ours are told apart by the ethernet source, ⚠ never by guessing
# from the direction of the numbers.
their_fins = [f for f in seen if not f[0] and f[1] & fin_bit]
our_fins = [f for f in seen if f[0] and f[1] & fin_bit]
print("their-fins", len(their_fins))
print("our-fins", len(our_fins))
for mine, bits, sequence, acknowledgment in our_fins[:1]:
    print("our-fin-acknowledges", acknowledgment)
    print("our-fin-carries-ack", 1 if bits & ack_bit else 0)
for mine, bits, sequence, acknowledgment in their_fins[:1]:
    print("their-fin-sits-at", sequence)
print("ss", " ".join(line.split()[0] for line in after.splitlines()[1:]) or "none")
' "$ethernet_header" "$ipv4_type" "$tcp_number" "$fin_bit" "$ack_bit" "$our_mac" \
        >"$work/closing.txt" 2>&1
    watched=$?

    kill -INT "$reader" 2>/dev/null
    wait "$reader" 2>/dev/null

    if [ "$watched" -ne 0 ]; then
        note_failure "the connection could not be opened, so nothing was closed"
        sed 's/^/      /' "$work/closing.txt" >&2
        return
    fi

    their_fins=$(awk '$1 == "their-fins" { print $2 }' "$work/closing.txt")
    our_fins=$(awk '$1 == "our-fins" { print $2 }' "$work/closing.txt")
    acknowledges=$(awk '$1 == "our-fin-acknowledges" { print $2 }' "$work/closing.txt")
    carries_ack=$(awk '$1 == "our-fin-carries-ack" { print $2 }' "$work/closing.txt")
    their_fin_at=$(awk '$1 == "their-fin-sits-at" { print $2 }' "$work/closing.txt")

    # ⚠ AC 1: our close reached the wire, seen by something that is not us.
    if [ "${our_fins:-0}" -lt 1 ]; then
        note_failure "our own close never reached the wire"
        sed 's/^/      /' "$work/closing.txt" >&2
        return
    fi
    # ⚠ AC 3, and ⚠ **it is the kernel's verdict and not ours**: it sent its FIN
    # once and stopped. ⚠ Five before this change, measured.
    if [ "${their_fins:-0}" -ne 1 ]; then
        note_failure "the kernel sent its FIN $their_fins times, so it is not satisfied with our answer"
        sed 's/^/      /' "$work/closing.txt" >&2
        return
    fi
    # ⚠ AC 2, read off the wire: it acknowledges past their FIN by exactly one.
    # ⚠ RFC 793: a FIN is "A control bit (finis) occupying one sequence number".
    if [ "${carries_ack:-0}" -ne 1 ] ||
       [ "$acknowledges" != "$(( (their_fin_at + 1) % 4294967296 ))" ]; then
        note_failure "our close acknowledges $acknowledges and their FIN sits at $their_fin_at"
        sed 's/^/      /' "$work/closing.txt" >&2
        return
    fi
    # ⚠ Our own stack's word, which says less than the octets above.
    assert_file_contains "$work/out.txt" "1 connection finished" \
        "the connection was released once our close was acknowledged"
    # ⚠ Counted under its own name and ⚠ **not as the answer**: one is a
    # handshake, the other a close, and a stack counting them together would say
    # it answered twice.
    assert_file_contains "$work/out.txt" "1 of our own closes left the device" \
        "our close is counted as a close and not as an answer"
    assert_file_contains "$work/out.txt" "1 connection was opened and 1 answered" \
        "the answer is still counted as an answer"

    printf '    the kernel sent %s FIN and we answered with %s; ss then said: %s\n' \
        "$their_fins" "$our_fins" \
        "$(awk '$1 == "ss" { $1 = ""; print substr($0, 2) }' "$work/closing.txt")"
}

# ⚠ hidetzu/tcpip-stack#67. ⚠ **The milestone's proof, and the verdict is the
# kernel's**: `TIME-WAIT` is the state RFC 793 Figures 6 and 13 put on the side
# that closed first, ⚠ **entered only once it has had our FIN and acknowledged
# it.** ⚠ Reaching it is somebody else's judgement on our sequence numbers.
#
# ⚠ **The connection disappearing after 2 MSL is deliberately not asserted**
# (hidetzu/tcpip-stack#67 Owner Decision 2): ⚠ that wait is the peer's own and
# ⚠ **nothing here can shorten it**, so a check that waited it out would be
# measuring the Linux kernel's timer and not this stack.
#
# ⚠ **The second `connect()` is evidence about OUR connection block and nothing
# else** (Owner Decision 3). ⚠ It is never called evidence that `TIME-WAIT`
# ended — ⚠ **the peer's `TIME-WAIT` is on the peer, and our block is here.**
inside_the_kernel_reaches_time_wait_and_our_block_is_free_again() {
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
    sysctl -qw net.ipv6.conf.tap0.disable_ipv6=1
    ip addr add 10.0.0.1/24 dev tap0
    ip link set tap0 up

    # ⚠ python holds nothing of ours: it calls connect(), close(), reads ss, and
    # ⚠ **prints only what those told it.**
    LC_ALL=C python3 -c '
import socket, subprocess, sys, time

def what_ss_says():
    return subprocess.run(["ss", "-tan"], capture_output=True, text=True).stdout

first = socket.socket()
first.settimeout(5)
try:
    first.connect(("10.0.0.2", 80))
except Exception as why:
    print("first-connect-failed", why); sys.exit(1)
here = first.getsockname()
first.close()

# ⚠ Watched for a moment, because the closing exchange is not instant. ⚠ What is
# waited for is the state changing, ⚠ **never a fixed sleep long enough to hide
# a slow answer.**
state = "none"
deadline = time.time() + 4.0
while time.time() < deadline:
    for line in what_ss_says().splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 5 and parts[3] == "%s:%d" % here:
            state = parts[0]
            break
    if state not in ("none", "ESTAB", "FIN-WAIT-1", "FIN-WAIT-2"):
        break
    time.sleep(0.1)
print("state-after-close", state)

# ⚠ A second connect(), and ⚠ **what it is evidence of is our connection block
# being free again** — not the first connection being gone from the peer.
second = socket.socket()
second.settimeout(5)
try:
    second.connect(("10.0.0.2", 80))
    print("second-connect", "yes")
except Exception as why:
    print("second-connect", "no", why)
second.close()
' >"$work/closing.txt" 2>&1
    watched=$?

    # ⚠ Long enough for the second connection to be answered and reported.
    sleep 1
    kill -INT "$reader" 2>/dev/null
    wait "$reader" 2>/dev/null

    if [ "$watched" -ne 0 ]; then
        note_failure "connect() to $ours:$port did not succeed, so nothing was closed"
        sed 's/^/      /' "$work/closing.txt" >&2
        return
    fi

    state=$(awk '$1 == "state-after-close" { print $2 }' "$work/closing.txt")
    second=$(awk '$1 == "second-connect" { print $2 }' "$work/closing.txt")

    # ⚠ AC 1. ⚠ **TIME-WAIT and nothing else**: `FIN-WAIT-1` or `FIN-WAIT-2`
    # would mean the kernel is still waiting for our close, and `CLOSE-WAIT`
    # would mean it thinks we closed first.
    if [ "$state" != "TIME-WAIT" ]; then
        note_failure "the kernel is in $state after close(), not TIME-WAIT, so it has not accepted our closing sequence"
        sed 's/^/      /' "$work/closing.txt" >&2
        printf '    what the stack said:\n' >&2
        grep -v '^  [0-9a-f]' "$work/out.txt" | tail -20 | sed 's/^/      /' >&2
        return
    fi

    # ⚠ AC 3, and ⚠ **it is evidence about our block and about nothing on the
    # peer** (Owner Decision 3). ⚠ The first connection is still in TIME-WAIT
    # over there while this succeeds, which is exactly why the two must not be
    # spoken of as one thing.
    if [ "$second" != "yes" ]; then
        note_failure "a later connect() was refused, so our own connection block was not freed"
        sed 's/^/      /' "$work/closing.txt" >&2
        return
    fi

    # ⚠ Both connections are closed by the peer, so ⚠ **both finish** — and
    # ⚠ the second could only be opened at all because the first gave its block
    # back. ⚠ That is what "our slot was freed" means here, and ⚠ **it says
    # nothing about the first connection's TIME-WAIT on the peer.**
    assert_file_contains "$work/out.txt" "2 connections finished" \
        "both connections were released when our closes were acknowledged"
    assert_file_contains "$work/out.txt" "2 connections were opened and 2 answered" \
        "the block the first connection gave back was used by the second"
    assert_file_contains "$work/out.txt" "0 were refused for want of room" \
        "the second SYN was not refused, which it would have been had the block stayed taken"

    printf '    ss said %s after close(), and a later connect() then succeeded, which\n' "$state"
    printf '    says our own connection block was free again and nothing about TIME-WAIT\n'
}

# ⚠ hidetzu/tcpip-stack#67 AC 2, and ⚠ **it is what stops the case above passing
# for a stack that never checked.**
#
# ⚠ The pattern hidetzu/tcpip-stack#35 and #44 both hit: ⚠ **a stack that answers
# a ping while computing the checksum wrong still answers the ping.** ⚠ A stack
# that closed back on any FIN at all would still reach `TIME-WAIT` above.
#
# ⚠ The whole connection is driven by hand over `AF_PACKET`, from a hardware
# address and an address nobody owns, ⚠ **so the kernel never joins in** — not
# even with a RST. ⚠ Our own answer is read off the wire to learn the sequence
# number we chose, ⚠ **never assumed from a constant in src/**.
inside_a_fin_whose_sequence_number_we_do_not_expect_is_not_answered() {
    ours=10.0.0.2
    our_mac=02:00:00:00:00:02

    "$TCPIP_STACK" --dev tap0 --mac "$our_mac" --ipv4 "$ours" --tcp-port 80 \
        --timeout 6000 >"$work/out.txt" 2>"$work/err.txt" &
    reader=$!

    if ! wait_for_interface tap0; then
        note_failure "tap0 never appeared while the stack was attached"
        kill "$reader" 2>/dev/null
        wait "$reader" 2>/dev/null
        return
    fi
    sysctl -qw net.ipv6.conf.tap0.disable_ipv6=1
    ip addr add 10.0.0.1/24 dev tap0
    ip link set tap0 up

    fin_bit=$(constant src/tcp.h TCP_CONTROL_FIN)
    ack_bit=$(constant src/tcp.h TCP_CONTROL_ACK)
    syn_bit=$(constant src/tcp.h TCP_CONTROL_SYN)

    LC_ALL=C python3 -c '
import socket, struct, sys, time

fin_bit, ack_bit, syn_bit = (int(a.rstrip("uU"), 0) for a in sys.argv[1:4])

OURS = b"\x02\x00\x00\x00\x00\x02"
THEIRS = b"\x02\xaa\xaa\xaa\xaa\xaa"
source = socket.inet_aton("10.0.0.99")
destination = socket.inet_aton("10.0.0.2")
THEIR_PORT = 40001
THEIR_ISN = 700000

def sum_of(octets):
    total = 0
    for i in range(0, len(octets) - 1, 2):
        total += (octets[i] << 8) | octets[i + 1]
    if len(octets) % 2:
        total += octets[-1] << 8
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff

wire = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
wire.bind(("tap0", 0))
wire.settimeout(0.3)

def send(bits, sequence, acknowledgment):
    segment = struct.pack("!HHIIBBHHH", THEIR_PORT, 80, sequence, acknowledgment,
                          5 << 4, bits, 64240, 0, 0)
    pseudo = source + destination + bytes([0, 6, 0, len(segment)])
    segment = segment[:16] + struct.pack("!H", sum_of(pseudo + segment)) + segment[18:]
    header = struct.pack("!BBHHHBBH", 0x45, 0, 20 + len(segment), 1, 0, 64, 6, 0) \
        + source + destination
    header = header[:10] + struct.pack("!H", sum_of(header)) + header[12:]
    wire.send(OURS + THEIRS + b"\x08\x00" + header + segment)

# ⚠ Every segment WE sent, for that long.
def ours_within(seconds):
    out = []
    end = time.time() + seconds
    while time.time() < end:
        try:
            frame = wire.recv(2048)
        except socket.timeout:
            continue
        except OSError:
            break
        if len(frame) < 54 or frame[12:14] != b"\x08\x00" or frame[14 + 9] != 6:
            continue
        if frame[6:12] != OURS:
            continue
        at = 14 + (frame[14] & 0x0f) * 4
        out.append((frame[at + 13], int.from_bytes(frame[at + 4:at + 8], "big"),
                    int.from_bytes(frame[at + 8:at + 12], "big")))
    return out

send(syn_bit, THEIR_ISN, 0)
answers = [a for a in ours_within(1.5) if a[0] & syn_bit]
if not answers:
    print("no-answer-to-our-syn"); sys.exit(1)
our_iss = answers[0][1]
print("our-iss", our_iss)
print("answer-acknowledges", answers[0][2])

send(ack_bit, THEIR_ISN + 1, our_iss + 1)
time.sleep(0.3)

# ⚠ A FIN far past the window we promised. ⚠ Nothing may come back for it.
send(fin_bit | ack_bit, THEIR_ISN + 1 + 500, our_iss + 1)
print("closes-after-a-wrong-fin",
      len([a for a in ours_within(1.5) if a[0] & fin_bit]))

# ⚠ The same FIN at the sequence number we ARE waiting for. ⚠ Without this half
# the case would pass for a stack that answers nothing at all.
send(fin_bit | ack_bit, THEIR_ISN + 1, our_iss + 1)
ours = [a for a in ours_within(1.5) if a[0] & fin_bit]
print("closes-after-the-right-fin", len(ours))
for bits, sequence, acknowledgment in ours[:1]:
    print("our-close-acknowledges", acknowledgment)
' "$fin_bit" "$ack_bit" "$syn_bit" >"$work/crafted.txt" 2>&1
    crafted=$?

    kill -INT "$reader" 2>/dev/null
    wait "$reader" 2>/dev/null

    if [ "$crafted" -ne 0 ]; then
        note_failure "the crafted connection could not be driven"
        sed 's/^/      /' "$work/crafted.txt" >&2
        return
    fi

    wrong=$(awk '$1 == "closes-after-a-wrong-fin" { print $2 }' "$work/crafted.txt")
    right=$(awk '$1 == "closes-after-the-right-fin" { print $2 }' "$work/crafted.txt")
    acknowledges=$(awk '$1 == "our-close-acknowledges" { print $2 }' "$work/crafted.txt")
    their_isn=700000

    if [ "${wrong:-1}" -ne 0 ]; then
        note_failure "a FIN 500 past what we asked for was answered $wrong times"
        sed 's/^/      /' "$work/crafted.txt" >&2
        return
    fi
    if [ "${right:-0}" -lt 1 ]; then
        note_failure "a FIN at the sequence number we are waiting for was not answered, so refusing the other one proves nothing"
        sed 's/^/      /' "$work/crafted.txt" >&2
        return
    fi
    # ⚠ And it acknowledges past THAT FIN, not past the one we refused.
    if [ "$acknowledges" != "$(( their_isn + 2 ))" ]; then
        note_failure "our close acknowledges $acknowledges, and the FIN we accepted sat at $(( their_isn + 1 ))"
        sed 's/^/      /' "$work/crafted.txt" >&2
        return
    fi
    # ⚠ Counted apart, and ⚠ **the refusal is not silent** (`.claude/rules/c.md`).
    assert_file_contains "$work/out.txt" \
        "1 FIN arrived that was not the next thing we were waiting for" \
        "a FIN we do not expect is counted on its own"
    assert_file_contains "$work/out.txt" "the other side closed 1 connection" \
        "only the FIN we were waiting for closed the connection"

    printf '    a FIN 500 past the window drew %s closes from us and the right one drew %s\n' \
        "$wrong" "$right"
}

# ⚠ hidetzu/tcpip-stack#74 AC 1 and AC 3, and ⚠ **the verdict is the kernel's**:
# it does not release a buffer until the octets in it have been acknowledged with
# numbers it accepts, so ⚠ **`Send-Q` reaching 0 is somebody else's judgement on
# our acknowledgment numbers.**
#
# ⚠ Measured before this change, same conditions, 2026-08-29: ⚠ **the peer sent
# one octet at one sequence number seven times and its `Send-Q` stayed at 5 for
# twelve seconds.**
#
# ⚠ The window is still 1 here (hidetzu/tcpip-stack#75 owns the number), so
# ⚠ **the peer advances one octet at a time** — which is what makes the sequence
# numbers visible at all.
inside_the_peers_send_queue_drains_once_we_acknowledge() {
    ours=10.0.0.2
    our_mac=02:00:00:00:00:02

    "$TCPIP_STACK" --dev tap0 --mac "$our_mac" --ipv4 "$ours" --tcp-port 80 \
        --timeout 6000 --hex >"$work/out.txt" 2>"$work/err.txt" &
    reader=$!

    if ! wait_for_interface tap0; then
        note_failure "tap0 never appeared while the stack was attached"
        kill "$reader" 2>/dev/null
        wait "$reader" 2>/dev/null
        return
    fi
    sysctl -qw net.ipv6.conf.tap0.disable_ipv6=1
    ip addr add 10.0.0.1/24 dev tap0
    ip link set tap0 up

    LC_ALL=C python3 -c '
import socket, subprocess, sys, time

def send_q():
    out = subprocess.run(["ss", "-tan"], capture_output=True, text=True).stdout
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 5 and parts[4] == "10.0.0.2:80":
            return parts[2]
    return "gone"

s = socket.socket()
s.settimeout(5)
try:
    s.connect(("10.0.0.2", 80))
except Exception as why:
    print("connect failed:", why); sys.exit(1)
s.sendall(b"hello")

# ⚠ Watched until it drains, ⚠ **never a fixed sleep long enough to hide a slow
# one.** ⚠ What is reported is the last value seen, whatever it is.
last = send_q()
deadline = time.time() + 4.0
while time.time() < deadline and last not in ("0", "gone"):
    time.sleep(0.1)
    last = send_q()
print("send-q", last)
' >"$work/drained.txt" 2>&1
    sent=$?

    kill -INT "$reader" 2>/dev/null
    wait "$reader" 2>/dev/null

    if [ "$sent" -ne 0 ]; then
        note_failure "connect() did not succeed, so nothing was sent"
        sed 's/^/      /' "$work/drained.txt" >&2
        return
    fi

    left=$(awk '$1 == "send-q" { print $2 }' "$work/drained.txt")

    # ⚠ AC 3, and ⚠ **it is the kernel's verdict and not ours.**
    if [ "$left" != "0" ]; then
        note_failure "the peer still holds $left octets, so it has not accepted our acknowledgments"
        sed 's/^/      /' "$work/drained.txt" >&2
        printf '    what the stack said:\n' >&2
        grep -v '^  [0-9a-f]' "$work/out.txt" | tail -14 | sed 's/^/      /' >&2
        return
    fi

    ethernet_header=$(constant src/ethernet.h ETHERNET_HEADER_BYTES)
    ipv4_type=$(constant src/ipv4.h IPV4_ETHERNET_LENGTH_TYPE)
    tcp_number=$(constant src/tcp.h TCP_PROTOCOL_NUMBER)

    # ⚠ The peer advanced: ⚠ **five octets at five different sequence numbers**,
    # which is what "it moved on" means. ⚠ Before this change all five arrivals
    # carried the same one.
    LC_ALL=C frames_as_hex "$work/out.txt" | python3 -c '
import sys

def number(text):
    return int(text.rstrip("uU"), 0)

ethernet_header, ipv4_type, tcp_number = (number(a) for a in sys.argv[1:4])
carrying = []
for line in sys.stdin:
    parts = line.split()
    if len(parts) != 2:
        continue
    octets = bytes.fromhex(parts[1])
    if len(octets) < ethernet_header + 20:
        continue
    if int.from_bytes(octets[ethernet_header - 2:ethernet_header], "big") != ipv4_type:
        continue
    if octets[ethernet_header + 9] != tcp_number:
        continue
    internet = (octets[ethernet_header] & 0x0f) * 4
    total = int.from_bytes(octets[ethernet_header + 2:ethernet_header + 4], "big")
    at = ethernet_header + internet
    if len(octets) < at + 20:
        continue
    data = total - internet - (octets[at + 12] >> 4) * 4
    if data > 0:
        carrying.append((data, int.from_bytes(octets[at + 4:at + 8], "big")))
print("octets-arrived", len(carrying))
print("distinct-sequence-numbers", len(set(sequence for _, sequence in carrying)))
print("distinct-lengths", " ".join(str(d) for d in sorted(set(d for d, _ in carrying))))
' "$ethernet_header" "$ipv4_type" "$tcp_number" >"$work/counted.txt"

    arrived=$(awk '$1 == "octets-arrived" { print $2 }' "$work/counted.txt")
    distinct=$(awk '$1 == "distinct-sequence-numbers" { print $2 }' "$work/counted.txt")
    lengths=$(awk '$1 == "distinct-lengths" { $1 = ""; print substr($0, 2) }' "$work/counted.txt")

    # ⚠ **The window decides how much the peer puts on the wire at a time**, and
    # ⚠ this is the wall for `CLAUDE.md` §9's row: ⚠ **a sentence about the peer
    # must be re-measured when the window changes, never carried across.**
    # ⚠ At a window of 1 every data segment carries exactly 1 octet; ⚠ **at 5 the
    # peer would send all five in one, and the count below would be 1, not 5.**
    if [ "$lengths" != "1" ]; then
        note_failure "the peer sent segments of $lengths octets, and the window we advertise is 1"
        sed 's/^/      /' "$work/counted.txt" >&2
        return
    fi
    if [ "${distinct:-0}" -ne 5 ]; then
        note_failure "the five octets arrived at $distinct different sequence numbers, not 5, so the peer did not advance one at a time"
        sed 's/^/      /' "$work/counted.txt" >&2
        return
    fi
    # ⚠ Our own count agrees, and ⚠ **the two numbers are kept apart**: how many
    # octets arrived, and how many times we said so.
    assert_file_contains "$work/out.txt" "5 acknowledgments for data left the device" \
        "one acknowledgment left for each octet taken"
    assert_file_contains "$work/out.txt" "5 octets of data were taken and discarded" \
        "all five octets were taken"

    printf '    the peer sent %s segments of %s octet at %s sequence numbers, and its\n' \
        "$arrived" "$lengths" "$distinct"
    printf '    Send-Q reached %s\n' "$left"
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
case_a_fin_reaches_us_once_the_window_is_open() {
    in_namespace a_fin_reaches_us_once_the_window_is_open
}
case_the_kernel_stops_retransmitting_once_we_close_back() {
    in_namespace the_kernel_stops_retransmitting_once_we_close_back
}
case_the_kernel_reaches_time_wait_and_our_block_is_free_again() {
    in_namespace the_kernel_reaches_time_wait_and_our_block_is_free_again
}
case_a_fin_whose_sequence_number_we_do_not_expect_is_not_answered() {
    in_namespace a_fin_whose_sequence_number_we_do_not_expect_is_not_answered
}
case_the_peers_send_queue_drains_once_we_acknowledge() {
    in_namespace the_peers_send_queue_drains_once_we_acknowledge
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

ALL_CASES="an_arp_request_the_kernel_generated_is_read_intact a_frame_larger_than_the_read_buffer_is_not_reported_as_a_known_length the_kernel_believes_the_address_we_answered_for ping_reports_no_loss_against_our_own_stack the_kernel_opens_a_connection_to_us a_fin_reaches_us_once_the_window_is_open the_kernel_stops_retransmitting_once_we_close_back the_kernel_reaches_time_wait_and_our_block_is_free_again a_fin_whose_sequence_number_we_do_not_expect_is_not_answered the_peers_send_queue_drains_once_we_acknowledge a_syn_whose_checksum_does_not_agree_is_not_answered"

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
