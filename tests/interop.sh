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
    # ⚠ Counted as what it actually was — ⚠ **begun past what we were waiting
    # for**, not as one we had read already (hidetzu/tcpip-stack#76). ⚠ Before
    # that split both landed on one number and this could not tell them apart.
    assert_file_contains "$work/out.txt" \
        "0 FINs arrived that we had read already, 1 began past what we were waiting for" \
        "a FIN 500 ahead is counted as ahead, not as one we had read"
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
# ⚠ Measured before hidetzu/tcpip-stack#74, same conditions, 2026-08-29:
# ⚠ **the peer sent one octet at one sequence number seven times and its
# `Send-Q` stayed at 5 for twelve seconds.**
#
# ⚠ **This case is also `CLAUDE.md` §9's wall**, and it has fired once: raising
# the window from 1 to 1460 (hidetzu/tcpip-stack#75) failed it with "the peer
# sent segments of 5 octets, and the window we advertise is 1". ⚠ **That is the
# wall working** — ⚠ a sentence about the peer must be re-measured when the
# window changes, never carried across.
#
# ⚠ **Re-measured at 1460**: five octets handed to `send()` arrive as ⚠ **one
# segment**, because the window now allows the peer to send them together.
# ⚠ Lower the window without re-measuring and this fails again.
# ⚠ hidetzu/tcpip-stack#119 AC 2. ⚠ **The window on the wire follows the device's
# MTU** — ⚠ not the constant it used to be, and ⚠ **not our own output**: the
# segment is read off an AF_PACKET socket (ADR 0009).
#
# ⚠ The device is brought up at 1400 HERE, before the stack starts, because
# ⚠ **a device the stack creates itself is always 1500** (measured, 3 runs) —
# ⚠ so a case that only ever saw 1500 could not tell a derivation from the old
# constant.
# ⚠ hidetzu/tcpip-stack#123 on the wire. ⚠ RFC 9293 §3.7.1, `MUST-14`.
#
# ⚠ **Both directions, against something we did not write** — the option we send
# is read off an AF_PACKET socket (ADR 0009), and ⚠ **the option we receive comes
# from the Linux kernel's own SYN**, which we do not get to choose.
#
# ⚠ Measured before the change, same conditions, 2026-08-29: ⚠ **the SYN,ACK
# carried a Data Offset of 5 and no options at all.**
# ⚠ hidetzu/tcpip-stack#126, and ⚠ **the criterion the owner set before any of it
# was built** (hidetzu/tcpip-stack#125), verbatim:
#
#   5 bytes を送れることではなく、MSS より大きいデータを渡したとき、
#   effective send MSS を超えない複数 segment として相手へ届くこと
#
# ⚠ **So this counts segments and measures each one.** ⚠ A check that only added
# the octets up would pass for a stack that sent all 3000 in one segment, ⚠ **and
# that stack would be violating MUST-16 while looking correct.**
#
# ⚠ The device is brought up at MTU 1400 so ⚠ **the effective send MSS is 1360
# and 3000 octets CANNOT fit in two segments** — three at least.
#
# ⚠ The other end is the Linux kernel's own `read()`, ⚠ **which is not something
# we wrote**, and the segments are counted off an AF_PACKET socket (ADR 0009).
# ⚠ hidetzu/tcpip-stack#129, and ⚠ **the owner's goal for it**, verbatim:
#
#   送信した data segment またはその ACK を1つ失っても、tcpip-stack が再送によって
#   Linux kernel へのデータ配送を完了できるようにしたい
#
# ⚠ **Both halves, in one case, because they are the same cure for different
# causes** — ⚠ and ⚠ **the case says which one it dropped**, so a build that
# only recovered from one would not pass for both.
#
# ⚠ `nft` drops exactly one segment on its way INTO the kernel. ⚠ Dropping the
# data segment and dropping its acknowledgment are the same recipe aimed at
# different traffic, ⚠ **and from this stack's side they are indistinguishable
# — which is the point.**
# ⚠ hidetzu/tcpip-stack#132 AC 6. ⚠ RFC 5681 §3.1: "upon a timeout ... cwnd MUST
# be set to no more than the loss window, LW, which equals 1 full-sized segment
# ... Therefore, after retransmitting the dropped segment the TCP sender uses the
# slow start algorithm to increase the window."
#
# ⚠ **What that looks like from outside**: ⚠ before the drop the segments leave
# in a burst; ⚠ **after it they leave one at a time and the burst grows back.**
#
# ⚠ **This counts what is on the wire, not what we say about ourselves**
# (ADR 0009).
# ⚠ hidetzu/tcpip-stack#138 AC 7. ⚠ RFC 9293 `MUST-54`: an ICMP error is directed
# to the connection that created it.
#
# ⚠ **The error is the Linux kernel's own, not one we wrote.** ⚠ `nft` is told to
# REJECT our data segments with an ICMP administratively-prohibited — ⚠ code 13,
# which §3.9.2.2 does not classify — ⚠ and then with code 3, which it calls HARD.
#
# ⚠ **A message we built ourselves would prove the parser and nothing about
# whether a real one ever arrives** (`.claude/rules/layers.md`, question 3).
inside_an_icmp_error_the_kernel_sent_reaches_the_connection() {
    ours=10.0.0.2
    our_mac=02:00:00:00:00:02

    for what in host-unreachable admin-prohibited; do
        ip tuntap add dev tap0 mode tap
        ip link set tap0 mtu 1400
        "$TCPIP_STACK" --dev tap0 --mac "$our_mac" --ipv4 "$ours" --tcp-port 80 \
            --send 3000 --timeout 4000 >"$work/out-$what.txt" 2>&1 &
        reader=$!
        if ! wait_for_interface tap0; then
            note_failure "tap0 never appeared while the stack was attached"
            kill "$reader" 2>/dev/null; wait "$reader" 2>/dev/null
            return
        fi
        sysctl -qw net.ipv6.conf.tap0.disable_ipv6=1
        ip addr add 10.0.0.1/24 dev tap0
        ip link set tap0 up

        # ⚠ In place BEFORE the connection, and ⚠ **measured to be needed**: with
        # the rule added 0.05 s after `connect()` returned, ⚠ **all 3000 octets
        # had already left and nothing was ever rejected.**
        #
        # ⚠ It matches only a FULL-SIZED data segment of ours — ⚠ the SYN,ACK is
        # 58 octets — ⚠ **so the handshake completes and there IS a connection
        # for the error to name.**
        nft add table ip guard
        nft add chain ip guard input "{ type filter hook input priority 0; }"
        nft add rule ip guard input tcp sport 80 ip length 1400 \
            counter reject with icmp type "$what"

        LC_ALL=C python3 -c '
import socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(3.0)
try:
    s.connect(("10.0.0.2", 80))
    time.sleep(2.0)
except Exception as e:
    print("error", repr(e))
finally:
    try: s.close()
    except Exception: pass
' >"$work/reject-$what.txt" 2>&1 || true

        kill -INT "$reader" 2>/dev/null; wait "$reader" 2>/dev/null
        nft delete table ip guard 2>/dev/null
        ip link del tap0 2>/dev/null
    done

    # ⚠ `host-unreachable` is Destination Unreachable code 1 — ⚠ **soft**, and
    # §3.9.2.2 says it MUST NOT abort the connection.
    if grep -q "^0 source quenches were discarded, 0 soft errors changed nothing" \
        "$work/out-host-unreachable.txt"; then
        note_failure "the kernel sent host-unreachable and no soft error was counted"
        sed -n 's/^/      /p' "$work/out-host-unreachable.txt" | tail -6 >&2
        return
    fi
    assert_file_contains "$work/out-host-unreachable.txt" \
        "that kind of trouble does not end a connection" \
        "a soft error is said and changes nothing"

    # ⚠ `admin-prohibited` is Destination Unreachable code 13 — ⚠ **one the
    # document does NOT classify.** ⚠ Silence is not a class, so it is its own
    # answer and the connection is left alone.
    assert_file_contains "$work/out-admin-prohibited.txt" \
        "an error arrived that the document does not say" \
        "an unclassified error is said as one"

    printf '    the kernel sent a soft error and an unclassified one; each was\n'
    printf '    matched to the connection and said as what it is\n'
}

inside_the_window_reopens_one_segment_at_a_time_after_a_loss() {
    ours=10.0.0.2
    our_mac=02:00:00:00:00:02
    total=30000

    ip tuntap add dev tap0 mode tap
    ip link set tap0 mtu 1400
    "$TCPIP_STACK" --dev tap0 --mac "$our_mac" --ipv4 "$ours" --tcp-port 80 \
        --send "$total" --timeout 9000 >"$work/out.txt" 2>&1 &
    reader=$!
    if ! wait_for_interface tap0; then
        note_failure "tap0 never appeared while the stack was attached"
        kill "$reader" 2>/dev/null; wait "$reader" 2>/dev/null
        return
    fi
    sysctl -qw net.ipv6.conf.tap0.disable_ipv6=1
    ip addr add 10.0.0.1/24 dev tap0
    ip link set tap0 up

    nft add table ip guard
    nft add chain ip guard input "{ type filter hook input priority 0; }"
    # ⚠ In place BEFORE the connection, and ⚠ **measured to be needed**: with the
    # rule added 0.4 s in, all 30000 octets had already left and ⚠ **nothing was
    # ever dropped**, so the case asserted nothing.
    #
    # ⚠ It matches only a FULL-SIZED data segment of ours — ⚠ the SYN,ACK is 58
    # octets — ⚠ **so the connection opens and the first burst is what loses a
    # segment.**
    nft add rule ip guard input tcp sport 80 ip length 1400 counter drop

    LC_ALL=C python3 -c '
import socket, subprocess, threading, time
TOTAL = int(__import__("sys").argv[1])
got = {}
def reader():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(8.0)
    try:
        s.connect(("10.0.0.2", 80))
        # ⚠ Taken away so the recovery can land. ⚠ Everything up to here is lost,
        # ⚠ **so the window is cut and then has to grow back** — which is what
        # slow start names.
        threading.Timer(0.5, lambda: subprocess.run(
            ["nft", "flush", "chain", "ip", "guard", "input"])).start()
        seen = b""
        while len(seen) < TOTAL:
            more = s.recv(65536)
            if not more: break
            seen += more
        got["octets"] = seen
    except Exception as e:
        got["error"] = repr(e)
    finally:
        try: s.close()
        except Exception: pass
listener = threading.Thread(target=reader, daemon=True)
listener.start()
listener.join(9.0)
print("read", len(got.get("octets", b"")))
if "error" in got: print("error", got["error"])
' "$total" >"$work/reopen.txt" 2>&1 || true

    kill -INT "$reader" 2>/dev/null; wait "$reader" 2>/dev/null
    nft delete table ip guard 2>/dev/null
    ip link del tap0 2>/dev/null

    read_back=$(awk '$1 == "read" { print $2 }' "$work/reopen.txt")

    # ⚠ 1. ⚠ **It still all arrives** — the window closing must not lose data.
    if [ "$read_back" != "$total" ]; then
        note_failure "after the loss the kernel read '$read_back' octets of $total"
        sed 's/^/      /' "$work/reopen.txt" >&2
        sed -n 's/^/      /p' "$work/out.txt" | tail -5 >&2
        return
    fi

    # ⚠ 2. ⚠ **The window really was cut** — otherwise nothing about slow start
    # was exercised and the first assertion alone would pass for a build with no
    # congestion control at all (`verify` §5).
    if grep -q "^0 congestion windows were cut" "$work/out.txt"; then
        note_failure "no congestion window was cut, so the loss changed nothing and nothing was proved"
        sed -n 's/^/      /p' "$work/out.txt" | tail -5 >&2
        return
    fi

    # ⚠ 3. ⚠ **And it reopened** — a window cut to one segment that never grew
    # back could not have carried the rest, ⚠ **so this is implied by the first
    # assertion and is said anyway**: it is what "slow start" names.
    again=$(awk '/octets of ours went out again/ { print $1 }' "$work/out.txt")
    printf '    %s octets arrived after one segment was dropped; the window was\n' "$read_back"
    printf '    cut and reopened, with %s octets sent again\n' "$again"
}

inside_a_lost_segment_or_a_lost_ack_still_gets_the_data_through() {
    ours=10.0.0.2
    our_mac=02:00:00:00:00:02
    total=3000

    for lose in data ack; do
        ip tuntap add dev tap0 mode tap
        ip link set tap0 mtu 1400
        "$TCPIP_STACK" --dev tap0 --mac "$our_mac" --ipv4 "$ours" --tcp-port 80 \
            --send "$total" --timeout 9000 >"$work/out-$lose.txt" 2>&1 &
        reader=$!
        if ! wait_for_interface tap0; then
            note_failure "tap0 never appeared while the stack was attached"
            kill "$reader" 2>/dev/null; wait "$reader" 2>/dev/null
            return
        fi
        sysctl -qw net.ipv6.conf.tap0.disable_ipv6=1
        ip addr add 10.0.0.1/24 dev tap0
        ip link set tap0 up

        if ! nft add table ip guard 2>"$work/nft-$lose.txt"; then
            note_failure "the check environment could not be built here: nft was refused"
            sed 's/^/      /' "$work/nft-$lose.txt" >&2
            kill -INT "$reader" 2>/dev/null; wait "$reader" 2>/dev/null
            return
        fi
        nft add chain ip guard input "{ type filter hook input priority 0; }"
        nft add chain ip guard output "{ type filter hook output priority 0; }"
        # ⚠ The data rule is safe to add now — nothing of ours carries data until
        # the connection is open. ⚠ **The ACK rule is NOT**: `tcp flags == ack`
        # and 40 octets is also the handshake's own third ACK, ⚠ **and dropping
        # that would stop the connection before there was anything to lose.**
        # ⚠ It is added from inside, after `connect()` returns.
        if [ "$lose" = data ]; then
            nft add rule ip guard input tcp sport 80 ip length 1400 counter drop
        fi

        LC_ALL=C python3 -c '
import socket, subprocess, sys, threading, time
TOTAL, WHICH = int(sys.argv[1]), sys.argv[2]

got = {}
def reader():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(8.0)
    try:
        s.connect(("10.0.0.2", 80))
        chain = "input" if WHICH == "data" else "output"
        if WHICH == "ack":
            # ⚠ Added only now: before connect() returned, this rule would have
            # matched the third ACK of the handshake itself.
            # ⚠ No apostrophe in this block: the whole python is one
            # single-quoted shell word, and one would close it.
            subprocess.run(["nft", "add", "rule", "ip", "guard", "output",
                            "tcp", "dport", "80", "tcp", "flags", "==", "ack",
                            "counter", "drop"])
        seen = b""
        # ⚠ Take the rule away so the recovery can land.
        threading.Timer(1.4, lambda: subprocess.run(
            ["nft", "flush", "chain", "ip", "guard", chain])).start()
        while len(seen) < TOTAL:
            more = s.recv(65536)
            if not more: break
            seen += more
        got["octets"] = seen
        # ⚠ Held open past the deadline ON PURPOSE, and only for the ACK half.
        # ⚠ MEASURED 2026-08-29: with the kernel ACKs dropped, ALL 3000 OCTETS
        # ARE ALREADY THERE — ⚠ losing an acknowledgment costs US the knowing,
        # not THEM the data. ⚠ So delivery completes with no retransmission at
        # all, ⚠ and closing here would end the run before the deadline and
        # prove nothing about recovery.
        # ⚠ Holding on shows the other half: ⚠ we send it again because nobody
        # told us, ⚠ AND THE KERNEL STILL ENDS WITH EXACTLY 3000 — it discards
        # the duplicate. ⚠ That is what makes resending safe.
        if WHICH == "ack":
            time.sleep(1.0)
    except Exception as e:
        got["error"] = repr(e)
    finally:
        try: s.close()
        except Exception: pass

listener = threading.Thread(target=reader, daemon=True)
listener.start()
listener.join(9.0)
octets = got.get("octets", b"")
print("read", len(octets))
print("correct", "yes" if octets and
      octets == bytes((i % 251) for i in range(len(octets))) else "no")
if "error" in got: print("error", got["error"])
' "$total" "$lose" >"$work/lost-$lose.txt" 2>&1 || true

        nft list chain ip guard input >"$work/counter-$lose.txt" 2>/dev/null || true
        nft list chain ip guard output >>"$work/counter-$lose.txt" 2>/dev/null || true
        kill -INT "$reader" 2>/dev/null; wait "$reader" 2>/dev/null
        nft delete table ip guard 2>/dev/null
        ip link del tap0 2>/dev/null

        read_back=$(awk '$1 == "read" { print $2 }' "$work/lost-$lose.txt")
        correct=$(awk '$1 == "correct" { print $2 }' "$work/lost-$lose.txt")

        # ⚠ 1. ⚠ **THE GOAL**: every octet still arrives.
        if [ "$read_back" != "$total" ]; then
            note_failure "losing one $lose left the kernel with '$read_back' of $total octets"
            sed 's/^/      /' "$work/lost-$lose.txt" >&2
            sed -n 's/^/      /p' "$work/out-$lose.txt" | tail -4 >&2
            continue
        fi
        # ⚠ 2. ⚠ **The RIGHT octets** — a stack that resent the wrong ones would
        # pass the count alone.
        if [ "$correct" != yes ]; then
            note_failure "losing one $lose delivered $total octets that were not the ones asked for"
        fi
        # ⚠ 3. ⚠ **The two halves are NOT the same assertion, and measuring
        # said so** (2026-08-29):
        #
        #   losing a data segment  ⚠ the kernel has a HOLE. ⚠ Nothing past it can
        #                          be delivered, and ⚠ ONLY A RETRANSMISSION
        #                          completes it. ⚠ So: something MUST have been
        #                          sent again
        #   losing an acknowledgment  ⚠ THE KERNEL ALREADY HAS THE DATA. ⚠ What
        #                          was lost is OUR KNOWING, not THEIR receiving —
        #                          ⚠ and acknowledgments are CUMULATIVE, so a
        #                          later one covers the loss and even our knowing
        #                          is restored. ⚠ So: delivery completes AND
        #                          NOTHING NEEDS RESENDING
        #
        # ⚠ **Asserting a retransmission for the ACK half would be asserting a
        # defect.** ⚠ Contriving a window where it were needed would be testing
        # the contrivance.
        if [ "$lose" = data ]; then
            if grep -q "^0 octets of ours went out again" "$work/out-$lose.txt"; then
                note_failure "losing one data segment, nothing was sent again — so nothing was dropped and nothing was proved"
            fi
        else
            # ⚠ The other half for the ACK case: ⚠ **the drop must have
            # happened**, or this half asserts nothing at all.
            if ! grep -q "packets [1-9]" "$work/counter-$lose.txt" 2>/dev/null; then
                note_failure "losing one ack: nft matched nothing, so nothing was dropped and nothing was proved"
            fi
        fi
    done

    printf '    tried losing one data segment and one acknowledgment, %s octets each\n' "$total"
}

inside_data_larger_than_the_mss_arrives_in_segments_it_bounds() {
    ours=10.0.0.2
    our_mac=02:00:00:00:00:02
    total=3000

    ip tuntap add dev tap0 mode tap
    ip link set tap0 mtu 1400
    "$TCPIP_STACK" --dev tap0 --mac "$our_mac" --ipv4 "$ours" --tcp-port 80 \
        --send "$total" --timeout 6000 >"$work/out.txt" 2>&1 &
    reader=$!
    if ! wait_for_interface tap0; then
        note_failure "tap0 never appeared while the stack was attached"
        kill "$reader" 2>/dev/null; wait "$reader" 2>/dev/null
        return
    fi
    sysctl -qw net.ipv6.conf.tap0.disable_ipv6=1
    ip addr add 10.0.0.1/24 dev tap0
    ip link set tap0 up

    headers=$(constant src/handshake.h HANDSHAKE_HEADERS_BEFORE_DATA)
    bound=$(( 1400 - ${headers%u} ))

    LC_ALL=C python3 -c '
import socket, struct, sys, threading, time
TOTAL = int(sys.argv[1])

got = {}
def reader():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5.0)
    try:
        s.connect(("10.0.0.2", 80))
        seen = b""
        while len(seen) < TOTAL:
            more = s.recv(65536)
            if not more: break
            seen += more
        got["octets"] = seen
    except Exception as e:
        got["error"] = repr(e)
    finally:
        try: s.close()
        except Exception: pass

wire = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
wire.bind(("tap0", 0))
wire.settimeout(5.0)
listener = threading.Thread(target=reader, daemon=True)
listener.start()

sizes = []
deadline = time.monotonic() + 5.0
while sum(sizes) < TOTAL and time.monotonic() < deadline:
    try: frame = wire.recv(2048)
    except socket.timeout: break
    if len(frame) < 54 or frame[12:14] != b"\x08\x00" or frame[14 + 9] != 6:
        continue
    ihl = (frame[14] & 0x0f) * 4
    at = 14 + ihl
    total = int.from_bytes(frame[16:18], "big")
    data = total - ihl - (frame[at + 12] >> 4) * 4
    # ⚠ Ours are the ones from port 80.
    if int.from_bytes(frame[at:at + 2], "big") != 80: continue
    if data > 0: sizes.append(data)

# ⚠ The wire loop finishes as soon as the octets are ON the wire, ⚠ which is
# BEFORE the kernel has delivered them to the socket. ⚠ Reading `got` here
# without waiting is a stale result overwriting a newer one
# (`.claude/skills/change-review/SKILL.md` §4) — ⚠ it read 0 the first time this
# case ran, and the stack was correct.
listener.join(6.0)
print("sizes", " ".join(str(n) for n in sizes))
octets = got.get("octets", b"")
print("read", len(octets))
# ⚠ An empty read must not pass this: ⚠ b"" equals the pattern of length 0.
print("correct", "yes" if octets and
      octets == bytes((i % 251) for i in range(len(octets))) else "no")
if "error" in got: print("error", got["error"])
' "$total" >"$work/sent.txt" 2>"$work/sent-err.txt" || true

    kill -INT "$reader" 2>/dev/null; wait "$reader" 2>/dev/null
    ip link del tap0 2>/dev/null

    sizes=$(awk '$1 == "sizes" { $1 = ""; print }' "$work/sent.txt")
    read_back=$(awk '$1 == "read" { print $2 }' "$work/sent.txt")
    correct=$(awk '$1 == "correct" { print $2 }' "$work/sent.txt")

    # ⚠ 1. The kernel got all of it, ⚠ **and it got the RIGHT octets** — a stack
    # that sent 3000 of anything would pass the first half alone.
    if [ "$read_back" != "$total" ]; then
        note_failure "the kernel read '$read_back' octets and we were asked to send $total"
        sed 's/^/      /' "$work/sent.txt" >&2
        return
    fi
    if [ "$correct" != "yes" ]; then
        note_failure "the kernel read $total octets and they were not the ones we were asked to send"
    fi

    # ⚠ 2. ⚠ **More than one segment.** ⚠ This is the half the criterion exists
    # for: 3000 octets in one segment is the same octet count and a different
    # thing entirely.
    count=$(printf '%s\n' $sizes | grep -c .)
    if [ "$count" -lt 3 ]; then
        note_failure "the $total octets arrived in $count segment(s), and at $bound each they need at least 3"
    fi

    # ⚠ 3. ⚠ **Not one segment carries more than the effective send MSS.**
    for n in $sizes; do
        if [ "$n" -gt "$bound" ]; then
            note_failure "a segment carried $n octets and the effective send MSS is $bound"
        fi
    done

    # ⚠ 4. The other half (`verify` §5): ⚠ **they must add up**, or a check that
    # only bounded each segment would pass for a stack that sent three of them
    # and stopped.
    sum=0
    for n in $sizes; do sum=$(( sum + n )); done
    if [ "$sum" != "$total" ]; then
        note_failure "the segments carry $sum octets between them, not $total"
    fi

    printf '    %s octets reached the kernel in %s segments, none above %s\n' \
        "$read_back" "$count" "$bound"
}

inside_the_mss_option_goes_both_ways_with_the_kernel() {
    ours=10.0.0.2
    our_mac=02:00:00:00:00:02

    ip tuntap add dev tap0 mode tap
    ip link set tap0 mtu 1400
    "$TCPIP_STACK" --dev tap0 --mac "$our_mac" --ipv4 "$ours" --tcp-port 80 \
        --timeout 3000 >"$work/out.txt" 2>&1 &
    reader=$!
    if ! wait_for_interface tap0; then
        note_failure "tap0 never appeared while the stack was attached"
        kill "$reader" 2>/dev/null; wait "$reader" 2>/dev/null
        return
    fi
    sysctl -qw net.ipv6.conf.tap0.disable_ipv6=1
    ip addr add 10.0.0.1/24 dev tap0
    ip link set tap0 up

    kind=$(constant src/tcp.h TCP_OPTION_MAXIMUM_SEGMENT_SIZE)
    length=$(constant src/tcp.h TCP_OPTION_MAXIMUM_SEGMENT_SIZE_BYTES)

    LC_ALL=C python3 -c '
import socket, struct, sys, subprocess
KIND, LENGTH = int(sys.argv[1].rstrip("uU"), 0), int(sys.argv[2].rstrip("uU"), 0)

def options_of(frame):
    ihl = (frame[14] & 0x0f) * 4
    at = 14 + ihl
    offset = (frame[at + 12] >> 4) * 4
    return frame[at + 20:at + offset], frame[at + 13]

def mss_in(options):
    i = 0
    while i < len(options):
        if options[i] == 0: return None
        if options[i] == 1: i += 1; continue
        if i + 1 >= len(options): return None
        n = options[i + 1]
        if n < 2: return None
        if options[i] == KIND and n == LENGTH:
            return int.from_bytes(options[i + 2:i + 4], "big")
        i += n
    return None

wire = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
wire.bind(("tap0", 0))
wire.settimeout(3.0)
subprocess.Popen(["timeout", "2", "bash", "-c", "exec 3<>/dev/tcp/10.0.0.2/80 || true"])
theirs = ours = None
while theirs is None or ours is None:
    frame = wire.recv(2048)
    if len(frame) < 54 or frame[12:14] != b"\x08\x00" or frame[14 + 9] != 6:
        continue
    options, control = options_of(frame)
    if control & 0x12 == 0x02 and theirs is None:      # a bare SYN: the kernel to us
        theirs = mss_in(options)
    elif control & 0x12 == 0x12 and ours is None:      # SYN,ACK: us to the kernel
        ours = mss_in(options)
print("kernel", theirs)
print("ours", ours)
' "$kind" "$length" >"$work/mss.txt" 2>"$work/mss-err.txt" || true

    kill -INT "$reader" 2>/dev/null; wait "$reader" 2>/dev/null
    ip link del tap0 2>/dev/null

    headers=$(constant src/handshake.h HANDSHAKE_HEADERS_BEFORE_DATA)
    want=$(( 1400 - ${headers%u} ))
    got=$(awk '$1 == "ours" { print $2 }' "$work/mss.txt")
    theirs=$(awk '$1 == "kernel" { print $2 }' "$work/mss.txt")

    if [ "$got" != "$want" ]; then
        note_failure "our SYN,ACK carried an MSS of '$got' and the device leaves $want"
    fi
    # ⚠ The other end is the kernel's, and ⚠ **we assert only that it is there
    # and is a number** — ⚠ never what it will be right now
    # (`.claude/rules/testing.md`).
    if [ -z "$theirs" ] || [ "$theirs" = "None" ]; then
        note_failure "the kernel's SYN carried no MSS Option, so nothing was judged about reading one"
    fi
    # ⚠ And our own report must say it read one.
    assert_file_contains "$work/out.txt" "1 connection was opened" "the connection opened"

    printf '    our SYN,ACK carried MSS %s at MTU 1400; the kernel'"'"'s SYN carried %s\n' \
        "$got" "$theirs"
}

inside_the_window_on_the_wire_follows_the_mtu() {
    ours=10.0.0.2
    our_mac=02:00:00:00:00:02

    headers=$(constant src/handshake.h HANDSHAKE_HEADERS_BEFORE_DATA)
    headers=${headers%u}

    for mtu in 1400 1500; do
        ip tuntap add dev tap0 mode tap
        ip link set tap0 mtu "$mtu"
        "$TCPIP_STACK" --dev tap0 --mac "$our_mac" --ipv4 "$ours" --tcp-port 80 \
            --timeout 2500 --hex >"$work/out-$mtu.txt" 2>&1 &
        reader=$!
        if ! wait_for_interface tap0; then
            note_failure "tap0 never appeared at MTU $mtu"
            kill "$reader" 2>/dev/null; wait "$reader" 2>/dev/null
            return
        fi
        sysctl -qw net.ipv6.conf.tap0.disable_ipv6=1
        ip addr add 10.0.0.1/24 dev tap0
        ip link set tap0 up

        # ⚠ Read off the wire, not out of our own report (ADR 0009).
        LC_ALL=C python3 -c '
import socket, struct, sys
wire = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
wire.bind(("tap0", 0))
wire.settimeout(2.0)
import subprocess
subprocess.Popen(["timeout", "2", "bash", "-c",
                  "exec 3<>/dev/tcp/10.0.0.2/80 || true"])
while True:
    frame = wire.recv(2048)
    if len(frame) < 14 + 20 + 20: continue
    if frame[12:14] != b"\x08\x00": continue
    ihl = (frame[14] & 0x0f) * 4
    if frame[14 + 9] != 6: continue
    at = 14 + ihl
    control = frame[at + 13]
    if not (control & 0x12) == 0x12:   # SYN and ACK
        continue
    print(struct.unpack("!H", frame[at + 14:at + 16])[0])
    break
' >"$work/window-$mtu.txt" 2>"$work/wire-$mtu.txt" || true

        kill -INT "$reader" 2>/dev/null; wait "$reader" 2>/dev/null
        ip link del tap0 2>/dev/null
    done

    for mtu in 1400 1500; do
        want=$(( mtu - headers ))
        got=$(cat "$work/window-$mtu.txt" 2>/dev/null)
        if [ -z "$got" ]; then
            note_failure "no SYN,ACK was captured at MTU $mtu, so nothing was judged"
        elif [ "$got" != "$want" ]; then
            note_failure "at MTU $mtu the SYN,ACK carried a window of $got and one frame carries $want"
        fi
    done

    # ⚠ The other half: ⚠ **the two must DIFFER**, or a build that ignored the
    # MTU entirely would pass both (`verify` §5).
    if [ "$(cat "$work/window-1400.txt" 2>/dev/null)" = "$(cat "$work/window-1500.txt" 2>/dev/null)" ]; then
        note_failure "the window was the same at MTU 1400 and 1500, so it does not follow the device"
    fi

    printf '    the SYN,ACK carried %s at MTU 1400 and %s at MTU 1500\n' \
        "$(cat "$work/window-1400.txt" 2>/dev/null)" "$(cat "$work/window-1500.txt" 2>/dev/null)"
}

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

    # ⚠ The peer put all five in one segment, ⚠ **because the window allows it**,
    # and it never had to send any of them twice. ⚠ Before hidetzu/tcpip-stack#74
    # the same five arrived seven times, all at one sequence number.
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
    # ⚠ At a window of 1460 all five octets fit in one segment; ⚠ **at 1 there
    # would be five segments of one octet, and both numbers below would be 5.**
    if [ "$lengths" != "5" ]; then
        note_failure "the peer sent segments of $lengths octets, and five were handed to send() with a window that fits them all"
        sed 's/^/      /' "$work/counted.txt" >&2
        return
    fi
    if [ "${distinct:-0}" -ne 1 ]; then
        note_failure "the five octets arrived at $distinct different sequence numbers, so the peer did not send them together"
        sed 's/^/      /' "$work/counted.txt" >&2
        return
    fi
    # ⚠ Our own count agrees, and ⚠ **the two numbers are kept apart**: how many
    # octets arrived, and how many times we said so.
    # ⚠ One acknowledgment, ⚠ **because one segment arrived** — the two numbers
    # are in different units and the line says which is which.
    assert_file_contains "$work/out.txt" "1 acknowledgment for data left the device" \
        "one acknowledgment left for the one segment that arrived"
    assert_file_contains "$work/out.txt" "5 octets of data were taken and discarded" \
        "all five octets were taken"

    printf '    the peer sent %s segment of %s octets at %s sequence number, and its\n' \
        "$arrived" "$lengths" "$distinct"
    printf '    Send-Q reached %s\n' "$left"
}

# ⚠ hidetzu/tcpip-stack#77 — the milestone's proof, in one run, and
# ⚠ **every verdict in it belongs to the kernel**: `send()` returning,
# `Send-Q` reaching 0, and `ss` reporting `TIME-WAIT`.
#
# ⚠ Measured before this milestone, same conditions, 2026-08-29: with nothing
# acknowledging, ⚠ **the peer's `Send-Q` stayed at 5 for twelve seconds** and
# the connection was never closed.
#
# ⚠ **Data and the close in the same connection on purpose.** ⚠ Each has its
# own case already; ⚠ **what this one asserts is that they still hold
# together** — a data path that broke the closing sequence would pass both
# separately.
inside_a_connection_carries_data_and_then_closes_properly() {
    ours=10.0.0.2
    our_mac=02:00:00:00:00:02

    "$TCPIP_STACK" --dev tap0 --mac "$our_mac" --ipv4 "$ours" --tcp-port 80 \
        --timeout 8000 >"$work/out.txt" 2>"$work/err.txt" &
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

HOW_MUCH = 3000

def ss():
    return subprocess.run(["ss", "-tan"], capture_output=True, text=True).stdout

def about(here):
    for line in ss().splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 5 and parts[3] == "%s:%d" % here:
            return parts[0], parts[2]
    return "gone", "gone"

s = socket.socket()
s.settimeout(5)
try:
    s.connect(("10.0.0.2", 80))
except Exception as why:
    print("connect-failed", why); sys.exit(1)
here = s.getsockname()

began = time.time()
s.sendall(b"z" * HOW_MUCH)
print("sendall-returned-after", round(time.time() - began, 3))

# ⚠ Watched until the queue empties, ⚠ **never a fixed sleep long enough to
# hide a slow one.** ⚠ What is printed is the last value seen, whatever it is.
state, queued = about(here)
deadline = time.time() + 5.0
while time.time() < deadline and queued not in ("0", "gone"):
    time.sleep(0.05)
    state, queued = about(here)
print("send-q", queued)

s.close()
state, queued = about(here)
deadline = time.time() + 4.0
while time.time() < deadline and state in ("ESTAB", "FIN-WAIT-1", "FIN-WAIT-2"):
    time.sleep(0.1)
    state, queued = about(here)
print("state-after-close", state)
print("how-much", HOW_MUCH)
' >"$work/run.txt" 2>&1
    ran=$?

    kill -INT "$reader" 2>/dev/null
    wait "$reader" 2>/dev/null

    if [ "$ran" -ne 0 ]; then
        note_failure "the connection could not be opened, so nothing was sent"
        sed 's/^/      /' "$work/run.txt" >&2
        return
    fi

    queued=$(awk '$1 == "send-q" { print $2 }' "$work/run.txt")
    state=$(awk '$1 == "state-after-close" { print $2 }' "$work/run.txt")
    how_much=$(awk '$1 == "how-much" { print $2 }' "$work/run.txt")

    # ⚠ AC 1. ⚠ **The kernel does not release a buffer until the octets in it
    # have been acknowledged with numbers it accepts.**
    if [ "$queued" != "0" ]; then
        note_failure "the peer still holds $queued octets, so it has not accepted our acknowledgments"
        sed 's/^/      /' "$work/run.txt" >&2
        printf '    what the stack said:\n' >&2
        grep -v '^  [0-9a-f]' "$work/out.txt" | tail -14 | sed 's/^/      /' >&2
        return
    fi
    # ⚠ AC 3. ⚠ **The data path did not break the closing sequence.**
    if [ "$state" != "TIME-WAIT" ]; then
        note_failure "the kernel is in $state after close(), not TIME-WAIT, so carrying data broke the closing sequence"
        sed 's/^/      /' "$work/run.txt" >&2
        return
    fi
    # ⚠ Our own count agrees, and ⚠ **every octet handed to send() was taken** —
    # not merely enough of them for the queue to empty.
    assert_file_contains "$work/out.txt" "$how_much octets of data were taken and discarded" \
        "every octet handed to send() was taken"
    assert_file_contains "$work/out.txt" "1 connection finished" \
        "the connection was released after carrying data"

    printf '    %s octets went through, the peer Send-Q reached %s, and ss then said %s\n' \
        "$how_much" "$queued" "$state"
}

# ⚠ hidetzu/tcpip-stack#77 AC 2, and ⚠ **it is what stops the case above passing
# for a stack that acknowledged optimistically.**
#
# ⚠ The pattern hidetzu/tcpip-stack#35, #44 and #67 all hit: ⚠ **a stack that
# acknowledged every arriving segment with a number ahead of what it took would
# still drain the peer's queue.**
#
# ⚠ A peer that sends MORE than the window allows is not something the Linux
# kernel does — it honours the window, measured. ⚠ **So it is built here by
# hand**, from an address nobody owns, over `AF_PACKET`.
#
# ⚠ The device's MTU is raised for this case only: ⚠ **a segment carrying more
# than we asked for has to fit in a frame**, and 1460 is what one frame carries
# at the default MTU. ⚠ **That is the case building its own hostile input, not a
# claim about what the window means.**
inside_an_acknowledgment_never_covers_an_octet_we_did_not_take() {
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
    ip link set tap0 mtu 1700
    ip link set tap0 up

    # ⚠ Read out of the header rather than written here a second time, and
    # ⚠ **the `u` suffix stripped** — the shell compares text, and `40u` is not
    # `40` (`CLAUDE.md` §3).
    #
    # ⚠ **Repointed at hidetzu/tcpip-stack#119.** ⚠ This named `HANDSHAKE_WINDOW`
    # until the window stopped being a constant and became what the device's MTU
    # leaves. ⚠ **The check was NOT widened and the assertion did not weaken**
    # (`.claude/rules/testing.md`): it still asks what one frame carries, and
    # ⚠ **it now performs the arithmetic the code performs, from the same
    # constant** — so a change to either follows through to here.
    #
    # ⚠ 1500 is what the device is brought up with above, in this file, by this
    # case. ⚠ **It is the harness's own number and not an assumption about
    # somebody's device.**
    headers=$(constant src/handshake.h HANDSHAKE_HEADERS_BEFORE_DATA)
    window=$(( 1500 - ${headers%u} ))
    ack_bit=$(constant src/tcp.h TCP_CONTROL_ACK)
    syn_bit=$(constant src/tcp.h TCP_CONTROL_SYN)

    LC_ALL=C python3 -c '
import socket, struct, sys, time

window, ack_bit, syn_bit = (int(a.rstrip("uU"), 0) for a in sys.argv[1:4])
MORE = window + 140

OURS = b"\x02\x00\x00\x00\x00\x02"
THEIRS = b"\x02\xaa\xaa\xaa\xaa\xaa"
source = socket.inet_aton("10.0.0.99")
destination = socket.inet_aton("10.0.0.2")
THEIR_PORT = 40011
THEIR_ISN = 500000

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

def send(bits, sequence, acknowledgment, payload=b""):
    segment = struct.pack("!HHIIBBHHH", THEIR_PORT, 80, sequence, acknowledgment,
                          5 << 4, bits, 64240, 0, 0) + payload
    pseudo = source + destination + bytes([0, 6, len(segment) >> 8, len(segment) & 0xff])
    segment = segment[:16] + struct.pack("!H", sum_of(pseudo + segment)) + segment[18:]
    header = struct.pack("!BBHHHBBH", 0x45, 0, 20 + len(segment), 1, 0, 64, 6, 0) \
        + source + destination
    header = header[:10] + struct.pack("!H", sum_of(header)) + header[12:]
    wire.send(OURS + THEIRS + b"\x08\x00" + header + segment)

def ours(seconds):
    out = []
    end = time.time() + seconds
    while time.time() < end:
        try:
            frame = wire.recv(4096)
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
answers = [a for a in ours(1.5) if a[0] & syn_bit]
if not answers:
    print("no-answer-to-our-syn"); sys.exit(1)
our_iss = answers[0][1]
send(ack_bit, THEIR_ISN + 1, our_iss + 1)
time.sleep(0.3)

send(ack_bit, THEIR_ISN + 1, our_iss + 1, b"z" * MORE)
back = ours(1.5)
print("segments-back", len(back))
for bits, sequence, acknowledgment in back[:1]:
    print("acknowledges", (acknowledgment - (THEIR_ISN + 1)) % 4294967296)
print("we-sent", MORE)
print("the-window", window)
' "$window" "$ack_bit" "$syn_bit" >"$work/over.txt" 2>&1
    crafted=$?

    kill -INT "$reader" 2>/dev/null
    wait "$reader" 2>/dev/null

    if [ "$crafted" -ne 0 ]; then
        note_failure "the crafted connection could not be driven"
        sed 's/^/      /' "$work/over.txt" >&2
        return
    fi

    back=$(awk '$1 == "segments-back" { print $2 }' "$work/over.txt")
    acknowledges=$(awk '$1 == "acknowledges" { print $2 }' "$work/over.txt")
    we_sent=$(awk '$1 == "we-sent" { print $2 }' "$work/over.txt")

    # ⚠ It answered at all — or refusing to over-acknowledge would prove nothing.
    if [ "${back:-0}" -lt 1 ]; then
        note_failure "nothing came back for $we_sent octets, so this says nothing about what we acknowledge"
        sed 's/^/      /' "$work/over.txt" >&2
        return
    fi
    # ⚠ AC 2, and it is the whole point: ⚠ **exactly what the window covers, and
    # not one octet more.**
    if [ "$acknowledges" != "$window" ]; then
        note_failure "we acknowledged $acknowledges octets of the $we_sent that arrived, and the window is $window"
        sed 's/^/      /' "$work/over.txt" >&2
        return
    fi
    assert_file_contains "$work/out.txt" "$window octets of data were taken and discarded" \
        "exactly the window was taken from an oversized segment"

    printf '    %s octets arrived in one segment and we acknowledged %s, the window\n' \
        "$we_sent" "$acknowledges"
    printf '    being %s\n' "$window"
}

# ⚠ hidetzu/tcpip-stack#80 AC 6, and ⚠ **the loss is made to happen on purpose**
# because nothing is lost on a TAP device in a namespace — ⚠ which is why no
# check here had ever reached this state.
#
# ⚠ `nft` drops our acknowledgment for data on its way into the kernel: exactly
# `ACK`, no `SYN` and no `FIN`, and forty octets, ⚠ **so the SYN-ACK and the
# close still get through** and the connection opens and closes normally.
#
# ⚠ **The verdict is the kernel's**: it does not release a buffer until the
# octets in it have been acknowledged with numbers it accepts.
#
# ⚠ Measured 2026-08-29: with the acknowledgment dropped, `Send-Q` stays at 5
# for 2.4 seconds; ⚠ **with the rule removed it reaches 0 within 0.8**, and
# ⚠ **what saves it is the acknowledgment for a segment we REFUSED** — the
# retransmission is a duplicate, every octet of which we had taken already.
inside_a_peer_whose_acknowledgment_was_lost_recovers() {
    ours=10.0.0.2
    our_mac=02:00:00:00:00:02

    "$TCPIP_STACK" --dev tap0 --mac "$our_mac" --ipv4 "$ours" --tcp-port 80 \
        --timeout 12000 >"$work/out.txt" 2>"$work/err.txt" &
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

    if ! nft add table ip guard 2>"$work/nft.txt"; then
        note_failure "the check environment could not be built here: nft was refused"
        sed 's/^/      /' "$work/nft.txt" >&2
        kill -INT "$reader" 2>/dev/null
        wait "$reader" 2>/dev/null
        return
    fi
    nft add chain ip guard input "{ type filter hook input priority 0; }"
    nft add rule ip guard input tcp sport 80 tcp flags == ack ip length 40 drop

    LC_ALL=C python3 -c '
import socket, subprocess, sys, time

HOW_MUCH = 5

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
    print("connect-failed", why); sys.exit(1)
s.sendall(b"z" * HOW_MUCH)

# ⚠ Watched while the acknowledgment is being dropped. ⚠ What is printed is the
# highest value seen, ⚠ **so a queue that emptied for a moment would show.**
stuck = "0"
end = time.time() + 2.0
while time.time() < end:
    time.sleep(0.2)
    q = send_q()
    if q not in ("0", "gone"):
        stuck = q
print("while-dropping", stuck)

subprocess.run(["nft", "flush", "ruleset"])
began = time.time()
q = send_q()
end = time.time() + 6.0
while time.time() < end and q not in ("0", "gone"):
    time.sleep(0.1)
    q = send_q()
print("after-the-rule-went", q)
print("recovered-in-seconds", round(time.time() - began, 2))
print("how-much", HOW_MUCH)
' >"$work/lost.txt" 2>&1
    ran=$?

    kill -INT "$reader" 2>/dev/null
    wait "$reader" 2>/dev/null

    if [ "$ran" -ne 0 ]; then
        note_failure "the connection could not be opened, so nothing was lost"
        sed 's/^/      /' "$work/lost.txt" >&2
        return
    fi

    stuck=$(awk '$1 == "while-dropping" { print $2 }' "$work/lost.txt")
    after=$(awk '$1 == "after-the-rule-went" { print $2 }' "$work/lost.txt")
    how_much=$(awk '$1 == "how-much" { print $2 }' "$work/lost.txt")

    # ⚠ The loss actually happened — or the recovery below proves nothing.
    if [ "$stuck" != "$how_much" ]; then
        note_failure "the peer's Send-Q was $stuck while its acknowledgment was being dropped, not $how_much, so nothing was lost"
        sed 's/^/      /' "$work/lost.txt" >&2
        return
    fi
    # ⚠ AC 6. ⚠ **The kernel's verdict**, and it recovered from a loss.
    if [ "$after" != "0" ]; then
        note_failure "the peer still holds $after octets after the loss stopped, so it did not recover"
        sed 's/^/      /' "$work/lost.txt" >&2
        printf '    what the stack said:\n' >&2
        grep -v '^  [0-9a-f]' "$work/out.txt" | tail -12 | sed 's/^/      /' >&2
        return
    fi
    # ⚠ And ⚠ **what saved it was the acknowledgment for a segment we refused**,
    # not one for data we took: the retransmission was a duplicate.
    assert_file_contains "$work/out.txt" "said where we are without accepting anything" \
        "the recovery came from an acknowledgment that accepted nothing"

    printf '    Send-Q was %s while our acknowledgment was dropped and reached %s in %s\n' \
        "$stuck" "$after" \
        "$(awk '$1 == "recovered-in-seconds" { print $2 }' "$work/lost.txt")"
    printf '    seconds once it stopped\n'
}

# ⚠ hidetzu/tcpip-stack#86 AC 3, and ⚠ **it is the check that was missing when
# the defect went in**: nothing here had ever turned ECN on.
#
# ⚠ RFC 9293 §3.1: `Reserved` is four bits and "must be ignored in received
# segments". ⚠ The two above it are `CWR` and `ECE`, and ⚠ **nothing here
# implements ECN** — they are read and acted on by nothing (ADR 0024 clause 3).
#
# ⚠ Measured 2026-08-29 before the fix: the kernel's first SYN carries
# `CWR|ECE|SYN` and was thrown away as malformed; ⚠ **the connection opened only
# because Linux fell back to a plain SYN.** ⚠ It replied, and not for the right
# reason.
#
# ⚠ **So the fallback SYN must not be what opens it.** ⚠ The segment that opened
# the connection is read off the wire and its control bits are asserted.
inside_a_syn_carrying_the_ecn_bits_is_the_one_that_opens_it() {
    ours=10.0.0.2
    our_mac=02:00:00:00:00:02

    "$TCPIP_STACK" --dev tap0 --mac "$our_mac" --ipv4 "$ours" --tcp-port 80 \
        --timeout 5000 --hex >"$work/out.txt" 2>"$work/err.txt" &
    reader=$!

    if ! wait_for_interface tap0; then
        note_failure "tap0 never appeared while the stack was attached"
        kill "$reader" 2>/dev/null
        wait "$reader" 2>/dev/null
        return
    fi
    sysctl -qw net.ipv6.conf.tap0.disable_ipv6=1
    # ⚠ The whole point of the case. ⚠ Without this the kernel sends a plain SYN
    # and nothing here is exercised.
    if ! sysctl -qw net.ipv4.tcp_ecn=1; then
        note_failure "the check environment could not be built here: net.ipv4.tcp_ecn could not be set"
        kill -INT "$reader" 2>/dev/null
        wait "$reader" 2>/dev/null
        return
    fi
    ip addr add 10.0.0.1/24 dev tap0
    ip link set tap0 up

    LC_ALL=C python3 -c '
import socket, sys, time
s = socket.socket()
s.settimeout(4)
try:
    s.connect(("10.0.0.2", 80))
except Exception as why:
    print("connect-failed", why); sys.exit(1)
print("connect", "ok")
s.sendall(b"hello")
time.sleep(0.6)
s.close()
time.sleep(0.4)
' >"$work/ecn.txt" 2>&1
    ran=$?

    kill -INT "$reader" 2>/dev/null
    wait "$reader" 2>/dev/null

    if [ "$ran" -ne 0 ]; then
        note_failure "connect() with ECN turned on did not succeed"
        sed 's/^/      /' "$work/ecn.txt" >&2
        printf '    what the stack said:\n' >&2
        grep -v '^  [0-9a-f]' "$work/out.txt" | tail -12 | sed 's/^/      /' >&2
        return
    fi

    ethernet_header=$(constant src/ethernet.h ETHERNET_HEADER_BYTES)
    ipv4_type=$(constant src/ipv4.h IPV4_ETHERNET_LENGTH_TYPE)
    tcp_number=$(constant src/tcp.h TCP_PROTOCOL_NUMBER)
    syn_bit=$(constant src/tcp.h TCP_CONTROL_SYN)
    cwr_bit=$(constant src/tcp.h TCP_CONTROL_CWR)
    ece_bit=$(constant src/tcp.h TCP_CONTROL_ECE)

    LC_ALL=C frames_as_hex "$work/out.txt" | python3 -c '
import sys

def number(text):
    return int(text.rstrip("uU"), 0)

ethernet_header, ipv4_type, tcp_number, syn_bit, cwr_bit, ece_bit = (
    number(a) for a in sys.argv[1:7])

syns = []
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
    at = ethernet_header + (octets[ethernet_header] & 0x0f) * 4
    if len(octets) < at + 20:
        continue
    bits = octets[at + 13]
    if bits & syn_bit:
        syns.append(bits)
print("syns", len(syns))
print("first-syn-bits", "0x%02x" % syns[0] if syns else "none")
print("first-syn-carries-ecn",
      1 if syns and (syns[0] & (cwr_bit | ece_bit)) == (cwr_bit | ece_bit) else 0)
' "$ethernet_header" "$ipv4_type" "$tcp_number" "$syn_bit" "$cwr_bit" "$ece_bit" \
        >"$work/counted.txt"

    syns=$(awk '$1 == "syns" { print $2 }' "$work/counted.txt")
    bits=$(awk '$1 == "first-syn-bits" { print $2 }' "$work/counted.txt")
    carries=$(awk '$1 == "first-syn-carries-ecn" { print $2 }' "$work/counted.txt")

    # ⚠ The kernel really did offer ECN — or the rest of this case is about
    # nothing.
    if [ "${carries:-0}" -ne 1 ]; then
        note_failure "the kernel's first SYN was $bits and carried no ECN bits, so this case exercised nothing"
        sed 's/^/      /' "$work/counted.txt" >&2
        return
    fi
    # ⚠ AC 3. ⚠ **One SYN**: a second would mean the first was thrown away and
    # Linux fell back. ⚠ Measured before the fix: two.
    if [ "${syns:-0}" -ne 1 ]; then
        note_failure "the kernel sent $syns SYNs, so the one carrying the ECN bits was not the one that opened it"
        sed 's/^/      /' "$work/counted.txt" >&2
        return
    fi
    # ⚠ And nothing was thrown away.
    assert_file_contains "$work/out.txt" "0 TCP headers were malformed" \
        "a SYN carrying the ECN bits is not malformed"
    assert_file_contains "$work/out.txt" "1 connection was opened and 1 answered" \
        "it opened a connection"
    assert_file_contains "$work/out.txt" "5 octets of data were taken and discarded" \
        "the connection carried data afterwards"

    printf '    the kernel offered ECN with a single SYN of %s and it opened the\n' "$bits"
    printf '    connection; nothing fell back\n'
}

# ⚠ hidetzu/tcpip-stack#103. ⚠ **`--ttl` reaches the wire**, and ⚠ **at a value
# that is not the default** — otherwise the check could not tell a setting from
# the constant it replaced.
#
# ⚠ RFC 9293 `MUST-49`: "The TTL value used to send TCP segments MUST be
# configurable."
#
# ⚠ **One value covers TCP and the ICMP echo reply alike** (Owner Decision,
# 2026-08-29). ⚠ **That claims slightly more than the requirement asks**, which
# names TCP segments, and ⚠ this case asserts both so the claim is not wider
# than what is checked.
inside_the_time_to_live_we_were_given_reaches_the_wire() {
    ours=10.0.0.2
    our_mac=02:00:00:00:00:02
    asked_for=42

    "$TCPIP_STACK" --dev tap0 --mac "$our_mac" --ipv4 "$ours" --tcp-port 80 \
        --ttl "$asked_for" --timeout 4000 >"$work/out.txt" 2>"$work/err.txt" &
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

    icmp=$(constant src/ipv4.h IPV4_PROTOCOL_ICMP)
    tcp=$(constant src/tcp.h TCP_PROTOCOL_NUMBER)

    LC_ALL=C python3 -c '
import socket, subprocess, sys, threading, time

icmp, tcp = (int(a.rstrip("uU"), 0) for a in sys.argv[1:3])
OURS = bytes.fromhex(sys.argv[3].replace(":", ""))

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
        if len(frame) < 34 or frame[12:14] != b"\x08\x00":
            continue
        if frame[6:12] != OURS:
            continue
        seen.append((frame[14 + 9], frame[14 + 8]))

watcher = threading.Thread(target=watch)
watcher.start()

subprocess.run(["ping", "-c", "1", "-W", "1", "10.0.0.2"],
               capture_output=True)
s = socket.socket()
s.settimeout(3)
try:
    s.connect(("10.0.0.2", 80))
except Exception as why:
    stop.set(); watcher.join()
    print("connect-failed", why); sys.exit(1)
s.close()
time.sleep(0.8)
stop.set(); watcher.join()

for protocol, name in ((tcp, "tcp"), (icmp, "icmp")):
    values = sorted({ttl for p, ttl in seen if p == protocol})
    print(name, " ".join(str(v) for v in values) or "none")
' "$icmp" "$tcp" "$our_mac" >"$work/ttl.txt" 2>&1
    watched=$?

    kill -INT "$reader" 2>/dev/null
    wait "$reader" 2>/dev/null

    if [ "$watched" -ne 0 ]; then
        note_failure "the connection could not be opened, so nothing was sent"
        sed 's/^/      /' "$work/ttl.txt" >&2
        return
    fi

    over_tcp=$(awk '$1 == "tcp" { $1 = ""; print substr($0, 2) }' "$work/ttl.txt")
    over_icmp=$(awk '$1 == "icmp" { $1 = ""; print substr($0, 2) }' "$work/ttl.txt")

    # ⚠ `MUST-49` is about TCP segments, and ⚠ **one value, not a mixture**.
    if [ "$over_tcp" != "$asked_for" ]; then
        note_failure "we asked for a time to live of $asked_for and the TCP segments carried $over_tcp"
        sed 's/^/      /' "$work/ttl.txt" >&2
        return
    fi
    # ⚠ The reply we send for a ping shares it, which is the Owner Decision.
    if [ "$over_icmp" != "$asked_for" ]; then
        note_failure "the ICMP reply carried $over_icmp and we asked for $asked_for"
        sed 's/^/      /' "$work/ttl.txt" >&2
        return
    fi
    # ⚠ The other half: ⚠ **it is a setting and not a new constant.** ⚠ 42 is not
    # the default, so a build ignoring the option would show 64 here.
    default=$(constant src/ipv4.h IPV4_TIME_TO_LIVE_WE_SEND)
    if [ "$asked_for" = "${default%u}" ]; then
        note_failure "this case asks for the default, so it cannot tell a setting from a constant"
        return
    fi

    printf '    asked for %s and both the TCP segments and the ICMP reply carried it;\n' "$asked_for"
    printf '    the default is %s\n' "${default%u}"
}

# ⚠ hidetzu/tcpip-stack#99. ⚠ RFC 9293 `MUST-57` on the wire, ⚠ **and the part
# that is not met asserted beside it.**
#
# ⚠ Measured before the change, same conditions, 2026-08-29: with
# `--ipv4 10.0.0.255` a `SYN` to `10.0.0.255` opened a connection and was
# answered. ⚠ **That one still does** — a directed broadcast cannot be told from
# a host address without a netmask, ⚠ **and this case pins it so the gap cannot
# close by accident.**
# ⚠ hidetzu/tcpip-stack#112 on the wire. ⚠ RFC 9293 `MUST-63`, §3.9.2.3: "An
# incoming SYN with an invalid source address MUST be ignored either by TCP or
# by the IP layer ... (see Section 3.2.1.3)."
#
# ⚠ Measured before the change, same conditions, 2026-08-29: ⚠ **a `SYN` whose
# source was 255.255.255.255 opened a connection and was answered.**
#
# ⚠ The `SYN` is built by hand over `AF_PACKET`, ⚠ **because no kernel will send
# one from an address RFC 1122 forbids as a source** — ⚠ that is the point of
# the requirement, and it is why the other end here is a raw socket rather than
# the kernel's stack. ⚠ **The kernel is still the other end for the half that
# must keep working**: an ordinary source is answered.
inside_a_syn_from_an_impossible_source_is_not_answered() {
    ours=10.0.0.2
    our_mac=02:00:00:00:00:02

    for source in 0.0.0.0 127.0.0.1 255.255.255.255 224.0.0.1 10.0.0.99; do
        "$TCPIP_STACK" --dev tap0 --mac "$our_mac" --ipv4 "$ours" --tcp-port 80 \
            --timeout 1500 >"$work/out-$source.txt" 2>&1 &
        reader=$!
        if ! wait_for_interface tap0; then
            note_failure "tap0 never appeared while the stack was attached for $source"
            kill "$reader" 2>/dev/null
            wait "$reader" 2>/dev/null
            return
        fi
        sysctl -qw net.ipv6.conf.tap0.disable_ipv6=1
        ip addr add 10.0.0.1/24 dev tap0
        ip link set tap0 up

        LC_ALL=C python3 -c '
import socket, struct, sys
def sum_of(o):
    t = 0
    for i in range(0, len(o) - 1, 2): t += (o[i] << 8) | o[i + 1]
    if len(o) % 2: t += o[-1] << 8
    while t >> 16: t = (t & 0xffff) + (t >> 16)
    return (~t) & 0xffff
OURS = bytes.fromhex(sys.argv[1].replace(":", ""))
source = socket.inet_aton(sys.argv[2])
destination = socket.inet_aton("10.0.0.2")
segment = struct.pack("!HHIIBBHHH", 41000, 80, 1000, 0, 5 << 4, 0x02, 64240, 0, 0)
pseudo = source + destination + bytes([0, 6, 0, len(segment)])
segment = segment[:16] + struct.pack("!H", sum_of(pseudo + segment)) + segment[18:]
header = struct.pack("!BBHHHBBH", 0x45, 0, 20 + len(segment), 1, 0, 64, 6, 0) \
    + source + destination
header = header[:10] + struct.pack("!H", sum_of(header)) + header[12:]
wire = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
wire.bind(("tap0", 0))
wire.send(OURS + b"\x02\xaa\xaa\xaa\xaa\xaa" + b"\x08\x00" + header + segment)
' "$our_mac" "$source" >"$work/sent-$source.txt" 2>&1
        sleep 0.6
        kill -INT "$reader" 2>/dev/null
        wait "$reader" 2>/dev/null
        ip link del tap0 2>/dev/null
    done

    # ⚠ Refused, ⚠ **and no connection opened** — `MUST-63` says "ignored", and
    # ⚠ a connection taken and then dropped would not have been ignored.
    for source in 0.0.0.0 127.0.0.1 255.255.255.255 224.0.0.1; do
        assert_file_contains "$work/out-$source.txt" \
            "1 segment was from an address that can never send anything" \
            "a SYN from $source is refused and counted"
        assert_file_contains "$work/out-$source.txt" \
            "0 connections were opened and 0 answered" \
            "no connection state was created for a SYN from $source"
    done

    # ⚠ The other half: ⚠ **an ordinary source is still answered**, or refusing
    # these would pass for a stack that refuses everything.
    assert_file_contains "$work/out-10.0.0.99.txt" "1 connection was opened and 1 answered" \
        "an ordinary source is still answered"
    assert_file_contains "$work/out-10.0.0.99.txt" \
        "0 segments were from an address that can never send anything" \
        "an ordinary source is not counted as an impossible one"

    printf '    SYNs from 0.0.0.0, 127.0.0.1, 255.255.255.255 and 224.0.0.1 opened\n'
    printf '    nothing; one from 10.0.0.99 opened a connection. ⚠ A directed\n'
    printf '    broadcast source is NOT covered and is still answered\n'
}

inside_a_syn_to_everyone_is_not_answered() {
    our_mac=02:00:00:00:00:02
    for ours in 255.255.255.255 224.0.0.1 10.0.0.2; do
        "$TCPIP_STACK" --dev tap0 --mac "$our_mac" --ipv4 "$ours" --tcp-port 80 \
            --timeout 1500 >"$work/out-$ours.txt" 2>&1 &
        reader=$!
        if ! wait_for_interface tap0; then
            note_failure "tap0 never appeared while the stack was attached for $ours"
            kill "$reader" 2>/dev/null
            wait "$reader" 2>/dev/null
            return
        fi
        sysctl -qw net.ipv6.conf.tap0.disable_ipv6=1
        ip addr add 10.0.0.1/24 dev tap0
        ip link set tap0 up

        LC_ALL=C python3 -c '
import socket, struct, sys
def sum_of(o):
    t = 0
    for i in range(0, len(o) - 1, 2): t += (o[i] << 8) | o[i + 1]
    if len(o) % 2: t += o[-1] << 8
    while t >> 16: t = (t & 0xffff) + (t >> 16)
    return (~t) & 0xffff
OURS = bytes.fromhex(sys.argv[1].replace(":", ""))
source = socket.inet_aton("10.0.0.99")
destination = socket.inet_aton(sys.argv[2])
segment = struct.pack("!HHIIBBHHH", 41000, 80, 1000, 0, 5 << 4, 0x02, 64240, 0, 0)
pseudo = source + destination + bytes([0, 6, 0, len(segment)])
segment = segment[:16] + struct.pack("!H", sum_of(pseudo + segment)) + segment[18:]
header = struct.pack("!BBHHHBBH", 0x45, 0, 20 + len(segment), 1, 0, 64, 6, 0) \
    + source + destination
header = header[:10] + struct.pack("!H", sum_of(header)) + header[12:]
wire = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
wire.bind(("tap0", 0))
wire.send(OURS + b"\x02\xaa\xaa\xaa\xaa\xaa" + b"\x08\x00" + header + segment)
' "$our_mac" "$ours" >"$work/sent.txt" 2>&1
        sleep 0.6
        kill -INT "$reader" 2>/dev/null
        wait "$reader" 2>/dev/null
        ip link del tap0 2>/dev/null
    done

    # ⚠ The two the address alone can name: refused, and ⚠ **no connection
    # opened**, which is the reason the document gives.
    for ours in 255.255.255.255 224.0.0.1; do
        assert_file_contains "$work/out-$ours.txt" \
            "1 segment was addressed to a broadcast or multicast address" \
            "a SYN to $ours is refused and counted"
        assert_file_contains "$work/out-$ours.txt" "0 connections were opened and 0 answered" \
            "no connection state was created for $ours"
    done
    # ⚠ The other half: ⚠ **an ordinary address is still answered.**
    assert_file_contains "$work/out-10.0.0.2.txt" "1 connection was opened and 1 answered" \
        "an ordinary address is still answered"
    assert_file_contains "$work/out-10.0.0.2.txt" \
        "0 segments were addressed to a broadcast or multicast address" \
        "an ordinary address is not counted as a broadcast"

    printf '    a SYN to 255.255.255.255 and to 224.0.0.1 opened nothing; one to\n'
    printf '    10.0.0.2 opened a connection. ⚠ A directed broadcast is not covered\n'
}

# ⚠ hidetzu/tcpip-stack#101 on the wire. ⚠ RFC 9293 `MUST-66`.
#
# ⚠ Measured before the change, same conditions, 2026-08-29: a `RST,ACK` on an
# open connection changed nothing — ⚠ **the connection stayed open, took 13
# octets afterwards and acknowledged them.**
#
# ⚠ The connection is driven by hand over `AF_PACKET` from an address nobody
# owns, ⚠ **so the kernel never joins in** and the reset is ours to time.
inside_a_reset_ends_a_connection_on_the_wire() {
    ours=10.0.0.2
    our_mac=02:00:00:00:00:02

    "$TCPIP_STACK" --dev tap0 --mac "$our_mac" --ipv4 "$ours" --tcp-port 80 \
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

    rst=$(constant src/tcp.h TCP_CONTROL_RST)
    ack=$(constant src/tcp.h TCP_CONTROL_ACK)
    syn=$(constant src/tcp.h TCP_CONTROL_SYN)

    LC_ALL=C python3 -c '
import socket, struct, sys, time

rst, ack, syn = (int(a.rstrip("uU"), 0) for a in sys.argv[1:4])
OURS = bytes.fromhex(sys.argv[4].replace(":", ""))
THEIRS = b"\x02\xaa\xaa\xaa\xaa\xaa"
source = socket.inet_aton("10.0.0.99")
destination = socket.inet_aton("10.0.0.2")
PORT = 40031
THEIR_ISN = 300000

def sum_of(o):
    t = 0
    for i in range(0, len(o) - 1, 2): t += (o[i] << 8) | o[i + 1]
    if len(o) % 2: t += o[-1] << 8
    while t >> 16: t = (t & 0xffff) + (t >> 16)
    return (~t) & 0xffff

wire = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
wire.bind(("tap0", 0))
wire.settimeout(0.3)

def send(bits, sequence, acknowledgment, payload=b""):
    seg = struct.pack("!HHIIBBHHH", PORT, 80, sequence, acknowledgment,
                      5 << 4, bits, 64240, 0, 0) + payload
    pseudo = source + destination + bytes([0, 6, len(seg) >> 8, len(seg) & 0xff])
    seg = seg[:16] + struct.pack("!H", sum_of(pseudo + seg)) + seg[18:]
    h = struct.pack("!BBHHHBBH", 0x45, 0, 20 + len(seg), 1, 0, 64, 6, 0) \
        + source + destination
    h = h[:10] + struct.pack("!H", sum_of(h)) + h[12:]
    wire.send(OURS + THEIRS + b"\x08\x00" + h + seg)

def ours(seconds):
    out = []
    end = time.time() + seconds
    while time.time() < end:
        try:
            f = wire.recv(2048)
        except socket.timeout:
            continue
        except OSError:
            break
        if len(f) < 54 or f[12:14] != b"\x08\x00" or f[14 + 9] != 6:
            continue
        if f[6:12] != OURS:
            continue
        at = 14 + (f[14] & 0x0f) * 4
        out.append((f[at + 13], int.from_bytes(f[at + 4:at + 8], "big")))
    return out

send(syn, THEIR_ISN, 0)
answers = [a for a in ours(1.5) if a[0] & syn]
if not answers:
    print("no-answer-to-our-syn"); sys.exit(1)
iss = answers[0][1]
send(ack, THEIR_ISN + 1, iss + 1)
time.sleep(0.3)

send(rst | ack, THEIR_ISN + 1, iss + 1)
print("back-for-the-reset", len(ours(0.8)))

# ⚠ The connection must be gone: data after it draws nothing.
send(ack, THEIR_ISN + 1, iss + 1, b"after-the-reset")
print("back-for-data-after-it", len(ours(1.2)))
' "$rst" "$ack" "$syn" "$our_mac" >"$work/reset.txt" 2>&1
    driven=$?

    kill -INT "$reader" 2>/dev/null
    wait "$reader" 2>/dev/null

    if [ "$driven" -ne 0 ]; then
        note_failure "the crafted connection could not be driven"
        sed 's/^/      /' "$work/reset.txt" >&2
        return
    fi

    for_reset=$(awk '$1 == "back-for-the-reset" { print $2 }' "$work/reset.txt")
    after=$(awk '$1 == "back-for-data-after-it" { print $2 }' "$work/reset.txt")

    # ⚠ Nothing is sent for a reset.
    if [ "${for_reset:-1}" -ne 0 ]; then
        note_failure "$for_reset segments came back for a reset, and nothing should"
        sed 's/^/      /' "$work/reset.txt" >&2
        return
    fi
    # ⚠ And the connection really is gone. ⚠ Measured before the change: 1.
    if [ "${after:-1}" -ne 0 ]; then
        note_failure "data after the reset drew $after segments, so the connection survived it"
        sed 's/^/      /' "$work/reset.txt" >&2
        printf '    what the stack said:\n' >&2
        grep -v '^  [0-9a-f]' "$work/out.txt" | tail -12 | sed 's/^/      /' >&2
        return
    fi
    assert_file_contains "$work/out.txt" "the other side reset 1 connection" \
        "the reset is counted as one"
    assert_file_contains "$work/out.txt" "0 octets of data were taken and discarded" \
        "nothing was taken after the connection was gone"

    printf '    the reset drew nothing and data after it drew nothing; the connection\n'
    printf '    was gone\n'
}

# ⚠ The half that stops the case above passing for a stack that never looked at
# a checksum (hidetzu/tcpip-stack#44 AC 2, and `CLAUDE.md` §1).
#
# ⚠ The segment is built here and handed to the kernel on a raw socket, so ⚠ the
# kernel routes it out tap0 and our stack reads it exactly as it reads anything
# else. ⚠ Why not write the frame onto the device directly: ⚠ **two processes
# cannot hold one TAP device**, which `tests/isolated.sh`
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
case_an_icmp_error_the_kernel_sent_reaches_the_connection() {
    in_namespace an_icmp_error_the_kernel_sent_reaches_the_connection
}

case_the_window_reopens_one_segment_at_a_time_after_a_loss() {
    in_namespace the_window_reopens_one_segment_at_a_time_after_a_loss
}

case_a_lost_segment_or_a_lost_ack_still_gets_the_data_through() {
    in_namespace a_lost_segment_or_a_lost_ack_still_gets_the_data_through
}

case_data_larger_than_the_mss_arrives_in_segments_it_bounds() {
    in_namespace data_larger_than_the_mss_arrives_in_segments_it_bounds
}

case_the_mss_option_goes_both_ways_with_the_kernel() {
    in_namespace the_mss_option_goes_both_ways_with_the_kernel
}

case_the_window_on_the_wire_follows_the_mtu() {
    in_namespace the_window_on_the_wire_follows_the_mtu
}

case_the_peers_send_queue_drains_once_we_acknowledge() {
    in_namespace the_peers_send_queue_drains_once_we_acknowledge
}
case_a_connection_carries_data_and_then_closes_properly() {
    in_namespace a_connection_carries_data_and_then_closes_properly
}
case_an_acknowledgment_never_covers_an_octet_we_did_not_take() {
    in_namespace an_acknowledgment_never_covers_an_octet_we_did_not_take
}
case_a_peer_whose_acknowledgment_was_lost_recovers() {
    in_namespace a_peer_whose_acknowledgment_was_lost_recovers
}
case_a_syn_carrying_the_ecn_bits_is_the_one_that_opens_it() {
    in_namespace a_syn_carrying_the_ecn_bits_is_the_one_that_opens_it
}
case_the_time_to_live_we_were_given_reaches_the_wire() {
    in_namespace the_time_to_live_we_were_given_reaches_the_wire
}
case_a_syn_from_an_impossible_source_is_not_answered() {
    in_namespace a_syn_from_an_impossible_source_is_not_answered
}

case_a_syn_to_everyone_is_not_answered() {
    in_namespace a_syn_to_everyone_is_not_answered
}
case_a_reset_ends_a_connection_on_the_wire() {
    in_namespace a_reset_ends_a_connection_on_the_wire
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

ALL_CASES="an_arp_request_the_kernel_generated_is_read_intact a_frame_larger_than_the_read_buffer_is_not_reported_as_a_known_length the_kernel_believes_the_address_we_answered_for ping_reports_no_loss_against_our_own_stack the_kernel_opens_a_connection_to_us a_fin_reaches_us_once_the_window_is_open the_kernel_stops_retransmitting_once_we_close_back the_kernel_reaches_time_wait_and_our_block_is_free_again a_fin_whose_sequence_number_we_do_not_expect_is_not_answered the_peers_send_queue_drains_once_we_acknowledge the_window_on_the_wire_follows_the_mtu the_mss_option_goes_both_ways_with_the_kernel data_larger_than_the_mss_arrives_in_segments_it_bounds a_lost_segment_or_a_lost_ack_still_gets_the_data_through the_window_reopens_one_segment_at_a_time_after_a_loss an_icmp_error_the_kernel_sent_reaches_the_connection a_connection_carries_data_and_then_closes_properly an_acknowledgment_never_covers_an_octet_we_did_not_take a_peer_whose_acknowledgment_was_lost_recovers a_syn_carrying_the_ecn_bits_is_the_one_that_opens_it the_time_to_live_we_were_given_reaches_the_wire a_syn_to_everyone_is_not_answered a_syn_from_an_impossible_source_is_not_answered a_reset_ends_a_connection_on_the_wire a_syn_whose_checksum_does_not_agree_is_not_answered"

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
select_cases interop "$ALL_CASES" "$@"

$MAKE -s build || exit 2

if ! unshare -Urn true 2>/dev/null; then
    printf 'interop: the check environment could not be built here: unshare -Urn was refused.\n' >&2
    printf 'interop: 0 cases ran. Nothing was checked, and nothing was disproved either.\n' >&2
    exit 2
fi

run_selected_cases
