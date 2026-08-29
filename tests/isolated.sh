#!/bin/sh
# real — a TAP device, brought up inside a fresh network namespace, with actual
# packets going through it. ⚠ Nothing outside this machine is involved, and
# nothing outside this repository is the other end.
#
# ⚠ No sudo, no setcap, no persistent device. The capability comes from
# `unshare -Urn` (docs/adr/0001-*).

set -u
cd "$(dirname -- "$0")/.." || exit 2
. tests/lib.sh

TCPIP_STACK=./build/tcpip-stack
MAKE=${MAKE:-make}

# The device appears when tcpip-stack attaches and is gone when it lets go, so
# everything that inspects it has to wait for it first.
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

wait_for_interface_to_go() {
    i=0
    while [ "$i" -lt 60 ]; do
        if ! ip link show "$1" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.05
        i=$((i + 1))
    done
    return 1
}

SEND_ONE_FRAME=./build/send-one-frame

# The kernel's own counters for the device, as one line:
# "<rx_bytes> <rx_packets> <rx_dropped>".
#
# ⚠ This is what says a frame arrived. ⚠ write(2) returning a number says only
# that we handed it over (`CLAUDE.md` §1, in the sending direction).
#
# ⚠ ip(8) and not /sys/class/net: sysfs is not remounted by `unshare -Urn`, so
# inside the namespace it shows the host's devices and not this one's — reading
# it there fails with "No such file or directory" (measured 2026-08-26).
# ⚠ ip asks the kernel over netlink, which is namespace-aware.
tap_received() {
    ip -s link show "$1" | awk '/RX:/ { getline; print $1, $2, $4 }'
}

# Waits for a line to appear in a file something else is still writing to.
wait_for_line() {  # file text
    i=0
    while [ "$i" -lt 60 ]; do
        if grep -qF -- "$2" "$1" 2>/dev/null; then
            return 0
        fi
        sleep 0.05
        i=$((i + 1))
    done
    return 1
}

# ---- the cases, as they run inside the namespace -------------------------

inside_the_interface_exists_only_while_it_is_attached() {
    "$TCPIP_STACK" --dev tap0 --count 1 --timeout 3000 >"$work/out.txt" 2>"$work/err.txt" &
    reader=$!

    if ! wait_for_interface tap0; then
        note_failure "tap0 never appeared while tcpip-stack was attached"
        kill "$reader" 2>/dev/null
        wait "$reader" 2>/dev/null
        return
    fi
    assert_true "while tcpip-stack holds it" ip link show tap0

    kill "$reader" 2>/dev/null
    wait "$reader" 2>/dev/null

    # ⚠ The other half. A check that only asserts the device appears stays green
    # when it never goes away (`verify` §5).
    if ! wait_for_interface_to_go tap0; then
        note_failure "tap0 was still there after tcpip-stack let go of the fd"
    fi

    assert_file_contains "$work/out.txt" "listening on tap0" "the first line"
}

inside_count_zero_reads_nothing() {
    "$TCPIP_STACK" --dev tap0 --count 0 >"$work/out.txt" 2>"$work/err.txt"
    assert_exit_code 0 $? "reading no frames at all"
    assert_file_is "$work/out.txt" "listening on tap0
read 0 frames, 0 read errors
0 frames were malformed, 0 carried an IEEE 802.3 Length, 0 carried a length/type the standard does not define" "reading no frames at all"
    assert_file_is "$work/err.txt" "" "reading no frames at all"
}

inside_a_timer_running_out_has_its_own_exit_code() {
    # tap0 is created but never brought up, so nothing is put on it.
    "$TCPIP_STACK" --dev tap0 --count 1 --timeout 300 >"$work/out.txt" 2>"$work/err.txt"
    assert_exit_code 2 $? "the timer running out"
    assert_file_is "$work/err.txt" \
        "listened on tap0 for 300 ms and read 0 frames. Nothing arrived here; that does not say whether anything was sent." \
        "the timer running out"
    assert_file_is "$work/out.txt" "listening on tap0
read 0 frames, 0 read errors
0 frames were malformed, 0 carried an IEEE 802.3 Length, 0 carried a length/type the standard does not define" "the timer running out"
}

# ⚠ What this proves and what it does not: it proves that a stop request reaches
# a reader that is waiting without any time limit, and that the reader then
# reports what it read. ⚠ It does not prove the narrow window is closed — a
# request arriving between the loop testing its flag and the wait beginning
# cannot be aimed at from a shell. That window is closed by construction
# (`src/tap.h`: the signals are blocked around the loop and unblocked only
# inside ppoll), and construction is reasoning, not a measurement.
inside_a_stop_request_reaches_a_reader_that_is_waiting() {
    # No --count and no --timeout: it waits until something arrives or it is told
    # to stop, and nothing is ever put on this device.
    "$TCPIP_STACK" --dev tap0 >"$work/out.txt" 2>"$work/err.txt" &
    reader=$!
    if ! wait_for_interface tap0; then
        note_failure "tap0 never appeared while tcpip-stack was attached"
        kill -9 "$reader" 2>/dev/null
        wait "$reader" 2>/dev/null
        return
    fi

    kill -INT "$reader" 2>/dev/null

    i=0
    while kill -0 "$reader" 2>/dev/null && [ "$i" -lt 60 ]; do
        sleep 0.05
        i=$((i + 1))
    done
    if kill -0 "$reader" 2>/dev/null; then
        note_failure "tcpip-stack was still waiting 3 s after being asked to stop"
        kill -9 "$reader" 2>/dev/null
        wait "$reader" 2>/dev/null
        return
    fi

    wait "$reader"
    assert_exit_code 0 $? "being asked to stop"
    assert_file_is "$work/out.txt" "listening on tap0
read 0 frames, 0 read errors
0 frames were malformed, 0 carried an IEEE 802.3 Length, 0 carried a length/type the standard does not define" "being asked to stop"
}

inside_a_second_attach_to_the_same_device_is_refused() {
    "$TCPIP_STACK" --dev tap0 --count 1 --timeout 3000 >"$work/first.txt" 2>&1 &
    reader=$!
    if ! wait_for_interface tap0; then
        note_failure "tap0 never appeared while tcpip-stack was attached"
        kill "$reader" 2>/dev/null
        wait "$reader" 2>/dev/null
        return
    fi

    "$TCPIP_STACK" --dev tap0 --count 1 --timeout 300 >"$work/out.txt" 2>"$work/err.txt"
    second=$?

    kill "$reader" 2>/dev/null
    wait "$reader" 2>/dev/null

    assert_exit_code 3 "$second" "attaching to a device someone else holds"
    assert_file_contains "$work/err.txt" \
        "could not attach to tap0: creating the device failed:" \
        "attaching to a device someone else holds"
}

# ⚠ The wait says what it saw. `ip link del` detaches every fd attached to the
# device, and ppoll then reports POLLERR — ⚠ it SUCCEEDS, returning 1, so there
# is no errno and the line names none (hidetzu/tcpip-stack#8).
#
# ⚠ This replaces a_read_that_could_not_be_made_is_its_own_outcome, which
# reached the read-failure path through the very gap #8 closed. ⚠ The behaviour
# it covered has not gone: the line and the two counts are now asserted in the
# static tier, without a device (docs/SPEC.md §1).
inside_the_wait_says_the_device_stopped_being_usable() {
    "$TCPIP_STACK" --dev tap0 --timeout 3000 >"$work/out.txt" 2>"$work/err.txt" &
    reader=$!
    if ! wait_for_interface tap0; then
        note_failure "tap0 never appeared while the stack was attached"
        kill "$reader" 2>/dev/null
        wait "$reader" 2>/dev/null
        return
    fi

    # ⚠ If the device could not be taken away, nothing below is a statement
    # about our code (`verify` §4).
    if ! ip link del tap0; then
        note_failure "tap0 could not be removed, so the wait was never made to report an error"
        kill "$reader" 2>/dev/null
        wait "$reader" 2>/dev/null
        return
    fi

    wait "$reader"
    assert_exit_code 3 $? "the device stopped being usable"

    # ⚠ Once, not eight times. ⚠ Before #8 this printed eight read failures and a
    # give-up line, because the wait said READY on an error.
    assert_file_is "$work/err.txt" \
        "could not keep listening on tap0: the device stopped being usable.
  Waiting for a frame will not help. Nothing here can say why." \
        "the device stopped being usable"

    # ⚠ No frame was read and no read was attempted, so neither count moved.
    assert_file_is "$work/out.txt" "listening on tap0
read 0 frames, 0 read errors
0 frames were malformed, 0 carried an IEEE 802.3 Length, 0 carried a length/type the standard does not define" "the device stopped being usable"
}

# ⚠ A frame handed to the device reaches the kernel, and the kernel's own
# counters are what say so. ⚠ write(2) returning 60 says we handed over 60; it
# does not say 60 octets reached anybody.
#
# ⚠ The length/type is one the kernel does not handle, on purpose. So RX moves
# and the frames are dropped after arriving — ⚠ "it arrived" and "the kernel
# acted on it" stay two different facts, and the check can see both.
inside_a_frame_handed_over_reaches_the_kernel() {
    frames=3
    octets=60

    # ⚠ The driver waits on stdin, so the counters are read while the device
    # exists and before anything is written. A sleep here would be a guess.
    fifo="$work/fifo"
    mkfifo "$fifo" || { note_failure "could not make a fifo"; return; }
    "$SEND_ONE_FRAME" --dev tap0 --count "$frames" --bytes "$octets" \
        <"$fifo" >"$work/out.txt" 2>"$work/err.txt" &
    sender=$!
    exec 9>"$fifo"

    if ! wait_for_interface tap0; then
        note_failure "tap0 never appeared while the sender was attached"
        exec 9>&-
        kill "$sender" 2>/dev/null
        wait "$sender" 2>/dev/null
        return
    fi
    ip link set tap0 up

    before=$(tap_received tap0)
    printf '\n' >&9

    # ⚠ The counters are read while the sender still holds the device. It is
    # gone the moment that fd closes (`docs/SPEC.md` §1), so waiting for the
    # process to exit first would leave nothing to count.
    if ! wait_for_line "$work/out.txt" "handed over"; then
        note_failure "the sender never said what it handed over"
        exec 9>&-
        kill "$sender" 2>/dev/null
        wait "$sender" 2>/dev/null
        return
    fi
    after=$(tap_received tap0)

    printf '\n' >&9
    wait "$sender"
    assert_exit_code 0 $? "handing frames over"
    exec 9>&-

    before_bytes=$(printf '%s' "$before" | cut -d' ' -f1)
    before_packets=$(printf '%s' "$before" | cut -d' ' -f2)
    after_bytes=$(printf '%s' "$after" | cut -d' ' -f1)
    after_packets=$(printf '%s' "$after" | cut -d' ' -f2)
    moved_bytes=$((after_bytes - before_bytes))
    moved_packets=$((after_packets - before_packets))

    if [ "$moved_packets" -ne "$frames" ] || [ "$moved_bytes" -ne $((frames * octets)) ]; then
        note_failure "the kernel received $moved_packets frames and $moved_bytes octets, not $frames and $((frames * octets))"
        printf '    what the sender said:\n' >&2
        sed 's/^/      /' "$work/out.txt" >&2
        return
    fi

    assert_file_contains "$work/out.txt" \
        "handed over $frames frames, $((frames * octets)) octets, 0 could not be handed over, 0 short, 0 with the wrong step" \
        "handing frames over"

    # ⚠ Recorded, never asserted: what the kernel did with them afterwards is
    # its business, and this check is about arrival (`verify` §4).
    printf '    the kernel then dropped %s of them\n' \
        "$(printf '%s' "$after" | cut -d' ' -f3)"
}

# ⚠ A write that could not be made is not a frame sent. ⚠ Counting it as one
# would make a frame that never left look exactly like one that did.
#
# ⚠ The failure is produced the same way hidetzu/tcpip-stack#4 produced a failing
# read: `ip link del` detaches every fd attached to the device. ⚠ The kernel
# produces the failure; the harness only takes the device away.
inside_a_write_that_could_not_be_made_is_not_a_frame_sent() {
    fifo="$work/fifo"
    mkfifo "$fifo" || { note_failure "could not make a fifo"; return; }
    "$SEND_ONE_FRAME" --dev tap0 --count 2 --bytes 60 \
        <"$fifo" >"$work/out.txt" 2>"$work/err.txt" &
    sender=$!
    exec 9>"$fifo"

    if ! wait_for_interface tap0; then
        note_failure "tap0 never appeared while the sender was attached"
        exec 9>&-
        kill "$sender" 2>/dev/null
        wait "$sender" 2>/dev/null
        return
    fi

    # ⚠ If the device could not be taken away, no write was ever made to fail
    # and nothing below is a statement about our code (`verify` §4).
    if ! ip link del tap0; then
        note_failure "tap0 could not be removed, so no write was ever made to fail"
        exec 9>&-
        kill "$sender" 2>/dev/null
        wait "$sender" 2>/dev/null
        return
    fi

    printf '\n' >&9
    if ! wait_for_line "$work/out.txt" "handed over"; then
        note_failure "the sender never said what it handed over"
        exec 9>&-
        kill "$sender" 2>/dev/null
        wait "$sender" 2>/dev/null
        return
    fi
    printf '\n' >&9
    wait "$sender"
    sender_exit=$?
    exec 9>&-

    assert_exit_code 1 "$sender_exit" "a write that could not be made"

    # ⚠ Nothing was handed over, and the failures are counted somewhere else.
    # ⚠ If one counter served both, this line would say "handed over 2 frames".
    assert_file_contains "$work/out.txt" \
        "handed over 0 frames, 0 octets, 2 could not be handed over, 0 short, 0 with the wrong step" \
        "a write that could not be made"

    # ⚠ Recorded, never asserted: which errno the kernel chose
    # (`.claude/rules/testing.md`).
    printf '    the writes came back with: errno %s\n' \
        "$(sed -n 's/^could not hand it over: errno //p' "$work/out.txt" | head -1)"
}

# ---- outer: each case gets its own namespace -----------------------------

in_namespace() {
    if ! unshare -Urn "$0" --inside "$1"; then
        current_case_ok=0
    fi
}

case_the_interface_exists_only_while_it_is_attached() {
    in_namespace the_interface_exists_only_while_it_is_attached
}
case_count_zero_reads_nothing() { in_namespace count_zero_reads_nothing; }
case_a_timer_running_out_has_its_own_exit_code() {
    in_namespace a_timer_running_out_has_its_own_exit_code
}
case_a_stop_request_reaches_a_reader_that_is_waiting() {
    in_namespace a_stop_request_reaches_a_reader_that_is_waiting
}
case_a_second_attach_to_the_same_device_is_refused() {
    in_namespace a_second_attach_to_the_same_device_is_refused
}
case_the_wait_says_the_device_stopped_being_usable() {
    in_namespace the_wait_says_the_device_stopped_being_usable
}
case_a_frame_handed_over_reaches_the_kernel() {
    in_namespace a_frame_handed_over_reaches_the_kernel
}
case_a_write_that_could_not_be_made_is_not_a_frame_sent() {
    in_namespace a_write_that_could_not_be_made_is_not_a_frame_sent
}
case_each_kind_of_frame_moves_its_own_counter() {
    in_namespace each_kind_of_frame_moves_its_own_counter
}
case_a_timer_of_ours_ends_the_wait_without_ending_the_program() {
    in_namespace a_timer_of_ours_ends_the_wait_without_ending_the_program
}
case_only_a_frame_puts_off_giving_up_on_reading() {
    in_namespace only_a_frame_puts_off_giving_up_on_reading
}
case_the_answer_really_goes_out_again() {
    in_namespace the_answer_really_goes_out_again
}

# ⚠ A frame of each kind moves the counter that belongs to it, and no other.
#
# ⚠ What was held before this and what was not (hidetzu/tcpip-stack#52):
#
#   ethernet_parse_header gives the right answer      ⚠ yes, tests/static.sh
#   report_ethernet_summary prints what it is handed  ⚠ yes, tests/static.sh
#   ⚠ an arriving frame moves the right counter        ⚠ **nothing**
#
# ⚠ So the two ends were held and the wire between them was not: ⚠ **swapping two
# lines of that switch broke no check.** ⚠ `.claude/rules/c.md` — an uncounted
# drop is invisible — and ⚠ **a count under the wrong name is worse, because it
# looks like a measurement.**
#
# ⚠ The frames are put on the wire with AF_PACKET, ⚠ **because two processes
# cannot hold one TAP device** (`a_second_attach_to_the_same_device_is_refused`
# asserts that, and hidetzu/tcpip-stack#44 hit it). ⚠ AF_PACKET needs only what
# `unshare -Urn` already gives, the same standing ADR 0001 gave CAP_NET_ADMIN,
# and ⚠ **it needs no address and no route** — the device merely has to be up.
#
# ⚠ Why `real` and not `foreign`: ⚠ **the other end is not the kernel's stack.**
# The frames are ours and the kernel only carries them (`verify` §1).
#
# ⚠ **One of the three cannot be reached at all, and that is measured, not
# assumed**: see `docs/SPEC.md` §2. ⚠ A frame shorter than an ethernet header is
# refused by AF_PACKET with EINVAL, ⚠ **and by the tun fd too**
# (hidetzu/tcpip-stack#17, recorded in src/tap.h). ⚠ So `malformed` stays 0 here
# and this case asserts that it does — ⚠ **not that it can be made to move.**
inside_each_kind_of_frame_moves_its_own_counter() {
    # ⚠ No --count: the kernel puts IPv6 frames on a device it has just brought
    # up, and ⚠ a count would stop the reader before our own frames arrived.
    # ⚠ Those frames carry a Type, so they move none of the three counters —
    # which is what the third frame below asserts on purpose.
    "$TCPIP_STACK" --dev tap0 --timeout 2000 >"$work/out.txt" 2>"$work/err.txt" &
    reader=$!

    i=0
    while [ "$i" -lt 60 ] && ! ip link show tap0 >/dev/null 2>&1; do
        sleep 0.05
        i=$((i + 1))
    done
    if ! ip link show tap0 >/dev/null 2>&1; then
        note_failure "tap0 never appeared while tcpip-stack was attached"
        kill "$reader" 2>/dev/null
        wait "$reader" 2>/dev/null
        return
    fi
    # ⚠ Up, and nothing else. No address, no route: the kernel is only the wire.
    ip link set tap0 up

    # ⚠ The three length/type values, taken from the constants src/ uses so this
    # file cannot drift from the parser (`CLAUDE.md` §3): one at the top of the
    # Length range, one just above it in the gap the standard does not define,
    # and one that is plainly a Type.
    # ⚠ The trailing `u` the header writes on these is stripped: it is C's, not
    # part of the number.
    length_max=$(awk '$1 == "#define" && $2 == "ETHERNET_LENGTH_MAX" { sub(/[uU]$/, "", $3); print $3 }' \
        src/ethernet.h)
    type_min=$(awk '$1 == "#define" && $2 == "ETHERNET_TYPE_MIN" { sub(/[uU]$/, "", $3); print $3 }' \
        src/ethernet.h)
    if [ -z "$length_max" ] || [ -z "$type_min" ]; then
        note_failure "the length/type boundaries could not be read out of src/ethernet.h"
        kill "$reader" 2>/dev/null
        wait "$reader" 2>/dev/null
        return
    fi

    LC_ALL=C ETHERNET_LENGTH_MAX="$length_max" ETHERNET_TYPE_MIN="$type_min" \
        python3 -c '
import os, socket, sys

a_length = int(os.environ["ETHERNET_LENGTH_MAX"], 0)          # at the top of Length
undefined = a_length + 1                                       # in the gap
a_type = int(os.environ["ETHERNET_TYPE_MIN"], 0)               # plainly a Type

wire = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
wire.bind(("tap0", 0))
destination = b"\x02\x00\x00\x00\x00\x02"
source = b"\x02\x11\x11\x11\x11\x11"
# ⚠ Different numbers of each, and that is not decoration: ⚠ **with one of each
# the two counters are symmetric and swapping them changes nothing.** ⚠ Measured
# — the first version of this case sent one of each and ⚠ **passed with the two
# counters exchanged**, which is the very defect it exists to catch.
for value, how_many in ((a_length, 1), (undefined, 2), (a_type, 1)):
    for _ in range(how_many):
        frame = destination + source + value.to_bytes(2, "big") + bytes(46)
        if wire.send(frame) != len(frame):
            print("a frame was not handed over whole", file=sys.stderr)
            sys.exit(1)

# ⚠ The one that cannot be sent, asserted as unsendable rather than skipped.
try:
    wire.send(destination + source + b"\x01")
    print("a frame shorter than an ethernet header was accepted", file=sys.stderr)
    sys.exit(1)
except OSError:
    pass
' >"$work/sent.txt" 2>&1
    sent_exit=$?

    wait "$reader"
    reader_exit=$?

    if [ "$sent_exit" -ne 0 ]; then
        note_failure "the frames could not be put on the wire"
        sed 's/^/      /' "$work/sent.txt" >&2
        return
    fi
    if [ "$reader_exit" -ne 0 ] && [ "$reader_exit" -ne 2 ]; then
        note_failure "tcpip-stack stopped with exit code $reader_exit"
        sed 's/^/      /' "$work/err.txt" >&2
        return
    fi

    # ⚠ Read out of what the program printed, never out of a structure of ours.
    #
    # ⚠ One Length and TWO undefined, so ⚠ **the two counters cannot be swapped
    # without the numbers saying so.** ⚠ Zero malformed, because a frame shorter
    # than an ethernet header cannot be sent at all. ⚠ And the Type frame — plus
    # whatever IPv6 the kernel sent — moves none of the three.
    assert_file_contains "$work/out.txt" \
        "0 frames were malformed, 1 carried an IEEE 802.3 Length, 2 carried a length/type the standard does not define" \
        "each kind of frame moves its own counter"

    # ⚠ The other half: frames really did arrive. ⚠ Without this the line above
    # would pass for a run where nothing was read and every count stayed 0 —
    # except the two that are not 0, which is why the numbers differ.
    if ! grep -qE "^read [1-9][0-9]* frames?, 0 read errors" "$work/out.txt"; then
        note_failure "no frames were read, so the counts above say nothing"
        sed 's/^/      /' "$work/out.txt" >&2
    fi
}

# ⚠ The milestone's proof: ⚠ **the answer really goes out again on the wire**,
# counted by something that is not our own output.
#
# ⚠ Our own summary says we answered again. ⚠ **That is our word for it**, and
# `.claude/rules/layers.md` question 3 is why that is not enough: a stack that
# only agrees with its own tests has proved nothing.
#
# ⚠ So the frames are counted with an AF_PACKET socket on tap0, which ⚠ **neither
# holds the tun fd nor asks any parser of ours what it is looking at** (ADR 0009).
# ⚠ It must be opened with ETH_P_ALL: ⚠ **a packet socket opened with protocol 0
# receives nothing**, measured 2026-08-29 — the first attempt at this saw no
# frames at all and that was the instrument, not the system.
#
# ⚠ It waits about four seconds of real time. ⚠ `docs/SPEC.md` §3 carries what
# this tier costs.
inside_the_answer_really_goes_out_again() {
    ours=10.0.0.2
    our_mac=02:00:00:00:00:02

    "$TCPIP_STACK" --dev tap0 --mac "$our_mac" --ipv4 "$ours" --tcp-port 80 \
        --timeout 4000 >"$work/out.txt" 2>"$work/err.txt" &
    reader=$!

    i=0
    while [ "$i" -lt 60 ] && ! ip link show tap0 >/dev/null 2>&1; do
        sleep 0.05
        i=$((i + 1))
    done
    if ! ip link show tap0 >/dev/null 2>&1; then
        note_failure "tap0 never appeared while tcpip-stack was attached"
        kill "$reader" 2>/dev/null
        wait "$reader" 2>/dev/null
        return
    fi
    sysctl -qw net.ipv6.conf.tap0.disable_ipv6=1
    ip addr add 10.0.0.1/24 dev tap0
    ip link set tap0 up

    LC_ALL=C python3 -c '
import socket, struct, sys, time

def sum_of(octets):
    total = 0
    for i in range(0, len(octets) - 1, 2):
        total += (octets[i] << 8) | octets[i + 1]
    if len(octets) % 2:
        total += octets[-1] << 8
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff

OURS = b"\x02\x00\x00\x00\x00\x02"

# ⚠ ETH_P_ALL, or it receives nothing at all.
wire = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
wire.bind(("tap0", 0))
wire.settimeout(0.3)

# ⚠ A source hardware address and address nobody owns, so nothing answers our
# answer and the kernel sends nothing back — not even a RST.
source = socket.inet_aton("10.0.0.99")
destination = socket.inet_aton("10.0.0.2")
segment = struct.pack("!HHIIBBHHH", 40000, 80, 5000, 0, 5 << 4, 0x02, 64240, 0, 0)
checksum = sum_of(source + destination + bytes([0, 6, 0, len(segment)]) + segment)
segment = segment[:16] + struct.pack("!H", checksum) + segment[18:]
header = struct.pack("!BBHHHBBH", 0x45, 0, 20 + len(segment), 1, 0, 64, 6, 0) \
    + source + destination
header = header[:10] + struct.pack("!H", sum_of(header)) + header[12:]
wire.send(OURS + b"\x02\xaa\xaa\xaa\xaa\xaa" + b"\x08\x00" + header + segment)

# ⚠ Watched for a second beyond the schedule, so ⚠ **a third answer would be
# seen if there were one.**
answers = []
end = time.time() + 4.0
while time.time() < end:
    try:
        frame = wire.recv(2048)
    except socket.timeout:
        continue
    except OSError:
        break
    if len(frame) < 34 or frame[12:14] != b"\x08\x00" or frame[14 + 9] != 6:
        continue
    if frame[6:12] != OURS:
        continue
    length = (frame[14] & 0x0f) * 4
    tcp = frame[14 + length:]
    if tcp[13] != (0x02 | 0x10):
        continue
    answers.append((int.from_bytes(tcp[4:8], "big"), int.from_bytes(tcp[8:12], "big"),
                    frame[0:6]))

print("answers on the wire: %d" % len(answers))
if len(set(answers)) not in (0, 1):
    print("they were not all the same answer: %r" % (set(answers),), file=sys.stderr)
    sys.exit(1)
' >"$work/watched.txt" 2>&1
    watch_exit=$?

    wait "$reader"
    reader_exit=$?

    if [ "$watch_exit" -ne 0 ]; then
        note_failure "the wire could not be watched, or the answers differed"
        sed 's/^/      /' "$work/watched.txt" >&2
        return
    fi
    if [ "$reader_exit" -ne 2 ]; then
        note_failure "tcpip-stack stopped with exit code $reader_exit, not the timer running out"
        sed 's/^/      /' "$work/err.txt" >&2
        return
    fi

    # ⚠ Three: the first answer and two more. ⚠ Counted on the wire, not in our
    # own output. ⚠ And no fourth, because the watch outlasted the schedule.
    assert_file_contains "$work/watched.txt" "answers on the wire: 3" \
        "the answer really goes out again, twice"

    # ⚠ Our own count agrees. ⚠ It says less than the line above — it is our word
    # — and it is here so "we answered again" can never be mistaken for "nothing
    # happened" (`.claude/rules/c.md`).
    assert_file_contains "$work/out.txt" \
        "2 answers went out again because nobody had confirmed them" \
        "answering again is counted once the wire took it"
    assert_file_contains "$work/out.txt" \
        "1 connection was given up on after nobody confirmed it" \
        "and then it was given up on"
}

# ⚠ Only a frame moves the deadline for giving up reading — ⚠ **not a timer of
# ours** (hidetzu/tcpip-stack#58 Owner Decision 1).
#
# ⚠ Asserted by counting frames rather than by measuring time: ⚠ **a time-based
# assertion is the least reproducible thing there is** (`CLAUDE.md` §6).
#
# ⚠ Four frames are sent 200 ms apart with a 300 ms limit. ⚠ **Each gap is under
# the limit and the whole run is well over it**, which is what tells the two
# apart:
#
#   ⚠ with the deadline moving on each frame   all four are read
#   ⚠ without it                               only the first, then it stops
#
# ⚠ This was unasserted before hidetzu/tcpip-stack#58. ⚠ **The first version of
# this case sent two frames 400 ms apart with a 600 ms limit and the mutation
# still passed** — both arrived inside the first deadline, so ⚠ **it could not
# tell whether the deadline had moved at all.**
inside_only_a_frame_puts_off_giving_up_on_reading() {
    "$TCPIP_STACK" --dev tap0 --timeout 300 >"$work/out.txt" 2>"$work/err.txt" &
    reader=$!

    i=0
    while [ "$i" -lt 60 ] && ! ip link show tap0 >/dev/null 2>&1; do
        sleep 0.05
        i=$((i + 1))
    done
    if ! ip link show tap0 >/dev/null 2>&1; then
        note_failure "tap0 never appeared while tcpip-stack was attached"
        kill "$reader" 2>/dev/null
        wait "$reader" 2>/dev/null
        return
    fi
    # ⚠ IPv6 is turned off on the device before it comes up, so ⚠ **the only
    # frames read are the two below.** ⚠ Measured 2026-08-28, 3 runs of 3: a bare
    # link that is merely up gives 6 frames of the kernel's own, and none with
    # this. ⚠ Without it the count would be the kernel's business rather than
    # this case's.
    #
    # ⚠ AF_PACKET needs the device up, so ⚠ **leaving it down is not an option** —
    # the send fails with "Network is down". Measured the same day.
    sysctl -qw net.ipv6.conf.tap0.disable_ipv6=1
    ip link set tap0 up

    LC_ALL=C python3 -c '
import socket, time
wire = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
wire.bind(("tap0", 0))
frame = b"\x02\x00\x00\x00\x00\x02" + b"\x02\x11\x11\x11\x11\x11" + b"\x90\x00" \
    + bytes(46)
# ⚠ The device goes away with the program, so a send after it stopped fails.
# ⚠ Stopping quietly here means the case fails on the count below — ⚠ **which is
# what it is named for** — rather than on the sender falling over (`verify` §5:
# read whether it failed for the reason you intended).
for _ in range(4):
    try:
        wire.send(frame)
    except OSError:
        break
    time.sleep(0.2)
' >"$work/sent.txt" 2>&1
    sent_exit=$?

    wait "$reader"
    reader_exit=$?

    if [ "$sent_exit" -ne 0 ]; then
        note_failure "the frames could not be put on the wire"
        sed 's/^/      /' "$work/sent.txt" >&2
        return
    fi
    if [ "$reader_exit" -ne 2 ]; then
        note_failure "tcpip-stack stopped with exit code $reader_exit, not the timer running out"
        sed 's/^/      /' "$work/err.txt" >&2
        return
    fi

    # ⚠ All four, which can only happen if each one put off the deadline: the
    # last arrives 600 ms after the first and the limit is 300 ms.
    assert_file_contains "$work/out.txt" "read 4 frames, 0 read errors" \
        "a frame puts off giving up on reading"
}

# ⚠ A wait that runs out is not one thing any more: ⚠ **a timer of ours, or
# nothing having arrived.** ⚠ This is the case that says they are told apart on a
# real device (hidetzu/tcpip-stack#58).
#
# ⚠ How a connection is left unconfirmed: a SYN is put on the wire with
# AF_PACKET ⚠ **from a source hardware address nobody owns**, so our answer goes
# to a machine that is not there and ⚠ **the kernel sends nothing back, not even
# a RST** (measured 2026-08-28, and it is why hidetzu/tcpip-stack#59 is possible
# at all).
#
# ⚠ What is asserted is the loop waking on our own timer and carrying on —
# ⚠ **not that anything went out on the wire.** ⚠ Nothing is sent until #59, and
# `src/handshake.h` says an answer that became due is a spent attempt.
#
# ⚠ It waits about three and a half seconds of real time. ⚠ **That is most of
# what this tier costs**, and `docs/SPEC.md` §3 carries the number.
inside_a_timer_of_ours_ends_the_wait_without_ending_the_program() {
    ours=10.0.0.2
    our_mac=02:00:00:00:00:02

    # ⚠ Longer than the three seconds the schedule takes, so the connection is
    # given up on before the program stops reading (ADR 0019).
    "$TCPIP_STACK" --dev tap0 --mac "$our_mac" --ipv4 "$ours" --tcp-port 80 \
        --timeout 3500 >"$work/out.txt" 2>"$work/err.txt" &
    reader=$!

    i=0
    while [ "$i" -lt 60 ] && ! ip link show tap0 >/dev/null 2>&1; do
        sleep 0.05
        i=$((i + 1))
    done
    if ! ip link show tap0 >/dev/null 2>&1; then
        note_failure "tap0 never appeared while tcpip-stack was attached"
        kill "$reader" 2>/dev/null
        wait "$reader" 2>/dev/null
        return
    fi
    ip addr add 10.0.0.1/24 dev tap0
    ip link set tap0 up

    LC_ALL=C python3 -c '
import socket, struct

def sum_of(octets):
    total = 0
    for i in range(0, len(octets) - 1, 2):
        total += (octets[i] << 8) | octets[i + 1]
    if len(octets) % 2:
        total += octets[-1] << 8
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff

# ⚠ An address and a hardware address nobody owns, so nothing answers our answer.
source = socket.inet_aton("10.0.0.99")
destination = socket.inet_aton("10.0.0.2")
segment = struct.pack("!HHIIBBHHH", 40000, 80, 5000, 0, 5 << 4, 0x02, 64240, 0, 0)
checksum = sum_of(source + destination + bytes([0, 6, 0, len(segment)]) + segment)
segment = segment[:16] + struct.pack("!H", checksum) + segment[18:]

header = struct.pack("!BBHHHBBH", 0x45, 0, 20 + len(segment), 1, 0, 64, 6, 0) \
    + source + destination
header = header[:10] + struct.pack("!H", sum_of(header)) + header[12:]

wire = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
wire.bind(("tap0", 0))
wire.send(b"\x02\x00\x00\x00\x00\x02" + b"\x02\xaa\xaa\xaa\xaa\xaa" + b"\x08\x00"
          + header + segment)
' >"$work/sent.txt" 2>&1
    sent_exit=$?

    wait "$reader"
    reader_exit=$?

    if [ "$sent_exit" -ne 0 ]; then
        note_failure "the SYN could not be put on the wire"
        sed 's/^/      /' "$work/sent.txt" >&2
        return
    fi
    # ⚠ 2 is the timer running out, which is how this run is meant to end.
    if [ "$reader_exit" -ne 2 ]; then
        note_failure "tcpip-stack stopped with exit code $reader_exit, not the timer running out"
        sed 's/^/      /' "$work/err.txt" >&2
        return
    fi

    # ⚠ The connection opened, ⚠ the wait ended on our timer twice without the
    # program stopping, and ⚠ it was given up on — all three, in order.
    assert_file_contains "$work/out.txt" "asked to open a connection" \
        "the crafted SYN opened a connection"
    went_again=$(grep -c 'has not confirmed it; the answer went out again' "$work/out.txt")
    if [ "$went_again" -ne 2 ]; then
        note_failure "the answer went out again $went_again times, and the schedule says twice"
        sed 's/^/      /' "$work/out.txt" >&2
        return
    fi
    assert_file_contains "$work/out.txt" \
        "never confirmed it; the connection was given up on" \
        "the connection was given up on"
    assert_file_contains "$work/out.txt" \
        "1 connection was given up on after nobody confirmed it" \
        "giving up is counted"

    # ⚠ And the other reason still works: the program DID stop, on its own
    # timeout, ⚠ **after the timers were done** — so the two are not one thing.
    assert_file_contains "$work/err.txt" "listened on tap0 for 3500 ms" \
        "the program still stops when nothing arrives"
}

ALL_CASES="the_interface_exists_only_while_it_is_attached count_zero_reads_nothing a_timer_running_out_has_its_own_exit_code a_stop_request_reaches_a_reader_that_is_waiting a_second_attach_to_the_same_device_is_refused the_wait_says_the_device_stopped_being_usable a_frame_handed_over_reaches_the_kernel a_write_that_could_not_be_made_is_not_a_frame_sent each_kind_of_frame_moves_its_own_counter a_timer_of_ours_ends_the_wait_without_ending_the_program only_a_frame_puts_off_giving_up_on_reading the_answer_really_goes_out_again"

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
select_cases isolated "$ALL_CASES" "$@"

$MAKE -s build build-harness || exit 2

# ⚠ If the namespace cannot be built, zero cases ran. That is NOT-VERIFIED, and
# it is not a statement about this change (`verify` §4).
if ! unshare -Urn true 2>/dev/null; then
    printf 'isolated: the check environment could not be built here: unshare -Urn was refused.\n' >&2
    printf 'isolated: 0 cases ran. Nothing was checked, and nothing was disproved either.\n' >&2
    exit 2
fi

run_selected_cases
