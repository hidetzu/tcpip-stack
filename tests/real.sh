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

ALL_CASES="the_interface_exists_only_while_it_is_attached count_zero_reads_nothing a_timer_running_out_has_its_own_exit_code a_stop_request_reaches_a_reader_that_is_waiting a_second_attach_to_the_same_device_is_refused the_wait_says_the_device_stopped_being_usable a_frame_handed_over_reaches_the_kernel a_write_that_could_not_be_made_is_not_a_frame_sent"

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
select_cases real "$ALL_CASES" "$@"

$MAKE -s build build-harness || exit 2

# ⚠ If the namespace cannot be built, zero cases ran. That is NOT-VERIFIED, and
# it is not a statement about this change (`verify` §4).
if ! unshare -Urn true 2>/dev/null; then
    printf 'real: the check environment could not be built here: unshare -Urn was refused.\n' >&2
    printf 'real: 0 cases ran. Nothing was checked, and nothing was disproved either.\n' >&2
    exit 2
fi

run_selected_cases
