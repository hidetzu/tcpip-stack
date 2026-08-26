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

TAP_READ=./build/tap-read
MAKE=${MAKE:-make}

# The device appears when tap-read attaches and is gone when it lets go, so
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

# ⚠ The limit is read out of the source rather than written here a second time:
# if it changes, this check follows it instead of asserting a number nothing
# produces any more (`CLAUDE.md` §3).
read_consecutive_read_failures_allowed() {
    awk '/^#define CONSECUTIVE_READ_FAILURES_ALLOWED/ { print $3 }' src/tap_read.c
}

# ---- the cases, as they run inside the namespace -------------------------

inside_the_interface_exists_only_while_it_is_attached() {
    "$TAP_READ" --dev tap0 --count 1 --timeout 3000 >"$work/out.txt" 2>"$work/err.txt" &
    reader=$!

    if ! wait_for_interface tap0; then
        note_failure "tap0 never appeared while tap-read was attached"
        kill "$reader" 2>/dev/null
        wait "$reader" 2>/dev/null
        return
    fi
    assert_true "while tap-read holds it" ip link show tap0

    kill "$reader" 2>/dev/null
    wait "$reader" 2>/dev/null

    # ⚠ The other half. A check that only asserts the device appears stays green
    # when it never goes away (`verify` §5).
    if ! wait_for_interface_to_go tap0; then
        note_failure "tap0 was still there after tap-read let go of the fd"
    fi

    assert_file_contains "$work/out.txt" "listening on tap0" "the first line"
}

inside_count_zero_reads_nothing() {
    "$TAP_READ" --dev tap0 --count 0 >"$work/out.txt" 2>"$work/err.txt"
    assert_exit_code 0 $? "reading no frames at all"
    assert_file_is "$work/out.txt" "listening on tap0
read 0 frames, 0 read errors" "reading no frames at all"
    assert_file_is "$work/err.txt" "" "reading no frames at all"
}

inside_a_timer_running_out_has_its_own_exit_code() {
    # tap0 is created but never brought up, so nothing is put on it.
    "$TAP_READ" --dev tap0 --count 1 --timeout 300 >"$work/out.txt" 2>"$work/err.txt"
    assert_exit_code 2 $? "the timer running out"
    assert_file_is "$work/err.txt" \
        "listened on tap0 for 300 ms and read 0 frames. Nothing arrived here; that does not say whether anything was sent." \
        "the timer running out"
    assert_file_is "$work/out.txt" "listening on tap0
read 0 frames, 0 read errors" "the timer running out"
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
    "$TAP_READ" --dev tap0 >"$work/out.txt" 2>"$work/err.txt" &
    reader=$!
    if ! wait_for_interface tap0; then
        note_failure "tap0 never appeared while tap-read was attached"
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
        note_failure "tap-read was still waiting 3 s after being asked to stop"
        kill -9 "$reader" 2>/dev/null
        wait "$reader" 2>/dev/null
        return
    fi

    wait "$reader"
    assert_exit_code 0 $? "being asked to stop"
    assert_file_is "$work/out.txt" "listening on tap0
read 0 frames, 0 read errors" "being asked to stop"
}

inside_a_second_attach_to_the_same_device_is_refused() {
    "$TAP_READ" --dev tap0 --count 1 --timeout 3000 >"$work/first.txt" 2>&1 &
    reader=$!
    if ! wait_for_interface tap0; then
        note_failure "tap0 never appeared while tap-read was attached"
        kill "$reader" 2>/dev/null
        wait "$reader" 2>/dev/null
        return
    fi

    "$TAP_READ" --dev tap0 --count 1 --timeout 300 >"$work/out.txt" 2>"$work/err.txt"
    second=$?

    kill "$reader" 2>/dev/null
    wait "$reader" 2>/dev/null

    assert_exit_code 3 "$second" "attaching to a device someone else holds"
    assert_file_contains "$work/err.txt" \
        "could not attach to tap0: creating the device failed:" \
        "attaching to a device someone else holds"
}

# ⚠ A read that could not be made is neither a frame nor silence. It gets its
# own line, and it is counted apart from the frames that were read
# (`CLAUDE.md` §1: not captured ≠ not sent).
#
# ⚠ How the failure is produced without adding a seam to src/: `ip link del` on
# a tap device detaches every fd attached to it, so the wait comes back with an
# error on the fd and the next read(2) fails. ⚠ The kernel produces the failure;
# the harness only takes the device away.
#
# ⚠ Which errno comes back is the kernel's choice, so it is recorded and not
# asserted (`.claude/rules/testing.md`). What is asserted is our own reporting.
inside_a_read_that_could_not_be_made_is_its_own_outcome() {
    allowed=$(read_consecutive_read_failures_allowed)
    if [ -z "$allowed" ]; then
        note_failure "could not read CONSECUTIVE_READ_FAILURES_ALLOWED out of src/tap_read.c"
        return
    fi

    "$TAP_READ" --dev tap0 --timeout 3000 >"$work/out.txt" 2>"$work/err.txt" &
    reader=$!
    if ! wait_for_interface tap0; then
        note_failure "tap0 never appeared while tap-read was attached"
        kill "$reader" 2>/dev/null
        wait "$reader" 2>/dev/null
        return
    fi

    # ⚠ If the device could not be taken away, no read was ever made to fail and
    # nothing below is a statement about our code (`verify` §4).
    if ! ip link del tap0; then
        note_failure "tap0 could not be removed, so no read was ever made to fail"
        kill "$reader" 2>/dev/null
        wait "$reader" 2>/dev/null
        return
    fi

    wait "$reader"
    assert_exit_code 3 $? "a read that could not be made"

    failure_lines=$(grep -c '^frame [0-9][0-9]*  could not be read: ' "$work/err.txt")
    if [ "$failure_lines" -ne "$allowed" ]; then
        note_failure "expected $allowed reads that could not be made, each on its own line, and found $failure_lines"
        printf '    what was said:\n' >&2
        sed 's/^/      /' "$work/err.txt" >&2
        return
    fi

    # ⚠ The frames-read counter did not move, and the failures were counted
    # somewhere else. ⚠ If one counter served both, this line would say
    # "read $allowed frames" instead.
    #
    # ⚠ The other half — the frames-read counter moving while the read-error
    # counter stays at 0 — is `an_arp_request_the_kernel_generated_is_read_intact`
    # in tests/foreign.sh (`verify` §5).
    assert_file_is "$work/out.txt" "listening on tap0
read 0 frames, $allowed read errors" "a read that could not be made"

    # ⚠ Recorded, never asserted: what actually came back (`verify` §4).
    printf '    the reads came back with: %s\n' \
        "$(sed -n '1s/^frame [0-9][0-9]*  could not be read: //p' "$work/err.txt")"
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
case_a_read_that_could_not_be_made_is_its_own_outcome() {
    in_namespace a_read_that_could_not_be_made_is_its_own_outcome
}

ALL_CASES="the_interface_exists_only_while_it_is_attached count_zero_reads_nothing a_timer_running_out_has_its_own_exit_code a_stop_request_reaches_a_reader_that_is_waiting a_second_attach_to_the_same_device_is_refused a_read_that_could_not_be_made_is_its_own_outcome"

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

$MAKE -s build || exit 2

# ⚠ If the namespace cannot be built, zero cases ran. That is NOT-VERIFIED, and
# it is not a statement about this change (`verify` §4).
if ! unshare -Urn true 2>/dev/null; then
    printf 'real: the check environment could not be built here: unshare -Urn was refused.\n' >&2
    printf 'real: 0 cases ran. Nothing was checked, and nothing was disproved either.\n' >&2
    exit 2
fi

run_selected_cases
