#!/bin/sh
# static — what can be known without a TAP device, a namespace, a clock or any
# elevated capability.
#
# ⚠ A clean build says nothing about what goes on the wire (`CLAUDE.md` §2).

set -u
cd "$(dirname -- "$0")/.." || exit 2
. tests/lib.sh

MAKE=${MAKE:-make}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

case_build_warnings_are_errors() {
    if ! $MAKE -s build >"$work/build.txt" 2>&1; then
        note_failure "the build did not succeed"
        sed 's/^/      /' "$work/build.txt" >&2
    fi
}

case_build_with_sanitizers() {
    if ! $MAKE -s build-sanitized >"$work/build-san.txt" 2>&1; then
        note_failure "the sanitized build did not succeed"
        sed 's/^/      /' "$work/build-san.txt" >&2
    fi
}

# The Report layer, against the captured frame. This binary announces its own
# case count — ⚠ never copy that number into a document (`docs/SPEC.md`).
case_report_lines() {
    $MAKE -s build-sanitized >/dev/null 2>&1 || {
        note_failure "the sanitized build did not succeed"
        return
    }
    if ! ./build/test_report.sanitized --fixtures tests/fixtures >"$work/report.txt" 2>&1; then
        note_failure "the Report layer produced something other than the approved wording"
        sed 's/^/      /' "$work/report.txt" >&2
        return
    fi
    sed 's/^/    /' "$work/report.txt"
}

# ⚠ Refusing the name happens before /dev/net/tun is touched, so this needs no
# device and no capability.
case_a_device_name_that_is_too_long_is_refused() {
    $MAKE -s build >/dev/null 2>&1 || { note_failure "the build did not succeed"; return; }
    ./build/tap-read --dev a-name-that-is-far-too-long --count 1 \
        >"$work/out.txt" 2>"$work/err.txt"
    assert_exit_code 3 $? "a device name that cannot exist"
    assert_file_is "$work/err.txt" \
        'could not attach to "a-name-that-is-far-too-long": a device name is 1 to 15 characters.' \
        "a device name that cannot exist"
}

select_cases static "build_warnings_are_errors build_with_sanitizers report_lines a_device_name_that_is_too_long_is_refused" "$@"
run_selected_cases
