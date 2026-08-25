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

# ⚠ What this catches and what it does not. It catches "What asserts it" naming
# a case that does not exist. ⚠ It cannot catch a case that exists but does not
# cover the clause it is named against — ⚠ and that is exactly what happened
# (`CLAUDE.md` §9). Reading the case is still the reviewer's job.
case_spec_names_checks_that_exist() {
    # ⚠ §1 only. §2 is what is deliberately absent and names no checks.
    sed -n '/^## 1\. What this implements/,/^## 2\./p' docs/SPEC.md |
        awk -F'|' '
            /^\|/ {
                claimed_by = $(NF - 1)
                if (claimed_by ~ /What asserts it/) next
                if (claimed_by ~ /^[- ]*$/) next
                pieces = split(claimed_by, part, "`")
                # Backticked tokens are the even-numbered pieces.
                for (i = 2; i <= pieces; i += 2) print part[i]
            }
        ' >"$work/claimed.txt"

    named_script=""
    scripts_seen=0
    cases_seen=0
    while read -r token; do
        case "$token" in
        tests/*.sh)
            named_script=$token
            scripts_seen=$((scripts_seen + 1))
            if [ ! -x "$named_script" ]; then
                note_failure "docs/SPEC.md names $named_script, which is not an entry point here"
            fi
            ;;
        *)
            [ -n "$named_script" ] || continue
            cases_seen=$((cases_seen + 1))
            if ! "$named_script" --list | grep -qx -- "$token"; then
                note_failure "docs/SPEC.md says $named_script asserts $token, and that case does not exist"
            fi
            ;;
        esac
    done <"$work/claimed.txt"

    # ⚠ The other half. Without this the case stays green if the table is empty,
    # if the section headings are renamed, or if the parsing quietly matches
    # nothing (`verify` §5).
    if [ "$scripts_seen" -eq 0 ] || [ "$cases_seen" -eq 0 ]; then
        note_failure "read $scripts_seen entry points and $cases_seen case names out of docs/SPEC.md §1, which cannot be right"
        return
    fi
    printf '    checked %d entry points and %d case names named by docs/SPEC.md §1\n' \
        "$scripts_seen" "$cases_seen"
}

select_cases static "build_warnings_are_errors build_with_sanitizers report_lines a_device_name_that_is_too_long_is_refused spec_names_checks_that_exist" "$@"
run_selected_cases
