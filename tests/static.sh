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

# The Parse layer, against the captured frame and against frames built for the
# boundaries of the length/type field. This binary announces its own case count
# — ⚠ never copy that number into a document (`docs/SPEC.md`).
case_ethernet_header() {
    $MAKE -s build-sanitized >/dev/null 2>&1 || {
        note_failure "the sanitized build did not succeed"
        return
    }
    if ! ./build/test_ethernet.sanitized --fixtures tests/fixtures >"$work/ethernet.txt" 2>&1; then
        note_failure "the Parse layer did not read the header the way it must"
        sed 's/^/      /' "$work/ethernet.txt" >&2
        return
    fi
    sed 's/^/    /' "$work/ethernet.txt"
}

# The State layer: what an arriving ARP packet means for us. This binary
# announces its own case count — ⚠ never copy that number into a document.
case_arp_responder() {
    $MAKE -s build-sanitized >/dev/null 2>&1 || {
        note_failure "the sanitized build did not succeed"
        return
    }
    if ! ./build/test_arp_responder.sanitized >"$work/responder.txt" 2>&1; then
        note_failure "the four reasons did not stay four things"
        sed 's/^/      /' "$work/responder.txt" >&2
        return
    fi
    sed 's/^/    /' "$work/responder.txt"
}

# The ARP Parse layer, against the captured frame and against packets built for
# the boundaries. This binary announces its own case count — ⚠ never copy that
# number into a document (`docs/SPEC.md`).
case_arp_packet() {
    $MAKE -s build-sanitized >/dev/null 2>&1 || {
        note_failure "the sanitized build did not succeed"
        return
    }
    if ! ./build/test_arp.sanitized --fixtures tests/fixtures >"$work/arp.txt" 2>&1; then
        note_failure "the ARP Parse layer did not read the packet the way it must"
        sed 's/^/      /' "$work/arp.txt" >&2
        return
    fi
    sed 's/^/    /' "$work/arp.txt"
}

# ⚠ Refusing the name happens before /dev/net/tun is touched, so this needs no
# device and no capability.
case_a_device_name_that_is_too_long_is_refused() {
    $MAKE -s build >/dev/null 2>&1 || { note_failure "the build did not succeed"; return; }
    ./build/tcpip-stack --dev a-name-that-is-far-too-long --count 1 \
        >"$work/out.txt" 2>"$work/err.txt"
    assert_exit_code 3 $? "a device name that cannot exist"
    assert_file_is "$work/err.txt" \
        'could not attach to "a-name-that-is-far-too-long": a device name is 1 to 15 characters.' \
        "a device name that cannot exist"
}

# ⚠ The one check that says the rename is finished. Without it nothing does:
# report_usage is asserted by no case at all, and the only output this tier
# compares byte for byte holds no program name (hidetzu/tcpip-stack#24).
#
# ⚠ The pattern is built by concatenation so this file does not contain the
# literal it is hunting for. ⚠ Excluding this file instead would leave it the one
# place the check cannot see, and `CLAUDE.md` §5 is about exactly this: otherwise
# the check picks up the very words written to describe it.
#
# ⚠ docs/adr/ is excluded on purpose. An ADR records what a thing was called on
# the day it was decided, and `CLAUDE.md` §4 forbids sweeping it.
case_the_old_program_name_is_gone() {
    old_hyphen="tap""-read"
    old_underscore="tap""_read"
    surviving="${old_underscore}_frame"

    if grep -rn --exclude-dir=.git --exclude-dir=build --exclude-dir=adr \
        -e "$old_hyphen" . >"$work/left.txt" 2>/dev/null; then
        note_failure "the old program name is still in the tree"
        sed 's/^/      /' "$work/left.txt" >&2
        return
    fi

    # ⚠ tap_read_frame() is not the program's name — it reads a frame from the
    # tap — so it is the one spelling that stays.
    grep -rn --exclude-dir=.git --exclude-dir=build --exclude-dir=adr \
        -e "$old_underscore" . 2>/dev/null | grep -v -- "$surviving" \
        >"$work/left2.txt" || true
    if [ -s "$work/left2.txt" ]; then
        note_failure "the old name is still in the tree as an identifier"
        sed 's/^/      /' "$work/left2.txt" >&2
        return
    fi

    # ⚠ The other half. A check that only says "the old name is gone" stays green
    # when the rename swept away something it should not have (`verify` §5).
    if ! grep -rq --exclude-dir=build -- "$surviving" src/; then
        note_failure "the function that reads a frame from the tap is gone too, which is a rename that went too far"
    fi
}

# ⚠ What this catches and what it does not.
#
# It catches: a "What asserts it" column that names an entry point and no case,
# one that names nothing at all, a case name that does not exist, and a case
# named with no entry point in front of it to attribute it to.
#
# ⚠ It cannot catch a case that exists and does not cover the clause it is named
# against — ⚠ and that is exactly what happened (`CLAUDE.md` §9). Reading the
# case is still the reviewer's job.
spec_row_now=""
spec_row_layer=""
spec_row_entry_points=0
spec_row_cases=0

# ⚠ The "names a file but no case" rule can only be judged once the whole row has
# been read, so it is checked when the row ends.
finish_spec_row() {
    [ -n "$spec_row_now" ] || return 0
    if [ "$spec_row_entry_points" -gt 0 ] && [ "$spec_row_cases" -eq 0 ]; then
        note_failure "docs/SPEC.md §1 row $spec_row_now ($spec_row_layer) names an entry point and no case. A file says where to look; it does not say anything in there asserts this claim"
    fi
}

case_spec_names_checks_that_exist() {
    tab=$(printf '\t')

    # ⚠ §1 only. §2 is what is deliberately absent and names no checks.
    # ⚠ One line per token, carrying the row it came from: without that, a case
    # name gets attributed to an entry point named on some earlier row.
    sed -n '/^## 1\. What this implements/,/^## 2\./p' docs/SPEC.md |
        awk -F'|' -v OFS="$tab" '
            /^\|/ {
                if ($0 ~ /^\|[-| ]+\|$/) next
                claimed_by = $(NF - 1)
                if (claimed_by ~ /What asserts it/) next
                row++
                layer = $2
                gsub(/^ +| +$/, "", layer)
                pieces = split(claimed_by, part, "`")
                named = 0
                for (i = 2; i <= pieces; i += 2) {
                    kind = (part[i] ~ /^tests\/.*\.sh$/) ? "entry-point" : "case"
                    print row, layer, kind, part[i]
                    named++
                }
                # ⚠ A row that names nothing has to reach the shell too, or an
                # empty column is indistinguishable from no row at all.
                if (named == 0) print row, layer, "nothing", ""
            }
        ' >"$work/claimed.txt"

    spec_row_now=""
    rows_seen=0
    entry_points_seen=0
    cases_seen=0
    named_entry_point=""

    while IFS="$tab" read -r row layer kind value; do
        if [ "$row" != "$spec_row_now" ]; then
            finish_spec_row
            spec_row_now=$row
            spec_row_layer=$layer
            spec_row_entry_points=0
            spec_row_cases=0
            named_entry_point=""
            rows_seen=$((rows_seen + 1))
        fi

        case $kind in
        entry-point)
            named_entry_point=$value
            spec_row_entry_points=$((spec_row_entry_points + 1))
            entry_points_seen=$((entry_points_seen + 1))
            if [ ! -x "$named_entry_point" ]; then
                note_failure "docs/SPEC.md §1 names $named_entry_point, which is not an entry point here"
            fi
            ;;
        case)
            spec_row_cases=$((spec_row_cases + 1))
            cases_seen=$((cases_seen + 1))
            if [ -z "$named_entry_point" ]; then
                note_failure "docs/SPEC.md §1 row $row ($layer) names case $value with no entry point in front of it"
                continue
            fi
            if ! "$named_entry_point" --list | grep -qx -- "$value"; then
                note_failure "docs/SPEC.md says $named_entry_point asserts $value, and that case does not exist"
            fi
            ;;
        nothing)
            note_failure "docs/SPEC.md §1 row $row ($layer) names nothing in \"What asserts it\""
            ;;
        esac
    done <"$work/claimed.txt"
    finish_spec_row

    # ⚠ The other half. Without this the case stays green if the table is empty,
    # if the section headings are renamed, or if the parsing quietly matches
    # nothing (`verify` §5).
    if [ "$rows_seen" -eq 0 ] || [ "$entry_points_seen" -eq 0 ] || [ "$cases_seen" -eq 0 ]; then
        note_failure "read $rows_seen rows, $entry_points_seen entry points and $cases_seen case names out of docs/SPEC.md §1, which cannot be right"
        return
    fi
    printf '    checked %d rows, %d entry points and %d case names named by docs/SPEC.md §1\n' \
        "$rows_seen" "$entry_points_seen" "$cases_seen"
}

select_cases static "build_warnings_are_errors build_with_sanitizers report_lines ethernet_header arp_packet arp_responder a_device_name_that_is_too_long_is_refused the_old_program_name_is_gone spec_names_checks_that_exist" "$@"
run_selected_cases
