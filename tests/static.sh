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

# The internet checksum, against two numbers the Linux kernel computed. This
# binary announces its own case count — ⚠ never copy that number into a document.
case_internet_checksum() {
    $MAKE -s build-sanitized >/dev/null 2>&1 || {
        note_failure "the sanitized build did not succeed"
        return
    }
    if ! ./build/test_checksum.sanitized --fixtures tests/fixtures >"$work/checksum.txt" 2>&1; then
        note_failure "our sum is not the one the kernel computed"
        sed 's/^/      /' "$work/checksum.txt" >&2
        return
    fi
    sed 's/^/    /' "$work/checksum.txt"
}

# The internet header, against the captured echo request and against headers
# built for each outcome. This binary announces its own case count — ⚠ never
# copy that number into a document (`docs/SPEC.md`).
case_ipv4_header() {
    $MAKE -s build-sanitized >/dev/null 2>&1 || {
        note_failure "the sanitized build did not succeed"
        return
    }
    if ! ./build/test_ipv4.sanitized --fixtures tests/fixtures >"$work/ipv4.txt" 2>&1; then
        note_failure "the internet header did not come back as the outcome it must"
        sed 's/^/      /' "$work/ipv4.txt" >&2
        return
    fi
    sed 's/^/    /' "$work/ipv4.txt"
}

# An ICMP echo message and the reply built from it, against two captured frames
# — the kernel's request and the kernel's own answer to it. This binary
# announces its own case count — ⚠ never copy that number into a document.
case_icmp_message() {
    $MAKE -s build-sanitized >/dev/null 2>&1 || {
        note_failure "the sanitized build did not succeed"
        return
    }
    if ! ./build/test_icmp.sanitized --fixtures tests/fixtures >"$work/icmp.txt" 2>&1; then
        note_failure "the echo message did not read, or the reply is not the kernel's"
        sed 's/^/      /' "$work/icmp.txt" >&2
        return
    fi
    sed 's/^/    /' "$work/icmp.txt"
}

# The transitions from LISTEN to ESTABLISHED. This binary announces its own case
# count — ⚠ never copy that number into a document (`docs/SPEC.md`).
case_handshake() {
    $MAKE -s build-sanitized >/dev/null 2>&1 || {
        note_failure "the sanitized build did not succeed"
        return
    }
    if ! ./build/test_handshake.sanitized >"$work/handshake.txt" 2>&1; then
        note_failure "a connection was established on the wrong acknowledgment, or the sequence window is wrong"
        sed 's/^/      /' "$work/handshake.txt" >&2
        return
    fi
    sed 's/^/    /' "$work/handshake.txt"
}

# Where connection state lives: the first thing here that lives between frames.
# This binary announces its own case count — ⚠ never copy that number into a
# document (`docs/SPEC.md`).
case_connection_state() {
    $MAKE -s build-sanitized >/dev/null 2>&1 || {
        note_failure "the sanitized build did not succeed"
        return
    }
    if ! ./build/test_connection.sanitized >"$work/connection.txt" 2>&1; then
        note_failure "a connection was told apart wrongly, or a block handed back what the last one left"
        sed 's/^/      /' "$work/connection.txt" >&2
        return
    fi
    sed 's/^/    /' "$work/connection.txt"
}

# ⚠ Every function the Report layer declares is named by a case that runs it.
#
# ⚠ Why this exists: ⚠ **`CLAUDE.md` §9 already has a row for a docs/SPEC.md
# claim naming a check that did not assert it**, and ⚠ **it happened a second
# time** — hidetzu/tcpip-stack#44 shipped four Report functions and a §1 row
# saying `report_lines` asserted them, ⚠ **while no case touched one of them**
# (#50). ⚠ Three more had been unasserted for longer than that.
#
# ⚠ What this stops: a Report function with no case at all. ⚠ Seven of twenty had
# none when it was written, and ⚠ **it would have caught every one before a §1
# row was written about them.**
#
# ⚠ What this does NOT stop, and it matters: ⚠ **a case that names a function and
# asserts the wrong sentence.** ⚠ Naming is not asserting. ⚠ **Reading the case
# is still the reviewer's job** (`docs/SPEC.md` §1 says so, and §9 says why).
#
# ⚠ Comments are stripped from the case file before it is searched. ⚠ Otherwise
# this picks up the very words written to describe it (`CLAUDE.md` §5) — every
# comment in tests/test_report.c names the function it is about.
#
# ⚠ The loop below must not use `name`: ⚠ **that is what run_selected_cases holds
# the current case's name in**, and a case that clobbers it makes the runner
# print the wrong name for itself. ⚠ Measured — the first version of this case
# did exactly that and announced itself as `report_usage`.
case_every_report_function_has_a_case() {
    # ⚠ Each of /* and */ is put alone on a line first, so that ⚠ a comment
    # opening and closing on ONE line still forms a range sed can delete.
    # ⚠ Without that step a single-line comment opens a range that only ends at
    # the NEXT comment, and everything between — real code — goes with it.
    # ⚠ Measured: that is what the first version of this case did, and it
    # reported six functions as unasserted when they were not.
    sed 's|/\*|\n/*\n|g; s|\*/|\n*/\n|g' tests/test_report.c |
        sed '/^\/\*$/,/^\*\/$/d' >"$work/report-cases.txt"

    # ⚠ Two halves of the stripping, and both are needed (`verify` §5).
    # ⚠ Removing too much would make this pass by finding nothing to check.
    if [ "$(wc -c <"$work/report-cases.txt")" -lt 2000 ]; then
        note_failure "stripping comments left almost nothing of tests/test_report.c, which cannot be right"
        return
    fi
    # ⚠ Removing too little would let a name that appears only in a comment
    # count as a case (`CLAUDE.md` §5). "Owner Decision" appears in the comments
    # of that file and nowhere in its code.
    if grep -q "Owner Decision" "$work/report-cases.txt"; then
        note_failure "stripping comments left comment text behind, so a name in a comment would pass for a case"
        return
    fi

    declared=0
    unasserted=0
    for reported in $(awk '/^void report_[a-z_]*\(/ { sub(/\(.*/, "", $2); print $2 }' \
        src/report.h); do
        declared=$((declared + 1))
        if ! grep -q "$reported(" "$work/report-cases.txt"; then
            note_failure "src/report.h declares $reported and no case in tests/test_report.c runs it"
            unasserted=$((unasserted + 1))
        fi
    done

    # ⚠ And the other half again: reading no declarations at all would make this
    # green for a header that had been emptied or renamed.
    if [ "$declared" -lt 10 ]; then
        note_failure "read $declared functions out of src/report.h, which cannot be right"
        return
    fi

    printf '    %d functions declared in src/report.h, %d with no case\n' \
        "$declared" "$unasserted"
}

# The TCP header, against the SYN the kernel sent while opening a connection.
# This binary announces its own case count — ⚠ never copy that number into a
# document (`docs/SPEC.md`).
case_tcp_header() {
    $MAKE -s build-sanitized >/dev/null 2>&1 || {
        note_failure "the sanitized build did not succeed"
        return
    }
    if ! ./build/test_tcp.sanitized --fixtures tests/fixtures >"$work/tcp.txt" 2>&1; then
        note_failure "the TCP header did not read, or the option walk is wrong"
        sed 's/^/      /' "$work/tcp.txt" >&2
        return
    fi
    sed 's/^/    /' "$work/tcp.txt"
}

# The State layer for an arriving IPv4 datagram: what it means for us. This
# binary announces its own case count — ⚠ never copy that number into a document.
case_echo_responder() {
    $MAKE -s build-sanitized >/dev/null 2>&1 || {
        note_failure "the sanitized build did not succeed"
        return
    }
    if ! ./build/test_echo_responder.sanitized --fixtures tests/fixtures >"$work/echo.txt" 2>&1; then
        note_failure "the ten reasons did not stay ten things, or the reply is not the kernel's"
        sed 's/^/      /' "$work/echo.txt" >&2
        return
    fi
    sed 's/^/    /' "$work/echo.txt"
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

# ⚠ No sentence a human reads is written outside src/report.c.
#
# ⚠ The rule, `.claude/rules/layers.md`:
#
#     ### Report (what a human reads)
#     - MUST: ⚠ **All prose is written here, and only here.**
#
# ⚠ Why a check and not a reading: ⚠ **it had grown, not shrunk.** Nine lines
# when hidetzu/tcpip-stack#35 reported it, eleven when #51 moved them
# (hidetzu/tcpip-stack#44 added two). ⚠ **A reading stops the eleventh; a check
# stops the twelfth.**
#
# ⚠ How it decides what counts: ⚠ **a string literal handed to an output
# function** — fprintf, printf, fputs, fputc, puts, perror — in any src/ file
# but report.c. ⚠ That is narrow on purpose and ⚠ **here is what it does not
# stop**, said rather than left to be discovered:
#
#   ⚠ a sentence built into a variable and printed from it
#   ⚠ a sentence written with write(2) or with a function this list does not name
#   ⚠ a sentence inside src/report.c that belongs to no layer at all
#
# ⚠ Comments are stripped first (`CLAUDE.md` §5: when a check reads code or
# comments, strip the comments, or it picks up the very words written to
# describe it).
#
# ⚠ **Measured 2026-08-28, and said rather than assumed: stripping changes
# nothing today.** ⚠ No comment in any src/*.c contains a call shaped like the
# ones searched for, so ⚠ **removing the stripping breaks no check** — it is
# the one mutation of this case that does not fail.
#
# ⚠ It stays because the comments here quote code and documents freely — RFC
# text, struct layouts, `<SEQ=ISS><ACK=RCV.NXT>` — and ⚠ **a comment quoting one
# of these calls would otherwise be reported as prose in the wrong layer.**
# ⚠ That is a reason to keep it, ⚠ **not a claim that it is asserted.**
case_prose_lives_only_in_report() {
    offenders=0
    files=0
    for source in src/*.c; do
        [ "$source" = "src/report.c" ] && continue
        files=$((files + 1))

        # ⚠ Each of /* and */ alone on a line first, so a comment that opens and
        # closes on ONE line still forms a range (the defect #50 found).
        sed 's|/\*|\n/*\n|g; s|\*/|\n*/\n|g' "$source" |
            sed '/^\/\*$/,/^\*\/$/d' >"$work/no-comments.c"

        found=$(grep -cE '(fprintf|fputs|fputc|perror)[[:space:]]*\([^)]*"' \
            "$work/no-comments.c")
        found=$((found + $(grep -cE '(printf|puts)[[:space:]]*\("' \
            "$work/no-comments.c")))
        if [ "$found" -ne 0 ]; then
            note_failure "$source writes $found string(s) a human reads, and only src/report.c may"
            grep -nE '(fprintf|fputs|fputc|perror)[[:space:]]*\([^)]*"|(printf|puts)[[:space:]]*\("' \
                "$work/no-comments.c" | sed 's/^/      /' >&2
            offenders=$((offenders + 1))
        fi
    done

    # ⚠ The other halves (`verify` §5). ⚠ Reading no files, or a comment
    # stripper that removed everything, would each make this green for nothing.
    if [ "$files" -lt 5 ]; then
        note_failure "read $files files out of src/, which cannot be right"
        return
    fi
    sed 's|/\*|\n/*\n|g; s|\*/|\n*/\n|g' src/report.c | sed '/^\/\*$/,/^\*\/$/d' \
        >"$work/report-no-comments.c"
    if [ "$(grep -cE '(fprintf|fputs)[[:space:]]*\([^)]*"' \
        "$work/report-no-comments.c")" -lt 10 ]; then
        note_failure "the same search finds almost nothing in src/report.c, so it is not looking for what it should"
        return
    fi

    printf '    %d files in src/ besides report.c, %d writing prose\n' \
        "$files" "$offenders"
}

# ⚠ Half an identity is refused rather than quietly ignored, and ⚠ **so is a port
# with no identity to answer for it**.
#
# ⚠ Why this exists: ⚠ **`docs/SPEC.md` §1 claimed `report_lines` asserted this,
# and it did not** — the sentence is written in `src/tcpip_stack.c` and
# `tests/test_report.c` has never known about it. ⚠ **The row had been false
# since hidetzu/tcpip-stack#19** and was found by reading every row that names
# `report_lines` against the cases that exist (#50).
#
# ⚠ A stack that silently declined to answer would look exactly like one nobody
# asked (hidetzu/tcpip-stack#19 Owner Decision 6), so ⚠ **the exit code is
# asserted as well as the sentence.**
case_half_an_identity_is_refused() {
    $MAKE -s build >/dev/null 2>&1 || { note_failure "the build did not succeed"; return; }

    ./build/tcpip-stack --dev tap0 --mac 02:00:00:00:00:02 --count 0 \
        >"$work/out.txt" 2>"$work/err.txt"
    assert_exit_code 1 $? "a hardware address with no protocol address"
    assert_file_is "$work/err.txt" \
        '--mac and --ipv4 are given together or not at all.' \
        "a hardware address with no protocol address"

    ./build/tcpip-stack --dev tap0 --ipv4 10.0.0.2 --count 0 \
        >"$work/out.txt" 2>"$work/err.txt"
    assert_exit_code 1 $? "a protocol address with no hardware address"
    assert_file_is "$work/err.txt" \
        '--mac and --ipv4 are given together or not at all.' \
        "a protocol address with no hardware address"

    ./build/tcpip-stack --dev tap0 --tcp-port 80 --count 0 \
        >"$work/out.txt" 2>"$work/err.txt"
    assert_exit_code 1 $? "a port with no identity"
    assert_file_is "$work/err.txt" \
        '--tcp-port needs --mac and --ipv4 as well: nothing can be answered without them.' \
        "a port with no identity"

    # ⚠ The other half: neither given is not refused — the program reads without
    # answering, which is what it did before it could answer anything. ⚠ Without
    # this the case would pass for a build that refused every set of options.
    ./build/tcpip-stack --dev tap0 --count 0 >"$work/out.txt" 2>"$work/err.txt"
    neither=$?
    if [ "$neither" -eq 1 ]; then
        note_failure "neither address given was refused, and reading without answering is allowed"
        sed 's/^/      /' "$work/err.txt" >&2
    fi
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

select_cases static "build_warnings_are_errors build_with_sanitizers report_lines every_report_function_has_a_case ethernet_header arp_packet arp_responder internet_checksum ipv4_header icmp_message tcp_header connection_state handshake echo_responder a_device_name_that_is_too_long_is_refused half_an_identity_is_refused prose_lives_only_in_report the_old_program_name_is_gone spec_names_checks_that_exist" "$@"
run_selected_cases
