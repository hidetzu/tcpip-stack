# Shared plumbing for the three check entry points.
#
# ⚠ Every entry point must be able to run one named case, and to count without
# running anything heavy (`.claude/skills/verify/SKILL.md` §1). That is written
# here once, so the three tiers cannot drift apart.

set -u

tier_name=""
tier_total=0
selected_cases=""
selected_count=0
case_failures=0
cases_passed=0
current_case_ok=1

# select_cases TIER "case_a case_b ..." "$@"
select_cases() {
    tier_name=$1
    shift
    all_cases=$1
    shift

    tier_total=0
    for name in $all_cases; do
        tier_total=$((tier_total + 1))
    done

    only=""
    while [ $# -gt 0 ]; do
        case $1 in
        --count)
            # ⚠ Counts without building, without a namespace, without a device.
            if [ "$tier_total" -eq 1 ]; then
                printf '%s: 1 case\n' "$tier_name"
            else
                printf '%s: %d cases\n' "$tier_name" "$tier_total"
            fi
            exit 0
            ;;
        --list)
            for name in $all_cases; do printf '%s\n' "$name"; done
            exit 0
            ;;
        --case)
            if [ $# -lt 2 ]; then
                printf 'usage: %s [--case NAME] [--list] [--count]\n' "$0" >&2
                exit 2
            fi
            only=$2
            shift 2
            continue
            ;;
        *)
            printf 'usage: %s [--case NAME] [--list] [--count]\n' "$0" >&2
            exit 2
            ;;
        esac
    done

    selected_cases=""
    selected_count=0
    for name in $all_cases; do
        if [ -z "$only" ] || [ "$only" = "$name" ]; then
            selected_cases="$selected_cases $name"
            selected_count=$((selected_count + 1))
        fi
    done

    if [ "$selected_count" -eq 0 ]; then
        printf '%s: no case is named %s\n' "$tier_name" "$only" >&2
        exit 2
    fi

    # ⚠ The first line says which subset ran (`verify` §1).
    if [ -z "$only" ]; then
        printf '%s: running %d of %d cases\n' "$tier_name" "$selected_count" "$tier_total"
    else
        printf '%s: running %d of %d cases (%s)\n' "$tier_name" "$selected_count" \
            "$tier_total" "$only"
    fi
}

run_selected_cases() {
    for name in $selected_cases; do
        current_case_ok=1
        # ⚠ A name in the list with no function behind it used to print `ok`.
        # ⚠ **A case that cannot fail is not a case** (`.claude/rules/testing.md`),
        # and ⚠ **a case that does not exist is the extreme of that** — ⚠ it was
        # found by adding a name and forgetting the function
        # (hidetzu/tcpip-stack#92).
        if ! command -v "case_$name" >/dev/null 2>&1; then
            printf '  %-52s FAILED\n' "$name"
            printf '    no function named case_%s exists, so nothing ran\n' "$name" >&2
            case_failures=$((case_failures + 1))
            continue
        fi
        "case_$name"
        if [ "$current_case_ok" -eq 1 ]; then
            printf '  %-52s ok\n' "$name"
            cases_passed=$((cases_passed + 1))
        else
            printf '  %-52s FAILED\n' "$name"
            case_failures=$((case_failures + 1))
        fi
    done

    printf '%s: %d of %d cases passed\n' "$tier_name" "$cases_passed" "$selected_count"
    [ "$case_failures" -eq 0 ]
}

note_failure() {
    printf '    %s\n' "$1" >&2
    current_case_ok=0
}

assert_exit_code() {  # expected actual what
    if [ "$1" != "$2" ]; then
        note_failure "$3: expected exit code $1, got $2"
    fi
}

assert_file_is() {  # file expected_text what
    actual=$(cat "$1")
    if [ "$actual" != "$2" ]; then
        note_failure "$3: output does not match"
        printf '    expected:\n' >&2
        printf '%s\n' "$2" | sed 's/^/      /' >&2
        printf '    produced:\n' >&2
        printf '%s\n' "$actual" | sed 's/^/      /' >&2
    fi
}

assert_file_contains() {  # file text what
    if ! grep -qF -- "$2" "$1"; then
        note_failure "$3: did not find the expected line"
        printf '    looked for:\n      %s\n    in:\n' "$2" >&2
        sed 's/^/      /' "$1" >&2
    fi
}

assert_true() {  # what, then the command
    what=$1
    shift
    if ! "$@" >/dev/null 2>&1; then
        note_failure "$what: '$*' did not succeed"
    fi
}
