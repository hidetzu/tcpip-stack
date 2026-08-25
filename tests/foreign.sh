#!/bin/sh
# foreign — the other end of the conversation is the Linux kernel, which is not
# something we wrote (`.claude/rules/layers.md`, question 3).
#
# ⚠ Still nothing outside this machine: the namespace is private and the only
# other participant is the kernel's own stack.

set -u
cd "$(dirname -- "$0")/.." || exit 2
. tests/lib.sh

TAP_READ=./build/tap-read
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
# ⚠ This reads the bytes of a frame, and nothing in src/ does. That is not two
# implementations of the same question — there is no parser yet. ⚠ When one
# exists, this check has to stop deciding for itself what an ARP request looks
# like (`CLAUDE.md` §3).
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

inside_an_arp_request_the_kernel_generated_is_read_intact() {
    "$TAP_READ" --dev tap0 --count 3 --timeout 3000 --hex \
        >"$work/out.txt" 2>"$work/err.txt" &
    reader=$!

    if ! wait_for_interface tap0; then
        note_failure "tap0 never appeared while tap-read was attached"
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
        note_failure "tap-read stopped with exit code $reader_exit"
        sed 's/^/      /' "$work/err.txt" >&2
        return
    fi

    found_arp_request=0
    lengths_disagreeing=0
    frames_as_hex "$work/out.txt" >"$work/frames.txt"
    while read -r frame_length hex; do
        [ -n "${hex:-}" ] || continue
        # ⚠ Every byte printed, and no byte that was not read.
        if [ "${#hex}" -ne $((frame_length * 2)) ]; then
            lengths_disagreeing=$((lengths_disagreeing + 1))
        fi
        [ "$frame_length" -eq 42 ] || continue
        ethertype=$(printf '%s' "$hex" | cut -c25-28)
        sender_protocol_address=$(printf '%s' "$hex" | cut -c57-64)
        target_protocol_address=$(printf '%s' "$hex" | cut -c77-84)
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

in_namespace() {
    if ! unshare -Urn "$0" --inside "$1"; then
        current_case_ok=0
    fi
}

case_an_arp_request_the_kernel_generated_is_read_intact() {
    in_namespace an_arp_request_the_kernel_generated_is_read_intact
}

ALL_CASES="an_arp_request_the_kernel_generated_is_read_intact"

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
