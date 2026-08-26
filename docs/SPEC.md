# SPEC — what may be claimed

⚠ **This file holds what this stack may claim about itself.** ⚠ Nothing else.
**How to work** is [`CLAUDE.md`](../CLAUDE.md); **how to write it** is
[`.claude/rules/`](../.claude/rules/); **why** is [`adr/`](adr/).

⚠ **Never write a count in here** (`CLAUDE.md` §6, and the reason below).
⚠ **Counts are announced by whatever produced them**, at the moment it runs.
⚠ **A count written down here is stale from the moment it is written, and it makes every
parallel change conflict.**

---

## 1. What this implements

⚠ **A row goes in here only once the behaviour exists and a check asserts it.**
⚠ **Planned is not implemented** (`CLAUDE.md` §1).

⚠ **"What asserts it" names a case, not a file.** ⚠ **A file name says where to look; it does not
say that anything in there asserts this claim** — and a reader takes the column at its word.
⚠ **Run the case before filling the row in, and read whether it covers every clause of the claim.**
⚠ **Grounds: this went wrong here** (`CLAUDE.md` §9). `tests/static.sh` `spec_names_checks_that_exist`
stops a row that names an entry point and no case, a row that names nothing at all, a case name that
does not exist, and a case with no entry point in front of it to attribute it to.
⚠ **Nothing stops a case that exists and does not cover the clause** — ⚠ **reading the case is still
the reviewer's job, and that is the half this table got wrong.**

| Layer | What is supported | Which RFC, which section | What asserts it |
|---|---|---|---|
| Wire | Creating a Linux TAP device, attaching to it, and reading the ethernet frames that arrive on it. Each frame's length is reported, and its bytes on request | Not an RFC. Linux `/dev/net/tun`, `IFF_TAP \| IFF_NO_PI` (`Documentation/networking/tuntap.rst`) | `tests/real.sh` `count_zero_reads_nothing`, `tests/foreign.sh` `an_arp_request_the_kernel_generated_is_read_intact` |
| Wire | The device is created when the fd is taken and is gone when the fd is released. ⚠ Nothing persists between runs | same | `tests/real.sh` `the_interface_exists_only_while_it_is_attached` |
| Report | A frame read and a timer running out are different outcomes, each with its own line. ⚠ A timer running out and being unable to use the device each leave their own exit code | `CLAUDE.md` §1, §4-1 | `tests/static.sh` `report_lines`, `tests/real.sh` `a_timer_running_out_has_its_own_exit_code` |
| Wire | ⚠ A request to stop reaches a reader that is waiting with no time limit, and what was read up to then is reported | Not an RFC. `ppoll(2)` with the stop signals blocked around the loop | `tests/real.sh` `a_stop_request_reaches_a_reader_that_is_waiting` |
| Report | ⚠ A frame that exactly filled the read buffer is reported as a length we do not know, not as a measurement | `CLAUDE.md` §1 | `tests/static.sh` `report_lines`, `tests/foreign.sh` `a_frame_larger_than_the_read_buffer_is_not_reported_as_a_known_length` |

## 2. What this deliberately does not implement

⚠ **A gap named here is a decision.** ⚠ **An unnamed gap is just something not done yet** —
they are different things and the difference is stated, not implied.

| Not implemented | Deliberate? | Why |
|---|---|---|
| Sending a frame | yes | Read only for now. Sending arrives when something actually needs to send (hidetzu/tcpip-stack#2, Owner Decision 1) |
| Interpreting any byte of a frame | yes | There is no Parse layer yet. `tap-read` reports lengths and bytes and names no protocol |
| ⚠ A count of frames the kernel dropped | yes | ⚠ The harness cannot observe it. A drop happens in the kernel's queue, and printing a number we did not measure is a guess dressed as one (`CLAUDE.md` §1) |
| TUN (layer 3) mode | yes | The first milestone is ethernet, so the harness attaches as a TAP |
| ARP, IPv4, ICMP | ⚠ **no** | ⚠ Not yet written. Not a decision — the first milestone is to answer a ping |

## 3. Measured numbers

⚠ **Every number here carries the denominator of its claim, the date, and the conditions**
(`CLAUDE.md` §6): kernel version, MTU, how the namespace was built, how many runs, which percentile.

⚠ **A number without those is deleted, not corrected.**

All rows below share these conditions unless a row says otherwise:
Arch Linux, kernel `7.0.2-arch1-1`, x86_64, gcc 15.2.1, tap MTU 1500, namespace built with
`unshare -Urn` as uid 1000 with no `sudo`.

| What was measured | Value | When | Under what conditions |
|---|---|---|---|
| Whether creating a TAP device needs `sudo` | ⚠ **no**, inside `unshare -Urn` | 2026-08-26 | `ip tuntap add` and `ioctl(TUNSETIFF)`, both from uid 1000 |
| Cost of `make check-static` | 703 ms from a clean tree; 23 ms and 23 ms with the build already done | 2026-08-26 | 3 runs, all three values listed |
| Cost of `make check-real` | 479 / 487 / 463 ms | 2026-08-26 | 3 runs, all three values listed |
| Cost of `make check-foreign` | 2838 / 2659 / 2642 ms | 2026-08-26 | 3 runs, all three values listed. Two cases, each with its own namespace and its own `ping -c 2 -i 0.3` |
| Which ethertype the kernel put on a fresh tap first | ARP first in 3 runs, IPv6 first in 2 | 2026-08-26 | 5 runs of the same script. ⚠ **Why no check asserts which frame comes first** |
