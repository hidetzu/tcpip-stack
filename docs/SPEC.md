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
| Report | ⚠ A read that could not be made has a line of its own, and the frames read and the read errors are two numbers kept apart. ⚠ **Narrowed, and here is what is no longer exercised:** a real failing read reaching those two. ⚠ The only route to one was the gap hidetzu/tcpip-stack#8 closed; a replacement was searched for on 2026-08-27 and ⚠ **none was found** — with `POLLIN` set, six reads in six succeeded | `CLAUDE.md` §1 | `tests/static.sh` `report_lines` |
| Report | ⚠ A wait that came back reporting an error on the device is its own outcome, with its own line and its own exit code. ⚠ It names no errno, because `ppoll` succeeded — measured, reusing the older sentence prints "waiting for a frame failed: Success" | `CLAUDE.md` §1, §4-1 (hidetzu/tcpip-stack#8) | `tests/static.sh` `report_lines`, `tests/real.sh` `the_wait_says_the_device_stopped_being_usable` |
| Wire | ⚠ A frame handed to the device reaches the kernel: its own counters for the device move by the number of frames and by the exact number of octets. ⚠ A write that could not be made is not counted as a frame sent, and the step it failed at is the one recorded | Not an RFC. Linux `/dev/net/tun`, `IFF_TAP \| IFF_NO_PI` | `tests/real.sh` `a_frame_handed_over_reaches_the_kernel`, `a_write_that_could_not_be_made_is_not_a_frame_sent` |
| Parse | ⚠ The 14-octet ethernet header is read in host terms: destination address, source address, length/type. ⚠ Malformed, an IEEE 802.3 Length, and a value the standard does not define are three separate answers, and the addresses are still handed back for the two that decline the frame | Not an RFC. IEEE 802.3, the MAC frame format. ⚠ What the standard says about `0x05DD`..`0x05FF` is not confirmed here (ADR 0003) | `tests/static.sh` `ethernet_header` |
| Report | ⚠ Every frame's ethernet header is reported: destination, source and the length/type, ⚠ **as the value it is and never as a protocol name** — a name would be a lie for a VLAN-tagged frame (ADR 0003), and `0x0800` → IPv4 has not been taken from a standard here. ⚠ A header that could not be read shows no octets it never had, and the two answers that decline a readable header each say why. ⚠ The three are counted, and the counts are printed even when zero | `CLAUDE.md` §1, §4-1 (hidetzu/tcpip-stack#10 Owner Decisions 1 to 3) | `tests/static.sh` `report_lines` |
| Parse | ⚠ The internet checksum is computed as RFC 1071 describes, and ⚠ **it reproduces the two the Linux kernel put in a captured echo request** — over an IPv4 header and over an ICMP message, different octets and different lengths. ⚠ Flipping any one octet of the header changes it. ⚠ An odd length pairs the last octet with a zero, as the document says | RFC 1071. ⚠ Read 2026-08-27 and cross-checked against a second copy. ⚠ What it says about transmitting the pad, and about summing a block that still carries its checksum, was not read and is not relied on | `tests/static.sh` `internet_checksum` |
| Parse | ⚠ The fixed part of an ARP packet is read in host terms: `ar$hrd`, `ar$pro`, `ar$hln`, `ar$pln`, `ar$op` and the four addresses. ⚠ Malformed, address spaces we cannot place, and an opcode we do not act on are three separate outcomes, and the fixed fields are still handed back for the two that decline the packet | RFC 826. ⚠ Read on 2026-08-26 and cross-checked against a second copy; ADR 0005 records what was read and what was not taken from it. ⚠ RFC 826 uses no RFC 2119 keywords | `tests/static.sh` `arp_packet` |
| Parse | ⚠ The reply to an ARP request is built from the request and the two addresses we answer with, into a caller's buffer that is refused rather than truncated when it is too small. ⚠ It is the same 42 octets the Linux kernel builds for the same question, compared against a captured reply | RFC 826 for the field names (ADR 0005). ⚠ The ethernet length/type `0x0806` is observed in the fixtures and is not attributed to the RFC. ⚠ Where read and write live is ADR 0007 | `tests/static.sh` `arp_packet` |
| Parse | ⚠ The fixed part of the internet header is read in host terms, under RFC 791's own field names — ⚠ `Time to Live`, which the document does not abbreviate. ⚠ Five answers, none folded into another: malformed (fewer octets than a fixed header, an `IHL` below 5, an `IHL` or `Total Length` larger than what arrived, or the reserved flag bit set), a header checksum that does not agree, well-formed but unsupported (a version that is not 4, or `Options`), a fragment, and accepted. ⚠ Truncation is decided before support, and the addresses are still handed back for a datagram that is declined | RFC 791. ⚠ Read 2026-08-28 and cross-checked against a second copy; ADR 0010 records what was read and what was not taken from it. ⚠ RFC 791 uses no RFC 2119 keywords — ⚠ **that a set reserved bit is malformed is an owner decision reasoning from the document's words, and is not the document telling a receiver what to do** | `tests/static.sh` `ipv4_header` |
| Parse | ⚠ An ICMP echo message is read in host terms, under RFC 792's own field names: `Type`, `Code`, `Checksum`, `Identifier`, `Sequence Number`, `Data`. ⚠ Four answers, none folded into another: malformed (fewer octets than the fixed fields, or a `Code` that is not 0), a checksum that does not agree, a `Type` we do not act on — ⚠ **which includes an echo reply** — and accepted. ⚠ The checksum is decided before any field's content, and the `Type` before the `Code` | RFC 792. ⚠ Read 2026-08-28 and cross-checked against a second copy; ADR 0011 records what was read and what was not taken from it. ⚠ RFC 792 uses no RFC 2119 keywords — ⚠ **that a `Code` other than 0 is malformed is an owner decision reasoning from the document's words, and is not the document telling a receiver what to do** | `tests/static.sh` `icmp_message` |
| Parse | ⚠ The echo reply is built from the request into a caller's buffer that is refused rather than truncated when it is too small, ⚠ **with not one octet written into it when it is refused**. ⚠ `Data` comes back octet for octet whatever its length, including none. ⚠ It is the same 64 octets the Linux kernel answered with, compared against a captured reply to that very request | RFC 792 — "the type code changed to 0, and the checksum recomputed", and "For computing the checksum , the checksum field should be zero" (ADR 0011). ⚠ The IPv4 addresses the document also names are not in this file; hidetzu/tcpip-stack#35 owns them | `tests/static.sh` `icmp_message` |
| Parse | ⚠ A checksum is verified without copying the octets it covers: the field is counted as zero in place. ⚠ **One loop, two entry points** — a message whose `Data` has no length limit cannot be copied into a fixed scratch buffer, and inventing a limit would be inventing a claim | RFC 1071 (ADR 0011). ⚠ The shortcut of summing a block that still carries its checksum was not found in what was read and is not used | `tests/static.sh` `internet_checksum` |
| State | ⚠ An ARP request that asks for the address this stack was given is answered, and the Linux kernel's own neighbour table then holds the hardware address we answered with. ⚠ A request for any other address is not answered, and declining is counted apart from every other reason | RFC 826 (ADR 0005). ⚠ What it says beyond replying was not read, and no cache is kept — §2 records that as a decision | `tests/foreign.sh` `the_kernel_believes_the_address_we_answered_for`, `tests/static.sh` `arp_responder` |
| Report | ⚠ The result of an ARP packet is a decision and a reason kept apart — answered, or not answered because it was not for us, was malformed, named an address space we cannot place, or carried an opcode we do not act on. ⚠ Each of the four is counted on its own | `CLAUDE.md` §1, §4 (hidetzu/tcpip-stack#19 Owner Decisions 2 and 4) | `tests/static.sh` `report_lines`, `arp_responder` |
| Wire | ⚠ The addresses this stack answers with are given on the command line and never taken from the device. ⚠ Half an identity is refused rather than quietly ignored | Not an RFC. ADR 0008 | `tests/static.sh` `report_lines` |

## 2. What this deliberately does not implement

⚠ **A gap named here is a decision.** ⚠ **An unnamed gap is just something not done yet** —
they are different things and the difference is stated, not implied.

| Not implemented | Deliberate? | Why |
|---|---|---|
| Interpreting anything above an ICMP echo message | ⚠ **no** | ⚠ Not yet written, and not a decision. The Parse layer reads the ethernet header, an ARP packet, an IPv4 header and an ICMP echo message, and stops there |
| Any ICMP type but echo and echo reply | yes | ⚠ Destination unreachable, time exceeded and redirect were not read in RFC 792 and are not implemented. ⚠ They come back as a `Type` we do not act on, counted apart from a malformed message (ADR 0011) |
| Reading an 802.1Q VLAN tag | yes | ⚠ `0x8100` is read as any other length/type value and the tag itself is not read (ADR 0003). ⚠ So for a tagged frame that value does not name what the frame carries |
| ⚠ A count of frames the kernel dropped | yes | ⚠ The harness cannot observe it. A drop happens in the kernel's queue, and printing a number we did not measure is a guess dressed as one (`CLAUDE.md` §1) |
| TUN (layer 3) mode | yes | The first milestone is ethernet, so the harness attaches as a TAP |
| An ARP cache | yes | ⚠ Answering needs nothing remembered — everything the reply carries is in the request or is our own address. ⚠ What RFC 826 says beyond replying was not read, so this is a decision about what we do, not a reading of the document (ADR 0008) |
| Deciding to answer a ping, and sending the answer | ⚠ **no** | ⚠ Not yet written. Not a decision — the milestone is to answer a ping, and ⚠ **building a reply is not sending one**: nothing calls `ipv4_parse_header` or `icmp_parse_echo` outside their checks yet, and `ping` still reports 100% packet loss, measured 2026-08-27 |
| Reassembling IPv4 fragments | yes | ⚠ A fragment comes back as its own answer and ⚠ **nothing is reassembled**. ⚠ Kept apart from a version we do not support so the two are never one number (ADR 0010). ⚠ What RFC 791 says about reassembly was not read |
| Reading IPv4 `Options` | yes | ⚠ A header longer than five 32-bit words is declined as unsupported rather than skipped over. ⚠ Generalise once something needs them, never before (ADR 0010) |
| ⚠ Deciding what a `Total Length` shorter than its own header means | ⚠ **no** | ⚠ **Undecided, and it is accepted today.** ⚠ The approved decision order for hidetzu/tcpip-stack#33 has no row for it and that change did not invent one. ⚠ It has to be settled where a payload length is first computed from it (hidetzu/tcpip-stack#34) |

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
| Cost of `make check-static` | 5227 ms from a clean tree; 205 ms and 202 ms with the build already done | 2026-08-28 | 3 runs, all three values listed. ⚠ **Twelve cases, seven of them C check binaries built with the sanitizers** — ⚠ re-measured because that denominator moved again (hidetzu/tcpip-stack#34, on the same machine and the same day as the eleven-case row it replaces) |
| Cost of `make check-real` | 705 / 697 / 669 ms | 2026-08-26 | 3 runs, all three values listed, with the build already done. Eight cases, each with its own namespace |
| Cost of `make check-foreign` | 5001 / 4991 / 4988 ms | 2026-08-27 | 3 runs, all three values listed. Three cases, each with its own namespace and its own pings |
| Which ethertype the kernel put on a fresh tap first | ARP first in 3 runs, IPv6 first in 2 | 2026-08-26 | 5 runs of the same script. ⚠ **Why no check asserts which frame comes first** |
