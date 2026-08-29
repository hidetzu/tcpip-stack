/* State — what an arriving TCP segment means for a connection we are listening
 * for, and what moved as a result.
 *
 * ⚠ No fd, no clock, no prose, and ⚠ **nothing is sent**
 * (`.claude/rules/layers.md`, hidetzu/tcpip-stack#43 Out of Scope). This layer
 * is handed a header that was already read and checked, and it says what it
 * decided and why. ⚠ `report.c` is the only place any of it becomes a sentence,
 * and hidetzu/tcpip-stack#44 is what puts something on the wire.
 *
 * ⚠ The decision and the reason are two things, never one — the shape
 * hidetzu/tcpip-stack#19 Owner Decision 2 set for ARP and #35 followed. ⚠ Every
 * reason is counted on its own.
 *
 * ⚠ The rules are RFC 793's §3.9, read on 2026-08-28 from the document itself
 * rather than through a summary, and quoted where they are applied
 * (ADR 0016). */
#ifndef HANDSHAKE_H
#define HANDSHAKE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "connection.h"
#include "ethernet.h"
#include "icmp.h"
#include "ipv4.h"
#include "tcp.h"

/* How fast the initial send sequence number moves, in nanoseconds per step.
 *
 * ⚠ RFC 9293 §3.4, verbatim: "TCP initial sequence numbers are generated from a
 * number sequence that monotonically increases until it wraps, known loosely as
 * a 'clock'.  This clock is a 32-bit counter that typically increments at least
 * once every roughly 4 microseconds, although it is neither assumed to be
 * realtime nor precise, and need not persist across reboots."
 *
 * ⚠ **4000 nanoseconds is "roughly 4 microseconds", said in the unit
 * `struct moment` carries.** ⚠ The document says "at least once every", so
 * ⚠ **faster would also satisfy it**; this is the rate it names.
 *
 * ⚠ **It wraps every 4.77 hours** — 2^32 steps of 4 microseconds — which
 * ⚠ is the document's own figure: "it cycles approximately every 4.55 hours". */
#define HANDSHAKE_INITIAL_SEQUENCE_STEP_NANOSECONDS 4000u

/* The initial send sequence number for a connection taken at `now`.
 *
 * ⚠ RFC 9293 `MUST-8`: "A TCP implementation MUST use the above type of 'clock'
 * for clock-driven selection of initial sequence numbers."
 *
 * ⚠ **It was the constant `0xdeadbeef` until hidetzu/tcpip-stack#98.**
 * ⚠ ADR 0016 chose that because there was no clock, ⚠ **and named this "the
 * first thing to revisit when a clock arrives".** ⚠ The clock arrived at
 * hidetzu/tcpip-stack#56 and this did not change until Appendix B was read.
 *
 * ⚠ **RFC 9293's `SHLD-1` is deliberately not taken** — "SHOULD generate its
 * initial sequence numbers with the expression:
 * `ISN = M + F(localip, localport, remoteip, remoteport, secretkey)`".
 * ⚠ `F` needs a secret key and a pseudo-random function, ⚠ **and this
 * repository has neither and no cryptographic dependency**; `CLAUDE.md` §3
 * forbids introducing one without a reason (Owner Decision, 2026-08-29).
 * ⚠ **So the number is still guessable by anyone who can read a clock**, and
 * `docs/SPEC.md` §2 says so rather than letting `MUST-8` look like the whole
 * answer.
 *
 * ⚠ **Chosen once per connection and then remembered**: a retransmitted `SYN`
 * must be answered with the same number, ⚠ **or a peer that did get the first
 * answer is told a different one** (ADR 0016). */
uint32_t handshake_initial_send_sequence(struct moment now);

/* How long until the answer goes out again, and how long until we stop.
 *
 * ⚠ RFC 793 read verbatim on 2026-08-28: ⚠ **"the retransmission timeout must
 * be dynamically determined"**, and the procedure it gives needs a Round Trip
 * Time. ⚠ **Nothing here measures a round trip**, so ⚠ **this stack does not do
 * what the document asks**, and `docs/SPEC.md` §2 names that gap.
 *
 * ⚠ 1000 was RFC 793's own example lower bound — "LBOUND is a lower bound on the
 * timeout (e.g., 1 second)" — and ⚠ **going below it would have meant going
 * under the only floor that document offered, for the reason that a check is
 * cheaper that way** (hidetzu/tcpip-stack#57 Owner Decision 1).
 *
 * ⚠ **RFC 9293 is the baseline now (ADR 0024) and contains no such sentence** —
 * ⚠ measured, no `LBOUND` and no "e.g., 1 second". ⚠ It defers the algorithm to
 * RFC 6298, which ⚠ **ADR 0024 clause 3 does not pull in** because nothing here
 * measures a round trip. ⚠ **So 1000 is ours too now**
 * (hidetzu/tcpip-stack#87), and neither number is presented as a reading.
 *
 * ⚠ 3000 is ours and has no grounds in either document. ⚠ RFC 793's example upper
 * bound is a minute; ⚠ **a check that waits a minute would change what the real
 * tier costs by an order of magnitude** (`docs/SPEC.md` §3 holds what it costs).
 * ⚠ **Chosen for what a check can afford, and recorded as that** (ADR 0019).
 *
 * ⚠ So the answer goes out again twice — after a second and after two — and
 * ⚠ **the connection is given up on at three.** */
/* RFC 9293 §3.8.3's two thresholds.
 *
 * ⚠ §3.8.3 (a), quoted: "R1 and R2 might be measured in **time units or as a
 * count of retransmissions** (with the current RTO and corresponding backoffs as
 * a conversion factor, if needed)."
 *
 * ⚠ **So the two are expressed in the unit each document gives its value in**,
 * and ⚠ **no conversion of ours stands between them and the sentence they come
 * from.** ⚠ hidetzu/tcpip-stack#114 corrected a verdict that called the time
 * form wrong; ⚠ **it is one of the two the document offers.** */

/* ⚠ `SHLD-10`: "The value of R1 SHOULD correspond to at least 3
 * retransmissions, at the current RTO." ⚠ **A count, which is the unit the
 * sentence uses.** */
/* RFC 5681's congestion window, and ⚠ **every number here is the document's.**
 *
 * ⚠ **`SMSS` is the effective send MSS.** ⚠ RFC 5681 §2: "The SMSS is the size
 * of the largest segment that the sender can transmit. This value can be based
 * on the maximum transmission unit of the network ..., RMSS ..., or other
 * factors." ⚠ **That is exactly what `handshake_effective_send_mss` returns**
 * (RFC 9293 `MUST-16`), ⚠ **so no second idea of "how large a segment may be"
 * is introduced** (`CLAUDE.md` §3).
 *
 * ⚠ **`FlightSize` is `SND.NXT - SND.UNA`.** ⚠ §2: "The amount of data that has
 * been sent but not yet cumulatively acknowledged." */

/* ⚠ §3.1: "IW, the initial value of cwnd, MUST be set using the following
 * guidelines as an upper bound." ⚠ **The boundaries are the document's**, and
 * the upper bound is taken exactly — ⚠ **a smaller one would be ours to
 * defend.** */
#define HANDSHAKE_IW_SMSS_LARGE  2190u  /* above this: 2 segments */
#define HANDSHAKE_IW_SMSS_MEDIUM 1095u  /* above this: 3 segments */

/* ⚠ §3.1: "The initial value of ssthresh SHOULD be set arbitrarily high (e.g.,
 * to the size of the largest possible advertised window)." ⚠ **The example is
 * taken**: sixteen bits of `Window` is the largest one that can be advertised
 * without a scale option, ⚠ **and no scale option is implemented** (ADR 0024's
 * scope table). */
#define HANDSHAKE_SSTHRESH_AT_THE_START 65535u

/* ⚠ §3.1: "upon a timeout ... cwnd MUST be set to no more than the loss window,
 * LW, which equals 1 full-sized segment (regardless of the value of IW)."
 * ⚠ **In segments, because that is the unit the sentence uses.** */
#define HANDSHAKE_LW_SEGMENTS 1u

#define HANDSHAKE_R1_RETRANSMISSIONS 3u

/* ⚠ `SHLD-11`: "The value of R2 SHOULD correspond to at least 100 seconds."
 * ⚠ **A time, which is the unit that sentence uses.** */
#define HANDSHAKE_R2_FOR_DATA_MILLISECONDS 100000u

/* ⚠ `MUST-23`: "R2 for a SYN segment MUST be set large enough to provide
 * retransmission of the segment for at least 3 minutes."
 *
 * ⚠ **Owner Decision, hidetzu/tcpip-stack#131, 2026-08-29**: 「`MUST-23` は SYN
 * R2 を 180 秒以上とします。ただし通常の verification で実時間3分を毎回待つことは
 * 要求しません。」
 *
 * ⚠ **No check waits three minutes, and none needs a seam to avoid it.**
 * ⚠ ADR 0018 hands the State layer a moment rather than letting it read one,
 * ⚠ **so `at(180000)` and `at(179999)` judge the boundary exactly, in
 * microseconds** — ⚠ **that is the production signature and not a test hook.**
 *
 * ⚠ **What it replaced was 3000**, chosen at ADR 0019 for what a check could
 * afford and ⚠ **recorded as exactly that.** ⚠ The checks that waited it out on
 * a device are repointed at the retransmissions, ⚠ **which is what a device is
 * for** (`.claude/rules/testing.md`: when a check's subject moves, repoint it). */
#define HANDSHAKE_R2_FOR_A_SYN_MILLISECONDS 180000u

/* RFC 6298's constants, and ⚠ **every one of them is the document's.**
 *
 * ⚠ **Nanoseconds throughout**, matching `struct moment`. ⚠ That is not a
 * convenience: ⚠ **it is what removes the question of rounding.** ⚠ RFC 6298
 * gives no rule for integer arithmetic, and ⚠ **dividing nanoseconds by 8 and by
 * 4 truncates below a nanosecond**, which is under the granularity of the clock
 * this stack reads (see `HANDSHAKE_CLOCK_GRANULARITY_NANOSECONDS`). ⚠ **So no
 * rule had to be invented, and none was.** */

/* ⚠ §2.2 and §2.3: "RTO <- SRTT + max (G, K*RTTVAR) where K = 4". */
#define HANDSHAKE_RTO_K 4u

/* ⚠ §2.3: "The above SHOULD be computed using alpha=1/8 and beta=1/4".
 * ⚠ **Written as the shift each one is**, because that is how they are applied
 * and ⚠ a fraction would need a rounding rule the document does not give. */
#define HANDSHAKE_RTO_ALPHA_SHIFT 3u  /* alpha = 1/8  */
#define HANDSHAKE_RTO_BETA_SHIFT  2u  /* beta  = 1/4  */

/* ⚠ §2.1: "Until a round-trip time (RTT) measurement has been made ..., the
 * sender SHOULD set RTO <- 1 second". ⚠ **This is where the 1 second that used
 * to be a fixed interval belongs**, and ⚠ **it is an initial value here, not an
 * interval** (hidetzu/tcpip-stack#130). */
#define HANDSHAKE_RTO_BEFORE_ANY_SAMPLE_NANOSECONDS 1000000000ull

/* ⚠ §2.4: "Whenever RTO is computed, if it is less than 1 second, then the RTO
 * SHOULD be rounded up to 1 second."
 *
 * ⚠ **On a tap this floor decides every RTO there is.** ⚠ Round trips here are
 * microseconds; ⚠ **so the number stays 1000 ms and its grounds change
 * completely** — from a constant nobody could defend to a computation the
 * document gives, floored by a sentence the document gives. ⚠ A check that only
 * ever saw a tap could not tell those apart, ⚠ **so the checks feed round trips
 * large enough to lift it off the floor.** */
#define HANDSHAKE_RTO_LEAST_NANOSECONDS 1000000000ull

/* ⚠ §2.5: "A maximum value MAY be placed on RTO provided it is at least 60
 * seconds." ⚠ **Taken, at exactly the least the document allows** — ⚠ a larger
 * one would be ours to defend and there is nothing to defend it with. */
#define HANDSHAKE_RTO_MOST_NANOSECONDS 60000000000ull

/* The clock's granularity, `G` in RFC 6298 §4.
 *
 * ⚠ **Measured, not assumed** (hidetzu/tcpip-stack#130 AC 7). Arch Linux
 * 7.0.2-arch1-1, x86_64, `CLOCK_MONOTONIC`, 2026-08-29, three runs of 200000
 * back-to-back reads each: ⚠ **the smallest non-zero step observed was 10, 10
 * and 20 nanoseconds.** ⚠ `clock_getres` claims 1 ns, ⚠ **which is a different
 * question and is not what this records.**
 *
 * ⚠ **The largest of the three is taken**, because ⚠ §4 uses `G` as a floor on
 * the variance term and ⚠ **a floor that is too small does nothing while one
 * that is too large would inflate every RTO.**
 *
 * ⚠ **It never decides anything here**: `max(G, K*RTTVAR)` with G at 20 ns is
 * `K*RTTVAR` for any round trip worth measuring. ⚠ **Carried because the
 * document's formula has it**, and ⚠ **a formula written without a term it has
 * is not that formula.** */
#define HANDSHAKE_CLOCK_GRANULARITY_NANOSECONDS 20ull

/* ⚠ `struct handshake_round_trip` is in `connection.h`, ⚠ **because it is TCB
 * state and the TCB is defined there** (`.claude/rules/layers.md`). ⚠ The
 * functions that move it are here, with the constants they use. */
/* ⚠ RFC 6298 §2.1, before anything has been measured. */
void handshake_round_trip_begin(struct handshake_round_trip *estimate);

/* ⚠ RFC 6298 §2.2 on the first sample and §2.3 on every later one, ⚠ **then §2.4
 * and §2.5 on the result, in that order.**
 *
 * ⚠ **`r_nanoseconds` must not come from a segment that was retransmitted** —
 * ⚠ Karn's algorithm, §3: "RTT samples MUST NOT be made using segments that were
 * retransmitted". ⚠ **This function cannot know that and does not check**; the
 * caller is what refuses the sample (`.claude/rules/c.md`: one function does
 * mainly one thing).
 *
 * ⚠ **Pure**: no fd, no clock, no device. */
void handshake_round_trip_sample(struct handshake_round_trip *estimate,
                                 uint64_t r_nanoseconds);

/* The overhead one frame gives up before a single octet of data: an internet
 * header and a TCP header, both without options.
 *
 * ⚠ **Whose headers: THEIRS.** ⚠ The window is a promise about how much data the
 * peer may send us, so ⚠ **the frame that has to carry it is the peer's** — and
 * ⚠ **what this stack puts in its own headers has nothing to do with this
 * number.**
 *
 * ⚠ **Corrected 2026-08-29, the day it was written**: it first said "both are
 * twenty octets because this stack sends neither kind of option", ⚠ **which is
 * the wrong side of the conversation.** ⚠ The value was right and the grounds
 * were not, and ⚠ **a number is only as good as the sentence under it**
 * (`CLAUDE.md` §6).
 *
 * ⚠ Both are twenty octets because ⚠ **no option is negotiated in either
 * direction**: this stack sends none (ADR 0012, ADR 0013) and interprets none
 * of what arrives (ADR 0013), ⚠ **so nothing has agreed to anything that would
 * put options on an incoming segment.**
 *
 * ⚠ **The day an MSS Option is negotiated — RFC 9293 `MUST-14`, still not met —
 * this number becomes optimistic**: the window would promise more than one of
 * their frames actually delivers. ⚠ `the_window_is_what_one_frame_carries` is
 * what will say so, because it asserts an MTU of 1500 still gives 1460. */
#define HANDSHAKE_HEADERS_BEFORE_DATA 40u

/* Why a window could not be derived. ⚠ An enum never reaches a human. */
enum handshake_window {
    HANDSHAKE_WINDOW_OK = 0,

    /* ⚠ The MTU does not leave one octet after the two headers.
     *
     * ⚠ **Measured not to occur on a tap**, Arch Linux 7.0.2-arch1-1,
     * `unshare -Urn`, 3 runs, every run identical, 2026-08-29: ⚠ **the kernel
     * refuses an MTU below 68, and 68 leaves 28.** ⚠ **So this is a guard and
     * not a path** — ⚠ asserted against the function directly, with no device,
     * because ⚠ **contriving a device to reach it would be testing the
     * contrivance.** */
    HANDSHAKE_WINDOW_THE_MTU_LEAVES_NOTHING,

    /* ⚠ What is left will not fit the sixteen bits RFC 793 gives the field.
     *
     * ⚠ **Refused, never truncated**: the promise a peer reads must be the
     * promise we made (`CLAUDE.md` §1). ⚠ Until hidetzu/tcpip-stack#119 a
     * `_Static_assert` did this job, ⚠ **and it could, because the window was a
     * constant.** ⚠ **It is a device's answer now**, so the same job is done at
     * the moment the answer arrives.
     *
     * ⚠ **Also measured not to occur on a tap**: the largest MTU one accepts is
     * 65521, which leaves 65481. */
    HANDSHAKE_WINDOW_WOULD_NOT_FIT_THE_FIELD
};

/* How many octets to promise, for a device that carries frames of `mtu` bytes.
 *
 * ⚠ **The number this stack advertises as its `Window`, and ⚠ it is a promise.**
 *
 * ⚠ RFC 793: "Window: 16 bits - The number of data octets beginning with the one
 * indicated in the acknowledgment field which the sender of this segment is
 * willing to accept."
 *
 * ⚠ **What it claims is "a whole segment's worth"** (hidetzu/tcpip-stack#75
 * Owner Decision 1). ⚠ Until hidetzu/tcpip-stack#119 that claim was carried by
 * the constant `1460` with a sentence beside it saying `1500 - 20 - 20`;
 * ⚠ **the arithmetic is performed now, on the MTU the device actually reported**
 * (ADR 0027, ADR 0028).
 *
 * ⚠ **What backs it is not a buffer**: this stack takes delivery and discards
 * (hidetzu/tcpip-stack#64 Owner Decision 2), so ⚠ **there is no size at which
 * taking becomes impossible** — ⚠ which is why the number is chosen for what it
 * claims rather than for what fits.
 *
 * ⚠ **Measured before the shape was chosen**, 3000 octets handed to `sendall`,
 * same conditions as `docs/SPEC.md` §3, 2026-08-29:
 *
 *     window   segments   octets each   Send-Q reached 0
 *     1        2400       1             ⚠ no, not in 3 seconds
 *     5        480        5             ⚠ no, not in 1.5 seconds
 *     64       47         56 .. 64      yes
 *     1460     6          388 .. 536    yes
 *     65535    6          320 .. 536    yes
 *
 * ⚠ **1460 and 65535 behave the same**: past a point ⚠ **the segment size is the
 * peer's MSS and congestion window deciding, not our window.**
 *
 * ⚠ **It never shrinks**: every octet is discarded as it is taken, so the window
 * is always this many from `RCV.NXT`, and `RCV.NXT` only advances. RFC 793: "The
 * total of RCV.NXT and RCV.WND should not be reduced."
 *
 * ⚠ **The number has moved three times and each time what backs it moved
 * first**: 0 while nothing accepted an octet, 1 once one was taken, 1460 once
 * each was acknowledged, ⚠ **and now whatever the device reports.**
 *
 * ⚠ **Pure**: no fd, no clock, no device (`.claude/rules/c.md`). */
enum handshake_window handshake_window_for_mtu(unsigned int mtu, uint16_t *window);

/* The Maximum Segment Size this stack advertises, for a device that carries
 * frames of `mtu` bytes.
 *
 * ⚠ RFC 9293 §3.7.1: "TCP endpoints MUST implement both sending and receiving
 * the MSS Option (MUST-14)."
 *
 * ⚠ **The same number as the window, and that is not a coincidence.** ⚠ Both
 * answer "how much data of theirs fits in one of their frames" — ⚠ the MSS says
 * it per segment, the `Window` says how many we will take — ⚠ **so they are the
 * same arithmetic and this returns the same value** (ADR 0029).
 *
 * ⚠ **It is derived, never chosen.** ⚠ hidetzu/tcpip-stack#123 Owner Decision:
 * ⚠ **no constant is placed here as an owner value** — the device's MTU is
 * measurable since hidetzu/tcpip-stack#115, and ⚠ **a number nobody measured is
 * a number nobody can defend** (`CLAUDE.md` §6).
 *
 * ⚠ RFC 9293 `MUST-67` asks that the value be based on `MMS_R`, "the maximum
 * message size that can be received"; ⚠ **the MTU less the two headers is that,
 * for a device that does not reassemble** — and ⚠ **this stack refuses a
 * fragment outright** (ADR 0010), so nothing larger can arrive whole.
 *
 * ⚠ **Pure**: no fd, no clock, no device. */
enum handshake_window handshake_maximum_segment_size_for_mtu(unsigned int mtu,
                                                             uint16_t *mss);

/* The largest segment this stack will actually put on the wire.
 *
 * ⚠ RFC 9293 §3.7.1, quoted: "The maximum size of a segment that a TCP endpoint
 * really sends, the 'effective send MSS', MUST be the smaller (MUST-16) of the
 * send MSS (that reflects the available reassembly buffer size at the remote
 * host, the EMTU_R) and the largest transmission size permitted by the sender".
 *
 * ⚠ **`send_mss` is what they told us**, or RFC 9293 `MUST-15`'s default of 536
 * when they told us nothing. ⚠ **`mtu` gives the other half**: what one of our
 * frames can carry, which is the same arithmetic the window and our own MSS use.
 *
 * ⚠ **The smaller of the two, and nothing else.** ⚠ It is not clamped, rounded
 * or floored — ⚠ **the document says "the smaller", and a third rule of ours
 * would be a claim we cannot cite.**
 *
 * ⚠ **Pure**: no fd, no clock, no device. */
enum handshake_window handshake_effective_send_mss(uint16_t send_mss,
                                                   unsigned int mtu,
                                                   uint16_t *effective);

/* RFC 5681 §3.1's initial congestion window, for a sender whose `SMSS` is this.
 *
 * ⚠ Quoted whole, because ⚠ **each line has two limits and both bind**:
 *
 *     If SMSS > 2190 bytes:
 *         IW = 2 * SMSS bytes and MUST NOT be more than 2 segments
 *     If (SMSS > 1095 bytes) and (SMSS <= 2190 bytes):
 *         IW = 3 * SMSS bytes and MUST NOT be more than 3 segments
 *     if SMSS <= 1095 bytes:
 *         IW = 4 * SMSS bytes and MUST NOT be more than 4 segments
 *
 * ⚠ **The two limits agree here**: `n * SMSS` bytes IS `n` segments when a
 * segment is `SMSS`. ⚠ **Said rather than assumed** — a build that sent smaller
 * segments would have to satisfy both, and this one does not send smaller ones.
 *
 * ⚠ **Pure**: no fd, no clock, no device. */
uint32_t handshake_initial_congestion_window(uint16_t smss);

/* One octet of what we were asked to send, by its offset from the first.
 *
 * ⚠ **A pattern, not a buffer.** ⚠ Nothing is allocated and nothing is freed;
 * ⚠ **the octet at an offset is always the same octet**, so a segment can be
 * built from a sequence number alone.
 *
 * ⚠ **It is a check's counterpart too**: a harness can compute what it should
 * have received without being told, ⚠ **so "3000 octets arrived" and "the right
 * 3000 octets arrived" are different assertions and both can be made.** */
uint8_t handshake_octet_at(uint32_t offset);

enum handshake_decision {
    /* ⚠ The connection moved to a state it was not in. `outcome->state` says
     * which. */
    HANDSHAKE_MOVED = 0,

    /* ⚠ Nothing moved, and `outcome->reason` says why. ⚠ That includes the
     * ordinary case of a retransmitted SYN, which is not an error. */
    HANDSHAKE_STAYED
};

/* Which segment was built into the caller's reply buffer, if any.
 *
 * ⚠ Its own field so that ⚠ **the caller never has to work out from a state
 * which counter to move** — that rule would then live in two layers, and one of
 * them would go stale (`CLAUDE.md` §3). ⚠ An enum never reaches a human. */
enum handshake_reply {
    HANDSHAKE_REPLY_NONE = 0,

    /* The `<SEQ=ISS><ACK=RCV.NXT><CTL=SYN,ACK>` that answers a SYN. */
    HANDSHAKE_REPLY_THE_ANSWER,

    /* ⚠ A bare acknowledgment for data we took.
     *
     * ⚠ RFC 793's seventh step, verbatim: "When the TCP takes responsibility
     * for delivering the data to the user it must also acknowledge the receipt
     * of the data ... Send an acknowledgment of the form:
     * <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>".
     *
     * ⚠ **Nothing here delivers anything to a user** — there is none, and the
     * octets are discarded (hidetzu/tcpip-stack#64 Owner Decision 2). ⚠ **What
     * is acknowledged is what was taken**, and that is what `RCV.NXT` says.
     *
     * ⚠ The document adds: "This acknowledgment should be piggybacked on a
     * segment being transmitted if possible without incurring undue delay."
     * ⚠ **Nothing else is ever being transmitted here**, so there is nothing to
     * piggyback on. */
    HANDSHAKE_REPLY_THE_DATA_IS_ACKNOWLEDGED,

    /* ⚠ An acknowledgment for a segment we would not take — ⚠ **it accepts
     * nothing, it says where we are.**
     *
     * ⚠ RFC 9293 §3.10.7.4, verbatim — ⚠ **and "should" is lowercase there, so
     * it is the document describing behaviour and not requiring it** (§2):
     * "If an incoming segment is not acceptable, an acknowledgment should be
     * sent in reply
     * (unless the RST bit is set, if so drop the segment and return):
     * <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>. After sending the acknowledgment,
     * drop the unacceptable segment and return."
     *
     * ⚠ **The same shape as the acknowledgment for data we took, and a
     * different event.** ⚠ One says we accepted something, the other says we
     * did not — ⚠ **counted apart, because folding them together would make a
     * peer that is repeating itself look like one that is getting through**
     * (hidetzu/tcpip-stack#80). */
    HANDSHAKE_REPLY_WHERE_WE_ARE,

    /* ⚠ Our own FIN, ⚠ **carrying the acknowledgment of theirs in the same
     * segment.** ⚠ Measured 2026-08-29, in a namespace on `lo`: when its
     * application closes the moment the peer's FIN arrives, ⚠ **the Linux
     * kernel sends one segment carrying `FIN,ACK`** — and two segments when the
     * close comes later. ⚠ ADR 0022 puts this stack in the first situation
     * always, because the FIN's arrival IS the close here (ADR 0023). */
    /* ⚠ Data we were asked to send, not an answer to anything that arrived.
     * ⚠ **The first segment this stack builds that nothing prompted.** */
    HANDSHAKE_REPLY_THE_DATA_WE_WERE_ASKED_FOR,

    HANDSHAKE_REPLY_OUR_FIN
};

enum handshake_reason {
    HANDSHAKE_REASON_NONE = 0, /* it moved */

    /* ⚠ Not an error, and ⚠ not folded in with anything that is. ⚠ The Linux
     * kernel retransmits its SYN — 7 times in one measured `connect()`,
     * 2026-08-28 — so ⚠ **this is the ordinary case, not a rare one.**
     * ⚠ Nothing is re-chosen: the same `iss` stands, so a peer that did get our
     * first answer is not told a different number (ADR 0016). */
    HANDSHAKE_REASON_ASKED_AGAIN,

    /* ⚠ RFC 793: "If SND.UNA =< SEG.ACK =< SND.NXT then enter ESTABLISHED
     * state". ⚠ This is what happens when it is not. ⚠ The document says a reset
     * should be formed; ⚠ **nothing is sent here**, and `docs/SPEC.md` §2 names
     * that gap rather than leaving it silent. */
    HANDSHAKE_REASON_ACKNOWLEDGMENT_WE_ARE_NOT_WAITING_FOR,

    /* ⚠ A segment for a connection we hold, carrying something this state has
     * no rule for here. ⚠ Counted apart from a wrong acknowledgment: one is the
     * sender being early, the other is the sender being wrong. */
    HANDSHAKE_REASON_NOT_EXPECTED_IN_THIS_STATE,

    /* ⚠ Nothing is listening for it and it is not a request to open one.
     * ⚠ RFC 793: "Any acknowledgment is bad if it arrives on a connection still
     * in the LISTEN state." ⚠ The document says a reset should be formed;
     * nothing is sent here. */
    HANDSHAKE_REASON_NO_CONNECTION_HELD,

    /* ⚠ The other side reset the connection, and ⚠ **it is gone.**
     *
     * ⚠ RFC 9293 §3.10.7.4, for the synchronised states: "If the RST bit is set,
     * then any outstanding RECEIVEs and SEND should receive 'reset' responses.
     * All segment queues should be flushed.  Users should also receive an
     * unsolicited general 'connection reset' signal.  Enter the CLOSED state,
     * delete the TCB, and return."
     *
     * ⚠ **There is no user and there are no queues** (ADR 0022). ⚠ What is left
     * is deleting the block, ⚠ **and telling the human who is watching** — which
     * is what the Report layer is for.
     *
     * ⚠ For `SYN-RECEIVED` the document says to "return this connection to
     * LISTEN state ... The user need not be informed", and ⚠ **holding nothing
     * IS our LISTEN**, so the two come to the same thing here. ⚠ **The only
     * difference the document draws is in what a user is told**, and there is
     * none.
     *
     * ⚠ **RFC 5961's three checks are not implemented.** ⚠ The document makes
     * them conditional — "For stacks implementing the protection described in
     * RFC 5961" — and ⚠ ADR 0024 clause 3 adds a deferred document only when
     * that function is implemented. */
    HANDSHAKE_REASON_THE_OTHER_SIDE_RESET_IT,

    /* ⚠ A `RST` whose sequence number the window does not cover. ⚠ **Dropped,
     * and nothing is sent for it.**
     *
     * ⚠ RFC 9293 §3.10.7.4's first step says an unacceptable segment draws an
     * acknowledgment ⚠ **"(unless the RST bit is set, if so drop the segment and
     * return)"** — ⚠ **so this one draws nothing**, unlike refused data or a
     * refused `FIN`.
     *
     * ⚠ Counted on its own: ⚠ **a reset we could not place is not a connection
     * that was reset**, and folding them together would make an attempt to cut
     * a connection look like a connection cut. */
    HANDSHAKE_REASON_A_RESET_OUTSIDE_THE_WINDOW,

    /* ⚠ A segment carrying `URG`. ⚠ **The pointer is read and nothing is done
     * with it.**
     *
     * ⚠ RFC 9293 asks that the urgent pointer be processed and the user
     * signalled. ⚠ **There is no user** (ADR 0022), so ⚠ **this counts the
     * segment and says so, rather than letting it pass as ordinary.**
     *
     * ⚠ It is not a refusal: ⚠ **whatever else the segment carries is still
     * acted on.** ⚠ This reason is only reached when nothing else was. */
    HANDSHAKE_REASON_URGENT_AND_NOBODY_TO_TELL,

    /* ⚠ The segment is addressed to a broadcast or a multicast address, and
     * ⚠ **nothing is done with it — no state, no reply.**
     *
     * ⚠ RFC 9293 `MUST-57`: "A TCP implementation MUST silently discard an
     * incoming SYN segment that is addressed to a broadcast or multicast
     * address ... This prevents connection state and replies from being
     * erroneously generated."
     *
     * ⚠ **Counted apart from every other reason.** ⚠ "Silently" forbids a reply
     * on the wire, ⚠ **not a line telling the human who is watching** — and
     * ⚠ a drop nobody counted is indistinguishable from a segment that never
     * arrived (`.claude/rules/c.md`).
     *
     * ⚠ **It applies to every segment and not only a `SYN`.** ⚠ The document
     * names the `SYN` because that is what creates state; ⚠ **refusing the rest
     * as well is ours, and is the narrower behaviour** (hidetzu/tcpip-stack#99). */
    HANDSHAKE_REASON_ADDRESSED_TO_EVERYONE,

    /* ⚠ The segment's SOURCE address is one that may never be a source, and
     * ⚠ **nothing is done with it — no state, no reply.**
     *
     * ⚠ RFC 9293 `MUST-63`, §3.9.2.3: "An incoming SYN with an invalid source
     * address MUST be ignored either by TCP or by the IP layer ... (see
     * Section 3.2.1.3)." ⚠ Which forms, and which one is still missing, are in
     * `ipv4.h` beside the predicate — ⚠ **not repeated here** (`CLAUDE.md`:
     * written in two places, one goes stale).
     *
     * ⚠ **Counted apart from `ADDRESSED_TO_EVERYONE`.** ⚠ They are refusals for
     * opposite reasons — ⚠ **one is where it was going, the other is where it
     * claims to have come from** — and ⚠ a count that merged them could not tell
     * a misdirected segment from a forged one.
     *
     * ⚠ **This one IS the sender's**, and the sentence may say so: the address
     * it used is one RFC 1122 says must not be used. ⚠ That is not the shape
     * `CLAUDE.md` §4-1 forbids, which is blaming the sender for a gap of ours.
     *
     * ⚠ **It applies to every segment and not only a `SYN`.** ⚠ §3.9.2.3 says
     * "implementers should note that this guidance is applicable to all incoming
     * segments" ⚠ **in lowercase, so it is not a requirement** — ⚠ refusing the
     * rest as well is ours, and is the narrower behaviour, exactly as it is for
     * `ADDRESSED_TO_EVERYONE` (hidetzu/tcpip-stack#112). */
    HANDSHAKE_REASON_FROM_AN_IMPOSSIBLE_SOURCE,

    /* ⚠ Data of ours left the stack. ⚠ Its own reason, because ⚠ **it is the
     * only line that is not about something that arrived.** */
    HANDSHAKE_REASON_WE_SENT_WHAT_WE_WERE_ASKED_TO,

    /* ⚠ There is data to send and the peer's window has no room for it.
     * ⚠ **Ours to wait, not theirs to blame** — they said what they can hold and
     * we are holding to it (`CLAUDE.md` §4-1). ⚠ Counted, because ⚠ **a send
     * that did not happen looks exactly like having nothing to send.** */
    HANDSHAKE_REASON_THEIR_WINDOW_HAD_NO_ROOM,

    /* ⚠ An ICMP error naming this connection, by class.
     *
     * ⚠ RFC 9293 §3.9.2.2 classifies them and ⚠ **each class is a different
     * answer**: ⚠ a Source Quench is discarded and nothing is said on the wire,
     * ⚠ a soft error leaves the connection alone, ⚠ a hard one ends it, and
     * ⚠ **one the document does not classify is its own thing** — ⚠ silence is
     * not a class (`CLAUDE.md` §1). */
    HANDSHAKE_REASON_A_SOURCE_QUENCH_WE_DISCARDED,
    HANDSHAKE_REASON_A_SOFT_ERROR_THAT_CHANGES_NOTHING,
    HANDSHAKE_REASON_A_HARD_ERROR_THAT_ENDS_IT,
    HANDSHAKE_REASON_AN_ERROR_THE_DOCUMENT_DOES_NOT_CLASSIFY,

    /* ⚠ An error about a connection nobody here holds. ⚠ **Not ours and not the
     * sender's**: it may name one that has since closed. */
    HANDSHAKE_REASON_AN_ERROR_FOR_NO_CONNECTION_WE_HOLD,

    /* ⚠ Ours, not the sender's: every block is in use
     * (hidetzu/tcpip-stack#42 Owner Decision 1). */
    HANDSHAKE_REASON_NO_ROOM,

    /* ⚠ Nobody has confirmed it yet, and the answer went out again. ⚠ **Not the
     * same event as a retransmitted SYN arriving**, and ⚠ not counted with it:
     * one is how many times they asked, the other how many times we answered
     * (hidetzu/tcpip-stack#59 Owner Decision 1).
     *
     * ⚠ Until #59 these shared `ASKED_AGAIN`, and ⚠ **the sentence printed for
     * our own timer said the sender had asked again, which was false.** */
    HANDSHAKE_REASON_THE_ANSWER_WENT_OUT_AGAIN,

    /* ⚠ Nobody acknowledged our FIN, and we stopped waiting. ⚠ Counted apart
     * from a handshake nobody confirmed: ⚠ **one is a connection that never
     * opened, the other one that would not finish closing** — the same division
     * hidetzu/tcpip-stack#59 had to make when one reason was doing two jobs.
     *
     * ⚠ RFC 793 for LAST-ACK: "The only thing that can arrive in this state is
     * an acknowledgment of our FIN." ⚠ The document gives no timeout for it
     * beyond the user timeout, and ⚠ **the interval used is ours** (ADR 0019). */
    HANDSHAKE_REASON_NOBODY_ACKNOWLEDGED_OUR_FIN,

    /* ⚠ Our FIN went out again because nobody had acknowledged it. ⚠ Counted
     * apart from the answer going out again, for the same reason as above.
     *
     * ⚠ RFC 793: "All segments preceding and including FIN will be
     * retransmitted until acknowledged." */
    HANDSHAKE_REASON_OUR_FIN_WENT_OUT_AGAIN,

    /* ⚠ Nobody confirmed it, and we stopped waiting. ⚠ Not the sender being
     * wrong about anything — ⚠ **the sentence a human reads says so**
     * (`CLAUDE.md` §4-1). ⚠ RFC 793's USER TIMEOUT is what this follows:
     * "delete the TCB, enter the CLOSED state and return." */
    HANDSHAKE_REASON_NOBODY_CONFIRMED_IT,

    /* ⚠ A FIN we have read already. ⚠ `RCV.NXT` has moved past where it sits.
     *
     * ⚠ **This is the measured case, not a rare one**: nothing acknowledged the
     * FIN before hidetzu/tcpip-stack#66, and the Linux kernel sent five copies
     * of it in one `close()`. ⚠ Since #66 it stops after one, ⚠ **but a copy
     * that crossed our answer on the wire still lands here.**
     *
     * ⚠ Told apart from one that begins too far ahead since
     * hidetzu/tcpip-stack#76: ⚠ **one is a peer repeating itself and the other
     * is a peer ahead of us**, and a single number could not show a
     * retransmitting peer apart from a broken one. */
    HANDSHAKE_REASON_A_FIN_WE_HAVE_READ_ALREADY,

    /* ⚠ A FIN that begins past what we are waiting for — ⚠ **there are octets
     * before it we have not taken.**
     *
     * ⚠ RFC 793 says a segment with a higher beginning sequence number "may be
     * held for later processing." ⚠ **Nothing here holds anything**, and
     * `docs/SPEC.md` §2 names that gap.
     *
     * ⚠ It is what a FIN riding more octets than the window covers becomes:
     * ⚠ **the data is trimmed to the window, and the FIN then sits past what we
     * took** (hidetzu/tcpip-stack#75). */
    HANDSHAKE_REASON_A_FIN_THAT_BEGINS_TOO_FAR_AHEAD,

    /* ⚠ A FIN arrived and ⚠ **nothing is held for the connection it names.**
     *
     * ⚠ RFC 793, verbatim: "Do not process the FIN if the state is CLOSED,
     * LISTEN or SYN-SENT since the SEG.SEQ cannot be validated; drop the
     * segment and return." ⚠ **Holding nothing is our LISTEN.**
     *
     * ⚠ Counted apart from any other segment arriving for no connection we
     * hold: ⚠ **the document gives this one its own sentence and its own
     * reason**, and folding it in would lose why it was dropped. */
    HANDSHAKE_REASON_A_FIN_WE_CANNOT_PLACE,

    /* ⚠ Data arrived on an open connection, ⚠ **we took delivery of it, and we
     * had nobody to give it to** (hidetzu/tcpip-stack#64 Owner Decision 2).
     *
     * ⚠ Counted apart from a segment the state did not expect: ⚠ **this one was
     * expected** — it is exactly what advertising a window invites — and the two
     * are not the same event.
     *
     * ⚠ `RCV.NXT` advanced, so ⚠ **the same octet is not taken twice**, and
     * ⚠ **the sender is told** — an acknowledgment is built for it
     * (hidetzu/tcpip-stack#74). ⚠ Until then nothing was sent for data at all,
     * and ⚠ **the peer resent the same octet seven times in eight seconds**,
     * measured. */
    HANDSHAKE_REASON_THE_DATA_WAS_TAKEN_AND_DISCARDED,

    /* ⚠ Data every octet of which we have taken already. ⚠ `RCV.NXT` has moved
     * past the end of it.
     *
     * ⚠ **This is what a peer whose acknowledgment was lost sends**, and
     * ⚠ **it is the ordinary case once data moves**, not a rare one. ⚠ Measured
     * 2026-08-29 before hidetzu/tcpip-stack#74: 6 of 7 arrivals were this.
     *
     * ⚠ Nothing is sent for it, which is the gap hidetzu/tcpip-stack#80 owns. */
    HANDSHAKE_REASON_DATA_WE_HAVE_TAKEN_ALREADY,

    /* ⚠ Data that begins past what we are waiting for — ⚠ **there are octets
     * before it we have not seen.**
     *
     * ⚠ RFC 793: "segments with higher beginning sequence numbers may be held
     * for later processing." ⚠ **Nothing here holds anything**; it is refused
     * and counted, and `docs/SPEC.md` §2 names that gap.
     *
     * ⚠ Told apart from data we have taken already since
     * hidetzu/tcpip-stack#76. ⚠ **Until then both were one number and the
     * sentence a human read said "either, or"** — which was honest about what
     * the build knew, and ⚠ **the build knows now.** */
    HANDSHAKE_REASON_DATA_THAT_BEGINS_TOO_FAR_AHEAD,

    /* ⚠ Ours, not the sender's. ⚠ The connection moved and ⚠ the answer could
     * not be built into the buffer we were given. ⚠ Counted rather than dropped
     * in silence (`.claude/rules/c.md`), and ⚠ the sentence a human reads says
     * whose it is (`CLAUDE.md` §4-1). */
    HANDSHAKE_REASON_WE_COULD_NOT_BUILD_THE_REPLY
};

struct handshake_counts {
    unsigned long opened;
    unsigned long established;
    unsigned long asked_again;
    unsigned long acknowledgment_we_are_not_waiting_for;
    unsigned long not_expected_in_this_state;
    unsigned long no_connection_held;
    unsigned long we_could_not_build_the_reply;
    unsigned long given_up_on;
    unsigned long answered_again;

    /* ⚠ **Octets, not segments** — the denominator is stated because the
     * counters around it are all segments (`CLAUDE.md` §6). ⚠ It is what we
     * took delivery of and discarded, and ⚠ **`RCV.NXT` advanced each time, so
     * no octet is counted twice.**
     *
     * ⚠ **Against a peer that honours the window, this reaches 1 and stops.**
     * ⚠ Measured 2026-08-29: with the window at 1 the Linux kernel sends one
     * octet at the same sequence number over and over — 7 copies in 8 seconds —
     * ⚠ **so every arrival after the first is behind `RCV.NXT` and is refused.**
     * ⚠ It climbs only for a peer that sends past what we asked for
     * (`CLAUDE.md` §9: this comment once claimed the opposite, reasoned from a
     * measurement taken with a window of 1024). */
    unsigned long octets_taken_and_discarded;

    /* ⚠ **Segments**, and ⚠ **two numbers where there was one**
     * (hidetzu/tcpip-stack#76): a peer repeating itself, and a peer ahead of us.
     * ⚠ Their sum is what `data_outside_the_window` used to be. */
    unsigned long data_we_have_taken_already;
    unsigned long data_that_begins_too_far_ahead;

    /* ⚠ **Segments.** ⚠ The other side closed and we read its FIN. ⚠ Counted
     * apart from `established`, ⚠ **and both can move for one segment**: RFC 793
     * takes the acknowledgment that opens a connection through to the FIN check
     * in the same pass. */
    unsigned long the_other_side_closed;

    /* ⚠ **Segments** — a FIN we have read already, a FIN beginning past what we
     * are waiting for, and a FIN naming a connection we hold nothing for.
     * ⚠ Kept apart from each other and from everything else
     * (hidetzu/tcpip-stack#65, split at #76). */
    unsigned long fin_we_have_read_already;
    unsigned long fin_that_begins_too_far_ahead;
    unsigned long fin_we_could_not_place;

    /* ⚠ **Segments.** ⚠ An acknowledgment sent for a segment we would not take,
     * counted only once the wire took it. ⚠ Apart from `data_acknowledged`:
     * ⚠ **that one accepted something and this one accepted nothing.** */
    unsigned long told_them_where_we_are;

    /* ⚠ **Segments**, not octets. ⚠ An acknowledgment for data we took, counted
     * only once the wire took the whole of it. ⚠ The caller moves this one.
     *
     * ⚠ Kept apart from `octets_taken_and_discarded`, which is in octets:
     * ⚠ **one says how much arrived, the other how many times we said so**, and
     * ⚠ at a window of 1 they happen to move together — ⚠ **which is exactly
     * why they must not be one number** (`CLAUDE.md` §6). */
    unsigned long data_acknowledged;

    /* ⚠ **Segments.** ⚠ Our own FIN, counted only once the wire took the whole
     * of it — ⚠ **a segment that was built is not a segment that left**, the
     * division everything here uses. ⚠ The caller moves these two, not this
     * file. */
    unsigned long our_fin_left;
    unsigned long our_fin_went_out_again;

    /* ⚠ **Connections.** ⚠ They acknowledged our FIN and the connection was
     * released, so ⚠ **the next SYN can open one** (ADR 0015: there is room for
     * one). */
    unsigned long closed;

    /* ⚠ **Segments** addressed to a broadcast or a multicast address. */
    unsigned long addressed_to_everyone;

    /* ⚠ Apart from the one above: ⚠ **where it was going, against where it
     * claims to have come from.** */
    unsigned long from_an_impossible_source;

    /* ⚠ Two facts, counted apart. ⚠ A `SYN` that carried an MSS Option, and one
     * that did not and got RFC 9293 `MUST-15`'s default of 536 instead.
     * ⚠ **Merged, a connection that told us nothing would be invisible**, and an
     * invisible fact looks exactly like one that never happened
     * (`.claude/rules/c.md`). */
    unsigned long they_told_us_their_segment_size;
    unsigned long they_told_us_nothing_so_we_assumed;

    /* ⚠ Data of ours that actually left, in segments and in octets.
     * ⚠ **Two numbers, because one of them alone cannot show segmentation**:
     * 3000 octets in one segment and 3000 in three are the same octet count and
     * ⚠ **a different thing entirely** (hidetzu/tcpip-stack#126). */
    unsigned long data_segments_we_sent;
    unsigned long data_octets_we_sent;

    /* ⚠ Asked to send and stopped by the peer's window. ⚠ Counted, because
     * ⚠ **a send that did not happen is invisible otherwise** and looks exactly
     * like having nothing to send (`.claude/rules/c.md`). */
    unsigned long their_window_had_no_room;

    /* ⚠ Segments and octets sent AGAIN, counted apart from first transmissions.
     * ⚠ **Octets sent twice are not octets delivered twice**, and a summary that
     * merged them would say this stack moved more data than it did
     * (`CLAUDE.md` §6). */
    unsigned long data_segments_we_sent_again;
    unsigned long data_octets_we_sent_again;

    /* ⚠ Round trips folded into the estimate, and ⚠ **ones refused because
     * Karn's algorithm forbids them.** ⚠ Counted apart: ⚠ **a refused sample is
     * not a sample that never happened**, and a stack whose samples were all
     * refused would look identical to one that measured nothing
     * (`CLAUDE.md` §1). */
    unsigned long round_trips_we_measured;
    unsigned long round_trips_we_would_not_use;

    /* ⚠ Connections where the same thing was sent again R1 times.
     * ⚠ RFC 9293 §3.8.3 (b) asks for negative advice to IP there; ⚠ **there is
     * no IP layer here to advise**, so ⚠ **this is counted and said and
     * `MUST-20` (b) stays not met** (`docs/conformance.md`). */
    unsigned long reached_r1;

    /* ⚠ Connections whose congestion window was cut to the loss window.
     * ⚠ RFC 5681 §3.1: "upon a timeout ... cwnd MUST be set to no more than the
     * loss window". ⚠ **Counted, because a window that shrank and one that was
     * never large look the same from outside** (`CLAUDE.md` §1). */
    unsigned long congestion_windows_we_cut;

    /* ⚠ ICMP errors, ⚠ **each class on its own.** ⚠ Merged, a connection ended
     * by a hard error would be indistinguishable from one left alone by a soft
     * one — ⚠ **which is the whole of what RFC 9293 §3.9.2.2 decides.** */
    unsigned long source_quenches_we_discarded;
    unsigned long soft_errors_that_changed_nothing;
    unsigned long hard_errors_that_ended_a_connection;
    unsigned long errors_the_document_does_not_classify;
    unsigned long errors_for_no_connection_we_hold;

    /* ⚠ **Connections** the other side reset. ⚠ Apart from every other ending:
     * one was closed properly, one timed out, ⚠ **this one was cut.** */
    unsigned long reset_by_the_other_side;

    /* ⚠ **Segments** carrying `URG`, which ⚠ **nothing here can act on.** */
    unsigned long urgent_and_nobody_to_tell;

    /* ⚠ **Segments** carrying a `RST` the window did not cover. */
    unsigned long reset_outside_the_window;

    /* ⚠ **Connections.** ⚠ Nobody acknowledged our FIN and we stopped waiting.
     * ⚠ Apart from `given_up_on`, which is a handshake that never finished. */
    unsigned long never_acknowledged_our_fin;

    /* ⚠ Counted only once the wire took the whole answer. ⚠ A reply that was
     * built is not a reply that left — the same division `arp_respond` and
     * `echo_respond` use (`CLAUDE.md` §1, in the sending direction). ⚠ The
     * caller moves this one, not this file. */
    unsigned long answered;

    /* ⚠ The refusal `src/connection.c` already counts, carried here so a caller
     * has one place to look (hidetzu/tcpip-stack#42). */
    struct connection_counts room;
};

struct handshake_outcome {
    enum handshake_decision decision;
    enum handshake_reason reason;

    /* ⚠ The state after. ⚠ Meaningful whenever a connection was held or taken;
     * `CONNECTION_LISTEN` when none was. */
    enum connection_state state;

    /* ⚠ Which connection this was about, filled whatever was decided, so a
     * caller can say so without reading the octets itself. */
    struct connection_id id;

    /* ⚠ For the sentence a human reads when an acknowledgment was not the one
     * we wait for. ⚠ Meaningful only for that reason. */
    uint32_t acknowledgment_we_had;
    uint32_t acknowledgment_we_expected;

    /* ⚠ How many octets of data we took delivery of and discarded. ⚠ 0 unless
     * the segment carried data the window covered, and ⚠ **it can be non-zero
     * alongside a connection reaching ESTABLISHED**: the acknowledgment that
     * opens a connection may carry data, and ⚠ **a payload nobody counted is
     * indistinguishable from one that never arrived** (`.claude/rules/c.md`).
     * ⚠ That is why this is a field and not a reason — ⚠ `counts` still gains
     * exactly one reason per segment. */
    uint16_t octets_taken;

    /* ⚠ True when this segment's FIN was read and `RCV.NXT` moved over it.
     * ⚠ Its own field rather than a reason, ⚠ **because a segment can both
     * open a connection and close it** — RFC 793 goes on to the FIN check after
     * entering ESTABLISHED, in the same pass — and ⚠ a reason cannot say two
     * things (hidetzu/tcpip-stack#65). */
    bool the_fin_was_read;

    /* ⚠ What we would acknowledge for this connection now, ⚠ **as a number.**
     * ⚠ Meaningful whenever a connection was held or taken. ⚠ It is `RCV.NXT`
     * after everything this segment moved, so ⚠ **a FIN that was read has
     * already been counted into it** — RFC 793: "advance RCV.NXT over the FIN".
     * ⚠ Nothing sends it; hidetzu/tcpip-stack#66 does. */
    uint32_t we_would_acknowledge;

    /* ⚠ Which segment was built, so ⚠ **a caller counts what left under the
     * right name without deciding which it was.** ⚠ `HANDSHAKE_REPLY_NONE`
     * whenever `reply_bytes` is 0. */
    enum handshake_reply reply;

    /* ⚠ How many octets of the caller's reply buffer were written. ⚠ 0 unless a
     * SYN opened a connection, and ⚠ a caller must not send what was not
     * built. */
    size_t reply_bytes;
};

/* Take one already-read segment through whatever transition it causes.
 *
 * `header` must have come back `TCP_PARSE_OK` from `tcp_parse_header` — ⚠ this
 * layer never re-checks what the Parse layer already decided, and ⚠ it must not
 * be handed a segment whose checksum was not judged (`CLAUDE.md` §1, the whole
 * reason hidetzu/tcpip-stack#41 made that an outcome).
 *
 * `id` is the connection the segment belongs to, ⚠ built by the caller from the
 * internet header and the ports — ⚠ this layer reads no address.
 *
 * `listening_port` is the port this stack answers for. ⚠ A segment for any other
 * local port is not ours to open.
 *
 * ⚠ `counts` gains exactly one, under the reason decided — ⚠ **with one
 * exception the document forces**: a segment that both opens a connection and
 * closes it moves `established` and `the_other_side_closed` together, because
 * ⚠ **RFC 793 goes on to the FIN check after entering ESTABLISHED, in the same
 * pass**, and ⚠ a single reason cannot say two things (ADR 0022). ⚠ The octets
 * taken are their own number for the same cause.
 * ⚠ Nothing is sent here and nothing is printed here. */
/* `requester_hardware_address` is the arriving frame's ethernet source — ⚠ where
 * an answer would have to go, taken from that frame and ⚠ never from a table
 * this stack does not keep.
 *
 * `reply` is the caller's buffer for a whole frame, ⚠ ethernet header included.
 *
 * ⚠ What goes in the answer, and none of it is guessed:
 *
 *     Control Bits     SYN and ACK — RFC 793: "<SEQ=ISS><ACK=RCV.NXT>
 *                      <CTL=SYN,ACK>"
 *     Sequence Number  ISS
 *     Acknowledgment   RCV.NXT
 *     Window           ⚠ `RCV.WND`, what one frame carries on this device,
 *                      and ⚠ **it is a promise this
 *                      stack keeps in taking**: `take_the_data` accepts that
 *                      many octets and discards them
 *                      (hidetzu/tcpip-stack#64 Owner Decisions 1 and 2)
 *     Options          ⚠ none (Owner Decision 2)
 *
 * ⚠ Since hidetzu/tcpip-stack#74 the same buffer also carries a bare
 * acknowledgment for data we took:
 *
 *     Control Bits     ACK — RFC 793: "<SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>"
 *     Sequence Number  `SND.NXT`, ⚠ **unmoved**: an ACK is "A control bit
 *                      (acknowledge) occupying no sequence space", so
 *                      ⚠ **nothing is consumed and there is nothing to
 *                      retransmit**
 *     Acknowledgment   RCV.NXT, ⚠ already advanced over what was taken
 *
 * ⚠ Since hidetzu/tcpip-stack#66 the same buffer also carries our own FIN:
 *
 *     Control Bits     FIN and ACK — ⚠ **one segment, not two**, measured
 *     Sequence Number  `SND.NXT` before the FIN, ⚠ which is the sequence
 *                      number the FIN occupies and ⚠ **the one every
 *                      retransmission of it repeats**
 *     Acknowledgment   RCV.NXT, ⚠ already advanced over their FIN
 *
 * ⚠ An answer is built only when a SYN opened a connection. ⚠ The three places
 * RFC 793 §3.9 asks for a reset or an ack produce a counted reason and nothing
 * on the wire; `docs/SPEC.md` §2 names them. */
void handshake_receive(const struct tcp_header *header, const struct connection_id *id,
                       uint16_t listening_port, uint16_t window,
                       uint16_t maximum_segment_size, uint32_t octets_to_send,
                       struct moment now,
                       uint8_t time_to_live,
                       const uint8_t *requester_hardware_address,
                       const uint8_t *our_hardware_address,
                       struct connections *connections,
                       uint8_t *reply, size_t reply_bytes,
                       struct handshake_counts *counts,
                       struct handshake_outcome *outcome);

/* What a timer says should happen now. ⚠ An enum never reaches a human. */
enum handshake_due {
    /* ⚠ Nothing is waiting, or what is waiting is not due yet. */
    HANDSHAKE_NOTHING_DUE = 0,

    /* ⚠ The answer should go out again. ⚠ The timer is already reinitialised
     * when this is returned — RFC 793 makes sending again and reinitialising one
     * step, and ⚠ **a caller that then fails to send has spent the attempt.**
     * ⚠ It cannot spin: the give-up timer still runs. */
    HANDSHAKE_ANSWER_AGAIN,

    /* ⚠ Nobody confirmed it and we have stopped waiting. ⚠ The connection is
     * already released when this is returned, so ⚠ **the next SYN can open
     * one** — there is room for exactly one (ADR 0015). */
    HANDSHAKE_GIVE_UP
};

/* Say what `now` makes due, and move the state accordingly.
 *
 * ⚠ `now` is handed in and never read here (ADR 0018), which is why ⚠ **every
 * check of this runs with no clock and no waiting.**
 *
 * ⚠ Giving up is decided before answering again, so ⚠ **at the moment both are
 * due the connection is given up on rather than answered a third time.**
 *
 * ⚠ `counts` gains exactly one when a connection is given up on. ⚠ Answering
 * again is NOT counted here — ⚠ **a reply that was built is not a reply that
 * left**, and the caller counts what the wire took (`CLAUDE.md` §1).
 *
 * ⚠ Nothing is sent here and nothing is printed here. */
/* ⚠ `reply` is the caller's buffer for a whole frame, ⚠ ethernet header
 * included, exactly as `handshake_receive` takes one. ⚠ On
 * `HANDSHAKE_ANSWER_AGAIN` the answer is built into it and `outcome->reply_bytes`
 * says how much; ⚠ **0 for everything else, and a caller must not send what was
 * not built.**
 *
 * `our_hardware_address` is ours; ⚠ **the requester's is remembered in the
 * connection**, because a retransmission has no arriving frame to read it from. */
enum handshake_due handshake_what_is_due(struct connections *connections,
                                         struct moment now, uint8_t time_to_live,
                                         const uint8_t *our_hardware_address,
                                         uint8_t *reply, size_t reply_bytes,
                                         struct handshake_counts *counts,
                                         struct handshake_outcome *outcome);

/* Build the next data segment, if one is due.
 *
 * ⚠ Returns false when nothing is due — nothing left to send, no connection
 * open, or ⚠ **the peer's window has no room.**
 *
 * ⚠ **The caller drains this in a loop** (`src/tcpip_stack.c`). ⚠ Putting the
 * loop here would mean this function owning the device, and ⚠ **the State layer
 * does not touch an fd** (`.claude/rules/layers.md`).
 *
 * ⚠ **At most the effective send MSS of data per segment** — RFC 9293
 * `MUST-16` — ⚠ **and never past `SND.UNA + SND.WND`.**
 *
 * ⚠ **`now` is handed in and never read** (ADR 0018). ⚠ It decides whether the
 * earliest unacknowledged octet is due again — ⚠ **RFC 6298 §5.4: "Retransmit
 * the earliest segment that has not been acknowledged."**
 *
 * ⚠ **Winding `SND.NXT` back to `SND.UNA` reproduces exactly what was sent**,
 * because the octets are a pattern and not a buffer (ADR 0030). ⚠ **That is a
 * simplification this stack has and a real one does not**, and
 * `docs/SPEC.md` §2 says so.
 *
 * ⚠ **`mtu`, not a precomputed size.** ⚠ The effective send MSS is the smaller
 * of what the PEER told us and what one of OUR frames carries, and ⚠ **the first
 * half is per connection** — so it is computed here, per block, rather than
 * handed in as one number for all of them. */
bool handshake_send_what_is_next(struct connections *connections,
                                 unsigned int mtu, struct moment now,
                                 uint8_t time_to_live,
                                 const uint8_t *our_hardware_address,
                                 uint8_t *reply, size_t reply_bytes,
                                 struct handshake_counts *counts,
                                 struct handshake_outcome *outcome);

/* The next moment anything is waiting for, if anything is.
 *
 * ⚠ Returns false when nothing is waiting. ⚠ For a caller about to decide how
 * long to wait (hidetzu/tcpip-stack#58). */
/* An ICMP error naming one of our connections.
 *
 * ⚠ RFC 9293 `MUST-54`: "TCP implementations MUST act on an ICMP error message
 * passed up from the IP layer, **directing it to the connection that created the
 * error**."
 *
 * ⚠ `id` is built from what the error carried back — ⚠ **the addresses from the
 * internet header it quotes and the ports from the first 64 bits of the
 * datagram's data** (RFC 792). ⚠ **It is in the same orientation every other
 * caller here uses**: `local` is ours.
 *
 * ⚠ **Nothing is sent, ever.** ⚠ Not for a Source Quench — `MUST-55`'s
 * "silently" forbids it — ⚠ and not for the others either: RFC 9293 asks for a
 * connection to be left alone or ended, ⚠ **and neither is a segment.**
 *
 * ⚠ **`connections` is not const**: a hard error deletes a block. */
void handshake_receive_error(struct connections *connections,
                             const struct connection_id *id,
                             enum icmp_error_class what,
                             struct handshake_counts *counts,
                             struct handshake_outcome *outcome);

bool handshake_next_moment(const struct connections *connections,
                           struct moment *due);

#endif /* HANDSHAKE_H */
