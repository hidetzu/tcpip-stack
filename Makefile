# How each check is started.
#
# ⚠ Which checks to run, and in what order, is `.claude/skills/verify/SKILL.md`.
# ⚠ This file never says that (written in two places, one of them goes stale).

CC      ?= cc
# ⚠ -std=c11 alone hides everything POSIX and GNU: no sigset_t, no ppoll,
# no getopt_long, no open_memstream. The feature macro is set here, once, so no
# translation unit can end up compiled against a different set of declarations
# from the header it includes.
STD     := -std=c11 -D_GNU_SOURCE
WARN    := -Wall -Wextra -Werror
OPT     ?= -O2 -g
BUILD   := build

# ⚠ ASan and UBSan, and neither of them allowed to keep going after a finding:
# a sanitizer that reports and continues turns a defect into a log line.
SANITIZE := -fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all

HEADERS      := src/tap.h src/report.h src/ethernet.h src/arp.h src/arp_responder.h src/checksum.h src/ipv4.h src/icmp.h
LIB_SOURCES  := src/tap.c src/report.c src/ethernet.c src/arp.c src/arp_responder.c src/checksum.c src/ipv4.c src/icmp.c
MAIN_SOURCE  := src/tcpip_stack.c

# What a static-tier check binary links besides its own case file. ⚠ The same
# files are in LIB_SOURCES: the program answers ARP requests, so it links them
# (hidetzu/tcpip-stack#19).
#
# ⚠ This comment used to open by saying the Parse layer was deliberately kept
# out of tcpip-stack. ⚠ That stopped being true at #19, and the sentence was left
# standing above the line that contradicted it — ⚠ replaced here rather than
# added to (`CLAUDE.md` §5: a stale comment misleads harder than stale code).
#
# ⚠ src/checksum.c, src/ipv4.c and src/icmp.c have no caller in the program yet
# (hidetzu/tcpip-stack#35). ⚠ They are compiled at -O2 with -Werror and the
# sanitizers either way, by the checks below.
PARSE_SOURCES := src/ethernet.c src/arp.c src/arp_responder.c src/checksum.c src/ipv4.c src/icmp.c

# ⚠ verify §1's contract — one named case, counting without loading anything
# heavy, the first line saying which subset ran — is implemented once, in
# tests/check.c, and linked into every static-tier binary (`CLAUDE.md` §3).
# ⚠ A real-tier driver, and it is harness rather than product: tests/ never
# src/, and nothing in the shipped binary calls it (`CLAUDE.md` §3). It has its
# own target so the real tier does not have to build the static tier's binaries
# to get at it.
SEND_ONE_FRAME_SOURCE := tests/send_one_frame.c

CHECK_SOURCES        := tests/check.c
CHECK_HEADERS        := tests/check.h
TEST_REPORT_SOURCE   := tests/test_report.c
TEST_ETHERNET_SOURCE := tests/test_ethernet.c
TEST_ARP_SOURCE      := tests/test_arp.c
TEST_RESPONDER_SOURCE := tests/test_arp_responder.c
TEST_CHECKSUM_SOURCE  := tests/test_checksum.c
TEST_IPV4_SOURCE      := tests/test_ipv4.c
TEST_ICMP_SOURCE      := tests/test_icmp.c

TCPIP_STACK         := $(BUILD)/tcpip-stack
TCPIP_STACK_SANITIZED := $(BUILD)/tcpip-stack.sanitized
TEST_REPORT         := $(BUILD)/test_report.sanitized
TEST_ETHERNET       := $(BUILD)/test_ethernet.sanitized
TEST_ARP            := $(BUILD)/test_arp.sanitized
TEST_RESPONDER      := $(BUILD)/test_arp_responder.sanitized
TEST_CHECKSUM       := $(BUILD)/test_checksum.sanitized
TEST_IPV4           := $(BUILD)/test_ipv4.sanitized
TEST_ICMP           := $(BUILD)/test_icmp.sanitized
SEND_ONE_FRAME      := $(BUILD)/send-one-frame

# Passed through to a check script, so one named case can be run on its own:
#   make check-static CHECK_ARGS="--case report_lines"
CHECK_ARGS ?=

.PHONY: all build build-sanitized build-harness check check-static check-real check-foreign clean

all: build

build: $(TCPIP_STACK)

build-sanitized: $(TCPIP_STACK_SANITIZED) $(TEST_REPORT) $(TEST_ETHERNET) $(TEST_ARP) $(TEST_RESPONDER) $(TEST_CHECKSUM) $(TEST_IPV4) $(TEST_ICMP)

build-harness: $(SEND_ONE_FRAME)

$(TCPIP_STACK): $(MAIN_SOURCE) $(LIB_SOURCES) $(HEADERS)
	@mkdir -p $(@D)
	$(CC) $(STD) $(WARN) $(OPT) -Isrc -o $@ $(MAIN_SOURCE) $(LIB_SOURCES)

$(TCPIP_STACK_SANITIZED): $(MAIN_SOURCE) $(LIB_SOURCES) $(HEADERS)
	@mkdir -p $(@D)
	$(CC) $(STD) $(WARN) $(OPT) $(SANITIZE) -Isrc -o $@ $(MAIN_SOURCE) $(LIB_SOURCES)

$(TEST_REPORT): $(TEST_REPORT_SOURCE) $(CHECK_SOURCES) $(LIB_SOURCES) $(HEADERS) $(CHECK_HEADERS)
	@mkdir -p $(@D)
	$(CC) $(STD) $(WARN) $(OPT) $(SANITIZE) -Isrc -Itests -o $@ \
		$(TEST_REPORT_SOURCE) $(CHECK_SOURCES) $(LIB_SOURCES)

$(TEST_ETHERNET): $(TEST_ETHERNET_SOURCE) $(CHECK_SOURCES) $(PARSE_SOURCES) $(HEADERS) $(CHECK_HEADERS)
	@mkdir -p $(@D)
	$(CC) $(STD) $(WARN) $(OPT) $(SANITIZE) -Isrc -Itests -o $@ \
		$(TEST_ETHERNET_SOURCE) $(CHECK_SOURCES) $(PARSE_SOURCES)

$(TEST_ICMP): $(TEST_ICMP_SOURCE) $(CHECK_SOURCES) $(PARSE_SOURCES) $(HEADERS) $(CHECK_HEADERS)
	@mkdir -p $(@D)
	$(CC) $(STD) $(WARN) $(OPT) $(SANITIZE) -Isrc -Itests -o $@ \
		$(TEST_ICMP_SOURCE) $(CHECK_SOURCES) $(PARSE_SOURCES)

$(TEST_IPV4): $(TEST_IPV4_SOURCE) $(CHECK_SOURCES) $(PARSE_SOURCES) $(HEADERS) $(CHECK_HEADERS)
	@mkdir -p $(@D)
	$(CC) $(STD) $(WARN) $(OPT) $(SANITIZE) -Isrc -Itests -o $@ \
		$(TEST_IPV4_SOURCE) $(CHECK_SOURCES) $(PARSE_SOURCES)

$(TEST_CHECKSUM): $(TEST_CHECKSUM_SOURCE) $(CHECK_SOURCES) $(PARSE_SOURCES) $(HEADERS) $(CHECK_HEADERS)
	@mkdir -p $(@D)
	$(CC) $(STD) $(WARN) $(OPT) $(SANITIZE) -Isrc -Itests -o $@ \
		$(TEST_CHECKSUM_SOURCE) $(CHECK_SOURCES) $(PARSE_SOURCES)

$(TEST_RESPONDER): $(TEST_RESPONDER_SOURCE) $(CHECK_SOURCES) $(PARSE_SOURCES) $(HEADERS) $(CHECK_HEADERS)
	@mkdir -p $(@D)
	$(CC) $(STD) $(WARN) $(OPT) $(SANITIZE) -Isrc -Itests -o $@ \
		$(TEST_RESPONDER_SOURCE) $(CHECK_SOURCES) $(PARSE_SOURCES)

$(TEST_ARP): $(TEST_ARP_SOURCE) $(CHECK_SOURCES) $(PARSE_SOURCES) $(HEADERS) $(CHECK_HEADERS)
	@mkdir -p $(@D)
	$(CC) $(STD) $(WARN) $(OPT) $(SANITIZE) -Isrc -Itests -o $@ \
		$(TEST_ARP_SOURCE) $(CHECK_SOURCES) $(PARSE_SOURCES)

$(SEND_ONE_FRAME): $(SEND_ONE_FRAME_SOURCE) $(LIB_SOURCES) $(HEADERS)
	@mkdir -p $(@D)
	$(CC) $(STD) $(WARN) $(OPT) $(SANITIZE) -Isrc -o $@ \
		$(SEND_ONE_FRAME_SOURCE) $(LIB_SOURCES)

check: check-static check-real check-foreign

check-static:
	@MAKE="$(MAKE)" tests/static.sh $(CHECK_ARGS)

check-real:
	@MAKE="$(MAKE)" tests/real.sh $(CHECK_ARGS)

check-foreign:
	@MAKE="$(MAKE)" tests/foreign.sh $(CHECK_ARGS)

clean:
	rm -rf $(BUILD)
