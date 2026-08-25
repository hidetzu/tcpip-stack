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

HEADERS      := src/tap.h src/report.h
LIB_SOURCES  := src/tap.c src/report.c
MAIN_SOURCE  := src/tap_read.c
TEST_SOURCE  := tests/test_report.c

TAP_READ            := $(BUILD)/tap-read
TAP_READ_SANITIZED  := $(BUILD)/tap-read.sanitized
TEST_REPORT         := $(BUILD)/test_report.sanitized

# Passed through to a check script, so one named case can be run on its own:
#   make check-static CHECK_ARGS="--case report_lines"
CHECK_ARGS ?=

.PHONY: all build build-sanitized check check-static check-real check-foreign clean

all: build

build: $(TAP_READ)

build-sanitized: $(TAP_READ_SANITIZED) $(TEST_REPORT)

$(TAP_READ): $(MAIN_SOURCE) $(LIB_SOURCES) $(HEADERS)
	@mkdir -p $(@D)
	$(CC) $(STD) $(WARN) $(OPT) -Isrc -o $@ $(MAIN_SOURCE) $(LIB_SOURCES)

$(TAP_READ_SANITIZED): $(MAIN_SOURCE) $(LIB_SOURCES) $(HEADERS)
	@mkdir -p $(@D)
	$(CC) $(STD) $(WARN) $(OPT) $(SANITIZE) -Isrc -o $@ $(MAIN_SOURCE) $(LIB_SOURCES)

$(TEST_REPORT): $(TEST_SOURCE) $(LIB_SOURCES) $(HEADERS)
	@mkdir -p $(@D)
	$(CC) $(STD) $(WARN) $(OPT) $(SANITIZE) -Isrc -o $@ $(TEST_SOURCE) $(LIB_SOURCES)

check: check-static check-real check-foreign

check-static:
	@MAKE="$(MAKE)" tests/static.sh $(CHECK_ARGS)

check-real:
	@MAKE="$(MAKE)" tests/real.sh $(CHECK_ARGS)

check-foreign:
	@MAKE="$(MAKE)" tests/foreign.sh $(CHECK_ARGS)

clean:
	rm -rf $(BUILD)
