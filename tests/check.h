/* The plumbing every static-tier check binary needs.
 *
 * ⚠ `.claude/skills/verify/SKILL.md` §1 makes three things a contract: run one
 * named case on its own, count without loading anything heavy, and say on the
 * first line which subset ran. ⚠ It is implemented here once, so two binaries
 * cannot drift apart from each other or from the shell tiers (`CLAUDE.md` §3).
 *
 * ⚠ Nothing here knows anything about a layer. It runs cases and reads
 * fixtures; what a case asserts belongs to the binary that declares it. */
#ifndef CHECK_H
#define CHECK_H

#include <stdbool.h>
#include <stddef.h>

struct test_case {
    const char *name;
    bool (*run)(void);
};

/* Reads a hex fixture into a caller-supplied buffer, from wherever --fixtures
 * pointed. Lines starting with '#' are provenance, not octets.
 *
 * Returns the number of octets placed in `into`, or -1 with the reason already
 * printed. ⚠ Bounds come from `capacity`, never from the file's own size. */
long check_load_fixture(const char *name, unsigned char *into, size_t capacity);

/* Parses argv, runs the selected cases, and returns the process exit code:
 * 0 when every selected case passed, 1 when one did not, 2 when the arguments
 * did not name anything that could be run. */
int check_main(const char *suite_name, const struct test_case *cases, size_t case_count,
               int argc, char **argv);

#endif /* CHECK_H */
