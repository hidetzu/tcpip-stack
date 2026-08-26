#include "check.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FIXTURE_DIRECTORY_DEFAULT "tests/fixtures"

static const char *fixture_directory = FIXTURE_DIRECTORY_DEFAULT;

long check_load_fixture(const char *name, unsigned char *into, size_t capacity)
{
    char path[512];
    if ((size_t)snprintf(path, sizeof path, "%s/%s", fixture_directory, name) >= sizeof path) {
        fprintf(stderr, "  the path to fixture %s does not fit\n", name);
        return -1;
    }
    FILE *file = fopen(path, "r");
    if (file == NULL) {
        fprintf(stderr, "  could not read fixture %s: %s\n", path, strerror(errno));
        return -1;
    }

    long bytes = 0;
    char line[256];
    while (fgets(line, sizeof line, file) != NULL) {
        if (line[0] == '#' || line[0] == '\n') {
            continue;
        }
        for (const char *at = line; *at != '\0';) {
            if (*at == ' ' || *at == '\n' || *at == '\t' || *at == '\r') {
                at++;
                continue;
            }
            unsigned value = 0;
            if (sscanf(at, "%2x", &value) != 1) {
                fprintf(stderr, "  fixture %s has something that is not a byte\n", path);
                fclose(file);
                return -1;
            }
            if ((size_t)bytes >= capacity) {
                fprintf(stderr, "  fixture %s is larger than the buffer for it\n", path);
                fclose(file);
                return -1;
            }
            into[bytes++] = (unsigned char)value;
            at += 2;
        }
    }
    fclose(file);
    return bytes;
}

int check_main(const char *suite_name, const struct test_case *cases, size_t case_count,
               int argc, char **argv)
{
    const char *only = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--count") == 0) {
            /* ⚠ Counts without running and without touching a fixture. */
            printf("%s: %zu cases\n", suite_name, case_count);
            return 0;
        }
        if (strcmp(argv[i], "--list") == 0) {
            for (size_t c = 0; c < case_count; c++) {
                printf("%s\n", cases[c].name);
            }
            return 0;
        }
        if (strcmp(argv[i], "--case") == 0 && i + 1 < argc) {
            only = argv[++i];
            continue;
        }
        if (strcmp(argv[i], "--fixtures") == 0 && i + 1 < argc) {
            fixture_directory = argv[++i];
            continue;
        }
        fprintf(stderr, "usage: %s [--case NAME] [--fixtures DIR] [--list] [--count]\n",
                argv[0]);
        return 2;
    }

    size_t selected = 0;
    for (size_t c = 0; c < case_count; c++) {
        if (only == NULL || strcmp(only, cases[c].name) == 0) {
            selected++;
        }
    }
    if (selected == 0) {
        fprintf(stderr, "%s: no case is named %s\n", suite_name, only);
        return 2;
    }

    /* ⚠ The first line says which subset ran (`.claude/skills/verify` §1). */
    if (only == NULL) {
        printf("%s: running %zu of %zu cases\n", suite_name, selected, case_count);
    } else {
        printf("%s: running %zu of %zu cases (%s)\n", suite_name, selected, case_count, only);
    }

    size_t passed = 0;
    for (size_t c = 0; c < case_count; c++) {
        if (only != NULL && strcmp(only, cases[c].name) != 0) {
            continue;
        }
        bool ok = cases[c].run();
        printf("  %-44s %s\n", cases[c].name, ok ? "ok" : "FAILED");
        if (ok) {
            passed++;
        }
    }

    printf("%s: %zu of %zu cases passed\n", suite_name, passed, selected);
    return passed == selected ? 0 : 1;
}
