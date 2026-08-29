#!/usr/bin/env python3
# ⚠ A quotation carrying a lowercase `should` or `must` must not be introduced as
# something the authority REQUIRES.
#
# ⚠ Grounds: `CLAUDE.md` §9. ⚠ It happened three times in one day — a claim called
# "contradicted", an issue cut for it, and a comment saying "the document's rule
# and not ours" — ⚠ **each about a sentence whose keyword was lowercase.**
#
# ⚠ RFC 2119 keywords bind only in capitals, and RFC 9293 §2 says so of itself.
# ⚠ `CLAUDE.md` §1 already listed four things — MUST, SHOULD, MAY and silence.
# ⚠ **A lowercase keyword is a fifth, and it looks exactly like the second.**
#
# ⚠ **What this cannot stop**: a requirement claimed with no quotation at all.
# ⚠ That is the harder half and it is named rather than pretended away.
#
# Exit: 0 when nothing is claimed that way, 1 otherwise.
import os
import re
import sys

# ⚠ Words that introduce a quotation as an obligation. ⚠ Every one of them was
# in the text that had to be withdrawn.
CLAIMS_A_REQUIREMENT = (
    r"(asks for|requires|required by|the document's rule|the document requires"
    r"|is required|the standard requires)"
)
A_QUOTATION = r'"([^"]{20,400}?)"'
LOWERCASE_KEYWORD = r"\b(should|must)\b"
A_CAPITALISED_KEYWORD = r"\b(MUST|SHOULD|MAY)\b"

# ⚠ How far either side counts as "introduced by". ⚠ Measured against the three
# real cases: the furthest was 240 characters.
NEAR = 300

# ⚠ In a Markdown table one row is one line, and ⚠ **300 characters straddles
# two of them.** ⚠ Measured: `docs/SPEC.md` had two unrelated rows, one quoting
# a lowercase keyword and the next saying "asks for" about something else, and
# ⚠ **this check called it a hit.** ⚠ So for Markdown the window stops at the
# line, ⚠ which is where a row's meaning stops.


def files_to_read(root):
    for where in ("src", "tests", "docs"):
        for directory, _, names in os.walk(os.path.join(root, where)):
            for name in sorted(names):
                if name.endswith((".c", ".h", ".md", ".sh")):
                    yield os.path.join(directory, name)


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else "."
    read = 0
    quotations = 0
    found = []
    for path in files_to_read(root):
        with open(path, encoding="utf-8", errors="replace") as handle:
            text = handle.read()
        read += 1
        for match in re.finditer(A_QUOTATION, text, re.S):
            quoted = match.group(1)
            if not re.search(LOWERCASE_KEYWORD, quoted):
                continue
            # ⚠ A quotation that also carries a capitalised keyword is a
            # requirement, and saying so is right.
            if re.search(A_CAPITALISED_KEYWORD, quoted):
                continue
            quotations += 1
            before_from = max(0, match.start() - NEAR)
            after_to = match.end() + NEAR
            if path.endswith(".md"):
                line_began = text.rfind("\n", 0, match.start()) + 1
                line_ended = text.find("\n", match.end())
                before_from = max(before_from, line_began)
                after_to = after_to if line_ended < 0 else min(after_to, line_ended)
            near = text[before_from:match.start()] + text[match.end():after_to]
            claim = re.search(CLAIMS_A_REQUIREMENT, near)
            # ⚠ Saying "lowercase" nearby is the whole point: the writer looked.
            if claim and not re.search(r"lowercase", near, re.I):
                line = text[:match.start()].count("\n") + 1
                found.append((os.path.relpath(path, root), line, claim.group(0),
                              quoted[:60].replace("\n", " ")))

    # ⚠ Both halves. ⚠ Reading nothing would make this green for an empty tree.
    if read < 20 or quotations < 10:
        print("    read %d files and %d quotations carrying a lowercase keyword, "
              "which cannot be right" % (read, quotations), file=sys.stderr)
        return 2

    for path, line, claim, quoted in found:
        print('    %s:%d introduces "%s..." with "%s"'
              % (path, line, quoted, claim), file=sys.stderr)
    print("    %d files, %d quotations carrying a lowercase keyword, %d claimed "
          "as a requirement" % (read, quotations, len(found)))
    return 1 if found else 0


sys.exit(main())
