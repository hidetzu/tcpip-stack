/* Report — everything a human reads, and the only place any of it is written.
 *
 * ⚠ No decision is taken here and no byte of a frame is interpreted. This layer
 * is handed numbers and turns them into sentences (`.claude/rules/layers.md`).
 *
 * ⚠ The wording below is an owner decision (hidetzu/tcpip-stack#2). It is not
 * changed on our own judgement, and the checks assert it byte for byte. */
#ifndef REPORT_H
#define REPORT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "tap.h"

void report_listening(FILE *out, const char *device_name);

/* `filled_buffer` is true when the read returned exactly as many bytes as the
 * buffer holds. ⚠ The length is then unknown, and the line says so rather than
 * printing it as if it were measured (`CLAUDE.md` §1). */
void report_frame(FILE *out, unsigned long frame_number, size_t bytes,
                  bool filled_buffer);

void report_frame_bytes(FILE *out, const uint8_t *frame, size_t bytes);

void report_read_failure(FILE *out, unsigned long frame_number,
                         const struct tap_failure *failure);

void report_summary(FILE *out, unsigned long frames_read, unsigned long read_errors);

/* ⚠ A timer running out is the absence of an answer, not an answer. The wording
 * says what we did and what reached us here, and claims nothing about what the
 * other side sent (`CLAUDE.md` §4-1). */
void report_timeout(FILE *out, const char *device_name, int timeout_ms,
                    unsigned long frames_read);

void report_attach_failure(FILE *out, const char *device_name,
                           const struct tap_failure *failure);

void report_wait_failure(FILE *out, const char *device_name,
                         const struct tap_failure *failure);

void report_usage(FILE *out, const char *program_name);

#endif /* REPORT_H */
