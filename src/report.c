#include "report.h"

#include <errno.h>
#include <string.h>

/* ⚠ 8 bytes, two spaces, 8 bytes — the shape the owner approved
 * (hidetzu/tcpip-stack#2). */
#define BYTES_PER_HEX_LINE 16
#define BYTES_PER_HEX_GROUP 8

static const char *plural(unsigned long count)
{
    return count == 1 ? "" : "s";
}

void report_listening(FILE *out, const char *device_name)
{
    fprintf(out, "listening on %s\n", device_name);
}

void report_frame(FILE *out, unsigned long frame_number, size_t bytes,
                  bool filled_buffer)
{
    if (filled_buffer) {
        fprintf(out, "frame %lu  %zu bytes (filled the buffer; it may have been longer)\n",
                frame_number, bytes);
        return;
    }
    fprintf(out, "frame %lu  %zu bytes\n", frame_number, bytes);
}

void report_frame_bytes(FILE *out, const uint8_t *frame, size_t bytes)
{
    for (size_t offset = 0; offset < bytes; offset += BYTES_PER_HEX_LINE) {
        fprintf(out, "  %04zx", offset);
        for (size_t i = 0; i < BYTES_PER_HEX_LINE && offset + i < bytes; i++) {
            /* Two spaces open a group of eight, one space separates bytes
             * inside it. ⚠ A short last line ends after its last byte — no
             * padding, so nothing looks like a byte that was not read. */
            const char *separator = (i % BYTES_PER_HEX_GROUP == 0) ? "  " : " ";
            fprintf(out, "%s%02x", separator, frame[offset + i]);
        }
        fputc('\n', out);
    }
}

void report_read_failure(FILE *out, unsigned long frame_number,
                         const struct tap_failure *failure)
{
    fprintf(out, "frame %lu  could not be read: %s\n", frame_number,
            strerror(failure->errnum));
}

void report_summary(FILE *out, unsigned long frames_read, unsigned long read_errors)
{
    fprintf(out, "read %lu frame%s, %lu read error%s\n", frames_read,
            plural(frames_read), read_errors, plural(read_errors));
}

void report_timeout(FILE *out, const char *device_name, int timeout_ms,
                    unsigned long frames_read)
{
    if (frames_read == 0) {
        fprintf(out,
                "listened on %s for %d ms and read 0 frames. Nothing arrived here; "
                "that does not say whether anything was sent.\n",
                device_name, timeout_ms);
        return;
    }
    fprintf(out,
            "listened on %s for %d ms after frame %lu and read no more. "
            "That does not say whether anything more was sent.\n",
            device_name, timeout_ms, frames_read);
}

void report_attach_failure(FILE *out, const char *device_name,
                           const struct tap_failure *failure)
{
    switch (failure->step) {
    case TAP_STEP_NAME:
        fprintf(out, "could not attach to \"%s\": a device name is 1 to %d characters.\n",
                device_name, TAP_DEVICE_NAME_MAX);
        return;
    case TAP_STEP_OPEN:
        fprintf(out, "could not attach to %s: opening /dev/net/tun failed: %s\n",
                device_name, strerror(failure->errnum));
        if (failure->errnum == ENOENT) {
            fprintf(out, "  The tun driver may not be loaded: modprobe tun.\n");
        }
        return;
    case TAP_STEP_ATTACH:
        fprintf(out, "could not attach to %s: creating the device failed: %s\n",
                device_name, strerror(failure->errnum));
        if (failure->errnum == EPERM) {
            fprintf(out,
                    "  Creating a TAP device needs CAP_NET_ADMIN in the namespace that "
                    "owns it. The checks here get it from unshare -Urn, without sudo.\n");
        }
        if (failure->errnum == EBUSY) {
            fprintf(out,
                    "  Something else is already attached to that device. "
                    "Choose another name with --dev.\n");
        }
        return;
    case TAP_STEP_NONE:
    case TAP_STEP_WAIT:
    case TAP_STEP_READ:
    case TAP_STEP_WRITE:
        break;
    }
    /* ⚠ Reached only if a step is added above without a sentence for it. Say
     * that plainly rather than printing the number (`CLAUDE.md` §4). */
    fprintf(out, "could not attach to %s, and this build has no wording for why.\n",
            device_name);
}

void report_wait_failure(FILE *out, const char *device_name,
                         const struct tap_failure *failure)
{
    fprintf(out, "could not keep listening on %s: waiting for a frame failed: %s\n",
            device_name, strerror(failure->errnum));
}

void report_usage(FILE *out, const char *program_name)
{
    fprintf(out,
            "%s reads the ethernet frames that arrive on a TAP device.\n"
            "\n"
            "  --dev NAME      device to create and attach to (default: tap0)\n"
            "  --count N       stop after N frames (default: until interrupted)\n"
            "  --timeout MS    give up waiting after MS milliseconds (default: no limit)\n"
            "  --hex           print the bytes of each frame as well as its length\n"
            "  --help          this text\n"
            "\n"
            "It reads only. Sending frames is not implemented yet.\n"
            "The device exists only while this program holds it open.\n",
            program_name);
}
