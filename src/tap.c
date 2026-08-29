#include "tap.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <poll.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

/* ⚠ Two places name the same limit. This is the mechanical cross-check that
 * stops them diverging (`CLAUDE.md` §3). */
_Static_assert(TAP_DEVICE_NAME_MAX == IFNAMSIZ - 1,
               "TAP_DEVICE_NAME_MAX must match the kernel's IFNAMSIZ");

static void set_failure(struct tap_failure *failure, enum tap_step step, int errnum)
{
    if (failure == NULL) {
        return;
    }
    failure->step = step;
    failure->errnum = errnum;
}

int tap_attach(const char *device_name, struct tap_failure *failure)
{
    set_failure(failure, TAP_STEP_NONE, 0);

    /* ⚠ Checked against what the kernel will accept, before it is copied into a
     * fixed-size field. IFNAMSIZ counts the terminator. */
    size_t name_length = strlen(device_name);
    if (name_length == 0 || name_length > TAP_DEVICE_NAME_MAX) {
        set_failure(failure, TAP_STEP_NAME, 0);
        return -1;
    }

    int fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) {
        set_failure(failure, TAP_STEP_OPEN, errno);
        return -1;
    }

    struct ifreq request;
    memset(&request, 0, sizeof request);
    /* IFF_TAP: ethernet frames, not bare IP packets.
     * IFF_NO_PI: no 4-byte header of the kernel's in front of each frame, so
     * what read(2) returns is exactly what was on the wire. */
    request.ifr_flags = IFF_TAP | IFF_NO_PI;
    memcpy(request.ifr_name, device_name, name_length + 1);

    if (ioctl(fd, TUNSETIFF, &request) < 0) {
        int attach_errno = errno;
        close(fd);
        set_failure(failure, TAP_STEP_ATTACH, attach_errno);
        return -1;
    }

    return fd;
}

void tap_detach(int fd)
{
    if (fd >= 0) {
        close(fd);
    }
}

enum tap_wait tap_wait_readable(int fd, int timeout_ms,
                                const sigset_t *deliverable_while_waiting,
                                struct tap_failure *failure)
{
    set_failure(failure, TAP_STEP_NONE, 0);

    struct pollfd waited_on;
    waited_on.fd = fd;
    waited_on.events = POLLIN;
    waited_on.revents = 0;

    struct timespec limit;
    struct timespec *limit_or_forever = NULL;
    if (timeout_ms >= 0) {
        limit.tv_sec = timeout_ms / 1000;
        limit.tv_nsec = (long)(timeout_ms % 1000) * 1000000L;
        limit_or_forever = &limit;
    }

    /* ⚠ ppoll, not poll: the mask is applied and the wait entered as one step,
     * so a signal cannot slip in between them (see tap.h). */
    int ready = ppoll(&waited_on, 1, limit_or_forever, deliverable_while_waiting);
    if (ready < 0) {
        if (errno == EINTR) {
            return TAP_WAIT_INTERRUPTED;
        }
        set_failure(failure, TAP_STEP_WAIT, errno);
        return TAP_WAIT_FAILED;
    }
    if (ready == 0) {
        return TAP_WAIT_TIMEOUT;
    }

    /* ⚠ ppoll returning 1 says something happened on the fd, not that a frame
     * can be read. ⚠ revents is what says which, and it is read rather than
     * assumed (hidetzu/tcpip-stack#8).
     *
     * ⚠ POLLIN wins when it is set alongside an error bit: octets are queued and
     * they can be read. ⚠ That combination has not been observed here, and this
     * is the safe reading of it, not a measurement. */
    if (waited_on.revents & POLLIN) {
        return TAP_WAIT_READY;
    }
    return TAP_WAIT_DEVICE_GONE;
}

ssize_t tap_read_frame(int fd, uint8_t *buffer, size_t buffer_bytes,
                       struct tap_failure *failure)
{
    set_failure(failure, TAP_STEP_NONE, 0);

    ssize_t bytes_read = read(fd, buffer, buffer_bytes);
    if (bytes_read < 0) {
        set_failure(failure, TAP_STEP_READ, errno);
        return -1;
    }
    return bytes_read;
}

ssize_t tap_write_frame(int fd, const uint8_t *frame, size_t frame_bytes,
                        struct tap_failure *failure)
{
    set_failure(failure, TAP_STEP_NONE, 0);

    ssize_t written = write(fd, frame, frame_bytes);
    if (written < 0) {
        set_failure(failure, TAP_STEP_WRITE, errno);
        return -1;
    }
    return written;
}

int tap_ask_mtu(const char *device_name, unsigned int *mtu,
                 struct tap_failure *failure)
{
    set_failure(failure, TAP_STEP_NONE, 0);

    /* ⚠ Checked before it is copied into a fixed-size field, the same way
     * tap_attach does. */
    size_t name_length = strlen(device_name);
    if (name_length == 0 || name_length > TAP_DEVICE_NAME_MAX) {
        set_failure(failure, TAP_STEP_NAME, 0);
        return -1;
    }

    /* ⚠ The TUN fd cannot answer this — measured, EINVAL (see tap.h). ⚠ The
     * socket is this function's and does not outlive it. */
    int asking = socket(AF_INET, SOCK_DGRAM, 0);
    if (asking < 0) {
        set_failure(failure, TAP_STEP_MTU, errno);
        return -1;
    }

    struct ifreq request;
    memset(&request, 0, sizeof request);
    memcpy(request.ifr_name, device_name, name_length + 1);

    if (ioctl(asking, SIOCGIFMTU, &request) < 0) {
        int asking_errno = errno;
        close(asking);
        set_failure(failure, TAP_STEP_MTU, asking_errno);
        return -1;
    }
    close(asking);

    /* ⚠ The kernel's field is a signed int. ⚠ A negative value has never been
     * observed here and nothing proves it cannot arrive, so it is refused
     * rather than cast into a large unsigned number (`CLAUDE.md` §1). */
    if (request.ifr_mtu < 0) {
        set_failure(failure, TAP_STEP_MTU, 0);
        return -1;
    }

    *mtu = (unsigned int)request.ifr_mtu;
    return 0;
}
