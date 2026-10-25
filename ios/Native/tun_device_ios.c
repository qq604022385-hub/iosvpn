// SPDX-License-Identifier: GPL-2.0-or-later
// A datagram queue replaces privileged /dev/tun operations. iOS owns the actual
// virtual interface via NEPacketTunnelProvider; no private utun API is used.
#include <library.h>
#include <networking/tun_device.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
extern void fot_deliver(const uint8_t*, size_t);
static int input_fd = -1;
static pthread_mutex_t input_lock = PTHREAD_MUTEX_INITIALIZER;
typedef struct {
    tun_device_t public;
    int fd[2], mtu;
    host_t *address;
    uint8_t prefix;
} ios_tun_t;
int fot_input(const uint8_t *packet, size_t length) {
    if (!packet || length < 20 || length > 65535 || packet[0] >> 4 != 4) return 0;
    pthread_mutex_lock(&input_lock);
    ssize_t sent = input_fd < 0 ? -1 : send(input_fd, packet, length, MSG_DONTWAIT);
    pthread_mutex_unlock(&input_lock);
    return sent == (ssize_t)length;
}
METHOD(tun_device_t, read_packet, bool, ios_tun_t *this, chunk_t *packet) {
    uint8_t buf[65535]; ssize_t n;
    do { n = recv(this->fd[0], buf, sizeof(buf), 0); } while (n < 0 && errno == EINTR);
    if (n <= 0) return FALSE;
    *packet = chunk_clone(chunk_create(buf, n));
    return TRUE;
}
METHOD(tun_device_t, write_packet, bool, ios_tun_t *this, chunk_t packet) {
    fot_deliver(packet.ptr, packet.len); return TRUE;
}
METHOD(tun_device_t, set_address, bool, ios_tun_t *this, host_t *addr, uint8_t prefix) {
    DESTROY_IF(this->address); this->address = addr->clone(addr); this->prefix = prefix; return TRUE;
}
METHOD(tun_device_t, get_address, host_t*, ios_tun_t *this, uint8_t *prefix) {
    if (prefix) *prefix = this->prefix; return this->address;
}
METHOD(tun_device_t, up, bool, ios_tun_t *this) { return TRUE; }
METHOD(tun_device_t, set_mtu, bool, ios_tun_t *this, int mtu) { this->mtu = mtu; return TRUE; }
METHOD(tun_device_t, get_mtu, int, ios_tun_t *this) { return this->mtu; }
METHOD(tun_device_t, get_name, char*, ios_tun_t *this) { return "forti-packet-flow"; }
METHOD(tun_device_t, get_fd, int, ios_tun_t *this) { return this->fd[0]; }
METHOD(tun_device_t, destroy, void, ios_tun_t *this) {
    pthread_mutex_lock(&input_lock); input_fd = -1;
    close(this->fd[0]); close(this->fd[1]); pthread_mutex_unlock(&input_lock);
    DESTROY_IF(this->address); free(this);
}
tun_device_t *tun_device_create(const char *name_tmpl) {
    ios_tun_t *this;
    INIT(this, .public = { .read_packet = _read_packet, .write_packet = _write_packet,
        .set_address = _set_address, .get_address = _get_address, .up = _up,
        .set_mtu = _set_mtu, .get_mtu = _get_mtu, .get_name = _get_name,
        .get_fd = _get_fd, .destroy = _destroy }, .mtu = 1280);
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, this->fd)) { free(this); return NULL; }
    int size = 1024 * 1024;
    setsockopt(this->fd[1], SOL_SOCKET, SO_SNDBUF, &size, sizeof(size));
    setsockopt(this->fd[0], SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
    pthread_mutex_lock(&input_lock); input_fd = this->fd[1]; pthread_mutex_unlock(&input_lock);
    return &this->public;
}
