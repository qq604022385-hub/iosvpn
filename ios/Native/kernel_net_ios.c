// SPDX-License-Identifier: GPL-2.0-or-later
#include <daemon.h>
#include <kernel/kernel_net.h>
#include <networking/tun_device.h>
#include <collections/linked_list.h>
#include <threading/mutex.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <unistd.h>
#include <arpa/inet.h>
extern char fot_gateway[16];
static struct in_addr outer_address;
static char outer_interface[IFNAMSIZ];
typedef struct { kernel_net_t public; host_t *physical, *vip; mutex_t *lock; char *iface; int refs; } ios_net_t;
METHOD(kernel_net_t, features, kernel_feature_t, ios_net_t *this) { return KERNEL_REQUIRE_EXCLUDE_ROUTE; }
METHOD(kernel_net_t, source, host_t*, ios_net_t *this, host_t *dest, host_t *src) {
    return this->physical->clone(this->physical);
}
METHOD(kernel_net_t, nexthop, host_t*, ios_net_t *this, host_t *dest, int prefix, host_t *src, char **iface) {
    if (iface) *iface = strdup(this->iface);
    return host_create_any(AF_INET);
}
METHOD(kernel_net_t, interface_, bool, ios_net_t *this, host_t *host, char **name) {
    bool found = FALSE; this->lock->lock(this->lock);
    if (this->vip && this->vip->ip_equals(this->vip, host)) {
        if (name) *name = strdup("forti-packet-flow"); found = TRUE;
    } else if (this->physical->ip_equals(this->physical, host)) {
        if (name) *name = strdup(this->iface); found = TRUE;
    }
    this->lock->unlock(this->lock); return found;
}
static void free_host(void *h) { host_t *host = h; host->destroy(host); }
static void free_list(void *data) { linked_list_t *list = data; list->destroy_function(list, free_host); }
METHOD(kernel_net_t, addresses, enumerator_t*, ios_net_t *this, kernel_address_type_t which) {
    linked_list_t *list = linked_list_create(); this->lock->lock(this->lock);
    if (which & ADDR_TYPE_REGULAR) list->insert_last(list, this->physical->clone(this->physical));
    if ((which & ADDR_TYPE_VIRTUAL) && this->vip) list->insert_last(list, this->vip->clone(this->vip));
    this->lock->unlock(this->lock);
    return enumerator_create_cleaner(list->create_enumerator(list), free_list, list);
}
METHOD(kernel_net_t, subnets, enumerator_t*, ios_net_t *this) { return enumerator_create_empty(); }
METHOD(kernel_net_t, add_ip, status_t, ios_net_t *this, host_t *vip, int prefix, char *iface) {
    if (vip->get_family(vip) != AF_INET) return NOT_SUPPORTED;
    this->lock->lock(this->lock);
    if (this->vip) {
        bool same = this->vip->ip_equals(this->vip, vip);
        if (same) this->refs++;
        this->lock->unlock(this->lock); return same ? SUCCESS : FAILED;
    }
    this->vip = vip->clone(vip); this->refs = 1;
    tun_device_t *tun = lib->get(lib, "kernel-libipsec-tun");
    bool ok = tun && tun->set_address(tun, vip, 32);
    this->lock->unlock(this->lock); return ok ? SUCCESS : FAILED;
}
METHOD(kernel_net_t, del_ip, status_t, ios_net_t *this, host_t *vip, int prefix, bool wait) {
    this->lock->lock(this->lock);
    if (this->vip && this->vip->ip_equals(this->vip, vip) && --this->refs == 0) {
        this->vip->destroy(this->vip); this->vip = NULL;
    }
    this->lock->unlock(this->lock); return SUCCESS;
}
METHOD(kernel_net_t, add_route, status_t, ios_net_t *this, chunk_t dst, uint8_t prefix,
       host_t *gateway, host_t *src, char *iface, bool pass) {
    // System routes are installed atomically by Swift only after CHILD_SA + VIP validation.
    // The library may request exclude routes for its outer transport.
    if (pass) return SUCCESS;
    return dst.len == 4 ? SUCCESS : NOT_SUPPORTED;
}
METHOD(kernel_net_t, del_route, status_t, ios_net_t *this, chunk_t dst, uint8_t prefix,
       host_t *gateway, host_t *src, char *iface, bool pass) { return SUCCESS; }
METHOD(kernel_net_t, destroy, void, ios_net_t *this) {
    this->physical->destroy(this->physical); DESTROY_IF(this->vip);
    this->lock->destroy(this->lock); free(this->iface); free(this);
}
kernel_net_t *fot_kernel_net_create(void) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0); if (fd < 0) return NULL;
    host_t *gateway = host_create_from_string(fot_gateway, 500);
    if (!gateway) { close(fd); return NULL; }
    bool connected = connect(fd, gateway->get_sockaddr(gateway), *gateway->get_sockaddr_len(gateway)) == 0;
    gateway->destroy(gateway);
    struct sockaddr_in addr; socklen_t len = sizeof(addr);
    if (!connected || getsockname(fd, (struct sockaddr*)&addr, &len)) { close(fd); return NULL; }
    close(fd); addr.sin_port = 0;
    host_t *physical = host_create_from_sockaddr((sockaddr_t*)&addr);
    struct ifaddrs *interfaces = NULL; char *iface = NULL;
    if (getifaddrs(&interfaces) == 0) {
        for (struct ifaddrs *it = interfaces; it; it = it->ifa_next) {
            if (it->ifa_addr && it->ifa_addr->sa_family == AF_INET &&
                ((struct sockaddr_in*)it->ifa_addr)->sin_addr.s_addr == addr.sin_addr.s_addr &&
                strncmp(it->ifa_name, "utun", 4) && !(it->ifa_flags & IFF_LOOPBACK)) {
                iface = strdup(it->ifa_name); break;
            }
        }
        freeifaddrs(interfaces);
    }
    if (!iface) { physical->destroy(physical); return NULL; } // Refuse another VPN as outer transport.
    outer_address = addr.sin_addr;
    snprintf(outer_interface, sizeof(outer_interface), "%s", iface);
    ios_net_t *this;
    INIT(this, .public = { .get_features = _features, .get_source_addr = _source,
        .get_nexthop = _nexthop, .get_interface = _interface_,
        .create_address_enumerator = _addresses, .create_local_subnet_enumerator = _subnets,
        .add_ip = _add_ip, .del_ip = _del_ip, .add_route = _add_route,
        .del_route = _del_route, .destroy = _destroy },
        .physical = physical, .iface = iface, .lock = mutex_create(MUTEX_TYPE_DEFAULT));
    return &this->public;
}
int fot_network_valid(void) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0); if (fd < 0) return 0;
    struct sockaddr_in target = { .sin_family = AF_INET, .sin_port = htons(500) };
    target.sin_len = sizeof(target);
    inet_pton(AF_INET, fot_gateway, &target.sin_addr);
    struct sockaddr_in source; socklen_t len = sizeof(source);
    int ok = connect(fd, (struct sockaddr*)&target, sizeof(target)) == 0 &&
        getsockname(fd, (struct sockaddr*)&source, &len) == 0 && source.sin_addr.s_addr == outer_address.s_addr;
    close(fd); if (!ok) return 0;
    struct ifaddrs *interfaces = NULL;
    if (getifaddrs(&interfaces)) return 0;
    ok = 0;
    for (struct ifaddrs *it = interfaces; it; it = it->ifa_next) {
        if (it->ifa_addr && it->ifa_addr->sa_family == AF_INET &&
            strcmp(it->ifa_name, outer_interface) == 0 && (it->ifa_flags & IFF_UP) &&
            ((struct sockaddr_in*)it->ifa_addr)->sin_addr.s_addr == outer_address.s_addr) { ok = 1; break; }
    }
    freeifaddrs(interfaces); return ok;
}