// SPDX-License-Identifier: GPL-2.0-or-later
#include "FortiBridge.h"
#include <library.h>
#include <daemon.h>
#include <bus/listeners/listener.h>
#include <bus/listeners/logger.h>
#include <kernel/kernel_net.h>
#include <plugins/plugin_feature.h>
#include <selectors/traffic_selector.h>
#include <sa/child_sa.h>
#include <sa/ike_sa.h>
#include <plugins/vici/libvici.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
#include <stdatomic.h>
#include <errno.h>
extern kernel_net_t *fot_kernel_net_create(void);
char fot_gateway[16];
static void *callback_context;
static fot_event_cb event_cb;
static fot_packet_cb packet_cb;
static bool library_live, charon_live;
static atomic_bool stopping, peer_seen;
static vici_conn_t *control;
static char *secrets[4];
static char socket_uri[128];
static const char *start_phase;
static void phase(const char *name);
static void notify(const char *event, const char *detail) {
    if (!atomic_load(&stopping) && event_cb) event_cb(callback_context, event, detail);
}
static void phase(const char *name) { start_phase = name; notify("phase", name); }
void fot_deliver(const uint8_t *packet, size_t length) {
    if (!atomic_load(&stopping) && packet_cb) packet_cb(callback_context, packet, length);
}
static level_t log_level(logger_t *logger, debug_t group) { return group == DBG_ENC ? -1 : 1; }
static void log_line(logger_t *logger, debug_t group, level_t level, int thread,
                     ike_sa_t *ike, const char *message) {
    // Do not forward peer-controlled XAuth text or payload dumps.
    if (strstr(message, "XAuth message:") || strstr(message, "credential round")) return;
    char safe[2048]; snprintf(safe, sizeof(safe), "%s", message);
    for (int s = 0; s < 4; s++) {
        if (!secrets[s] || !*secrets[s]) continue;
        char *match; size_t length = strlen(secrets[s]);
        // Replace in place; no copies of secret text leave this function.
        char *cursor = safe;
        while ((match = strstr(cursor, secrets[s]))) { memset(match, '*', length); cursor = match + length; }
    }
    notify("log", safe); memwipe(safe, sizeof(safe));
}
static logger_t logger = { .log = log_line, .get_level = log_level };
static bool child_event(listener_t *listener, ike_sa_t *ike, child_sa_t *child, bool up) {
    if (!up) { notify("down", "VPN 隧道已断开，请重新输入令牌。"); return TRUE; }
    bool full = FALSE; traffic_selector_t *ts;
    enumerator_t *enumerator = child->create_ts_enumerator(child, FALSE);
    while (enumerator->enumerate(enumerator, &ts)) {
        host_t *net = NULL; uint8_t prefix = 255;
        if (ts->to_subnet(ts, &net, &prefix)) {
            full |= net->get_family(net) == AF_INET && prefix == 0 &&
                    ts->get_protocol(ts) == 0 && ts->get_from_port(ts) == 0 && ts->get_to_port(ts) == 65535;
            net->destroy(net);
        }
    }
    enumerator->destroy(enumerator);
    host_t *vip; char address[INET_ADDRSTRLEN] = "";
    enumerator = ike->create_virtual_ip_enumerator(ike, TRUE);
    while (enumerator->enumerate(enumerator, &vip)) {
        if (vip->get_family(vip) == AF_INET) {
            chunk_t raw = vip->get_address(vip); inet_ntop(AF_INET, raw.ptr, address, sizeof(address)); break;
        }
    }
    enumerator->destroy(enumerator);
    if (!full || !*address || child->get_state(child) != CHILD_INSTALLED) {
        notify("error", "服务端未提供有效虚拟 IPv4 和完整 IPv4 隧道。");
    } else notify("ready", address);
    return TRUE;
}
static bool ike_event(listener_t *listener, ike_sa_t *ike, bool up) {
    if (!up) notify("down", "IKE 会话已断开，请重新输入令牌。"); return TRUE;
}
static bool peer_message(listener_t *listener, ike_sa_t *ike, message_t *message, bool incoming, bool plain) {
    if (incoming && plain) atomic_store(&peer_seen, TRUE);
    return TRUE;
}
static listener_t listener = { .child_updown = child_event, .ike_updown = ike_event, .message = peer_message };
static void kv(vici_req_t *r, char *name, const char *value) {
    vici_add_key_value(r, name, (void*)value, strlen(value));
}
static void list1(vici_req_t *r, char *name, const char *item) {
    vici_begin_list(r, name); vici_add_list_item(r, (void*)item, strlen(item)); vici_end_list(r);
}
static void proposals(vici_req_t *r, char *name, const char *first, const char *second) {
    vici_begin_list(r, name); vici_add_list_item(r, (void*)first, strlen(first));
    vici_add_list_item(r, (void*)second, strlen(second)); vici_end_list(r);
}
static bool submit(vici_req_t *r) {
    vici_res_t *result = vici_submit(r, control);
    if (!result) return FALSE;
    bool ok = streq(vici_find_str(result, "no", "success"), "yes");
    // Peer-controlled error text is not exposed; protocol logs are redacted separately.
    vici_free_res(result); return ok;
}
static bool load_secret(char *id, char *type, const char *value, const char *owner) {
    vici_req_t *r = vici_begin("load-shared");
    kv(r, "id", id); kv(r, "type", type); kv(r, "data", value); list1(r, "owners", owner);
    return submit(r);
}
void fot_stop(void) {
    atomic_store(&stopping, TRUE);
    if (control) { vici_disconnect(control); control = NULL; }
    if (charon_live) {
        charon->bus->remove_listener(charon->bus, &listener);
        // Keep the logger registered until charon shuts down; callbacks are suppressed.
        libcharon_deinit(); charon_live = FALSE;
    }
    if (library_live) { library_deinit(); library_live = FALSE; }
    for (int i = 0; i < 4; i++) if (secrets[i]) {
        memwipe(secrets[i], strlen(secrets[i])); free(secrets[i]); secrets[i] = NULL;
    }
    event_cb = NULL; packet_cb = NULL; callback_context = NULL;
    if (*socket_uri) { unlink(socket_uri + 7); socket_uri[0] = 0; }
}
int fot_start_on_port(const char *runtime, const char *gateway, const char *username,
              const char *password, const char *psk, const char *local_id,
              const char *token, int append_token, void *context,
              fot_event_cb event, fot_packet_cb packet, uint16_t remote_port) {
    bool awaiting_peer = FALSE;
    fot_stop(); atomic_store(&stopping, FALSE); atomic_store(&peer_seen, FALSE);
    callback_context = context; event_cb = event; packet_cb = packet;
    phase("校验配置与本地控制路径");
    if (!runtime || !gateway || !username || !password || !psk || !local_id ||
        !token || (remote_port != 500 && remote_port != 4500) || strlen(gateway) >= sizeof(fot_gateway) || strlen(token) != 6) goto fail;
    for (int i = 0; i < 6; i++) if (token[i] < '0' || token[i] > '9') goto fail;
    secrets[0] = strdup(password); secrets[1] = strdup(psk);
    secrets[2] = strdup(token); secrets[3] = strdup(username);
    snprintf(fot_gateway, sizeof(fot_gateway), "%s", gateway);
    if (snprintf(socket_uri, sizeof(socket_uri), "unix://%s/v", runtime) >= sizeof(socket_uri) ||
        strlen(socket_uri + 7) >= sizeof(((struct sockaddr_un*)0)->sun_path)) goto fail;
    // Only the provider sandbox can access this control socket.
    if (mkdir(runtime, 0700) && errno != EEXIST) goto fail;
    chmod(runtime, 0700); unlink(socket_uri + 7);
    phase("初始化协议库");
    if (!library_init("", "charon")) { library_live = lib != NULL; goto fail; }
    library_live = TRUE;
    lib->settings->set_int(lib->settings, "charon.port", 0);
    lib->settings->set_int(lib->settings, "charon.port_nat_t", 0);
    lib->settings->set_int(lib->settings, "charon.threads", 16);
    lib->settings->set_int(lib->settings, "charon.retransmit_tries", 3);
    lib->settings->set_bool(lib->settings, "charon.plugins.socket-default.use_ipv6", FALSE);
    lib->settings->set_bool(lib->settings, "charon.plugins.kernel-libipsec.raw_esp", FALSE);
    lib->settings->set_bool(lib->settings, "charon.forti_xauth_append", append_token != 0);
    lib->settings->set_str(lib->settings, "charon.plugins.vici.socket", socket_uri);
    if (!libcharon_init()) { charon_live = charon != NULL; goto fail; }
    charon_live = TRUE;
    charon->bus->add_logger(charon->bus, &logger);
    plugin_feature_t features[] = {
        PLUGIN_CALLBACK(kernel_net_register, fot_kernel_net_create),
        PLUGIN_PROVIDE(CUSTOM, "kernel-net"),
    };
    lib->plugins->add_static_features(lib->plugins, "forti-ios-net", features, countof(features), TRUE, NULL, NULL);
    phase("加载 IPsec 插件与外层网络");
    if (!charon->initialize(charon, "openssl nonce hmac kernel-libipsec socket-default vici xauth-generic")) goto fail;
    charon->bus->add_listener(charon->bus, &listener);
    charon->start(charon);
    phase("连接本地控制通道");
    control = vici_connect(socket_uri);
    if (!control) goto fail;
    phase("本地控制通道应答自检");
    vici_res_t *version = vici_submit(vici_begin("version"), control);
    if (!version) goto fail;
    bool version_ok = vici_find_str(version, NULL, "daemon") != NULL;
    vici_free_res(version);
    if (!version_ok) goto fail;
    notify("log", "本地控制通道自检通过，16 个工作线程可处理认证命令。");
    phase("加载 PSK"); if (!load_secret("psk", "IKE", psk, "%any")) goto fail;
    phase("加载 XAuth 密码"); if (!load_secret("password", "XAUTH", password, username)) goto fail;
    phase("加载本次动态令牌"); if (!load_secret("token", "PIN", token, username)) goto fail;
    notify("log", "已加载 IKEv1 / PSK / XAuth，本次令牌仅保留在内存。");
    phase("加载 IKEv1 连接参数");
    vici_req_t *r = vici_begin("load-conn");
    vici_begin_section(r, "one-tap");
    kv(r, "version", "1"); kv(r, "aggressive", "yes"); kv(r, "encap", "yes");
    kv(r, "fragmentation", "yes");
    if (remote_port == 4500) {
        char local_port[16];
        snprintf(local_port, sizeof(local_port), "%u", charon->socket->get_port(charon->socket, TRUE));
        kv(r, "local_port", local_port); kv(r, "remote_port", "4500");
        notify("log", "Wi-Fi 兼容重试：直接使用标准 UDP 4500 NAT-T 入口。");
    }
    list1(r, "remote_addrs", gateway); list1(r, "vips", "0.0.0.0");
    proposals(r, "proposals", "aes128-sha1-modp1536", "aes256-sha256-modp1536");
    kv(r, "rekey_time", "84600s"); kv(r, "over_time", "1800s"); kv(r, "dpd_delay", "30s");
    vici_begin_section(r, "local-1"); kv(r, "auth", "psk"); if (*local_id) kv(r, "id", local_id); vici_end_section(r);
    vici_begin_section(r, "local-2"); kv(r, "auth", "xauth"); kv(r, "xauth_id", username); vici_end_section(r);
    vici_begin_section(r, "remote-1"); kv(r, "auth", "psk"); kv(r, "id", "%any"); vici_end_section(r);
    vici_begin_section(r, "children"); vici_begin_section(r, "net");
    list1(r, "local_ts", "dynamic"); list1(r, "remote_ts", "0.0.0.0/0");
    proposals(r, "esp_proposals", "aes128-sha1-modp1536", "aes256-sha1-modp1536");
    kv(r, "life_time", "43200s"); kv(r, "rekey_time", "42120s"); kv(r, "dpd_action", "clear");
    vici_end_section(r); vici_end_section(r); vici_end_section(r);
    if (!submit(r)) goto fail;
    phase("等待网关 IKE / XAuth / 动态令牌协商（最多 30 秒）");
    r = vici_begin("initiate"); kv(r, "ike", "one-tap"); kv(r, "child", "net"); kv(r, "timeout", "30000");
    awaiting_peer = TRUE;
    if (!submit(r)) goto fail;
    awaiting_peer = FALSE;
    // A later reauthentication may not reuse this OTP.
    phase("销毁本次动态令牌");
    r = vici_begin("unload-shared"); kv(r, "id", "token"); if (!submit(r)) goto fail;
    memwipe(secrets[2], strlen(secrets[2])); free(secrets[2]); secrets[2] = NULL;
    return 1;
fail:;
    char failure[256];
    snprintf(failure, sizeof(failure), "Forti 建立失败（阶段：%s）。请使用新令牌重试并导出日志。", start_phase ? start_phase : "初始化");
    notify(awaiting_peer && !atomic_load(&peer_seen) ? "unreachable" : "error", failure);
    fot_stop(); return 0;
}

int fot_start(const char *runtime, const char *gateway, const char *username,
              const char *password, const char *psk, const char *local_id,
              const char *token, int append_token, void *context,
              fot_event_cb event, fot_packet_cb packet) {
    return fot_start_on_port(runtime,gateway,username,password,psk,local_id,
                             token,append_token,context,event,packet,500);
}
