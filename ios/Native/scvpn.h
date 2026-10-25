/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef ONETAP_HILLSTONE_H
#define ONETAP_HILLSTONE_H
#include <stddef.h>
#include <stdint.h>
#ifdef _WIN32
#define HS_API __declspec(dllexport)
#else
#define HS_API __attribute__((visibility("default")))
#endif
#ifdef __cplusplus
extern "C" {
#endif
typedef struct hs_session hs_session;
typedef int (*hs_protect_cb)(void *context, intptr_t socket_fd);
HS_API hs_session *hs_create(void);
/* TLS-only discovery returns certificate DER length; sends no credentials. */
HS_API int hs_probe_certificate(hs_session *,const char *host,unsigned port,int allow_legacy_tls,uint8_t *der,size_t capacity);
/* Pin is SHA-256 of certificate DER. Password is never retained or logged. */
HS_API int hs_connect(hs_session *,const char *host,unsigned port,const char *username,const char *password,const char *pin,int allow_legacy_tls,hs_protect_cb,void *);
HS_API int hs_send(hs_session *,const uint8_t *packet,size_t length);
/* Local NODATA for UDP AAAA and ICMPv6 no-route; 0 means forward normally. */
HS_API int hs_local_reply(const uint8_t *packet,size_t length,uint8_t *reply,size_t capacity);
/* Enable curated domestic A/HTTPS/SVCB queries via direct DNS; other names use VPN DNS. */
HS_API int hs_set_split_dns(hs_session *,int enabled);
HS_API int hs_dns_direct_enabled(hs_session *);
/* Shared DNS-only relay, serialized by its owner; poll fallback=1 returns the
 * original query to send through Forti or Hillstone, fallback=0 a local reply. */
HS_API hs_session *hs_dns_relay_create(const char *resolver);
HS_API int hs_dns_relay_submit(hs_session *,const uint8_t *,size_t);
HS_API int hs_dns_relay_poll(hs_session *,uint8_t *,size_t,int *fallback);
HS_API void hs_prepare_ipv4(uint8_t *,size_t);
HS_API int hs_check_dns(hs_session *);
/* In-VPN first-response comparison for public Google DNS, keeps custom/private DNS. */
HS_API int hs_select_public_dns(hs_session *);
HS_API int hs_stats(hs_session *,char *output,size_t capacity);
#ifdef _WIN32
HS_API int hs_win_wait(hs_session *,void *tun_event,unsigned timeout_ms);
#endif
/* >0: authenticated IPv4 packet, 0: timeout/heartbeat, -1: disconnected/error. */
HS_API int hs_receive(hs_session *,uint8_t *packet,size_t capacity,unsigned timeout_ms);
/* field: 0 assigned IPv4, 1 mask, 2 assigned DNS, 3 control gateway. */
HS_API int hs_ipv4(hs_session *,unsigned field,char *output,size_t capacity);
HS_API const char *hs_error(hs_session *);
HS_API int hs_ready(hs_session *);
/* Cancel can interrupt another thread; destroy only after that thread exits. */
HS_API void hs_cancel(hs_session *);
HS_API void hs_destroy(hs_session *);
#ifdef __cplusplus
}
#endif
#endif
