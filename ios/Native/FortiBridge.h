// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef FORTI_BRIDGE_H
#define FORTI_BRIDGE_H
#include <stddef.h>
#include <stdint.h>
typedef void (*fot_event_cb)(void *context, const char *event, const char *detail);
typedef void (*fot_packet_cb)(void *context, const uint8_t *packet, size_t length);
// All lifecycle calls are serialized by the extension's engine queue.
int fot_start(const char *runtime, const char *gateway, const char *username,
              const char *password, const char *psk, const char *local_id,
              const char *token, int append_token, void *context,
              fot_event_cb event, fot_packet_cb packet);
// Remote port is restricted to standard IKE (500) or NAT-T (4500).
int fot_start_on_port(const char *runtime, const char *gateway, const char *username,
              const char *password, const char *psk, const char *local_id,
              const char *token, int append_token, void *context,
              fot_event_cb event, fot_packet_cb packet, uint16_t remote_port);
void fot_stop(void);
int fot_network_valid(void);
int fot_input(const uint8_t *packet, size_t length);
void fot_deliver(const uint8_t *packet, size_t length);
#endif
#include "scvpn.h"
