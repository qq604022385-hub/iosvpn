/* SPDX-License-Identifier: GPL-2.0-or-later
 * Initial UDP path recovery only. Never changes the server port, keys, SPI,
 * ESP sequence or authentication rules. All candidates use the TLS source IP.
 */
#ifndef HS_UDP_INITIAL_MS
#define HS_UDP_INITIAL_MS 12000
#endif
#ifndef HS_UDP_RETRY_MS
#define HS_UDP_RETRY_MS 4000
#endif
#ifndef HS_UDP_PROBE_MS
#define HS_UDP_PROBE_MS 1000
#endif
static int hs_udp_open(hs_session *s,const struct sockaddr_in *remote,
                       const struct sockaddr_in *source,hs_protect_cb protect,void *context){
 hs_socket candidate=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);
 if(candidate==INVALID_HS_SOCKET)return fail(s,"data_socket_failed");
 const char *reason=NULL;struct sockaddr_in local=*source;local.sin_port=0;
 if(protect&&!protect(context,(intptr_t)candidate))reason="socket_protect_failed";
 else if(bind(candidate,(const struct sockaddr *)&local,sizeof(local)))reason="data_bind_failed";
 else if(connect(candidate,(const struct sockaddr *)remote,sizeof(*remote)))reason="data_connect_failed";
 if(reason){s->udp_last_os=hs_socket_error();hs_socket_close(candidate);return fail(s,reason);}
 socklen_t length=sizeof(local);
 if(getsockname(candidate,(struct sockaddr *)&local,&length)){
  hs_socket_close(candidate);return fail(s,"data_local_address_failed");
 }
 /* Bind the replacement before closing the previous socket so the OS cannot
  * immediately reuse its source port. Cancellation shares this ownership lock. */
 hs_mutex_lock(&s->send_lock);
 if(s->cancelled){hs_mutex_unlock(&s->send_lock);hs_socket_close(candidate);return 0;}
 hs_socket previous=s->data;s->data=candidate;hs_socket_buffers(s);
 s->udp_local_port=ntohs(local.sin_port);s->udp_paths++;
 if(previous!=INVALID_HS_SOCKET)hs_socket_close(previous);
 hs_mutex_unlock(&s->send_lock);
 return 1;
}
static int hs_udp_establish(hs_session *s,struct sockaddr_in *remote,
                            const struct sockaddr_in *source,hs_protect_cb protect,void *context){
 make_heartbeat(s);remote->sin_port=htons(s->data_port);
 for(unsigned path=0;path<3&&!s->cancelled;path++){
  if(!hs_udp_open(s,remote,source,protect,context))return 0;
  uint64_t deadline=now_ms()+(path?HS_UDP_RETRY_MS:HS_UDP_INITIAL_MS),next=0;
  while(!s->cancelled&&now_ms()<deadline){
   uint64_t now=now_ms();
   if(now>=next){
    if(!send_packet(s,s->heartbeat,sizeof(s->heartbeat))){
     if(s->cancelled||strcmp(hs_error(s),"data_send_failed"))return 0;
     s->udp_last_os=hs_socket_error();break;
    }
    s->udp_probes++;s->last_sent_heartbeat=now;next=now+HS_UDP_PROBE_MS;
   }
   uint8_t packet[2048];int n=receive_packet(s,packet,sizeof(packet),100);
   if(n==(int)sizeof(s->heartbeat)&&!CRYPTO_memcmp(packet,s->heartbeat,sizeof(s->heartbeat))){
    if(s->cancelled)return 0;
    s->last_received_heartbeat=now_ms();s->last_receive_tick=s->last_control_received=s->last_control_sent=now_ms();
    if(!nonblocking(s->control,1))return fail(s,"socket_mode_failed");
    s->error="none";s->ready=1;return !s->cancelled;
   }
   if(n<0){if(s->cancelled)return 0;break;} /* ICMP/socket error: try a new mapping. */
  }
 }
 if(s->cancelled)return 0;
 snprintf(s->error_detail,sizeof(s->error_detail),
  "data_heartbeat_timeout udp_port=%u local_port=%u paths=%u probes=%u raw=%u invalid=%u auth_bad=%u os=%d",
  s->data_port,s->udp_local_port,s->udp_paths,s->udp_probes,
  s->udp_raw,s->udp_invalid,s->udp_auth_bad,s->udp_last_os);
 return fail(s,s->error_detail);
}
