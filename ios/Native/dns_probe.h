/* SPDX-License-Identifier: GPL-2.0-or-later. Operational metadata only. */
HS_API int hs_check_dns(hs_session *s){
 if(!s||!hs_ready(s))return 0;
 uint8_t p[57]={0},reply[2048],random[4];if(RAND_bytes(random,sizeof(random))!=1)return fail(s,"dns_probe_random_failed");
 uint16_t port=(uint16_t)(49152+(get16(random)&16383)),id=get16(random+2);
 p[0]=0x45;put16(p+2,sizeof(p));p[8]=64;p[9]=17;memcpy(p+12,s->address,4);memcpy(p+16,s->dns,4);put16(p+10,checksum(p,20));
 put16(p+20,port);put16(p+22,53);put16(p+24,sizeof(p)-20);
 const uint8_t query[]={0,0,1,0,0,1,0,0,0,0,0,0,7,'e','x','a','m','p','l','e',3,'c','o','m',0,0,1,0,1};
 memcpy(p+28,query,sizeof(query));put16(p+28,id);uint16_t sum=hs_transport_checksum(p,sizeof(p),20);put16(p+26,sum?sum:65535);
 if(!hs_send(s,p,sizeof(p)))return 0;
 uint64_t deadline=now_ms()+5000,next=now_ms()+1000;unsigned attempts=1;
 while(!s->cancelled&&now_ms()<deadline){if(now_ms()>=next&&attempts<3){if(!hs_send(s,p,sizeof(p)))return 0;attempts++;next=now_ms()+1000;}int n=hs_receive(s,reply,sizeof(reply),100);if(n<0)return 0;if(n<40||reply[9]!=17)continue;size_t ihl=(reply[0]&15)*4;if(ihl<20||ihl+20>(size_t)n)continue;
  if(!memcmp(reply+12,s->dns,4)&&!memcmp(reply+16,s->address,4)&&get16(reply+ihl)==53&&get16(reply+ihl+2)==port&&get16(reply+ihl+8)==id&&(reply[ihl+10]&0x80)&&!(reply[ihl+11]&15)&&get16(reply+ihl+14)>0)return 1;
 }
 return fail(s,s->cancelled?"cancelled":"dns_probe_timeout");
}
HS_API int hs_stats(hs_session *s,char *out,size_t cap){
 if(!s||!out||cap<256)return 0;
 snprintf(out,cap,"tx=%llu rx=%llu direct_dns=%llu fallback_dns=%llu heartbeat_age_ms=%llu tx_bytes=%llu rx_bytes=%llu rcvbuf=%d direct_reply=%llu direct_avg_ms=%llu direct_max_ms=%llu vpn_dns=%llu vpn_reply=%llu vpn_avg_ms=%llu vpn_max_ms=%llu vpn_https=%llu tcp_syn=%llu syn_retry=%llu syn_reply=%llu syn_avg_ms=%llu syn_max_ms=%llu selected_dns_ms=%llu",(unsigned long long)atomic_load(&s->tx_packets),(unsigned long long)atomic_load(&s->rx_packets),(unsigned long long)atomic_load(&s->dns_direct_count),(unsigned long long)atomic_load(&s->dns_fallback_count),(unsigned long long)(now_ms()-s->last_received_heartbeat),(unsigned long long)atomic_load(&s->tx_bytes),(unsigned long long)atomic_load(&s->rx_bytes),s->receive_buffer,(unsigned long long)atomic_load(&s->dns_direct_replies),(unsigned long long)(atomic_load(&s->dns_direct_ms)/(atomic_load(&s->dns_direct_replies)?atomic_load(&s->dns_direct_replies):1)),(unsigned long long)atomic_load(&s->dns_direct_max_ms),(unsigned long long)atomic_load(&s->dns_vpn_queries),(unsigned long long)atomic_load(&s->dns_vpn_replies),(unsigned long long)(atomic_load(&s->dns_vpn_ms)/(atomic_load(&s->dns_vpn_replies)?atomic_load(&s->dns_vpn_replies):1)),(unsigned long long)atomic_load(&s->dns_vpn_max_ms),(unsigned long long)atomic_load(&s->dns_https_queries),(unsigned long long)atomic_load(&s->syn_packets),(unsigned long long)atomic_load(&s->syn_retries),(unsigned long long)atomic_load(&s->syn_replies),(unsigned long long)(atomic_load(&s->syn_ms)/(atomic_load(&s->syn_replies)?atomic_load(&s->syn_replies):1)),(unsigned long long)atomic_load(&s->syn_max_ms),(unsigned long long)s->selected_dns_ms);return 1;
}
/* Only replace a known public Google resolver; private/custom DNS remains intact.
 * Both probes are ESP packets inside the existing VPN, with distinct random IDs. */
HS_API int hs_select_public_dns(hs_session *s){
 if(!s||!hs_ready(s))return 0;
 s->selected_dns_ms=0;
 const uint8_t google[4]={8,8,8,8},google2[4]={8,8,4,4},cloudflare[4]={1,1,1,1};
 if(memcmp(s->dns,google,4)&&memcmp(s->dns,google2,4))return 1;
 uint8_t candidates[2][4];memcpy(candidates[0],s->dns,4);memcpy(candidates[1],cloudflare,4);
 uint8_t p[2][57]={{0}},random[8],reply[2048];if(RAND_bytes(random,sizeof(random))!=1)return fail(s,"dns_probe_random_failed");
 const uint8_t q[]={0,0,1,0,0,1,0,0,0,0,0,0,7,'e','x','a','m','p','l','e',3,'c','o','m',0,0,1,0,1};
 for(unsigned i=0;i<2;i++){
  p[i][0]=0x45;put16(p[i]+2,57);p[i][8]=64;p[i][9]=17;memcpy(p[i]+12,s->address,4);memcpy(p[i]+16,candidates[i],4);put16(p[i]+10,checksum(p[i],20));
  put16(p[i]+20,(uint16_t)(49152+(get16(random+i*4)&16383)));put16(p[i]+22,53);put16(p[i]+24,37);memcpy(p[i]+28,q,sizeof(q));put16(p[i]+28,get16(random+i*4+2));put16(p[i]+26,hs_transport_checksum(p[i],57,20));
 }
 uint64_t start=now_ms(),deadline=start+1200,next=start;unsigned attempts=0;
 while(!s->cancelled&&now_ms()<deadline){
  if(now_ms()>=next&&attempts<3){for(unsigned i=0;i<2;i++)if(!send_packet(s,p[i],57))return 0;attempts++;next=now_ms()+400;}
  int n=hs_receive(s,reply,sizeof(reply),50);if(n<0)return 0;if(n<57||reply[9]!=17)continue;
  size_t ihl=(reply[0]&15)*4;if(ihl<20||ihl+37>(size_t)n||get16(reply+ihl)!=53||get16(reply+ihl+4)!=(size_t)n-ihl||memcmp(reply+16,s->address,4))continue;
  if(get16(reply+ihl+6)&&hs_transport_checksum(reply,(size_t)n,ihl))continue;
  for(unsigned i=0;i<2;i++)if(!memcmp(reply+12,candidates[i],4)&&get16(reply+ihl+2)==get16(p[i]+20)&&get16(reply+ihl+8)==get16(p[i]+28)&&(reply[ihl+10]&0x80)&&!(reply[ihl+10]&2)&&!(reply[ihl+11]&15)&&get16(reply+ihl+12)==1&&get16(reply+ihl+14)>0&&!memcmp(reply+ihl+20,q+12,sizeof(q)-12)){
   memcpy(s->dns,candidates[i],4);s->selected_dns_ms=now_ms()-start;return 1;
  }
 }
 return s->cancelled?0:1; /* No valid answer: keep the server resolver for normal validation. */
}
