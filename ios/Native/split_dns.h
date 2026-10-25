/* SPDX-License-Identifier: GPL-2.0-or-later
 * Curated domestic A/HTTPS/SVCB queries use direct DNS in China split mode.
 * Queries outside this list always use the gateway resolver. */
#include "direct_domains.inc"
static int hs_rule_find(const char *key){size_t lo=0,hi=sizeof(hs_direct_domains)/sizeof(hs_direct_domains[0]);while(lo<hi){size_t mid=lo+(hi-lo)/2;int cmp=strcmp(key,hs_direct_domains[mid]);if(!cmp)return 1;if(cmp<0)hi=mid;else lo=mid+1;}return 0;}
static int hs_domestic_question(const uint8_t *p,size_t n){

 if(n<12||(p[2]&0xf8)||get16(p+4)!=1||get16(p+6)||get16(p+8))return 0;
 char name[254];size_t pos=12,used=0;
 while(pos<n&&p[pos]){size_t label=p[pos++];if(label>63||pos+label>=n||used+label+1>=sizeof(name))return 0;if(used)name[used++]='.';
  for(size_t i=0;i<label;i++){uint8_t c=p[pos++];if(c>='A'&&c<='Z')c+=32;if(!((c>='a'&&c<='z')||(c>='0'&&c<='9')||c=='-'||c=='_'))return 0;name[used++]=(char)c;}
 }
 if(pos+5>n||get16(p+pos+3)!=1)return 0;
 uint16_t type=get16(p+pos+1);if(type!=1&&type!=64&&type!=65)return 0;
 name[used]=0;
 char key[258];snprintf(key,sizeof(key),"E:%s",name);
 if(hs_rule_find(key))return (int)(pos+5);
 for(const char *part=name;part;){snprintf(key,sizeof(key),"S:%s",part);if(hs_rule_find(key))return (int)(pos+5);part=strchr(part,'.');if(part)part++;}
 return 0;
}
HS_API int hs_set_split_dns(hs_session *s,int enabled){
 if(!s||!s->ready||s->domestic!=INVALID_HS_SOCKET)return 0;
 if(!enabled)return 1;
 if(RAND_bytes((uint8_t *)&s->dns_sequence,sizeof(s->dns_sequence))!=1)return 0;
 struct sockaddr_in remote={0};remote.sin_family=AF_INET;remote.sin_port=htons(53);/* Never send the direct relay to the same /32 reserved for VPN DNS. */
 const uint8_t primary[4]={223,5,5,5};
 inet_pton(AF_INET,!memcmp(s->dns,primary,4)?"119.29.29.29":"223.5.5.5",&remote.sin_addr);
 s->domestic=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);
 if(s->domestic==INVALID_HS_SOCKET)return 0;
 if(connect(s->domestic,(struct sockaddr *)&remote,sizeof(remote))||!nonblocking(s->domestic,1)){hs_socket_close(s->domestic);s->domestic=INVALID_HS_SOCKET;return 0;}
 return 1;
}
static void hs_dns_lock(hs_session *s){while(atomic_flag_test_and_set(&s->dns_lock)){} }
static int hs_direct_query(hs_session *s,const uint8_t *p,size_t n){
 if(s->domestic==INVALID_HS_SOCKET||n<40||n>1500||(p[0]>>4)!=4||p[9]!=17||get16(p+2)!=n||(get16(p+6)&0x3fff)||memcmp(p+16,s->dns,4))return 0;
 size_t ihl=(p[0]&15)*4;if(ihl<20||ihl+20>n||get16(p+ihl+2)!=53||get16(p+ihl+4)!=n-ihl)return 0;
 int q=hs_domestic_question(p+ihl+8,n-ihl-8);if(!q)return 0;
 uint8_t raw[1500];size_t length=n-ihl-8;memcpy(raw,p+ihl+8,length);
 hs_dns_lock(s);size_t i;for(i=0;i<32;i++)if(!s->queries[i].length)break;
 if(i==32){atomic_flag_clear(&s->dns_lock);return 0;}
 uint16_t id=++s->dns_sequence;put16(raw,id);
 if(send(s->domestic,(char *)raw,(int)length,0)!=(int)length){atomic_flag_clear(&s->dns_lock);return 0;}
 s->queries[i].id=id;s->queries[i].length=n;s->queries[i].question=(size_t)q;s->queries[i].sent=now_ms();s->queries[i].deadline=s->queries[i].sent+1500;memcpy(s->queries[i].packet,p,n);
 atomic_fetch_add(&s->dns_direct_count,1);atomic_flag_clear(&s->dns_lock);return 1;
}
static int hs_direct_receive_mode(hs_session *s,uint8_t *out,size_t capacity,int *fallback){
 if(s->domestic==INVALID_HS_SOCKET)return 0;
 uint8_t raw[1500];int size=readable(s->domestic,0)?recv(s->domestic,(char *)raw,sizeof(raw),0):0,result=0;
 hs_dns_lock(s);
 for(size_t i=0;i<32;i++){
  if(!s->queries[i].length)continue;
  uint8_t *p=s->queries[i].packet;size_t ihl=(p[0]&15)*4,q=s->queries[i].question;
  int matched=size>=12&&get16(raw)==s->queries[i].id&&(raw[2]&0x80);
  int valid=matched&&(size_t)size>=q&&((raw[3]&15)==0||(raw[3]&15)==3)&&!(raw[2]&2)&&get16(raw+4)==1&&!memcmp(raw+12,p+ihl+20,q-12);
  if(valid&&ihl+8+(size_t)size<=capacity){
   size_t total=ihl+8+(size_t)size;memcpy(out,p,ihl+8);memcpy(out+ihl+8,raw,(size_t)size);put16(out+ihl+8,get16(p+ihl+8));
   memcpy(out+12,p+16,4);memcpy(out+16,p+12,4);out[8]=64;put16(out+2,(uint16_t)total);put16(out+10,0);put16(out+10,checksum(out,ihl));
   put16(out+ihl,get16(p+ihl+2));put16(out+ihl+2,get16(p+ihl));put16(out+ihl+4,(uint16_t)(total-ihl));put16(out+ihl+6,0);uint16_t sum=hs_transport_checksum(out,total,ihl);put16(out+ihl+6,sum?sum:65535);
   uint64_t elapsed=now_ms()-s->queries[i].sent;atomic_fetch_add(&s->dns_direct_replies,1);atomic_fetch_add(&s->dns_direct_ms,elapsed);if(elapsed>atomic_load(&s->dns_direct_max_ms))atomic_store(&s->dns_direct_max_ms,elapsed);
   s->queries[i].length=0;result=(int)total;break;
  }
  if(matched||now_ms()>=s->queries[i].deadline){
   atomic_fetch_add(&s->dns_fallback_count,1);
   if(fallback){
    if(s->queries[i].length>capacity)continue;
    memcpy(out,p,s->queries[i].length);result=(int)s->queries[i].length;*fallback=1;
   }else if(!send_packet(s,p,s->queries[i].length))result=-1;
   s->queries[i].length=0;if(result)break;
  }
 }
 atomic_flag_clear(&s->dns_lock);return result;
}
static int hs_direct_receive(hs_session *s,uint8_t *out,size_t capacity){return hs_direct_receive_mode(s,out,capacity,NULL);}

/* A DNS-only relay shared by both iOS transports. It never sends ESP. All calls
 * (including destruction) run on the provider state queue. A timeout returns
 * the original query for the caller to forward through its selected VPN. */
HS_API hs_session *hs_dns_relay_create(const char *resolver){
 hs_session *s=hs_create();if(!s)return NULL;
 if(!resolver||inet_pton(AF_INET,resolver,s->dns)!=1){hs_destroy(s);return NULL;}
 s->ready=1;
 if(!hs_set_split_dns(s,1)){hs_destroy(s);return NULL;}
 return s;
}
HS_API int hs_dns_relay_submit(hs_session *s,const uint8_t *p,size_t n){return s?hs_direct_query(s,p,n):0;}
HS_API int hs_dns_relay_poll(hs_session *s,uint8_t *out,size_t cap,int *fallback){
 if(!s||!out||!fallback)return 0;
 *fallback=0;return hs_direct_receive_mode(s,out,cap,fallback);
}
HS_API void hs_prepare_ipv4(uint8_t *p,size_t n){hs_clamp_mss(p,n);}

/* Fixed-size operational metadata only; no domain names or packet bodies retained. */
static void hs_observe_dns(hs_session *s,const uint8_t *p,size_t n,int response){
 if(n<40||(p[0]>>4)!=4||p[9]!=17||get16(p+2)!=n||(get16(p+6)&0x3fff))return;
 size_t ihl=(p[0]&15)*4;if(ihl<20||ihl+20>n||get16(p+ihl+4)!=n-ihl)return;
 if(memcmp(p+(response?12:16),s->dns,4)||get16(p+ihl+(response?0:2))!=53)return;
 const uint8_t *dns=p+ihl+8;size_t length=n-ihl-8;
 if(((dns[2]&0x80)!=0)!=response)return;
 uint16_t id=get16(dns),port=get16(p+ihl+(response?2:0));uint64_t now=now_ms();
 hs_dns_lock(s);
 size_t slot=64;
 for(size_t i=0;i<64;i++)if(s->vpn_queries[i].sent&&s->vpn_queries[i].id==id&&s->vpn_queries[i].port==port){slot=i;break;}
 if(response){
  if(slot<64){uint64_t elapsed=now-s->vpn_queries[slot].sent;atomic_fetch_add(&s->dns_vpn_replies,1);atomic_fetch_add(&s->dns_vpn_ms,elapsed);if(elapsed>atomic_load(&s->dns_vpn_max_ms))atomic_store(&s->dns_vpn_max_ms,elapsed);s->vpn_queries[slot].sent=0;}
 }else{
  atomic_fetch_add(&s->dns_vpn_queries,1);
  size_t q=12;while(q<length&&dns[q]&&dns[q]<=63&&q+1+dns[q]<length)q+=1+dns[q];
  if(q+5<=length&&!dns[q]&&(get16(dns+q+1)==64||get16(dns+q+1)==65))atomic_fetch_add(&s->dns_https_queries,1);
  if(slot==64){for(size_t i=0;i<64;i++)if(!s->vpn_queries[i].sent||now-s->vpn_queries[i].sent>15000){slot=i;break;}
   if(slot<64){s->vpn_queries[slot].id=id;s->vpn_queries[slot].port=port;s->vpn_queries[slot].sent=now;}}
 }
 atomic_flag_clear(&s->dns_lock);
}
