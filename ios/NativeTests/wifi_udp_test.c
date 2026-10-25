/* SPDX-License-Identifier: GPL-2.0-or-later. Real loopback UDP and ESP crypto. */
#define HS_UDP_INITIAL_MS 220
#define HS_UDP_RETRY_MS 220
#define HS_UDP_PROBE_MS 50
#include "../Native/scvpn.c"
#ifndef _WIN32
#include <pthread.h>
#endif
#define CHECK(x) do{if(!(x)){fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#x);return 1;}}while(0)
typedef struct {
 hs_socket fd;hs_session *client;atomic_int stop;
 unsigned ports[3],count,last_sequence;int mode,ordered;
} peer;
#ifdef _WIN32
static DWORD WINAPI serve(void *arg)
#else
static void *serve(void *arg)
#endif
{
 peer *p=arg;uint8_t raw[2048];
 while(!p->stop){
  if(!readable(p->fd,20))continue;
  struct sockaddr_in from;socklen_t length=sizeof(from);
  int n=recvfrom(p->fd,(char *)raw,sizeof(raw),0,(struct sockaddr *)&from,&length);
  if(n<=0)continue;
  unsigned port=ntohs(from.sin_port);
  if(!p->count||p->ports[p->count-1]!=port){if(p->count<3)p->ports[p->count++]=port;}
  unsigned sequence=get32(raw+4);if(sequence<=p->last_sequence)p->ordered=0;p->last_sequence=sequence;
  if(p->mode==3){hs_cancel(p->client);continue;}
  if(p->mode==0&&p->count<2)continue; /* Initial mapping blackholed. */
  if(p->mode==1)continue; /* All mappings blackholed. */
  if(p->mode==2)raw[n-1]^=1; /* Correct SPI, invalid HMAC. */
  sendto(p->fd,(char *)raw,n,0,(struct sockaddr *)&from,length);
 }
#ifdef _WIN32
 return 0;
#else
 return NULL;
#endif
}
static int protect_calls;
static int protected_socket(void *unused,intptr_t fd){(void)unused;(void)fd;protect_calls++;return 1;}
static int deny_socket(void *unused,intptr_t fd){(void)unused;(void)fd;return 0;}
static int exercise(int mode){
 hs_session *s=hs_create();CHECK(s);s->session_id=123;s->tx_spi=s->rx_spi=0x12345678;
 memset(s->tx_key,0x24,24);memcpy(s->rx_key,s->tx_key,24);
 memset(s->tx_auth,0x37,20);memcpy(s->rx_auth,s->tx_auth,20);
 /* nonblocking() is called on the live TLS socket only after UDP validation. */
 s->control=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);CHECK(s->control!=INVALID_HS_SOCKET);
 peer p={0};p.fd=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);CHECK(p.fd!=INVALID_HS_SOCKET);p.client=s;p.mode=mode;p.ordered=1;
 struct sockaddr_in endpoint={0};endpoint.sin_family=AF_INET;endpoint.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
 CHECK(!bind(p.fd,(struct sockaddr *)&endpoint,sizeof(endpoint)));socklen_t length=sizeof(endpoint);
 CHECK(!getsockname(p.fd,(struct sockaddr *)&endpoint,&length));s->data_port=ntohs(endpoint.sin_port);
 struct sockaddr_in source=endpoint;source.sin_port=0;protect_calls=0;
#ifdef _WIN32
 HANDLE thread=CreateThread(NULL,0,serve,&p,0,NULL);CHECK(thread);
#else
 pthread_t thread;CHECK(!pthread_create(&thread,NULL,serve,&p));
#endif
 uint64_t start=now_ms();int ok=hs_udp_establish(s,&endpoint,&source,protected_socket,NULL);uint64_t elapsed=now_ms()-start;
 p.stop=1;
#ifdef _WIN32
 CHECK(WaitForSingleObject(thread,2000)==WAIT_OBJECT_0);CloseHandle(thread);
#else
 pthread_join(thread,NULL);
#endif
 CHECK(elapsed<2000);CHECK(p.ordered);
 if(mode==0){
  CHECK(ok&&hs_ready(s));CHECK(p.count==2&&p.ports[0]!=p.ports[1]);
  CHECK(protect_calls==2&&s->udp_paths==2&&s->udp_raw==1&&s->udp_invalid==0);
  CHECK(s->rx_highest==s->tx_sequence&&s->tx_sequence>1);
  puts("PASS: blackholed initial mapping recovers using a different protected source port with valid ESP");
 }else if(mode==1||mode==2){
  CHECK(!ok&&!hs_ready(s));CHECK(p.count==3&&protect_calls==3);
  CHECK(p.ports[0]!=p.ports[1]&&p.ports[1]!=p.ports[2]);
  CHECK(strstr(hs_error(s),"data_heartbeat_timeout udp_port=")&&strstr(hs_error(s),"paths=3"));
  if(mode==1){CHECK(!s->udp_raw&&!s->udp_auth_bad);puts("PASS: silent network exhausts exactly three mappings within the time budget and reports no received UDP");}
  else {CHECK(s->udp_raw>0&&s->udp_auth_bad==s->udp_raw&&!s->rx_highest);puts("PASS: invalid HMAC replies stay rejected across source-port recovery and preserve replay state");}
 }else {CHECK(!ok&&!hs_ready(s));CHECK(protect_calls==1);CHECK(elapsed<500);puts("PASS: cancellation interrupts the handshake without creating another mapping");}
 hs_socket_close(p.fd);hs_destroy(s);return 0;
}
int main(void){
 for(int mode=0;mode<4;mode++)CHECK(!exercise(mode));
 hs_session *s=hs_create();CHECK(s);struct sockaddr_in endpoint={0};endpoint.sin_family=AF_INET;endpoint.sin_addr.s_addr=htonl(INADDR_LOOPBACK);endpoint.sin_port=htons(9);
 CHECK(!hs_udp_open(s,&endpoint,&endpoint,deny_socket,NULL));CHECK(!s->udp_paths&&s->data==INVALID_HS_SOCKET);CHECK(!strcmp(hs_error(s),"socket_protect_failed"));
 puts("PASS: rejected network protection cannot send a probe or install a UDP socket");hs_destroy(s);return 0;
}
