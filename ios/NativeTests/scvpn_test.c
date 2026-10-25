/* Host regression tests use the actual SCVPN implementation and OpenSSL.
 * They exercise no gateway and are not evidence of an iOS device build. */
#ifdef _WIN32
/* Match the system declaration that exposed the collision on Apple platforms.
 * Never call or implement this function; it only guards the C namespace. */
extern char *crypt(const char *, const char *);
#endif
#define HS_NATIVE_TEST 1
#include "../Native/scvpn.c"

#define CHECK(expression) do { \
    if (!(expression)) { \
        fprintf(stderr, "FAIL: %s (line %d)\n", #expression, __LINE__); \
        return 1; \
    } \
} while (0)

static int packet_tests(void){
 uint8_t p[1500]={0},out[1500],copy[1500];
 const uint8_t query[]={0x12,0x34,1,0,0,1,0,0,0,0,0,0,7,'e','x','a','m','p','l','e',3,'c','o','m',0,0,28,0,1};
 size_t n=28+sizeof(query);p[0]=0x45;put16(p+2,(uint16_t)n);p[8]=64;p[9]=17;p[12]=10;p[15]=2;p[16]=8;p[17]=8;p[18]=8;p[19]=8;
 put16(p+20,54321);put16(p+22,53);put16(p+24,(uint16_t)(8+sizeof(query)));memcpy(p+28,query,sizeof(query));put16(p+10,checksum(p,20));
 int got=hs_local_reply(p,n,out,sizeof(out));CHECK(got==(int)n);CHECK(get16(out+20)==53&&get16(out+22)==54321);CHECK(get16(out+28)==0x1234);CHECK(out[30]==0x81&&out[31]==0x80);CHECK(get16(out+34)==0);CHECK(!checksum(out,20));CHECK(!hs_transport_checksum(out,n,20));CHECK(!memcmp(out+12,p+16,4)&&!memcmp(out+16,p+12,4));
 puts("PASS: AAAA NODATA preserves question, transaction and valid IPv4/UDP checksums");
 p[n-3]=1;CHECK(!hs_local_reply(p,n,out,sizeof(out)));p[n-3]=28;CHECK(!hs_local_reply(p,n,out,n-1));CHECK(!hs_local_reply(p,27,out,sizeof(out)));
 puts("PASS: A queries and short input/output are not intercepted");
 p[6]=0x20;CHECK(!hs_local_reply(p,n,out,sizeof(out)));p[6]=0;p[40]=0xc0;CHECK(!hs_local_reply(p,n,out,sizeof(out)));p[40]=7;
 puts("PASS: fragmented and compressed/malformed DNS questions are not synthesized");
 memset(p,0,sizeof(p));n=44;p[0]=0x45;put16(p+2,(uint16_t)n);p[8]=64;p[9]=6;p[12]=10;p[15]=2;p[16]=1;p[19]=1;p[32]=0x60;p[33]=2;p[40]=2;p[41]=4;put16(p+42,1460);put16(p+36,hs_transport_checksum(p,n,20));put16(p+10,checksum(p,20));hs_clamp_mss(p,n);CHECK(get16(p+42)==1160);CHECK(!hs_transport_checksum(p,n,20));CHECK(!checksum(p,20));
 puts("PASS: SYN MSS clamped to 1160 with valid TCP and IP checksums");
 put16(p+42,1000);put16(p+36,0);put16(p+36,hs_transport_checksum(p,n,20));memcpy(copy,p,n);hs_clamp_mss(p,n);CHECK(!memcmp(p,copy,n));p[41]=5;memcpy(copy,p,n);hs_clamp_mss(p,n);CHECK(!memcmp(p,copy,n));
 puts("PASS: smaller MSS and malformed TCP options are unchanged");
 memset(p,0,sizeof(p));n=60;p[0]=0x60;put16(p+4,20);p[6]=6;p[7]=64;p[8]=0x20;p[9]=1;p[23]=2;p[24]=0x20;p[25]=1;p[39]=3;
 got=hs_local_reply(p,n,out,sizeof(out));CHECK(got==108);CHECK(out[6]==58&&out[40]==1&&out[41]==0);CHECK(!memcmp(out+8,p+24,16)&&!memcmp(out+24,p+8,16));CHECK(!memcmp(out+48,p,n));
 uint8_t pseudo[40+1500]={0};memcpy(pseudo,out+8,32);put32(pseudo+32,(uint32_t)(got-40));pseudo[39]=58;memcpy(pseudo+40,out+40,(size_t)got-40);CHECK(!checksum(pseudo,(size_t)got));
 puts("PASS: IPv6 no-route reply with independently assembled pseudo-header checksum");
 p[8]=0xff;CHECK(!hs_local_reply(p,n,out,sizeof(out)));p[8]=0x20;p[6]=58;CHECK(!hs_local_reply(p,n,out,sizeof(out)));p[6]=6;CHECK(!hs_local_reply(p,n,out,100));
 puts("PASS: no recursive ICMP errors, multicast replies or output overflows");
 memset(p+40,0,1460);n=1500;put16(p+4,1460);got=hs_local_reply(p,n,out,sizeof(out));CHECK(got==1280);
 puts("PASS: IPv6 error bounded to minimum MTU 1280");
 uint8_t domestic[]={1,2,1,0,0,1,0,0,0,0,0,0,3,'W','W','W',5,'B','A','I','D','U',3,'c','o','m',0,0,1,0,1};
 CHECK(hs_domestic_question(domestic,sizeof(domestic))==(int)sizeof(domestic));domestic[30]=28;CHECK(!hs_domestic_question(domestic,sizeof(domestic)));domestic[30]=1;
 uint8_t foreign[]={1,2,1,0,0,1,0,0,0,0,0,0,7,'c','h','a','t','g','p','t',3,'c','o','m',0,0,1,0,1};
 CHECK(!hs_domestic_question(foreign,sizeof(foreign)));domestic[12]=0xc0;CHECK(!hs_domestic_question(domestic,sizeof(domestic)));domestic[12]=3;
 puts("PASS: domestic suffix matching is case insensitive and foreign DNS stays on VPN");
 hs_session *s=hs_create();CHECK(s);memcpy(s->dns,"\10\10\10\10",4);
 hs_socket server=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);CHECK(server!=INVALID_HS_SOCKET);struct sockaddr_in endpoint={0};endpoint.sin_family=AF_INET;endpoint.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
 CHECK(!bind(server,(struct sockaddr *)&endpoint,sizeof(endpoint)));socklen_t endpoint_size=sizeof(endpoint);CHECK(!getsockname(server,(struct sockaddr *)&endpoint,&endpoint_size));
 s->domestic=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);CHECK(s->domestic!=INVALID_HS_SOCKET);CHECK(!connect(s->domestic,(struct sockaddr *)&endpoint,sizeof(endpoint)));CHECK(nonblocking(s->domestic,1));
 memset(p,0,sizeof(p));n=28+sizeof(domestic);p[0]=0x45;put16(p+2,(uint16_t)n);p[8]=64;p[9]=17;p[12]=10;p[15]=2;memcpy(p+16,s->dns,4);put16(p+20,54321);put16(p+22,53);put16(p+24,(uint16_t)(n-20));memcpy(p+28,domestic,sizeof(domestic));put16(p+10,checksum(p,20));
 CHECK(hs_direct_query(s,p,n));CHECK(readable(server,1000));uint8_t raw[1500];struct sockaddr_in from;socklen_t from_size=sizeof(from);int bytes=recvfrom(server,(char *)raw,sizeof(raw),0,(struct sockaddr *)&from,&from_size);CHECK(bytes==(int)sizeof(domestic));raw[2]=0x81;raw[3]=0x80;put16(raw+6,1);memcpy(raw+bytes,"\xc0\x0c\0\1\0\1\0\0\0\x3c\0\4\x99\3\xee\x7f",16);CHECK(sendto(server,(char *)raw,bytes+16,0,(struct sockaddr *)&from,from_size)==bytes+16);
 CHECK(readable(s->domestic,1000));got=hs_direct_receive(s,out,sizeof(out));CHECK(got==(int)n+16);CHECK(get16(out+28)==get16(domestic));CHECK(!checksum(out,20)&&!hs_transport_checksum(out,(size_t)got,20));CHECK(!memcmp(out+12,s->dns,4));CHECK(!s->queries[0].length);
 puts("PASS: actual UDP domestic relay preserves DNS identity and packet checksums");
 for(unsigned type=64;type<=65;type++){
  p[n-3]=(uint8_t)type;CHECK(hs_domestic_question(p+28,n-28)==(int)(n-28));
  CHECK(hs_direct_query(s,p,n));CHECK(readable(server,1000));from_size=sizeof(from);
  bytes=recvfrom(server,(char *)raw,sizeof(raw),0,(struct sockaddr *)&from,&from_size);CHECK(bytes==(int)sizeof(domestic));
  raw[2]=0x81;raw[3]=0x80;
  CHECK(sendto(server,(char *)raw,bytes,0,(struct sockaddr *)&from,from_size)==bytes);
  CHECK(readable(s->domestic,1000));got=hs_direct_receive(s,out,sizeof(out));CHECK(got==(int)n);
  CHECK(get16(out+n-4)==type);CHECK(get16(out+34)==0);CHECK(!s->queries[0].length);CHECK(!atomic_load(&s->dns_fallback_count));
  CHECK(!checksum(out,20)&&!hs_transport_checksum(out,(size_t)got,20));
 }
 puts("PASS: actual UDP SVCB/HTTPS NODATA returns immediately without gateway fallback");
 p[n-3]=1;CHECK(hs_direct_query(s,p,n));CHECK(readable(server,1000));from_size=sizeof(from);
 bytes=recvfrom(server,(char *)raw,sizeof(raw),0,(struct sockaddr *)&from,&from_size);CHECK(bytes==(int)sizeof(domestic));raw[2]=0x81;raw[3]=0x83;
 CHECK(sendto(server,(char *)raw,bytes,0,(struct sockaddr *)&from,from_size)==bytes);CHECK(readable(s->domestic,1000));
 got=hs_direct_receive(s,out,sizeof(out));CHECK(got==(int)n);CHECK((out[31]&15)==3);CHECK(!atomic_load(&s->dns_fallback_count));CHECK(atomic_load(&s->dns_direct_replies)==4);
 puts("PASS: valid NXDOMAIN is preserved without delayed gateway fallback");
 foreign[sizeof(foreign)-3]=65;CHECK(!hs_domestic_question(foreign,sizeof(foreign)));
 hs_observe_dns(s,p,n,0);CHECK(atomic_load(&s->dns_vpn_queries)==1);CHECK(s->vpn_queries[0].sent);
 s->vpn_queries[0].sent=now_ms()-25;
 memcpy(out,p,n);memcpy(out+12,p+16,4);memcpy(out+16,p+12,4);put16(out+20,53);put16(out+22,54321);out[30]|=0x80;
 hs_observe_dns(s,out,n,1);CHECK(atomic_load(&s->dns_vpn_replies)==1);CHECK(atomic_load(&s->dns_vpn_max_ms)>=25);CHECK(!s->vpn_queries[0].sent);
 puts("PASS: bounded gateway DNS metadata measures query/response elapsed time");

 s->data=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);CHECK(s->data!=INVALID_HS_SOCKET);CHECK(!connect(s->data,(struct sockaddr *)&endpoint,sizeof(endpoint)));memset(s->tx_key,0x42,24);memset(s->tx_auth,0x35,20);s->tx_spi=0x1001;
 for(unsigned truncated=0;truncated<=1;truncated++){
  CHECK(hs_direct_query(s,p,n));CHECK(readable(server,1000));from_size=sizeof(from);
  bytes=recvfrom(server,(char *)raw,sizeof(raw),0,(struct sockaddr *)&from,&from_size);CHECK(bytes==(int)sizeof(domestic));raw[2]=truncated?0x83:0x81;raw[3]=truncated?0x80:0x82;
  CHECK(sendto(server,(char *)raw,bytes,0,(struct sockaddr *)&from,from_size)==bytes);CHECK(readable(s->domestic,1000));
  CHECK(hs_direct_receive(s,out,sizeof(out))==0);CHECK(!s->queries[0].length);CHECK(readable(server,1000));bytes=recv(server,(char *)raw,sizeof(raw),0);CHECK(bytes>28);
  CHECK(hs_esp_cipher(s->tx_key,raw+8,raw+16,(size_t)bytes-28,out,0));CHECK(!memcmp(out,p,n));
 }
 puts("PASS: SERVFAIL and truncated direct DNS still fall back through encrypted gateway");
 CHECK(hs_direct_query(s,p,n));CHECK(readable(server,1000));CHECK(recv(server,(char *)raw,sizeof(raw),0)>0);s->queries[0].deadline=0;CHECK(hs_direct_receive(s,out,sizeof(out))==0);CHECK(!s->queries[0].length);CHECK(readable(server,1000));bytes=recv(server,(char *)raw,sizeof(raw),0);CHECK(bytes>28);CHECK(hs_esp_cipher(s->tx_key,raw+8,raw+16,(size_t)bytes-28,out,0));CHECK(!memcmp(out,p,n));
 puts("PASS: direct DNS timeout sends exact original query through encrypted gateway channel");
 CHECK(hs_dns_relay_submit(s,p,n));CHECK(readable(server,1000));CHECK(recv(server,(char *)raw,sizeof(raw),0)>0);
 s->queries[0].deadline=0;int fallback=0;
 got=hs_dns_relay_poll(s,out,sizeof(out),&fallback);
 CHECK(got==(int)n&&fallback==1&&!memcmp(out,p,n));CHECK(!s->queries[0].length);CHECK(!readable(server,0));
 puts("PASS: shared relay returns exact timeout query to either VPN without sending ESP itself");
 CHECK(hs_dns_relay_submit(s,p,n));CHECK(readable(server,1000));CHECK(recv(server,(char *)raw,sizeof(raw),0)>0);
 raw[2]=0x83;raw[3]=0x80; /* Truncated reply: preserve original TCP-capable VPN fallback. */
 CHECK(sendto(server,(char *)raw,(int)(n-28),0,(struct sockaddr *)&from,from_size)==(int)(n-28));CHECK(readable(s->domestic,1000));
 got=hs_dns_relay_poll(s,out,sizeof(out),&fallback);CHECK(got==(int)n&&fallback==1&&!memcmp(out,p,n));
 puts("PASS: truncated domestic reply falls back without returning incomplete DNS to apps");
 for(unsigned i=0;i<32;i++)CHECK(hs_dns_relay_submit(s,p,n));
 CHECK(!hs_dns_relay_submit(s,p,n));
 puts("PASS: shared relay caps outstanding queries at 32");
 hs_socket_close(server);hs_destroy(s);
 return 0;
}
static int resume_tests(void){
 hs_session *s=hs_create(),*peer=hs_create();CHECK(s&&peer);
 hs_socket server=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);CHECK(server!=INVALID_HS_SOCKET);
 struct sockaddr_in endpoint={0};endpoint.sin_family=AF_INET;endpoint.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
 CHECK(!bind(server,(struct sockaddr *)&endpoint,sizeof(endpoint)));socklen_t size=sizeof(endpoint);CHECK(!getsockname(server,(struct sockaddr *)&endpoint,&size));
 s->data=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);CHECK(s->data!=INVALID_HS_SOCKET);CHECK(!connect(s->data,(struct sockaddr *)&endpoint,sizeof(endpoint)));
 s->control_closed=1;s->ready=1;s->tx_spi=0x1001;s->rx_spi=0x1002;memset(s->tx_key,0x42,24);memset(s->tx_auth,0x35,20);memset(s->rx_key,0x24,24);memset(s->rx_auth,0x53,20);make_heartbeat(s);
 uint64_t old=now_ms()-20000;s->last_received_heartbeat=old;s->last_receive_tick=old;
 uint8_t packet[2048];CHECK(hs_receive(s,packet,sizeof(packet),0)==0);CHECK(hs_ready(s));CHECK(s->last_received_heartbeat==old);CHECK(s->resume_until>now_ms());
 CHECK(readable(server,1000));struct sockaddr_in from;size=sizeof(from);CHECK(recvfrom(server,(char *)packet,sizeof(packet),0,(struct sockaddr *)&from,&size)>0);
 peer->data=server;CHECK(!connect(server,(struct sockaddr *)&from,sizeof(from)));peer->tx_spi=s->rx_spi;memcpy(peer->tx_key,s->rx_key,24);memcpy(peer->tx_auth,s->rx_auth,20);
 CHECK(send_packet(peer,s->heartbeat,44));CHECK(hs_receive(s,packet,sizeof(packet),100)==0);CHECK(s->last_received_heartbeat>old);CHECK(hs_ready(s));
 puts("PASS: suspended worker sends heartbeat and accepts a real encrypted reply before expiration");
 /* A short scheduling gap must not discard an already buffered valid heartbeat. */
 s->last_receive_tick=now_ms();s->last_received_heartbeat=now_ms()-20000;s->resume_until=now_ms()-1;
 CHECK(send_packet(peer,s->heartbeat,44));CHECK(readable(s->data,1000));
 CHECK(hs_receive(s,packet,sizeof(packet),0)==0);CHECK(hs_ready(s));
 CHECK(now_ms()-s->last_received_heartbeat<1000);
 puts("PASS: buffered authenticated heartbeat is consumed before timeout evaluation");
 s->last_receive_tick=now_ms();s->last_received_heartbeat=now_ms()-20000;s->resume_until=now_ms()-1;
 CHECK(hs_receive(s,packet,sizeof(packet),0)==-1);CHECK(!strcmp(hs_error(s),"data_heartbeat_expired"));CHECK(!hs_ready(s));
 puts("PASS: silent gateway still expires after bounded resume grace; no fabricated heartbeat");
 hs_destroy(peer);hs_destroy(s);return 0;
}

#ifndef _WIN32
#include <pthread.h>
#endif
struct probe_fixture {hs_session *client,*peer;hs_socket server;int ok;};
#ifdef _WIN32
static DWORD WINAPI probe_responder(void *context){
#else
static void *probe_responder(void *context){
#endif
 struct probe_fixture *f=context;uint8_t wire[2048],plain[2048],selected[1500];size_t length=0;
 for(unsigned i=0;i<2;i++){
  if(!readable(f->server,1000))return 0;
  struct sockaddr_in from;socklen_t size=sizeof(from);int n=recvfrom(f->server,(char *)wire,sizeof(wire),0,(struct sockaddr *)&from,&size);
  if(n<36||!hs_esp_cipher(f->client->tx_key,wire+8,wire+16,(size_t)n-28,plain,0))return 0;
  if(connect(f->server,(struct sockaddr *)&from,sizeof(from)))return 0;
  if(!memcmp(plain+16,"\1\1\1\1",4)){length=get16(plain+2);memcpy(selected,plain,length);}
 }
 if(length!=57)return 0;
 uint8_t swap[4];memcpy(swap,selected+12,4);memcpy(selected+12,selected+16,4);memcpy(selected+16,swap,4);
 uint16_t port=get16(selected+20);put16(selected+20,53);put16(selected+22,port);selected[30]=0x81;selected[31]=0x80;put16(selected+34,1);
 memcpy(selected+length,"\xc0\x0c\0\1\0\1\0\0\0\x3c\0\4\x5d\xb8\xd8\x22",16);length+=16;
 put16(selected+2,(uint16_t)length);put16(selected+24,(uint16_t)(length-20));put16(selected+10,0);put16(selected+10,checksum(selected,20));put16(selected+26,0);put16(selected+26,hs_transport_checksum(selected,length,20));
 /* Wrong transaction ID cannot select the alternative DNS. */
 uint16_t id=get16(selected+28);put16(selected+28,(uint16_t)(id+1));put16(selected+26,0);put16(selected+26,hs_transport_checksum(selected,length,20));if(!send_packet(f->peer,selected,length))return 0;put16(selected+28,id);
 /* Match the clock used by the measured probe. Windows GetTickCount64 has
  * coarse ticks, so a single Sleep(20) can measure less than 20 ms. */
 uint64_t valid_after=now_ms()+20;
 while(now_ms()<valid_after){
#ifdef _WIN32
  Sleep(1);
#else
  usleep(1000);
#endif
 }
 put16(selected+26,0);put16(selected+26,hs_transport_checksum(selected,length,20));f->ok=send_packet(f->peer,selected,length);return 0;
}
static int selection_tests(void){
 hs_session *s=hs_create(),*peer=hs_create();CHECK(s&&peer);
 hs_socket server=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);CHECK(server!=INVALID_HS_SOCKET);
 struct sockaddr_in endpoint={0};endpoint.sin_family=AF_INET;endpoint.sin_addr.s_addr=htonl(INADDR_LOOPBACK);CHECK(!bind(server,(struct sockaddr *)&endpoint,sizeof(endpoint)));
 socklen_t size=sizeof(endpoint);CHECK(!getsockname(server,(struct sockaddr *)&endpoint,&size));
 s->data=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);CHECK(s->data!=INVALID_HS_SOCKET);CHECK(!connect(s->data,(struct sockaddr *)&endpoint,sizeof(endpoint)));
 s->control_closed=1;s->ready=1;s->tx_spi=0x1001;s->rx_spi=0x1002;memcpy(s->address,"\12\0\0\2",4);memcpy(s->dns,"\10\10\10\10",4);
 memset(s->tx_key,0x42,24);memset(s->tx_auth,0x35,20);memset(s->rx_key,0x24,24);memset(s->rx_auth,0x53,20);
 s->last_sent_heartbeat=s->last_received_heartbeat=s->last_receive_tick=now_ms();
 peer->data=server;peer->tx_spi=s->rx_spi;memcpy(peer->tx_key,s->rx_key,24);memcpy(peer->tx_auth,s->rx_auth,20);
 struct probe_fixture f={s,peer,server,0};
#ifdef _WIN32
 HANDLE thread=CreateThread(NULL,0,probe_responder,&f,0,NULL);CHECK(thread);
#else
 pthread_t thread;CHECK(!pthread_create(&thread,NULL,probe_responder,&f));
#endif
 CHECK(hs_select_public_dns(s)==1);
#ifdef _WIN32
 CHECK(WaitForSingleObject(thread,2000)==WAIT_OBJECT_0);CloseHandle(thread);
#else
 CHECK(!pthread_join(thread,NULL));
#endif
 CHECK(f.ok);CHECK(!memcmp(s->dns,"\1\1\1\1",4));CHECK(s->selected_dns_ms>=20&&s->selected_dns_ms<1200);
 puts("PASS: actual encrypted UDP public DNS comparison selects valid faster reply, ignoring wrong ID");
 memcpy(s->dns,"\12\2\3\4",4);CHECK(hs_select_public_dns(s)==1);CHECK(!memcmp(s->dns,"\12\2\3\4",4));CHECK(!readable(server,0));
 memcpy(s->dns,"\11\11\11\11",4);CHECK(hs_select_public_dns(s)==1);CHECK(!memcmp(s->dns,"\11\11\11\11",4));CHECK(!readable(server,0));
 puts("PASS: private and custom DNS are preserved without public resolver probes");
 memcpy(s->dns,"\10\10\10\10",4);CHECK(hs_select_public_dns(s)==1);CHECK(!memcmp(s->dns,"\10\10\10\10",4));CHECK(s->selected_dns_ms==0);
 puts("PASS: both public DNS probes unanswered retain configured resolver for normal validation");

 hs_destroy(peer);hs_destroy(s);return 0;
}
static int metric_tests(void){
 hs_session *s=hs_create();CHECK(s);uint8_t p[40]={0},reply[40];p[0]=0x45;put16(p+2,40);p[9]=6;memcpy(p+12,"\12\0\0\2",4);memcpy(p+16,"\x5d\xb8\xd8\x22",4);put16(p+20,54321);put16(p+22,443);put32(p+24,99);p[32]=0x50;p[33]=2;
 hs_observe_tcp(s,p,sizeof(p),0);CHECK(atomic_load(&s->syn_packets)==1);hs_observe_tcp(s,p,sizeof(p),0);CHECK(atomic_load(&s->syn_retries)==1);s->syn[0].sent=now_ms()-50;
 memcpy(reply,p,40);memcpy(reply+12,p+16,4);memcpy(reply+16,p+12,4);put16(reply+20,443);put16(reply+22,54321);put32(reply+28,100);reply[33]=18;
 hs_observe_tcp(s,reply,sizeof(reply),1);CHECK(atomic_load(&s->syn_replies)==1);CHECK(atomic_load(&s->syn_max_ms)>=50);CHECK(!s->syn[0].sent);
 hs_observe_tcp(s,reply,sizeof(reply),1);CHECK(atomic_load(&s->syn_replies)==1);
 puts("PASS: bounded TCP SYN/SYN-ACK metadata preserves first attempt time and counts retries");hs_destroy(s);return 0;
}
int main(void) {
    /* Fixed non-secret test values, independently checked with openssl enc. */
    const uint8_t key[24] = {
        0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
        0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0x01,
        0x45,0x67,0x89,0xab,0xcd,0xef,0x01,0x23
    };
    const uint8_t iv[8] = {0x12,0x34,0x56,0x78,0x90,0xab,0xcd,0xef};
    const uint8_t plain[16] = {
        0x4e,0x6f,0x77,0x20,0x69,0x73,0x20,0x74,
        0x68,0x65,0x20,0x74,0x69,0x6d,0x65,0x20
    };
    const uint8_t expected[16] = {
        0xf3,0xc0,0xff,0x02,0x6c,0x02,0x30,0x89,
        0x65,0x6f,0xbb,0x16,0x9d,0xef,0x7e,0xdb
    };
    uint8_t encrypted[32] = {0}, decrypted[32] = {0};
    CHECK(hs_esp_cipher(key, iv, plain, sizeof(plain), encrypted, 1));
    CHECK(memcmp(encrypted, expected, sizeof(expected)) == 0);
    puts("PASS: SCVPN 3DES-CBC known ciphertext");
    CHECK(hs_esp_cipher(key, iv, expected, sizeof(expected), decrypted, 0));
    CHECK(memcmp(decrypted, plain, sizeof(plain)) == 0);
    puts("PASS: SCVPN 3DES-CBC decryption");
    CHECK(!hs_esp_cipher(key, iv, plain, 15, encrypted, 1));
    puts("PASS: incomplete cipher block rejected without padding");
    hs_session *session = hs_create();
    CHECK(session != NULL);
    CHECK(!hs_ready(session));
    memcpy(session->tx_key,key,24);memcpy(session->rx_key,key,24);
    CHECK(hs_packet_cipher(session,iv,plain,16,encrypted,1));CHECK(!memcmp(encrypted,expected,16));
    EVP_CIPHER_CTX *tx=session->tx_cipher;
    for(unsigned i=0;i<256;i++){
      uint8_t next_iv[8];memcpy(next_iv,iv,8);next_iv[0]^=(uint8_t)i;
      uint8_t reference[32];CHECK(hs_esp_cipher(key,next_iv,plain,16,reference,1));
      CHECK(hs_packet_cipher(session,next_iv,plain,16,encrypted,1));CHECK(!memcmp(reference,encrypted,16));
      CHECK(hs_packet_cipher(session,next_iv,encrypted,16,decrypted,0));CHECK(!memcmp(decrypted,plain,16));
      CHECK(tx==session->tx_cipher&&session->rx_cipher!=session->tx_cipher);
    }
    puts("PASS: reused independent TX/RX cipher contexts match 256 per-packet IV vectors");
    CHECK(!hs_send(session, plain, sizeof(plain)));
    CHECK(hs_receive(session, decrypted, sizeof(decrypted), 0) == -1);
    hs_cancel(session);
    CHECK(!hs_ready(session));
    hs_destroy(session);
    hs_destroy(NULL);
    puts("PASS: SCVPN session lifecycle without network access");
    CHECK(packet_tests()==0);
    CHECK(resume_tests()==0);
    CHECK(selection_tests()==0);
    CHECK(metric_tests()==0);
    return 0;
}
