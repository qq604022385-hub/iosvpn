/* SPDX-License-Identifier: GPL-2.0-or-later
 * Independent legacy SCVPN: pinned TLS control and ESP over UDP.
 * No Hillstone binaries, IPC, service calls or vendor library dependencies.
 */
#include "scvpn.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdatomic.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
typedef SOCKET hs_socket;
#define INVALID_HS_SOCKET INVALID_SOCKET
#define hs_socket_close closesocket
#else
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
typedef int hs_socket;
#define INVALID_HS_SOCKET (-1)
#define hs_socket_close close
#endif
static int hs_socket_error(void){
#ifdef _WIN32
 return WSAGetLastError();
#else
 return errno;
#endif
}
#define HS_MAX 65536
/* Match this engine's atomic-flag locks while yielding during contention.
 * Socket sends are bounded to 100 ms; cancellation and socket replacement
 * must use the same lock as the existing packet sender. */
static void hs_mutex_lock(atomic_flag *lock){while(atomic_flag_test_and_set(lock)){
#ifdef _WIN32
 Sleep(1);
#else
 usleep(1000);
#endif
}}
static void hs_mutex_unlock(atomic_flag *lock){atomic_flag_clear(lock);}
static void hs_mutex_destroy(atomic_flag *lock){(void)lock;}
struct hs_session {
 SSL_CTX *tls_context; SSL *tls; hs_socket control,data,domestic;
 EVP_CIPHER_CTX *tx_cipher,*rx_cipher;int receive_buffer;
#ifdef _WIN32
 WSAEVENT data_event,domestic_event;
#endif
 atomic_flag dns_lock,path_lock;uint16_t dns_sequence;
 atomic_uint_fast64_t syn_packets,syn_retries,syn_replies,syn_ms,syn_max_ms;
 struct {uint8_t local[4],remote[4];uint16_t lp,rp;uint32_t seq;uint64_t sent;} syn[128];
 uint64_t selected_dns_ms;
 atomic_uint_fast64_t dns_direct_replies,dns_direct_ms,dns_direct_max_ms,dns_vpn_queries,dns_vpn_replies,dns_vpn_ms,dns_vpn_max_ms,dns_https_queries;
 struct {uint16_t id,port;uint64_t sent;} vpn_queries[64];atomic_uint_fast64_t tx_packets,rx_packets,dns_direct_count,dns_fallback_count,tx_bytes,rx_bytes;
 struct {uint8_t packet[1500];size_t length,question;uint16_t id;uint64_t deadline,sent;} queries[32];
 atomic_int cancelled; atomic_int ready;atomic_flag send_lock;int control_closed;char error_detail[256]; const char *error;
 uint8_t address[4],mask[4],dns[4],gateway[4],peer[4]; uint16_t data_port;
 unsigned udp_local_port,udp_paths,udp_probes,udp_raw,udp_invalid,udp_auth_bad;
 int udp_last_os;
 uint32_t session_id,tx_spi,rx_spi,tx_sequence,rx_highest;uint64_t replay;
 uint8_t tx_auth[20],tx_key[24],rx_auth[20],rx_key[24];
 uint8_t heartbeat[44];uint64_t last_sent_heartbeat,last_receive_tick,resume_until;atomic_uint_fast64_t last_received_heartbeat;
 uint8_t control_buffer[HS_MAX];size_t control_size;uint64_t last_control_sent,last_control_received;
};
typedef struct {uint8_t bytes[HS_MAX];size_t size;uint16_t command;uint8_t subtype;} hs_message;
static uint16_t get16(const uint8_t *p){return (uint16_t)((p[0]<<8)|p[1]);}
static uint32_t get32(const uint8_t *p){return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3];}
static void put16(uint8_t *p,uint16_t n){p[0]=(uint8_t)(n>>8);p[1]=(uint8_t)n;}
static void put32(uint8_t *p,uint32_t n){p[0]=(uint8_t)(n>>24);p[1]=(uint8_t)(n>>16);p[2]=(uint8_t)(n>>8);p[3]=(uint8_t)n;}
static uint64_t now_ms(void){
#ifdef _WIN32
 return GetTickCount64();
#else
 struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return (uint64_t)t.tv_sec*1000+(uint64_t)t.tv_nsec/1000000;
#endif
}
static int fail(hs_session *s,const char *reason){s->error=reason;s->ready=0;return 0;}
static int readable(hs_socket fd,unsigned ms){fd_set set;struct timeval tv={(long)(ms/1000),(long)(ms%1000)*1000};FD_ZERO(&set);FD_SET(fd,&set);return select((int)fd+1,&set,NULL,NULL,&tv)>0;}
static void timeout(hs_socket fd,unsigned ms){
#ifdef _WIN32
 DWORD value=ms;setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,(const char *)&value,sizeof(value));setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,(const char *)&value,sizeof(value));
#else
 struct timeval value={(long)(ms/1000),(long)(ms%1000)*1000};setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&value,sizeof(value));setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&value,sizeof(value));
#endif
}
static void message(hs_message *m,uint16_t command,uint8_t subtype){memset(m,0,sizeof(*m));m->size=8;m->bytes[0]=0x22;m->bytes[1]=subtype;put16(m->bytes+2,command);m->command=command;m->subtype=subtype;}
static int append(hs_message *m,uint16_t kind,const void *value,size_t length){size_t padded=(length+3)&~(size_t)3;if(length>65535||m->size+4+padded>HS_MAX)return 0;put16(m->bytes+m->size,kind);put16(m->bytes+m->size+2,(uint16_t)length);if(length)memcpy(m->bytes+m->size+4,value,length);m->size+=4+padded;return 1;}
static int number(hs_message *m,uint16_t kind,uint32_t n,unsigned width){uint8_t b[4];if(width==2)put16(b,(uint16_t)n);else put32(b,n);return append(m,kind,b,width);}
static int write_message(hs_session *s,hs_message *m){size_t sent=0;put32(m->bytes+4,(uint32_t)m->size);while(sent<m->size&&!s->cancelled){int n=SSL_write(s->tls,m->bytes+sent,(int)(m->size-sent));if(n<=0)return fail(s,"control_write_failed");sent+=(size_t)n;}return !s->cancelled;}
static int exact(hs_session *s,uint8_t *p,size_t size){size_t received=0;while(received<size&&!s->cancelled){int n=SSL_read(s->tls,p+received,(int)(size-received));if(n<=0)return fail(s,"control_read_failed");received+=(size_t)n;}return !s->cancelled;}
static int read_message(hs_session *s,hs_message *m){size_t padding=0;memset(m,0,sizeof(*m));do{if(!exact(s,m->bytes,4))return 0;if(get32(m->bytes))break;padding+=4;if(padding>HS_MAX)return fail(s,"control_padding_limit");}while(1);if(!exact(s,m->bytes+4,4))return 0;m->size=get32(m->bytes+4);m->command=get16(m->bytes+2);m->subtype=m->bytes[1];if(m->bytes[0]!=0x22||m->size<8||m->size>HS_MAX)return fail(s,"invalid_control_header");return exact(s,m->bytes+8,m->size-8);}
static const uint8_t *field(hs_message *m,uint16_t kind,size_t *length){const uint8_t *value=NULL;size_t count=0;for(size_t offset=8;offset<m->size;){if(offset+4>m->size)return NULL;size_t n=get16(m->bytes+offset+2),padded=(n+3)&~(size_t)3;if(offset+4+padded>m->size)return NULL;for(size_t i=n;i<padded;i++)if(m->bytes[offset+4+i])return NULL;if(get16(m->bytes+offset)==kind){value=m->bytes+offset+4;*length=n;count++;}offset+=4+padded;}return count==1?value:NULL;}
static int integer(hs_message *m,uint16_t kind,unsigned width,uint32_t *value){size_t n=0;const uint8_t *p=field(m,kind,&n);if(!p||n!=width)return 0;*value=width==2?get16(p):get32(p);return 1;}
static int ack(hs_session *s,hs_message *m,uint16_t command){uint32_t status;if(m->command!=command||m->subtype!=2||!integer(m,4,4,&status))return fail(s,"invalid_control_ack");return status==0?1:fail(s,"gateway_rejected_request");}
static uint16_t checksum(const uint8_t *p,size_t n){uint32_t sum=0;while(n>1){sum+=get16(p);p+=2;n-=2;}if(n)sum+=(uint32_t)*p<<8;while(sum>>16)sum=(sum&65535)+(sum>>16);return (uint16_t)~sum;}
static int expand_keys(hs_session *s,const uint8_t seed[48]){uint8_t expanded[200];unsigned n=0;for(unsigned i=0;i<10;i++){if(EVP_Digest(i?expanded:seed,i?i*20:48,expanded+i*20,&n,EVP_sha1(),NULL)!=1||n!=20){OPENSSL_cleanse(expanded,sizeof(expanded));return fail(s,"key_expansion_failed");}}memcpy(s->tx_auth,expanded,20);memcpy(s->tx_key,expanded+20,24);memcpy(s->rx_auth,expanded+44,20);memcpy(s->rx_key,expanded+64,24);OPENSSL_cleanse(expanded,sizeof(expanded));return 1;}
#ifdef HS_NATIVE_TEST
static int hs_esp_cipher(const uint8_t key[24],const uint8_t iv[8],const uint8_t *in,size_t length,uint8_t *out,int encrypt){int count=0,tail=0,ok=0;EVP_CIPHER_CTX *ctx=EVP_CIPHER_CTX_new();if(!ctx)return 0;if(EVP_CipherInit_ex(ctx,EVP_des_ede3_cbc(),NULL,key,iv,encrypt)==1&&EVP_CIPHER_CTX_set_padding(ctx,0)==1&&EVP_CipherUpdate(ctx,out,&count,in,(int)length)==1&&EVP_CipherFinal_ex(ctx,out+count,&tail)==1&&(size_t)(count+tail)==length)ok=1;EVP_CIPHER_CTX_free(ctx);return ok;}
#endif
#include "packet_compat.h"
#include "path_metrics.h"
static int hs_packet_cipher(hs_session *s,const uint8_t *iv,const uint8_t *in,size_t n,uint8_t *out,int encrypt){
 EVP_CIPHER_CTX **ctx=encrypt?&s->tx_cipher:&s->rx_cipher;int count=0,tail=0;
 if(!*ctx){*ctx=EVP_CIPHER_CTX_new();if(!*ctx||EVP_CipherInit_ex(*ctx,EVP_des_ede3_cbc(),NULL,encrypt?s->tx_key:s->rx_key,NULL,encrypt)!=1||EVP_CIPHER_CTX_set_padding(*ctx,0)!=1)return 0;}
 return EVP_CipherInit_ex(*ctx,NULL,NULL,NULL,iv,-1)==1&&EVP_CipherUpdate(*ctx,out,&count,in,(int)n)==1&&EVP_CipherFinal_ex(*ctx,out+count,&tail)==1&&(size_t)(count+tail)==n;
}
static void hs_socket_buffers(hs_session *s){
 for(int bytes=8*1024*1024;bytes>=65536;bytes/=2)if(!setsockopt(s->data,SOL_SOCKET,SO_RCVBUF,(const char *)&bytes,sizeof(bytes)))break;
 int bytes=1024*1024;setsockopt(s->data,SOL_SOCKET,SO_SNDBUF,(const char *)&bytes,sizeof(bytes));
#ifdef _WIN32
 int size=sizeof(s->receive_buffer);
#else
 socklen_t size=sizeof(s->receive_buffer);
#endif
 getsockopt(s->data,SOL_SOCKET,SO_RCVBUF,(char *)&s->receive_buffer,&size);
}
static int send_packet_unlocked(hs_session *s,const uint8_t *packet,size_t length){uint8_t plain[HS_MAX],out[HS_MAX],mac[EVP_MAX_MD_SIZE];unsigned mac_size=0;size_t padding=(8-((length+2)%8))%8,size=length+padding+2;if(s->cancelled||length<20||length>65472||s->tx_sequence==UINT32_MAX)return fail(s,"invalid_outbound_packet");memcpy(plain,packet,length);hs_clamp_mss(plain,length);for(size_t i=0;i<padding;i++)plain[length+i]=(uint8_t)(i+1);plain[length+padding]=(uint8_t)padding;plain[length+padding+1]=4;put32(out,s->tx_spi);put32(out+4,++s->tx_sequence);if(RAND_bytes(out+8,8)!=1||!hs_packet_cipher(s,out+8,plain,size,out+16,1))return fail(s,"packet_encrypt_failed");OPENSSL_cleanse(plain,size);if(!HMAC(EVP_sha1(),s->tx_auth,20,out,size+16,mac,&mac_size)||mac_size!=20)return fail(s,"packet_auth_failed");memcpy(out+16+size,mac,12);if(send(s->data,(const char *)out,(int)(size+28),0)!=(int)(size+28))return fail(s,"data_send_failed");atomic_fetch_add(&s->tx_packets,1);atomic_fetch_add(&s->tx_bytes,length);return 1;}
static int send_packet(hs_session *s,const uint8_t *p,size_t n){
 while(atomic_flag_test_and_set(&s->send_lock)){if(s->cancelled)return 0;}
 int result=send_packet_unlocked(s,p,n);atomic_flag_clear(&s->send_lock);return result;
}
static int nonblocking(hs_socket fd,int enabled){
#ifdef _WIN32
 u_long value=enabled;return ioctlsocket(fd,FIONBIO,&value)==0;
#else
 int flags=fcntl(fd,F_GETFL,0);return flags>=0&&fcntl(fd,F_SETFL,enabled?(flags|O_NONBLOCK):(flags&~O_NONBLOCK))==0;
#endif
}
static int connect_bounded(hs_session *s,struct sockaddr_in *remote){
 if(!nonblocking(s->control,1))return fail(s,"socket_mode_failed");
 int result=connect(s->control,(struct sockaddr *)remote,sizeof(*remote));
 if(result){uint64_t deadline=now_ms()+8000;int connected=0;
  while(!s->cancelled&&now_ms()<deadline){fd_set w;FD_ZERO(&w);FD_SET(s->control,&w);struct timeval tv={0,200000};
   if(select((int)s->control+1,NULL,&w,NULL,&tv)>0){int error=0;
#ifdef _WIN32
    int size=sizeof(error);
#else
    socklen_t size=sizeof(error);
#endif
    if(getsockopt(s->control,SOL_SOCKET,SO_ERROR,(char *)&error,&size)==0&&!error)connected=1;
    break;
   }
  }if(!connected)return fail(s,"control_connect_failed");
 }
 return nonblocking(s->control,0)?1:fail(s,"socket_mode_failed");
}
static int control_tick(hs_session *s){
 /* This legacy gateway sends TLS close_notify after KEY ACK (verified with two independent TLS stacks). UDP heartbeat is authoritative thereafter. */
 if(s->control_closed)return 1;
 uint64_t now=now_ms();
 /* Read buffered keepalives before evaluating age after suspension. */
 if(now-s->last_control_sent>=15000){hs_message m;message(&m,9,0);number(&m,0x33,s->session_id,4);number(&m,0x40,0,4);
  if(!write_message(s,&m))return 0;
  s->last_control_sent=now;
 }
 if(SSL_pending(s->tls)||readable(s->control,0)){
  if(s->control_size==HS_MAX)return fail(s,"control_buffer_limit");
  int n=SSL_read(s->tls,s->control_buffer+s->control_size,(int)(HS_MAX-s->control_size));
  if(n<=0){int e=SSL_get_error(s->tls,n);if(e==SSL_ERROR_ZERO_RETURN){s->control_closed=1;return 1;}if(e!=SSL_ERROR_WANT_READ&&e!=SSL_ERROR_WANT_WRITE){snprintf(s->error_detail,sizeof(s->error_detail),"control_channel_closed_ssl_%d_socket_%d",e,hs_socket_error());return fail(s,s->error_detail);}}
  else s->control_size+=(size_t)n;
 }
 while(s->control_size>=4){
  if(!get32(s->control_buffer)){memmove(s->control_buffer,s->control_buffer+4,s->control_size-4);s->control_size-=4;continue;}
  if(s->control_size<8)break;
  size_t size=get32(s->control_buffer+4);
  if(s->control_buffer[0]!=0x22||size<8||size>HS_MAX)return fail(s,"invalid_control_header");
  if(s->control_size<size)break;
  hs_message m;memcpy(m.bytes,s->control_buffer,size);m.size=size;m.command=get16(m.bytes+2);m.subtype=m.bytes[1];
  uint32_t status;
  if(m.command==9&&m.subtype==2&&integer(&m,0x40,4,&status)&&status!=UINT32_MAX)s->last_control_received=now;
  else return fail(s,m.command==5?"gateway_rekey_required":m.command==7?"gateway_disconnected":"unexpected_control_message");
  memmove(s->control_buffer,s->control_buffer+size,s->control_size-size);s->control_size-=size;
 }
 if(now-s->last_control_received>45000&&now>=s->resume_until)return fail(s,"control_keepalive_expired");
 return 1;
}
static int receive_packet(hs_session *s,uint8_t *packet,size_t capacity,unsigned ms){uint8_t raw[HS_MAX],plain[HS_MAX],mac[EVP_MAX_MD_SIZE];unsigned mac_size=0;if(!readable(s->data,ms))return 0;int n=recv(s->data,(char *)raw,sizeof(raw),0);if(n<=0){
#ifdef _WIN32
 if(n<0&&WSAGetLastError()==WSAEWOULDBLOCK)return 0;
#endif
 s->udp_last_os=hs_socket_error();return -1;}s->udp_raw++;if(n<36||((n-28)%8)||get32(raw)!=s->rx_spi){s->udp_invalid++;return 0;}uint32_t sequence=get32(raw+4);if(!sequence){s->udp_invalid++;return 0;}uint32_t distance=s->rx_highest>=sequence?s->rx_highest-sequence:0;if(sequence<=s->rx_highest&&(distance>=64||(s->replay&((uint64_t)1<<distance)))){s->udp_invalid++;return 0;}if(!HMAC(EVP_sha1(),s->rx_auth,20,raw,(size_t)n-12,mac,&mac_size)||mac_size!=20||CRYPTO_memcmp(mac,raw+n-12,12)){s->udp_auth_bad++;s->udp_invalid++;return 0;}size_t encrypted=(size_t)n-28;if(!hs_packet_cipher(s,raw+8,raw+16,encrypted,plain,0)){s->udp_invalid++;return 0;}size_t padding=plain[encrypted-2];if(padding>encrypted-2||plain[encrypted-1]!=4){s->udp_invalid++;return 0;}for(size_t i=0;i<padding;i++)if(plain[encrypted-2-padding+i]!=i+1){s->udp_invalid++;return 0;}size_t size=encrypted-padding-2;if(size<20||size>capacity||(plain[0]>>4)!=4||(plain[0]&15)<5||(size_t)(plain[0]&15)*4>size||get16(plain+2)!=size||checksum(plain,(plain[0]&15)*4)){s->udp_invalid++;return 0;}if(sequence>s->rx_highest){uint32_t shift=sequence-s->rx_highest;s->replay=shift>=64?1:(s->replay<<shift)|1;s->rx_highest=sequence;}else s->replay|=(uint64_t)1<<distance;memcpy(packet,plain,size);atomic_fetch_add(&s->rx_packets,1);atomic_fetch_add(&s->rx_bytes,size);OPENSSL_cleanse(plain,encrypted);return (int)size;}
static void make_heartbeat(hs_session *s){uint8_t *p=s->heartbeat;uint16_t identifier=(uint16_t)(s->session_id^(s->session_id>>16));memset(p,0,44);p[0]=0x45;put16(p+2,44);p[4]=(uint8_t)identifier;p[5]=(uint8_t)(identifier>>8);p[8]=76;p[9]=1;p[20]=8;p[24]=(uint8_t)identifier;p[25]=(uint8_t)(identifier>>8);put16(p+22,checksum(p+20,24));put16(p+10,checksum(p,20));}
#include "udp_connect.h"
HS_API hs_session *hs_create(void){
#ifdef _WIN32
 WSADATA wsa;if(WSAStartup(MAKEWORD(2,2),&wsa))return NULL;
#endif
 hs_session *s=calloc(1,sizeof(*s));if(s){s->control=s->data=s->domestic=INVALID_HS_SOCKET;s->error="none";atomic_flag_clear(&s->send_lock);atomic_flag_clear(&s->dns_lock);atomic_flag_clear(&s->path_lock);}return s;}
HS_API int hs_probe_certificate(hs_session *s,const char *host,unsigned port,int legacy,uint8_t *der,size_t capacity){
 struct sockaddr_in remote;
 if(!s||s->control!=INVALID_HS_SOCKET||!host||!der||!port||port>65535)return s?fail(s,"invalid_profile"):0;
 memset(&remote,0,sizeof(remote));remote.sin_family=AF_INET;remote.sin_port=htons((uint16_t)port);if(inet_pton(AF_INET,host,&remote.sin_addr)!=1)return fail(s,"gateway_requires_ipv4");
 s->control=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);if(s->control==INVALID_HS_SOCKET)return fail(s,"control_socket_failed");timeout(s->control,8000);if(!connect_bounded(s,&remote))return 0;
 s->tls_context=SSL_CTX_new(TLS_client_method());if(!s->tls_context)return fail(s,"tls_context_failed");SSL_CTX_set_min_proto_version(s->tls_context,legacy?TLS1_VERSION:TLS1_2_VERSION);if(legacy){SSL_CTX_set_max_proto_version(s->tls_context,TLS1_2_VERSION);SSL_CTX_set_security_level(s->tls_context,0);SSL_CTX_set_cipher_list(s->tls_context,"DEFAULT:@SECLEVEL=0");}SSL_CTX_set_verify(s->tls_context,SSL_VERIFY_NONE,NULL);
 s->tls=SSL_new(s->tls_context);if(!s->tls)return fail(s,"tls_setup_failed");SSL_set_fd(s->tls,(int)s->control);SSL_set_tlsext_host_name(s->tls,host);if(SSL_connect(s->tls)!=1)return fail(s,"tls_handshake_failed");
 X509 *certificate=SSL_get1_peer_certificate(s->tls);if(!certificate)return fail(s,"certificate_missing");int length=i2d_X509(certificate,NULL);if(length<=0||(size_t)length>capacity){X509_free(certificate);return fail(s,"certificate_buffer_limit");}unsigned char *output=der;int written=i2d_X509(certificate,&output);X509_free(certificate);return written==length?length:fail(s,"certificate_encoding_failed");
}
HS_API int hs_connect(hs_session *s,const char *host,unsigned port,const char *username,const char *password,const char *pin,int legacy,hs_protect_cb protect,void *context){
 hs_message m;uint8_t seed[48],random[6];struct sockaddr_in remote,local;socklen_t local_size=sizeof(local);uint32_t value=0;int ok=0;
 if(!s||s->control!=INVALID_HS_SOCKET||!host||!username||!password||!pin||strlen(pin)!=64||!strlen(username)||!strlen(password)||strlen(username)>200||strlen(password)>512||!port||port>65535)return s?fail(s,"invalid_profile"):0;
 memset(&remote,0,sizeof(remote));remote.sin_family=AF_INET;remote.sin_port=htons((uint16_t)port);if(inet_pton(AF_INET,host,&remote.sin_addr)!=1)return fail(s,"gateway_requires_ipv4");memcpy(s->gateway,&remote.sin_addr,4);
 s->control=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);if(s->control==INVALID_HS_SOCKET)return fail(s,"control_socket_failed");if(protect&&!protect(context,(intptr_t)s->control))return fail(s,"socket_protect_failed");timeout(s->control,8000);if(!connect_bounded(s,&remote))return 0;
 s->tls_context=SSL_CTX_new(TLS_client_method());if(!s->tls_context)return fail(s,"tls_context_failed");SSL_CTX_set_min_proto_version(s->tls_context,legacy?TLS1_VERSION:TLS1_2_VERSION);if(legacy){SSL_CTX_set_max_proto_version(s->tls_context,TLS1_2_VERSION);SSL_CTX_set_security_level(s->tls_context,0);SSL_CTX_set_cipher_list(s->tls_context,"DEFAULT:@SECLEVEL=0");}SSL_CTX_set_verify(s->tls_context,SSL_VERIFY_NONE,NULL);
 s->tls=SSL_new(s->tls_context);if(!s->tls)return fail(s,"tls_setup_failed");SSL_set_fd(s->tls,(int)s->control);SSL_set_tlsext_host_name(s->tls,host);if(SSL_connect(s->tls)!=1)return fail(s,"tls_handshake_failed");
 X509 *certificate=SSL_get1_peer_certificate(s->tls);uint8_t digest[32],expected[32];unsigned digest_size=0;if(!certificate)return fail(s,"certificate_missing");int hashed=X509_digest(certificate,EVP_sha256(),digest,&digest_size);X509_free(certificate);for(unsigned i=0;i<32;i++){unsigned byte;char part[3]={pin[i*2],pin[i*2+1],0};if(strspn(part,"0123456789abcdefABCDEF")!=2||sscanf(part,"%2x",&byte)!=1)return fail(s,"invalid_certificate_pin");expected[i]=(uint8_t)byte;}if(!hashed||digest_size!=32||CRYPTO_memcmp(digest,expected,32))return fail(s,"certificate_pin_mismatch");
 message(&m,1,0);append(&m,1,username,strlen(username));append(&m,2,password,strlen(password));number(&m,0x51,1,2);append(&m,0x54,"5.7.2.12941",11);append(&m,0x60,"",0);append(&m,0x61,"",0);if(!write_message(s,&m))goto done;OPENSSL_cleanse(&m,sizeof(m));if(!read_message(s,&m)||!ack(s,&m,1))goto done;
 if(getsockname(s->control,(struct sockaddr *)&local,&local_size)){fail(s,"local_address_failed");goto done;}
 message(&m,2,0);append(&m,5,&local.sin_addr,4);append(&m,6,&remote.sin_addr,4);number(&m,0x17,1,4);if(!write_message(s,&m)||!read_message(s,&m)||!ack(s,&m,2))goto done;
 int address_received=0,routes_received=0,complete=0;
 for(unsigned i=0;i<32;i++){if(!read_message(s,&m))goto done;if(m.subtype!=0){fail(s,"invalid_configuration_subtype");goto done;}if(m.command==3){size_t n=0;const uint8_t *p;if(address_received){fail(s,"duplicate_address_configuration");goto done;}p=field(&m,7,&n);if(!p||n!=4){fail(s,"invalid_tunnel_address");goto done;}memcpy(s->address,p,4);p=field(&m,11,&n);if(!p||n!=4){fail(s,"invalid_tunnel_mask");goto done;}memcpy(s->mask,p,4);uint32_t inverse=~get32(p);if(inverse&(inverse+1)){fail(s,"invalid_tunnel_mask");goto done;}p=field(&m,8,&n);if(!p||n!=4){fail(s,"invalid_peer_address");goto done;}memcpy(s->peer,p,4);if(!integer(&m,9,2,&value)||!value){fail(s,"invalid_data_port");goto done;}s->data_port=(uint16_t)value;p=field(&m,17,&n);if(p&&n>=4&&n%4==0)memcpy(s->dns,p,4);address_received=1;}else if(m.command==4){size_t n=0;if(!address_received||!field(&m,19,&n)){fail(s,"invalid_route_configuration");goto done;}routes_received=1;}else if(m.command==6){if(!address_received||!routes_received||!integer(&m,4,4,&value)||value){fail(s,"incomplete_configuration");goto done;}complete=1;break;}else{fail(s,"unexpected_configuration_command");goto done;}}
 if(!complete){fail(s,"configuration_message_limit");goto done;}if(RAND_bytes(seed,48)!=1||RAND_bytes(random,6)!=1){fail(s,"random_failed");goto done;}s->rx_spi=get32(random);if(s->rx_spi<256)s->rx_spi+=256;
 message(&m,5,0);number(&m,32,3,2);append(&m,16,seed,48);number(&m,48,s->rx_spi,4);number(&m,128,get16(random+4),2);if(!write_message(s,&m)||!read_message(s,&m)||!ack(s,&m,5))goto done;if(!integer(&m,48,4,&s->tx_spi)||!s->tx_spi||!integer(&m,49,2,&value)||value!=3||!integer(&m,50,2,&value)||value!=2||!integer(&m,129,2,&value)||value||!integer(&m,51,4,&s->session_id)){fail(s,"unsupported_key_exchange");goto done;}if(!expand_keys(s,seed))goto done;
 ok=hs_udp_establish(s,&remote,&local,protect,context);
 done:OPENSSL_cleanse(seed,sizeof(seed));OPENSSL_cleanse(random,sizeof(random));OPENSSL_cleanse(&m,sizeof(m));return ok;
}
#include "split_dns.h"
HS_API int hs_send(hs_session *s,const uint8_t *packet,size_t length){if(!s||!s->ready||!packet)return 0;if(hs_direct_query(s,packet,length))return 1;int sent=send_packet(s,packet,length);if(sent){hs_observe_dns(s,packet,length,0);hs_observe_tcp(s,packet,length,0);}return sent;}
HS_API int hs_dns_direct_enabled(hs_session *s){return s&&s->domestic!=INVALID_HS_SOCKET;}
/* Wake for either gateway ESP or direct DNS; never sleep through a ready DNS reply. */
static void hs_wait_udp(hs_session *s,unsigned ms){
 fd_set set;FD_ZERO(&set);FD_SET(s->data,&set);hs_socket largest=s->data;
 if(s->domestic!=INVALID_HS_SOCKET){FD_SET(s->domestic,&set);if(s->domestic>largest)largest=s->domestic;}
 struct timeval tv={(long)(ms/1000),(long)(ms%1000)*1000};select((int)largest+1,&set,NULL,NULL,&tv);
}
HS_API int hs_receive(hs_session *s,uint8_t *packet,size_t capacity,unsigned ms){
 if(!s||!s->ready||s->cancelled)return -1;
 uint64_t now=now_ms();
 /* A paused worker gets one bounded opportunity to exchange authenticated heartbeats.
  * Do not rewrite last_received_heartbeat or keep a dead gateway alive indefinitely. */
 if(s->last_receive_tick&&now-s->last_receive_tick>=8000)s->resume_until=now+12000;
 s->last_receive_tick=now;
 if(!control_tick(s))return -1;
 if(now-s->last_sent_heartbeat>=2000){if(!send_packet(s,s->heartbeat,44))return -1;s->last_sent_heartbeat=now;}
 if(now-s->last_received_heartbeat>12000&&now>=s->resume_until){
  /* Do not let busy direct DNS postpone liveness checks indefinitely. */
  int queued=receive_packet(s,packet,capacity,0);
  if(queued==44&&!CRYPTO_memcmp(packet,s->heartbeat,44)){s->last_received_heartbeat=now_ms();return 0;}
  fail(s,"data_heartbeat_expired");return -1;
 }
 int local=hs_direct_receive(s,packet,capacity);if(local)return local;
 if(ms){hs_wait_udp(s,ms);if(s->cancelled)return -1;local=hs_direct_receive(s,packet,capacity);if(local)return local;}
 int n=receive_packet(s,packet,capacity,0);
 if(n==44&&!CRYPTO_memcmp(packet,s->heartbeat,44)){s->last_received_heartbeat=now_ms();return 0;}
 /* A valid encrypted heartbeat may already be queued after scheduler latency.
  * Consume it before declaring expiry; unrelated traffic never renews liveness. */
 if(now_ms()-s->last_received_heartbeat>12000&&now_ms()>=s->resume_until){fail(s,"data_heartbeat_expired");return -1;}
 if(n>0){hs_observe_dns(s,packet,(size_t)n,1);hs_observe_tcp(s,packet,(size_t)n,1);}
 if(n<0)fail(s,"data_receive_failed");
 return n;
}

#include "dns_probe.h"
HS_API int hs_ipv4(hs_session *s,unsigned field_id,char *output,size_t capacity){const uint8_t *p;if(!s||!output||capacity<16)return 0;p=field_id==0?s->address:field_id==1?s->mask:field_id==2?s->dns:field_id==3?s->gateway:NULL;if(!p)return 0;snprintf(output,capacity,"%u.%u.%u.%u",p[0],p[1],p[2],p[3]);return 1;}
HS_API const char *hs_error(hs_session *s){return s?s->error:"allocation_failed";}
#ifdef _WIN32
HS_API int hs_win_wait(hs_session *s,void *tun_event,unsigned timeout_ms){
 if(!hs_ready(s))return -1;
 if(!s->data_event){s->data_event=WSACreateEvent();if(s->data_event==WSA_INVALID_EVENT||WSAEventSelect(s->data,s->data_event,FD_READ|FD_CLOSE))return -1;}
 HANDLE events[3]={tun_event,s->data_event,NULL};DWORD count=2;
 if(s->domestic!=INVALID_HS_SOCKET){if(!s->domestic_event){s->domestic_event=WSACreateEvent();if(s->domestic_event==WSA_INVALID_EVENT||WSAEventSelect(s->domestic,s->domestic_event,FD_READ))return -1;}events[count++]=s->domestic_event;}
 DWORD result=WaitForMultipleObjects(count,events,FALSE,timeout_ms);
 if(result==WAIT_FAILED)return -1;
 WSANETWORKEVENTS status;if(result==WAIT_OBJECT_0+1)WSAEnumNetworkEvents(s->data,s->data_event,&status);else if(result==WAIT_OBJECT_0+2)WSAEnumNetworkEvents(s->domestic,s->domestic_event,&status);
 return hs_ready(s)?1:-1;
}
#endif
HS_API int hs_ready(hs_session *s){return s&&s->ready&&!s->cancelled;}
HS_API void hs_cancel(hs_session *s){if(!s)return;s->cancelled=1;s->ready=0;if(s->control!=INVALID_HS_SOCKET)shutdown(s->control,2);hs_mutex_lock(&s->send_lock);if(s->data!=INVALID_HS_SOCKET)shutdown(s->data,2);hs_mutex_unlock(&s->send_lock);if(s->domestic!=INVALID_HS_SOCKET)shutdown(s->domestic,2);}
HS_API void hs_destroy(hs_session *s){if(!s)return;hs_cancel(s);
#ifdef _WIN32
 if(s->data_event)WSACloseEvent(s->data_event);
 if(s->domestic_event)WSACloseEvent(s->domestic_event);
#endif
 if(s->tx_cipher)EVP_CIPHER_CTX_free(s->tx_cipher);
 if(s->rx_cipher)EVP_CIPHER_CTX_free(s->rx_cipher);
 if(s->tls)SSL_free(s->tls);
 if(s->tls_context)SSL_CTX_free(s->tls_context);
 if(s->control!=INVALID_HS_SOCKET)hs_socket_close(s->control);
 if(s->data!=INVALID_HS_SOCKET)hs_socket_close(s->data);
 if(s->domestic!=INVALID_HS_SOCKET)hs_socket_close(s->domestic);
 hs_mutex_destroy(&s->send_lock);hs_mutex_destroy(&s->dns_lock);
 OPENSSL_cleanse(s,sizeof(*s));free(s);
#ifdef _WIN32
 WSACleanup();
#endif
}

