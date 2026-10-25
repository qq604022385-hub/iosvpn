/* SPDX-License-Identifier: GPL-2.0-or-later. Bounded TCP handshake metadata. */
static void hs_observe_tcp(hs_session *s,const uint8_t *p,size_t n,int inbound){
 if(n<40||(p[0]>>4)!=4||p[9]!=6||get16(p+2)!=n||(get16(p+6)&0x3fff))return;
 size_t ihl=(p[0]&15)*4;if(ihl<20||ihl+20>n)return;
 unsigned flags=p[ihl+13];if(!(flags&2))return;
 if(!inbound&&(flags&16))return;
 if(inbound&&!(flags&16))return;
 const uint8_t *local=p+(inbound?16:12),*remote=p+(inbound?12:16);
 uint16_t lp=get16(p+ihl+(inbound?2:0)),rp=get16(p+ihl+(inbound?0:2));
 uint64_t now=now_ms();uint32_t seq=inbound?get32(p+ihl+8)-1:get32(p+ihl+4);
 while(atomic_flag_test_and_set(&s->path_lock)){}
 size_t slot=128,empty=128;
 for(size_t i=0;i<128;i++){
  if(!s->syn[i].sent||now-s->syn[i].sent>30000){if(empty==128)empty=i;continue;}
  if(s->syn[i].seq==seq&&s->syn[i].lp==lp&&s->syn[i].rp==rp&&!memcmp(s->syn[i].local,local,4)&&!memcmp(s->syn[i].remote,remote,4)){slot=i;break;}
 }
 if(inbound){if(slot<128){uint64_t ms=now-s->syn[slot].sent;atomic_fetch_add(&s->syn_replies,1);atomic_fetch_add(&s->syn_ms,ms);if(ms>atomic_load(&s->syn_max_ms))atomic_store(&s->syn_max_ms,ms);s->syn[slot].sent=0;}}
 else{atomic_fetch_add(&s->syn_packets,1);if(slot<128)atomic_fetch_add(&s->syn_retries,1);else if(empty<128){s->syn[empty].sent=now;s->syn[empty].seq=seq;s->syn[empty].lp=lp;s->syn[empty].rp=rp;memcpy(s->syn[empty].local,local,4);memcpy(s->syn[empty].remote,remote,4);}}
 atomic_flag_clear(&s->path_lock);
}
