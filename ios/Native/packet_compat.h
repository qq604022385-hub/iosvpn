/* SPDX-License-Identifier: GPL-2.0-or-later
 * IPv4-only tunnel: bounded TCP MSS and prompt IPv6 fallback. */
static uint16_t hs_transport_checksum(const uint8_t *p,size_t length,size_t ihl){
 uint32_t sum=0;size_t n=length-ihl;
 for(size_t i=12;i<20;i+=2)sum+=get16(p+i);
 sum+=p[9]+(uint32_t)n;
 for(size_t i=ihl;i+1<length;i+=2)sum+=get16(p+i);
 if(n&1)sum+=(uint32_t)p[length-1]<<8;
 while(sum>>16)sum=(sum&65535)+(sum>>16);
 return (uint16_t)~sum;
}
static void hs_clamp_mss(uint8_t *p,size_t n){
 if(n<40||(p[0]>>4)!=4||get16(p+2)!=n||p[9]!=6||(get16(p+6)&0x3fff))return;
 size_t ihl=(p[0]&15)*4,th;
 if(ihl<20||ihl+20>n||!(p[ihl+13]&2))return;
 th=(p[ihl+12]>>4)*4;if(th<20||ihl+th>n)return;
 /* Validate the complete option list before changing checksum-covered bytes. */
 for(size_t i=ihl+20;i<ihl+th;){uint8_t kind=p[i];if(!kind)break;if(kind==1){i++;continue;}if(i+2>ihl+th||p[i+1]<2||i+p[i+1]>ihl+th)return;i+=p[i+1];}
 int changed=0;
 for(size_t i=ihl+20;i<ihl+th;){
  uint8_t kind=p[i];if(!kind)break;if(kind==1){i++;continue;}
  if(i+2>ihl+th||p[i+1]<2||i+p[i+1]>ihl+th)return;
  if(kind==2&&p[i+1]==4&&get16(p+i+2)>1160){put16(p+i+2,1160);changed=1;}
  i+=p[i+1];
 }
 if(changed){put16(p+ihl+16,0);put16(p+ihl+16,hs_transport_checksum(p,n,ihl));}
}
HS_API int hs_local_reply(const uint8_t *p,size_t n,uint8_t *out,size_t capacity){
 if(!p||!out||n<20)return 0;
 if((p[0]>>4)==6){
  if(n<40||get16(p+4)+40u!=n||(p[6]!=6&&p[6]!=17)||p[8]==0xff||p[24]==0xff)return 0;
  int nonzero=0;for(size_t i=8;i<24;i++)nonzero|=p[i];if(!nonzero)return 0;
  size_t quote=n>1232?1232:n,total=48+quote;if(capacity<total)return 0;
  memset(out,0,48);out[0]=0x60;put16(out+4,(uint16_t)(total-40));out[6]=58;out[7]=64;
  memcpy(out+8,p+24,16);memcpy(out+24,p+8,16);out[40]=1; /* ICMPv6 destination unreachable, no route. */
  memcpy(out+48,p,quote);uint32_t sum=(uint32_t)(total-40)+58;
  for(size_t i=8;i<total;i+=2)sum+=i+1<total?get16(out+i):(uint32_t)out[i]<<8;
  while(sum>>16)sum=(sum&65535)+(sum>>16);
  put16(out+42,(uint16_t)~sum);return (int)total;
 }
 if((p[0]>>4)!=4||p[9]!=17||get16(p+2)!=n||(get16(p+6)&0x3fff))return 0;
 size_t ihl=(p[0]&15)*4;if(ihl<20||ihl+20>n||get16(p+ihl+2)!=53||get16(p+ihl+4)!=n-ihl)return 0;
 const uint8_t *dns=p+ihl+8;size_t dn=n-ihl-8;
 if((dns[2]&0xf8)||get16(dns+4)!=1||get16(dns+6)||get16(dns+8))return 0;
 size_t q=12;
 while(q<dn&&dns[q]){size_t label=dns[q];if(label>63||q+1+label>=dn)return 0;q+=1+label;}
 if(q+5>dn||get16(dns+q+1)!=28||get16(dns+q+3)!=1)return 0;
 size_t total=ihl+8+q+5;if(capacity<total)return 0;
 memcpy(out,p,total);memcpy(out+12,p+16,4);memcpy(out+16,p+12,4);out[8]=64;
 put16(out+2,(uint16_t)total);put16(out+10,0);put16(out+10,checksum(out,ihl));
 put16(out+ihl,get16(p+ihl+2));put16(out+ihl+2,get16(p+ihl));put16(out+ihl+4,(uint16_t)(total-ihl));put16(out+ihl+6,0);
 uint8_t *reply=out+ihl+8;reply[2]=(dns[2]&1)|0x80;reply[3]=0x80|(dns[3]&0x10);memset(reply+6,0,6);
 uint16_t sum=hs_transport_checksum(out,total,ihl);put16(out+ihl+6,sum?sum:65535);return (int)total;
}
