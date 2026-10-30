/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Account-free resolver contract. Uses only synthetic data, local adapters,
 * localhost and numeric addresses. No remote DNS or game is required.
 */
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#ifndef AI_DNS_ONLY
#define AI_DNS_ONLY 0x10
#endif
static unsigned int checks, failures, frees;
#define CHECK(e) do { ++checks; if (!(e)) { ++failures; printf("FAIL line %u\n",__LINE__); } } while (0)
static void fixture_free( struct addrinfo *p ) { ++frees; free(p); }
#define freeaddrinfo fixture_free
#include "../../dlls/ws2_32/local-host-addrinfo.h"
#undef freeaddrinfo

static void unit(void)
{
    struct addrinfo *a=calloc(1,2*sizeof(*a)+2*sizeof(struct sockaddr_in)+32), hints={0};
    struct sockaddr_in *sa=(struct sockaddr_in *)(a+2);
    char *name=(char *)(sa+2), ip[4][4]={{127,0,0,1},{10,1,2,3},{(char)192,0,2,4},{0}};
    char *ips[]={ip[0],ip[1],ip[2],ip[3],NULL};
    struct hostent h={0};
    strcpy(name,"local.test");
    for(unsigned i=0;i<2;++i){a[i].ai_family=AF_INET;a[i].ai_flags=AI_ADDRCONFIG;
        a[i].ai_addrlen=sizeof(*sa);a[i].ai_addr=(struct sockaddr *)&sa[i];
        a[i].ai_socktype=i?SOCK_DGRAM:SOCK_STREAM;a[i].ai_protocol=i?IPPROTO_UDP:IPPROTO_TCP;
        sa[i].sin_family=AF_INET;sa[i].sin_port=htons(80+i);sa[i].sin_addr.s_addr=inet_addr("127.0.1.1");}
    a[0].ai_next=a+1;a[0].ai_canonname=name;
    CHECK(local_hostname_loopback_result("local.test","local.test",&hints,a));
    CHECK(local_hostname_loopback_result("LOCAL.TEST","local.test",&hints,a));
    CHECK(!local_hostname_loopback_result("localhost","localhost",&hints,a));
    CHECK(!local_hostname_loopback_result("local.test.extra","local.test",&hints,a));
    CHECK(!local_hostname_loopback_result(NULL,"local.test",&hints,a));
    CHECK(!local_hostname_loopback_result("local.test","local.test",&hints,NULL));
    hints.ai_flags=AI_NUMERICHOST;CHECK(!local_hostname_loopback_result("local.test","local.test",&hints,a));
    hints.ai_flags=AI_DNS_ONLY;CHECK(!local_hostname_loopback_result("local.test","local.test",&hints,a));
    hints.ai_flags=0;a[1].ai_family=AF_INET6;
    CHECK(!local_hostname_loopback_result("local.test","local.test",&hints,a));a[1].ai_family=AF_INET;
    sa[1].sin_addr.s_addr=inet_addr("10.1.2.3");
    CHECK(!local_hostname_loopback_result("local.test","local.test",&hints,a));sa[1].sin_addr.s_addr=inet_addr("127.0.1.1");
    struct addrinfo *before=a;
    CHECK(local_hostname_expand_ipv4(NULL,&a)==0 && a==before && !frees);
    h.h_addrtype=AF_INET;h.h_length=4;h.h_addr_list=ips;
    char *empty[]={ip[0],ip[3],NULL};h.h_addr_list=empty;
    CHECK(local_hostname_expand_ipv4(&h,&a)==0 && a==before && !frees);
    h.h_addr_list=ips;
    CHECK(local_hostname_expand_ipv4(&h,&a)==0 && a!=before && frees==1);
    unsigned i=0;
    for(struct addrinfo *p=a;p;p=p->ai_next,++i){
        struct sockaddr_in *v=(struct sockaddr_in *)p->ai_addr;
        CHECK(i<4 && p->ai_family==AF_INET && p->ai_addrlen==sizeof(*v) && v->sin_family==AF_INET);
        CHECK(!memcmp(&v->sin_addr,ip[1+i/2],4));
        CHECK(p->ai_socktype==(i%2?SOCK_DGRAM:SOCK_STREAM) && p->ai_protocol==(i%2?IPPROTO_UDP:IPPROTO_TCP));
        CHECK(ntohs(v->sin_port)==80+i%2 && p->ai_flags==AI_ADDRCONFIG);
        CHECK(i ? !p->ai_canonname : p->ai_canonname && !strcmp(p->ai_canonname,"local.test"));
    }
    CHECK(i==4);free(a);
}
static void native(void)
{
    char hostname[256],upper[256];
    struct addrinfo hints={0},*a=NULL;
    unsigned char expected[128][4];unsigned n=0,count=0;
    CHECK(!gethostname(hostname,sizeof(hostname)));
    struct hostent *host=gethostbyname(hostname);
    CHECK(host && host->h_addrtype==AF_INET && host->h_length==4);
    if(host)for(unsigned i=0;host->h_addr_list[i] && n<128;++i)
        if(local_hostname_real_address(host->h_addr_list[i]))memcpy(expected[n++],host->h_addr_list[i],4);
    CHECK(n>0);
    hints.ai_family=AF_INET;hints.ai_socktype=SOCK_STREAM;hints.ai_flags=AI_ADDRCONFIG;
    CHECK(!getaddrinfo(hostname,"45678",&hints,&a));
    for(struct addrinfo *p=a;p;p=p->ai_next){struct sockaddr_in *v=(struct sockaddr_in *)p->ai_addr;
        unsigned found=0;for(unsigned i=0;i<n;++i)found|=!memcmp(&v->sin_addr,expected[i],4);
        CHECK(found && p->ai_family==AF_INET && p->ai_socktype==SOCK_STREAM && ntohs(v->sin_port)==45678);++count;}
    CHECK(count>=n);freeaddrinfo(a);a=NULL;
    for(unsigned i=0;i<sizeof(upper);++i){upper[i]=toupper((unsigned char)hostname[i]);if(!hostname[i])break;}
    hints.ai_flags=AI_CANONNAME;
    CHECK(!getaddrinfo(upper,"80",&hints,&a));
    CHECK(a && a->ai_canonname && a->ai_canonname[0] && local_hostname_real_address((char *)&((struct sockaddr_in *)a->ai_addr)->sin_addr));
    freeaddrinfo(a);a=NULL;
    hints.ai_flags=AI_NUMERICHOST;
    CHECK(getaddrinfo(hostname,NULL,&hints,&a)!=0 && !a);
    CHECK(!getaddrinfo("127.0.1.1","80",&hints,&a));
    CHECK(a && ((struct sockaddr_in *)a->ai_addr)->sin_addr.s_addr==inet_addr("127.0.1.1"));freeaddrinfo(a);a=NULL;
    hints.ai_flags=0;CHECK(!getaddrinfo("localhost",NULL,&hints,&a));
    unsigned loop=0;for(struct addrinfo *p=a;p;p=p->ai_next)loop|=(ntohl(((struct sockaddr_in *)p->ai_addr)->sin_addr.s_addr)>>24)==127;
    CHECK(loop);freeaddrinfo(a);
    WCHAR wide[256];ADDRINFOW hw={0},*w=NULL;
    CHECK(MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,hostname,-1,wide,256)>0);
    hw.ai_family=AF_INET;hw.ai_socktype=SOCK_DGRAM;hw.ai_flags=AI_ADDRCONFIG;
    CHECK(!GetAddrInfoW(wide,L"12345",&hw,&w));
    CHECK(w && local_hostname_real_address((char *)&((struct sockaddr_in *)w->ai_addr)->sin_addr) &&
          w->ai_socktype==SOCK_DGRAM && ntohs(((struct sockaddr_in *)w->ai_addr)->sin_port)==12345);
    FreeAddrInfoW(w);
    hints.ai_family=AF_INET6;hints.ai_flags=AI_NUMERICHOST;a=NULL;
    CHECK(!getaddrinfo("::1",NULL,&hints,&a));CHECK(a && a->ai_family==AF_INET6);freeaddrinfo(a);
}
int main(void)
{
    WSADATA w;CHECK(!WSAStartup(MAKEWORD(2,2),&w));unit();native();WSACleanup();
    printf("CHECKS %u FAILURES %u\n",checks,failures);return failures?1:0;
}
