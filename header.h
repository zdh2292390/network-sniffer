#ifndef HEADER
#define HEADER
#include <QVariant>
#include "pcap.h"
#include <arpa/inet.h>
//#include <windows.h>
#include <string>
#include <iostream>
//#include <winsock2.h>

using namespace std;

enum Protocol_Flag
{ 
    ip,
    arp,
    tcp,
    udp,
    icmp,
    ospf,
    dhcp

 };


struct ETHER_HEADER
{
    u_int8_t ether_dhost[6]; //目的Mac地址
    u_int8_t ether_shost[6]; //源Mac地址
    u_int16_t ether_type;    //协议类型
}__attribute__((packed));

struct IP_HEADER
{
#if defined(WORDS_BIENDIAN)
    u_int8_t   ip_version : 4,
    ip_header_length : 4;
#else
    u_int8_t   ip_header_length : 4,
    ip_version : 4;
#endif
    u_int8_t    ip_tos;
    u_int16_t   ip_length;
    u_int16_t   ip_id;
    u_int16_t   ip_off;
    u_int8_t    ip_ttl;
    u_int8_t    ip_protocol;
    u_int16_t   ip_checksum;
    struct in_addr ip_souce_address;
    struct in_addr ip_destination_address;
}__attribute__((packed));

struct ARP_HEADER
{
    u_short HardwareType;
    u_short ProtocolType;
    u_char  MacLength;
    u_char  IPLength;
    u_short OP;
    u_char  srcmac[6];
    struct in_addr srcip;
    u_char desmac[6];
    struct in_addr desip;

}__attribute__((packed));

struct TCP_HEADER
{
    u_short SourPort;					// 源端口号16bit
    u_short DestPort;					// 目的端口号16bit
    unsigned int SequNum;			// 序列号32bit
    unsigned int AcknowledgeNum;	// 确认号32bit
    u_short HeaderLenAndFlag;			// 前4位：TCP头长度；中6位：保留；后6位：标志位
    u_short WindowSize;				// 窗口大小16bit
    u_short CheckSum;					// 检验和16bit
    u_short UrgentPointer;				// 紧急数据偏移量16bit
}__attribute__((packed));

struct UDP_HEADER
{
    unsigned short SourPort;		// 源端口号16bit
    unsigned short DestPort;		// 目的端口号16bit
    unsigned short Length;			// 数据包长度16bit
    unsigned short CheckSum;		// 校验和16bit
}__attribute__((packed));

struct ICMP_HEADER
{
    u_char type;
    u_char code;
    u_short checksum;
    u_int rest_part;
}__attribute__((packed));

struct DHCP_HEADER
{
    u_char op;      //报文类型;1表示请求报文;2表示回应报文。
    u_char htype;   //硬件地址类型;1表示10Mb/s的以太网的硬件地址。
    u_char hlen;    //硬件地址长度;以太网中该值为6。
    u_char hops;    //跳数。客户端设置为0;也能被一个代理服务器设置。  
    u_int xid;      //事务ID;由客户端选择的一个随机数;被服务器和客户端用来在它们之间交流请求和响应;客户端用它对请求和应答进行匹配。该ID由客户端设置并由服务器返回;为32位整数。
    u_short secs;   //由客户端填充;表示从客户端开始获得IP地址或IP地址续借后所使用了的秒数。
    u_short flags;  //标志字段。这个16比特的字段;目前只有最左边的一个比特有用;该位为0;表示单播;为1表示广播。
    struct in_addr ciaddr;  //客户端的IP地址。只有客户端是Bound、Renew、Rebinding状态;并且能响应ARP请求时;才能被填充。
    struct in_addr yiaddr;  //"你自己的"或客户端的IP地址。
    struct in_addr siaddr;  //表明DHCP协议流程的下一个阶段要使用的服务器的IP地址。
    struct in_addr giaddr;  //DHCP中继器的IP地址。注意：不是地址池中定义的网关
    u_char chaddr[16];  //客户端硬件地址。客户端必须设置它的"chaddr"字段。
    u_char sname[64];   //可选的服务器主机名;该字段是空结尾的字符串;由服务器填写。
    u_char file[128];       //启动文件名;是一个空结尾的字符串。
}__attribute__((packed));

Q_DECLARE_METATYPE(IP_HEADER)
Q_DECLARE_METATYPE(ARP_HEADER)
Q_DECLARE_METATYPE(TCP_HEADER)
Q_DECLARE_METATYPE(UDP_HEADER)
Q_DECLARE_METATYPE(ICMP_HEADER)
Q_DECLARE_METATYPE(DHCP_HEADER)
Q_DECLARE_METATYPE(ETHER_HEADER)

#endif // HEADER

