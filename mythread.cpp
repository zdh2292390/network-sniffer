#include "mythread.h"
#include <QThread>
#include <QDebug>
#include <pcap.h>
#include <string>
#include <iostream>
#include <sstream>
#include <QtGui>
#include <QtDebug>
#include <QString>
#include <qmessagebox.h>
using namespace std;
#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"packet.lib")
#pragma comment(lib,"ws2_32.lib")

/*以下是以太网协议格式*/
ETHER_HEADER etherData;
IP_HEADER ipData;
ARP_HEADER arpData;
TCP_HEADER tcpData;
UDP_HEADER udpData;
ICMP_HEADER icmpData;
DHCP_HEADER dhcpData;

int protoc_flag;



MyThread::MyThread(QThread *parent) : QThread(parent)
{
    stopped = false;
    qRegisterMetaType<QVariant>("QVariant");
}

void dhcp_callback(u_char ip_header_len,u_char udp_header_len, const u_char * packet)
{
  DHCP_HEADER *dhcp_header;
  dhcp_header=(DHCP_HEADER *)(packet+14+ip_header_len+udp_header_len);
  dhcpData=*dhcp_header;

}

void tcp_callback(u_char ip_header_len, const u_char * packet)
{
    TCP_HEADER * tcp_header;
    tcp_header = (TCP_HEADER * ) (packet+14+ip_header_len);
    tcpData=*tcp_header;
}
void udp_callback(u_char ip_header_len, const u_char * packet)
{
    UDP_HEADER * udp_header;
    udp_header = (UDP_HEADER *) (packet+14+ip_header_len);
    udpData=*udp_header;
    if(ntohs(udp_header->SourPort)==67 || ntohs(udp_header->SourPort)==68)
    {
       if(ntohs(udp_header->DestPort)==67 || ntohs(udp_header->DestPort)==68)
        {
            dhcp_callback(ip_header_len,8,packet);
            protoc_flag=dhcp;
        }
        else
            protoc_flag=udp;
    }
    else
        protoc_flag=udp;
}
void icmp_callback(u_char ip_header_len, const u_char * packet)
{
    ICMP_HEADER * icmp_header;
    icmp_header = (ICMP_HEADER *)(packet+14+ip_header_len);
    icmpData=*icmp_header;

}

void ospf_callback(u_char ip_header_len, const u_char * packet)
{

}



void ip_callback(u_char *argument, const struct pcap_pkthdr* packet_header, const u_char* packet_content)
{
    IP_HEADER *ip_protocol;
    u_int header_length = 0;
    u_int offset;
    u_char tos;
    u_int16_t checksum;
    //MAC首部是14位的，加上14位得到IP协议首部
    ip_protocol = (IP_HEADER *) (packet_content + 14);
    header_length=ip_protocol->ip_header_length;
    checksum = ntohs(ip_protocol->ip_checksum);
    tos = ip_protocol->ip_tos;
    offset = ntohs(ip_protocol->ip_off);

    ipData=*ip_protocol;

    switch (ip_protocol->ip_protocol)
    {
         case 1: icmp_callback(header_length,packet_content);protoc_flag=icmp;break;
         case 6: tcp_callback(header_length,packet_content);protoc_flag=tcp;break;
         case 17: udp_callback(header_length,packet_content);break;
         case 89: ospf_callback(header_length,packet_content);protoc_flag=ospf;break;
         default:protoc_flag=ip;break;
    }

}

void arp_callback(u_char * arg, const struct pcap_pkthdr * pkthdr, const u_char * packet)
{
    ARP_HEADER * arp_header;
    arp_header=(ARP_HEADER *) (packet+14);
    arpData=*arp_header;
}

static void ethernet_callback(u_char *argument, const struct pcap_pkthdr* packet_header, const u_char* packet_content)
{
    u_short ethernet_type;
    struct ETHER_HEADER *ether_header;
    static int packet_number = 1;

    ether_header = (struct ETHER_HEADER*)packet_content;//获得数据包内容
    ethernet_type = ntohs(ether_header->ether_type);//获得以太网类型

    etherData=*ether_header;
   
    switch (ethernet_type)
    {
      case 0x0800: {
        ip_callback(argument, packet_header, packet_content);
        break;
    }
      case 0x0806: {
        arp_callback(argument,packet_header,packet_content);
        protoc_flag=arp;
        break;
    }
      // default:printf("\n\n");break;
    }

    packet_number++;
}
void MyThread::set_filter(QString filter_str) {
    this->filter_str = filter_str;
}

void MyThread::run()
{
    char error_content[PCAP_ERRBUF_SIZE]; //存储错误信息
    bpf_u_int32 net_mask; //掩码地址
    bpf_u_int32 net_ip;  //网络地址
    
    char * net_interface;
    net_interface = pcap_lookupdev(error_content); //获得网络接口
    pcap_lookupnet(net_interface, &net_ip, &net_mask, error_content); //获得网络地址和掩码地址
    pcap_handle = pcap_open_live(net_interface, BUFSIZ, 1, 1, error_content); //打开网络接口

    struct bpf_program bpf_filter;  //BPF过滤规则

    QByteArray str = this->filter_str.toLatin1();
    char *bpf_filter_string =str.data() ; //过滤规则字符串，只分析IPv4的数据包
    printf("%s\n",bpf_filter_string);
    
    pcap_compile(pcap_handle, &bpf_filter, bpf_filter_string, 0, net_ip); //编译过滤规则
    pcap_setfilter(pcap_handle, &bpf_filter);//设置过滤规则
    
    if (pcap_datalink(pcap_handle) != DLT_EN10MB) //DLT_EN10MB表示以太网
        return;

    QVariant DataVar1;
    QVariant DataVar2;
    QVariant DataVar3;
    QVariant DataVar4;
    QVariant DataVar5;
    QVariant DataVar6;
    QVariant DataVar7;
    stopped = false;
    while (!stopped){
        pcap_loop(pcap_handle, 1, ethernet_callback, NULL); //捕获1个数据包进行分析
        DataVar1.setValue(ipData);
        DataVar2.setValue(arpData);
        DataVar3.setValue(tcpData);
        DataVar4.setValue(udpData);
        DataVar5.setValue(icmpData);
        DataVar6.setValue(dhcpData);
        DataVar7.setValue(etherData);
        emit stringChanged(protoc_flag,DataVar1,DataVar2,DataVar3,DataVar4,DataVar5,DataVar6,DataVar7);
        msleep(100);
    }
    
}

void MyThread::stop()
{
    stopped = true;
    pcap_close(this->pcap_handle);
}
