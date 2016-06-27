#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <sstream>
#include <QString>
#include <QTableWidget>
#include <iostream>

using namespace std;

QString mactoQstring(u_int8_t raw_mac[6]){
    QString a="";
    u_char *tmp;
    tmp=raw_mac;
    char *mac;
/*    sprintf(mac,"%02x:%02x:%02x:%02x:%02x:%02x\n",*tmp,*(tmp+1),*(tmp+2),*(tmp+3),*(tmp+4),*(tmp+5));
    a= QString(QLatin1String(mac));*/

     char mac_string[2];
     for(int i=0;i<5;i++){
         sprintf(mac_string,"%02x",*tmp);
         a+=mac_string[0];
         a+=mac_string[1];
         a+=":";
         tmp++;
     }
     sprintf(mac_string,"%02x",*tmp);
     a+=mac_string[0];
     a+=mac_string[1];

    return a;
}



MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    qRegisterMetaType<QVariant>("QVariant");
    connect(&thread, SIGNAL(stringChanged(int,QVariant,QVariant,QVariant,QVariant,QVariant,QVariant,QVariant)),
    this, SLOT(changeString(int,QVariant,QVariant,QVariant,QVariant,QVariant,QVariant,QVariant)));

    packet_count={0,0,0,0,0,0,0,0};

    ui->tableWidget->setColumnCount(4);    //设置列数
    ui->tableWidget->setRowCount(0);        //设置行数/
    ui->tableWidget->setSelectionBehavior(QAbstractItemView::SelectRows);  //单击选择一行  
    ui->tableWidget->setSelectionMode(QAbstractItemView::SingleSelection); //设置只能选择一行，不能多行选中

    QStringList headers;
    headers<<"信源ip"<<"信宿ip"<<"协议"<<"长度";
    ui->tableWidget->setHorizontalHeaderLabels(headers);
    ui->tableWidget->setColumnWidth(0,150);
    ui->tableWidget->setColumnWidth(1,150);
    ui->tableWidget->setColumnWidth(2,150);
    ui->tableWidget->setColumnWidth(3,150);

    // ui->tableWidget->setColumnWidth(4,200);
//    connect(ui->tableWidget,SIGNAL(cellDoubleClicked(int,int)),this,SLOT(testSlot(int,int)));
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::on_startButton_clicked()
{
    QString filter_str = ui->textEdit->toPlainText();
    thread.set_filter(filter_str);
    if (!thread.isRunning()){
        thread.start();
    }
    
    ui->startButton->setEnabled(false);
    ui->stopButton->setEnabled(true);
}
void MainWindow::on_stopButton_clicked()
{
    QString a="";
    if (thread.isRunning()) {
        thread.stop();
        // a=QString::number(packet_count.arp_num*100/packet_count.total);
        // ui->dt_arp->setText(a);

        // a=QString::number(packet_count.ip_num*100/packet_count.total);
        // ui->dt_ip->setText(a);

        // a=QString::number(packet_count.tcp_num*100/packet_count.total);
        // ui->dt_tcp->setText(a);

        // a=QString::number(packet_count.udp_num*100/packet_count.total);
        // ui->dt_udp->setText(a);

        // a=QString::number(packet_count.icmp_num*100/packet_count.total);
        // ui->dt_icmp->setText(a);


        ui->startButton->setEnabled(true);
        ui->stopButton->setEnabled(false);
    }
}
void MainWindow::changeString(int protoc_flag,QVariant ipdata,QVariant arptdata,QVariant tcpdata,
                        QVariant udpdata,QVariant icmpdata,QVariant dhcpdata,QVariant etherdata)
{
    IP_HEADER IPdata=ipdata.value<IP_HEADER>();
    ARP_HEADER ARPdata=arptdata.value<ARP_HEADER>();
    TCP_HEADER TCPdata=tcpdata.value<TCP_HEADER>();
    UDP_HEADER UDPdata=udpdata.value<UDP_HEADER>();
    ICMP_HEADER ICMPdata=icmpdata.value<ICMP_HEADER>();
    DHCP_HEADER DHCPdata=dhcpdata.value<DHCP_HEADER>();
    ETHER_HEADER ETHERdata=etherdata.value<ETHER_HEADER>();

    Packet_Info packet;
    stringstream stream;
    QString a;

    int row = ui->tableWidget->rowCount();
    ui->tableWidget->insertRow(row);

    if(protoc_flag==ip||protoc_flag==tcp||protoc_flag==udp||protoc_flag==icmp||protoc_flag==dhcp){

        stream.str("");
        stream << inet_ntoa(IPdata.ip_souce_address);
        a = QString::fromStdString(stream.str());
        ui->tableWidget->setItem(row,0,new QTableWidgetItem(a));
        packet.srcip=a;

        stream.str("");
        stream << inet_ntoa(IPdata.ip_destination_address);
        a = QString::fromStdString(stream.str());
        ui->tableWidget->setItem(row,1,new QTableWidgetItem(a));
        packet.desip=a;    

        stream.str("");
        stream << (int)IPdata.ip_version;
        a = QString::fromStdString(stream.str());
        packet.ipversion=a;

        stream.str("");
        stream << (int)IPdata.ip_length;
        a = QString::fromStdString(stream.str());  
        packet.iplength=a;

        stream.str("");
        stream << (int)IPdata.ip_checksum;
        a = QString::fromStdString(stream.str());
        packet.ipchecksum=a;            

        ui->tableWidget->setItem(row,3,new QTableWidgetItem(packet.iplength));
    }
    else if(protoc_flag==arp){
        stream.str("");
        stream << (int)ARPdata.HardwareType;
        a = QString::fromStdString(stream.str());
        packet.arp_HardwareType=a;

        stream.str("");
        stream << (int)ARPdata.ProtocolType;
        a = QString::fromStdString(stream.str());
        packet.arp_ProtocolType=a;

        stream.str("");
        stream << inet_ntoa(ARPdata.srcip);
        a = QString::fromStdString(stream.str());
        ui->tableWidget->setItem(row,0,new QTableWidgetItem(a));
        packet.srcip=a;

        stream.str("");
        stream << inet_ntoa(ARPdata.desip);
        a = QString::fromStdString(stream.str());
        ui->tableWidget->setItem(row,1,new QTableWidgetItem(a));
        packet.desip=a;

        ui->tableWidget->setItem(row,3,new QTableWidgetItem(QString::number(28)));
    }

    packet_count.total++;
    switch(protoc_flag)
    {
        case ip:{
            ui->tableWidget->setItem(row,2,new QTableWidgetItem(QString("ip")));
            packet_count.ip_num++;
            break;
        }

        case arp:{
            ui->tableWidget->setItem(row,2,new QTableWidgetItem(QString("arp")));
            packet_count.arp_num++;
            break;
        }
        case tcp:{
            ui->tableWidget->setItem(row,2,new QTableWidgetItem(QString("tcp")));
            packet_count.tcp_num++;
            packet_count.ip_num++;
            break;
        }
        case udp:{
            ui->tableWidget->setItem(row,2,new QTableWidgetItem(QString("udp")));
            packet_count.udp_num++;
            packet_count.ip_num++;
            break;
        }
        case icmp:{
            ui->tableWidget->setItem(row,2,new QTableWidgetItem(QString("icmp")));
            packet_count.icmp_num++;
            packet_count.ip_num++;
            break;
        }
        case ospf:{
            ui->tableWidget->setItem(row,2,new QTableWidgetItem(QString("ospf")));
            packet_count.ospf_num++;
            break;
        }
        case dhcp:{
            ui->tableWidget->setItem(row,2,new QTableWidgetItem(QString("dhcp")));
            packet_count.dhcp_num++;
            packet_count.udp_num++;
            packet_count.ip_num++;
            break;
        }
        default:break;
    }
    

    packet.proto_flag=protoc_flag;
    packet.srcmac=mactoQstring(ETHERdata.ether_shost);
    packet.desmac=mactoQstring(ETHERdata.ether_dhost);

    if(protoc_flag==tcp){
        stream.str("");
        stream << (int)TCPdata.SourPort;
        a = QString::fromStdString(stream.str());  
        packet.srcport=a;

        stream.str("");
        stream << (int)TCPdata.DestPort;
        a = QString::fromStdString(stream.str());  
        packet.desport=a;

        stream.str("");
        stream << (u_int)TCPdata.SequNum;
        a = QString::fromStdString(stream.str());
        packet.tcp_seq=a;

        stream.str("");
        stream << (u_int)TCPdata.AcknowledgeNum;
        a = QString::fromStdString(stream.str());
        packet.tcp_acknum=a;

        stream.str("");
        stream << (u_int)TCPdata.CheckSum;
        a = QString::fromStdString(stream.str());  
        packet.tcp_udp_checksum=a;        

        stream.str("");
        stream << (u_int)TCPdata.WindowSize;
        a = QString::fromStdString(stream.str());  
        packet.tcp_windowsize=a;

    }
    else if(protoc_flag==udp){
        stream.str("");
        stream << (int)UDPdata.SourPort;
        a = QString::fromStdString(stream.str());  
        packet.srcport=a;

        stream.str("");
        stream << (int)UDPdata.DestPort;
        a = QString::fromStdString(stream.str());
        packet.desport=a;

        stream.str("");
        stream << (int)UDPdata.CheckSum;
        a = QString::fromStdString(stream.str());  
        packet.tcp_udp_checksum=a;        

        stream.str("");
        stream << (int)UDPdata.Length;
        a = QString::fromStdString(stream.str());  
        packet.udp_length=a;

    }
    else if(protoc_flag==icmp){
        stream.str("");
        stream << (int)ICMPdata.type;
        a = QString::fromStdString(stream.str());
        packet.icmp_type=a;
        
        stream.str("");
        stream << (int)ICMPdata.code;
        a = QString::fromStdString(stream.str());
        packet.icmp_code=a;
    }

    packet_vect.push_back(packet);
    

    a=QString::number(packet_count.arp_num);
    ui->dt_arp->setText(a);

    a=QString::number(packet_count.ip_num);
    ui->dt_ip->setText(a);

    a=QString::number(packet_count.tcp_num);
    ui->dt_tcp->setText(a);

    a=QString::number(packet_count.udp_num);
    ui->dt_udp->setText(a);

    a=QString::number(packet_count.icmp_num);
    ui->dt_icmp->setText(a);

}

void MainWindow::on_tableWidget_itemClicked(QTableWidgetItem *item)
{

    int row = ui->tableWidget->row(item);//获取选中的行

    stringstream stream;

    ui->listWidget->clear();
    ui->listWidget->addItem("---------Ethernet Header---------");
    ui->listWidget->addItem("信源Mac地址:"+packet_vect[row].srcmac);
    ui->listWidget->addItem("信宿Mac地址:"+packet_vect[row].desmac);

    if(packet_vect[row].proto_flag==ip||packet_vect[row].proto_flag==tcp||packet_vect[row].proto_flag==udp||packet_vect[row].proto_flag==icmp)
    {
        ui->listWidget->addItem("------------IP Header------------");
        ui->listWidget->addItem("信源IP:"+packet_vect[row].srcip);
        ui->listWidget->addItem("信宿IP:"+packet_vect[row].desip);
        ui->listWidget->addItem("IP版本："+packet_vect[row].ipversion);
        ui->listWidget->addItem("IP包长度:"+packet_vect[row].iplength);
        ui->listWidget->addItem("IP校验和:"+packet_vect[row].ipchecksum);        
    }
    else if(packet_vect[row].proto_flag==arp)
    {
         ui->listWidget->addItem("------------ARP Header------------");
         ui->listWidget->addItem("信源IP:"+packet_vect[row].srcip);
         ui->listWidget->addItem("信宿IP:"+packet_vect[row].desip);
         ui->listWidget->addItem("硬件类型:"+packet_vect[row].arp_HardwareType);
         ui->listWidget->addItem("协议类型:"+packet_vect[row].arp_ProtocolType);
    }

    if (packet_vect[row].proto_flag==tcp)
    {
        ui->listWidget->addItem("------------TCP Header------------");
        ui->listWidget->addItem("源端口号:"+packet_vect[row].srcport);
        ui->listWidget->addItem("目的端口号:"+packet_vect[row].desport);
        ui->listWidget->addItem("序列号:"+packet_vect[row].tcp_seq);
        ui->listWidget->addItem("确认号:"+packet_vect[row].tcp_acknum);
        ui->listWidget->addItem("窗口大小:"+packet_vect[row].tcp_windowsize);    
        ui->listWidget->addItem("校验和:"+packet_vect[row].tcp_udp_checksum);

    }
    else if(packet_vect[row].proto_flag==udp || packet_vect[row].proto_flag==dhcp)
    {
        ui->listWidget->addItem("------------UDP Header------------");
        ui->listWidget->addItem("源端口号:"+packet_vect[row].srcport);
        ui->listWidget->addItem("目的端口号:"+packet_vect[row].desport);
        ui->listWidget->addItem("UDP包长度："+packet_vect[row].udp_length);
        ui->listWidget->addItem("校验和："+packet_vect[row].tcp_udp_checksum);
        if(packet_vect[row].proto_flag==dhcp)
        {
            ui->listWidget->addItem("------------DHCP Header------------");
            ui->listWidget->addItem("源端口号:"+packet_vect[row].srcport);

        }    

    }
    else if(packet_vect[row].proto_flag==icmp){
        ui->listWidget->addItem("------------ICMP Header------------");
        ui->listWidget->addItem("ICMP类型:"+packet_vect[row].icmp_type);
        ui->listWidget->addItem("代码:"+packet_vect[row].icmp_code);
    }
    

}
