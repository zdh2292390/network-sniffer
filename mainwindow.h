#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include "mythread.h"
#include <header.h>
#include <vector>
#include <QTableWidget>

namespace Ui {
class MainWindow;
}

struct Packet_Info
{
	int row;
	int proto_flag;
	QString srcmac;
	QString desmac;
	
	QString srcip;
	QString desip;
	QString ipversion;
	QString TTL;
	QString iplength;
	QString ipchecksum;

    QString arp_HardwareType;
    QString arp_ProtocolType;

	QString srcport;
	QString desport;
	QString udp_length;
	QString tcp_udp_checksum;
	QString tcp_acknum;
	QString tcp_seq;
    QString tcp_windowsize;

    QString icmp_type;
    QString icmp_code;
    QString icmp_checksum;

};

struct count_info{
    long total;
    long ip_num;
    long arp_num;
    long tcp_num;
    long udp_num;
    long icmp_num;
    long ospf_num;
    long dhcp_num;
};

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MyThread thread;
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();

private slots:
    void on_startButton_clicked();

    void on_stopButton_clicked();

    void changeString(int,QVariant,QVariant,QVariant,QVariant,QVariant,QVariant,QVariant);

    void on_tableWidget_itemClicked(QTableWidgetItem *item);

private:
    Ui::MainWindow *ui;
    vector<Packet_Info> packet_vect;
    count_info packet_count;

};

#endif // MAINWINDOW_H
