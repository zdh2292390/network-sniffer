#ifndef MYTHREAD_H
#define MYTHREAD_H

#include <QThread>
#include <header.h>

class MyThread : public QThread
{
    Q_OBJECT
public:
    void stop();
    explicit MyThread(QThread *parent = 0);
    volatile bool stopped;
    void set_filter(QString filter_str);
private:
	QString filter_str;
	pcap_t* pcap_handle; //libpcap句柄
protected:
    void run();

signals:
    void stringChanged(int,QVariant,QVariant,QVariant,QVariant,QVariant,QVariant,QVariant);

public slots:
};

#endif // MYTHREAD_H
