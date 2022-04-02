#ifndef STATTHREAD_H
#define STATTHREAD_H

#include <QThread>
class StatThread : public QThread
{
    Q_OBJECT
    std::string name;
    int adapter_id;
public:
    int is_finished = 0;
    StatThread(std::string adapter_name,int id,QObject* p);
    void run() override;
};

#endif // STATTHREAD_H
