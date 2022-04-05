#ifndef STATTHREAD_H
#define STATTHREAD_H

#include <QThread>
#include <atomic>
class StatThread : public QThread
{
    Q_OBJECT
    std::string name;
    int adapter_id;
public:
    static std::atomic_bool is_finished;
    StatThread(std::string adapter_name,int id,QObject* p);
    void run() override;
};

#endif // STATTHREAD_H
