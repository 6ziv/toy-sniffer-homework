#ifndef SNIFFTHREAD_H
#define SNIFFTHREAD_H

#include <QThread>
#include <string>
class SniffThread : public QThread {
  Q_OBJECT
private:
  std::string adapter_name;
  std::string cap_filter;
  bool is_promisc;
public:
  explicit SniffThread(QString name,bool promisc, QString capture_filter, QObject *parent = nullptr);
  void run() override;
};

#endif // SNIFFTHREAD_H
