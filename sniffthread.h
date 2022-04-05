#ifndef SNIFFTHREAD_H
#define SNIFFTHREAD_H

#include <QThread>
#include <string>
class SniffThread : public QThread {
  Q_OBJECT
private:
  std::string adapter_name;

public:
  explicit SniffThread(QString name, QObject *parent = nullptr);
  void run() override;
};

#endif // SNIFFTHREAD_H
