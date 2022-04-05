#pragma once
#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QTableWidget>
#include <QWidget>
#include <optional>
#include <vector>
#include <bitset>
class AbstractFilter;
class MainWindow : public QWidget {
  Q_OBJECT
private:
  QTableWidget *table;
  std::optional<unsigned long long> base_time;
  std::vector<std::tuple<unsigned long long, unsigned long long, QByteArray>>
      packets;
  std::bitset<69> mask;
public:
  AbstractFilter* filter;
  std::vector<uint32_t> stream_id;
  explicit MainWindow(QWidget *parent = nullptr);
public slots:
  void raiseError(QString text);
  void startCapture(QString friendly, QString adapter);
  void packetArrival(long ts_sec, long ts_usec, unsigned long long total_len,
                     QByteArray data);

signals:
};

#endif // MAINWINDOW_H
