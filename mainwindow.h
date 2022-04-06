#pragma once
#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QTableWidget>
#include <QWidget>
#include <optional>
#include <vector>
#include <bitset>
#include <qhexedit.h>
class AbstractFilter;
class MainWindow : public QWidget {
  Q_OBJECT
private:
  QTableWidget *table;
  std::optional<unsigned long long> base_time;
  std::vector<std::tuple<unsigned long long, unsigned long long, QByteArray>>
      packets;
  std::bitset<69> mask;

  QAction *not_later, *not_earlier, *is_eth, *is_arp, *is_ipv4, *is_ipv6, *is_tcp, *is_udp, *source_ip_address, *destination_ip_address,
          *trace_tcp_stream, *trace_udp_stream;
  QHexEdit *edit = nullptr;

public:
  AbstractFilter* filter;
  std::vector<std::pair<uint64_t,bool>> stream_id;
  explicit MainWindow(QWidget *parent = nullptr);
public slots:
  void raiseError(QString text);
  void startCapture(QString friendly, QString adapter);
  void packetArrival(long ts_sec, long ts_usec, unsigned long long total_len,
                     QByteArray data);
signals:
};

#endif // MAINWINDOW_H
