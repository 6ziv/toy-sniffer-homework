#pragma once
#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QWidget>
#include <QTableWidget>
#include <optional>
#include <vector>
class MainWindow : public QWidget
{
    Q_OBJECT
private:

    QTableWidget * table;
    std::optional<unsigned long long> base_time;
    std::vector<std::tuple<unsigned long long,unsigned long long,QByteArray>> packets;
public:
    std::vector<uint32_t> stream_id;
    explicit MainWindow(QWidget *parent = nullptr);
public slots:
    void raiseError(QString text);
    void startCapture(QString friendly,QString adapter);
    void packetArrival(long ts_sec,long ts_usec,unsigned long long total_len,QByteArray data);

signals:

};

#endif // MAINWINDOW_H
