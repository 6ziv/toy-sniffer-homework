#include "sniffthread.h"
#include <QByteArray>
#include <aixlog.hpp>
#include <iomanip>
#include <pcap.h>
SniffThread::SniffThread(QString name, QObject *parent)
    : QThread{parent}, adapter_name(name.toStdString()) {}
void dispatcher_handler_sniff(u_char *state, const struct pcap_pkthdr *header,
                              const u_char *pkt_data) {
  QByteArray data;
  data.resize(header->caplen);
  memcpy(data.data(), pkt_data, header->caplen);
  auto receiver = reinterpret_cast<QObject *>(state);
  QMetaObject::invokeMethod(
      receiver, "packetArrival", Qt::QueuedConnection,
      Q_ARG(long, header->ts.tv_sec), Q_ARG(long, header->ts.tv_usec),
      Q_ARG(unsigned long long, header->len), Q_ARG(QByteArray, data));
}

void SniffThread::run() {
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *pcap = pcap_create(adapter_name.c_str(), errbuf);
  // pcap_set_promisc(pcap,1);
  // pcap_t * pcap = pcap_open_live(adapter_name.c_str(),BUFSIZ,0,0,errbuf);
  if (pcap == nullptr) {
    LOG(ERROR) << "Can not listen on adapter "
               << std::quoted(adapter_name.c_str()) << "\n";
    LOG(ERROR) << "Reason: " << errbuf << "\n";
    QMetaObject::invokeMethod(
        this->parent(), "raiseError", Qt::BlockingQueuedConnection,
        Q_ARG(QString, tr("Failed to listen on adapter")));
  }
  pcap_set_buffer_size(pcap, 67108864);
  pcap_set_snaplen(pcap, 67108864);
  pcap_activate(pcap);
  pcap_loop(pcap, -1, dispatcher_handler_sniff,
            reinterpret_cast<uchar *>(this->parent()));
  pcap_close(pcap);
  // pcap_next()
}
