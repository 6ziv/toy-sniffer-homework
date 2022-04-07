#include "sniffthread.h"
#include <QByteArray>
#include <aixlog.hpp>
#include <iomanip>
#include <pcap.h>
SniffThread::SniffThread(QString name,bool promisc, QString capture_filter, QObject *parent)
    : QThread{parent}, adapter_name(name.toStdString()),cap_filter(capture_filter.toStdString()),is_promisc(promisc)
{}
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
  if(is_promisc)
      pcap_set_promisc(pcap,1);
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
  pcap_set_immediate_mode(pcap,1);
  pcap_activate(pcap);

  bpf_program program;
  bool bpf_ok = (0 == pcap_compile(pcap,&program,cap_filter.c_str(),1,PCAP_NETMASK_UNKNOWN));
  if(bpf_ok){
    bpf_ok &= (0==pcap_setfilter(pcap,&program));
    pcap_freecode(&program);
  }
  if(!bpf_ok){
      LOG(WARNING) << "Can not set capture filter "
                 << std::quoted(cap_filter.c_str()) << "\n";
      QMetaObject::invokeMethod(
          this->parent(), "raiseWarning", Qt::BlockingQueuedConnection,
          Q_ARG(QString, tr("Failed to apply filter \"%1\".\nNo capture filter will be applied.").arg(QString::fromStdString(cap_filter))));
    }
  pcap_loop(pcap, -1, dispatcher_handler_sniff,
            reinterpret_cast<uchar *>(this->parent()));
  pcap_close(pcap);
  // pcap_next()
}
