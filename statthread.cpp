#include "statthread.h"
#include "adapterselector.h"
#include "qdebug.h"
#include <numeric>
#include <pcap.h>
std::atomic_bool StatThread::is_finished = false;
StatThread::StatThread(std::string adapter_name, int id, QObject *p)
    : QThread(p), name(adapter_name), adapter_id(id) {}
unsigned long long timeval_to_ulonglong(const timeval *ts) {
  if (ts->tv_sec >= 0)
    return static_cast<unsigned long long>(ts->tv_sec) * 1000000 + ts->tv_usec;
  return (static_cast<unsigned long long>(
              std::numeric_limits<unsigned long>().max()) +
          1) *
             1000000 +
         ts->tv_usec;
}
struct UData {
  QObject *obj;
  unsigned long long old_timestamp;
  unsigned long long starttime;
  bool initialized;
  pcap_t *pcap;
  int id;
};
void dispatcher_handler_stat(u_char *state, const struct pcap_pkthdr *header,
                             const u_char *pkt_data) {
  UData *user_data = reinterpret_cast<UData *>(state);
  if (StatThread::is_finished)
    pcap_breakloop(user_data->pcap);

  unsigned long long current_timestamp = timeval_to_ulonglong(&header->ts);
  if (!user_data->initialized) {
    user_data->old_timestamp = current_timestamp;
    user_data->starttime = current_timestamp;
    user_data->initialized = true;
    return;
  }
  unsigned long long bps =
      reinterpret_cast<const unsigned long long *>(pkt_data)[1] * 1000000 /
      (current_timestamp - user_data->old_timestamp);

  user_data->old_timestamp = current_timestamp;

  QMetaObject::invokeMethod(
      user_data->obj, "update", Qt::QueuedConnection, Q_ARG(int, user_data->id),
      Q_ARG(unsigned long long, bps),
      Q_ARG(unsigned long long, current_timestamp - user_data->starttime));
}

void StatThread::run() {

  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *p = pcap_open_live(name.c_str(), BUFSIZ, 0, 100, errbuf);
  pcap_setmode(p, MODE_STAT);

  is_finished = 0;

  UData data;
  data.id = this->adapter_id;
  data.obj = this->parent();
  data.initialized = false;
  data.pcap = p;

  pcap_loop(p, -1, dispatcher_handler_stat, (PUCHAR)&data);
  pcap_close(p);
}
