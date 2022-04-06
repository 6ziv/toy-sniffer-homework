#include "mainwindow.h"
#include "adapterselector.h"
#include "packetinterpreter.hpp"
#include "qt-collapsible-section/Section.h"
#include "sniffthread.h"
#include "tracer.hpp"
#include <QApplication>
#include <QHeaderView>
#include <QHexView.h>
#include <QBuffer>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPushButton>
#include <QSplitter>
#include <QVBoxLayout>
#include <QMenu>
#include <QPair>
#include <QColor>
#include <optional>
#include <qhexedit.h>
#include "filter.hpp"
MainWindow::MainWindow(QWidget *parent) : QWidget{parent} {
  this->resize(1200, 800);
  this->show();
  this->filter=nullptr;
  this->setWindowTitle(tr("MySniffer: Adapter Selection."));
  AdapterSelector *selector = new AdapterSelector(this);
  selector->show();
}
void MainWindow::packetArrival(long ts_sec, long ts_usec,
                               unsigned long long total_len, QByteArray data) {
  unsigned long long timestamp =
      static_cast<unsigned long long>(ts_sec) * 1000000 + ts_usec;
  if (!base_time.has_value())
    base_time = timestamp;

  uint64_t id = packets.size();
  table->insertRow(id);
  table->setItem(
      id, 0, new QTableWidgetItem(QString::number(id), QTableWidgetItem::Type));
  table->setItem(
      id, 1,
      new QTableWidgetItem(
          QString::number((timestamp - base_time.value()) * 1.0 / 1000000),
          QTableWidgetItem::Type));
  auto packet =
      reinterpret_cast<const PacketInterpreter::EthernetPacket *>(data.data());
  table->setItem(
      id, 2,
      new QTableWidgetItem(packet->getDisplaySource(), QTableWidgetItem::Type));
  table->setItem(id, 3,
                 new QTableWidgetItem(packet->getDisplayDestination(),
                                      QTableWidgetItem::Type));
  table->setItem(id, 4,
                 new QTableWidgetItem(packet->get_protocols().back(),
                                      QTableWidgetItem::Type));
  table->setItem(
      id, 5,
      new QTableWidgetItem(QString::number(total_len), QTableWidgetItem::Type));
  table->setItem(
      id, 6,
      new QTableWidgetItem(packet->get_comment(), QTableWidgetItem::Type));
    for(int i=0;i<7;i++)
        table->item(id,i)->setData(Qt::UserRole,id);
  table->update();
  packets.emplace_back(timestamp, total_len, data);

  auto trace_info = Tracer::trace(packet);
  stream_id.push_back(trace_info);

  if(filter){
    Filter::FilterContext * ctx= new Filter::FilterContext(reinterpret_cast<const PacketInterpreter::EthernetPacket *>(data.data()),packets.size(),timestamp-base_time.value()/*,mask*/);
    bool show=filter->filter(ctx);
    delete ctx;
    if(!show)
      table->setRowHidden(id,true);
    }
}
void MainWindow::raiseError(QString text) {
  QMessageBox msgbox(QMessageBox::Critical, tr("Error"), text, QMessageBox::Ok,
                     this);
  msgbox.exec();
  QApplication::exit(0);
}
void MainWindow::raiseWarning(QString text) {
  QMessageBox *msgbox = new QMessageBox(QMessageBox::Warning, tr("Warning"), text, QMessageBox::Ok,
                     this);
  msgbox->exec();
}
void MainWindow::startCapture(QString friendly_name, QString adapter, bool promisc, QString capture_filter) {
  base_time.reset();
  packets.clear();

  QLineEdit *display_filter = new QLineEdit(this);
  display_filter->setGeometry(20, 5, this->width() - 150, 20);
  display_filter->show();

  QPushButton *apply_filter = new QPushButton(this);
  apply_filter->setGeometry(this->width() - 110, 5, 90, 20);
  apply_filter->setText(tr("Apply"));
  apply_filter->show();

  this->setWindowTitle(tr("Capturing on: ") + friendly_name);
  SniffThread *sniff_thread = new SniffThread(adapter, promisc, capture_filter, this);
  sniff_thread->start();

  QSplitter *splitter = new QSplitter(this);
  splitter->setGeometry(20, 50, this->width() - 40, this->height() - 70);
  splitter->setOrientation(Qt::Vertical);
  splitter->show();
  table = new QTableWidget(splitter);
  splitter->addWidget(table);
  table->show();
  table->verticalHeader()->hide();
  table->setColumnCount(7);
  table->setRowCount(0);
  table->setHorizontalHeaderLabels({tr("No."), tr("Time"), tr("Source"),
                                    tr("Destination"), tr("Protocol"),
                                    tr("Length"), tr("Info")});
  table->setEditTriggers(QTableWidget::NoEditTriggers);
  table->setSelectionMode(QTableWidget::SelectionMode::SingleSelection);
  table->setSelectionBehavior(QTableWidget::SelectionBehavior::SelectRows);

  QWidget *details = new QWidget(splitter);
  splitter->addWidget(details);
  details->show();
  QVBoxLayout *details_layout = new QVBoxLayout(details);
  details->setLayout(details_layout);

  QHexView *hex_view = new QHexView(splitter);
  hex_view->resize(splitter->width(), 200);
  hex_view->setMinimumHeight(100);
  splitter->addWidget(hex_view);
  hex_view->show();

  connect(table->selectionModel(), &QItemSelectionModel::selectionChanged,
          table, [=]() {
            auto rows = table->selectionModel()->selectedRows();
            if (rows.isEmpty())
              return;
            const auto &ref_data = std::get<2>(this->packets[rows[0].row()]);
            auto details_data =
                reinterpret_cast<const PacketInterpreter::EthernetPacket *>(
                    ref_data.data())
                    ->get_details();
            while (details_layout->count() > 0) {
              auto item = details_layout->takeAt(0);
              QWidget *w = item->widget();
              if (w)
                w->deleteLater();
              details_layout->removeItem(item);
            }

            std::function<void(QLayout * layout, QWidget * parent,
                               const std::wstring &name,
                               const PacketInterpreter::my_ptree &ptree)>
                insert_ptree = [details, hex_view, &insert_ptree](
                                   QLayout *layout, QWidget *parent,
                                   const std::wstring &name,
                                   const PacketInterpreter::my_ptree &ptree) {
                  if (ptree.empty()) {
                    auto *label =
                        new QPushButton(QString::fromStdWString(name) + ":" +
                                            std::get<0>(ptree.data()),
                                        parent);
                    label->setStyleSheet("text-align:left;");
                    label->setFlat(true);
                    label->resize(details->width() - 20, 50);
                    label->show();
                    layout->addWidget(label);
                    auto range_left = std::get<1>(ptree.data());
                    auto range_len = std::get<2>(ptree.data());
                    connect(label, &QPushButton::clicked, label,
                            [range_left, range_len, hex_view]() {
                              hex_view->setSelected(range_left, range_len);
                            });
                  } else {
                    ui::Section *section =
                        new ui::Section(QString::fromStdWString(name),
                                        ui::Section::DEFAULT_DURATION, parent);
                    section->resize(parent->size());
                    QVBoxLayout *section_layout = new QVBoxLayout;
                    for (const auto &child : ptree) {
                      insert_ptree(section_layout, section, child.first,
                                   child.second);
                    }
                    section->setContentLayout(*section_layout);
                    section->show();
                    layout->addWidget(section);
                  }
                };
            for (const auto &item : details_data)
              insert_ptree(details_layout, details, item.first, item.second);
            hex_view->clear();
            hex_view->setData(new QHexView::DataStorageArray(ref_data));
          });

  connect(apply_filter,&QPushButton::clicked,this,[this,display_filter](){
      filter = Filter::compile(display_filter->text().toStdString());
      if(filter){
          display_filter->setStyleSheet("background-color:rgba(200,255,200,255)");

      //mask.reset();
      //filter->prepare(mask);
      for(uint64_t i=0;i<packets.size();i++){
        Filter::FilterContext * ctx= new Filter::FilterContext(
                    reinterpret_cast<const PacketInterpreter::EthernetPacket *>(std::get<2>(packets[i]).data()),i,std::get<0>(packets[i])-base_time.value()/*,mask*/);
        bool show=filter->filter(ctx);
        delete ctx;
        if(!show)
            table->setRowHidden(i,true);
        else table->setRowHidden(i,false);
      }
      }else{
          display_filter->setStyleSheet("background-color:rgba(255,200,200,255)");
          for(uint64_t i=0;i<table->rowCount();i++)table->showRow(i);
      }
      if(display_filter->text().isEmpty()){
          display_filter->setStyleSheet("background-color:rgba(255,255,255,255)");
      }
  });

  table->setContextMenuPolicy(Qt::CustomContextMenu);
  QMenu *menu = new QMenu(table);
  QMenu* filter_menu = menu->addMenu(tr("Filter"));
  not_later = filter_menu->addAction(tr("No later than"),this,[display_filter,apply_filter,this](){
      display_filter->setText(not_later->data().toString());
      apply_filter->click();
  });
  not_earlier = filter_menu->addAction(tr("No earlier than"),this,[display_filter,apply_filter,this](){
      display_filter->setText(not_earlier->data().toString());
      apply_filter->click();
  });
  filter_menu->addSeparator();
  is_eth = filter_menu->addAction("Ethernet",this,[display_filter,apply_filter](){display_filter->setText("ethernet");apply_filter->click();});
  is_arp = filter_menu->addAction("ARP",this,[display_filter,apply_filter](){display_filter->setText("arp");apply_filter->click();});
  is_ipv4 = filter_menu->addAction("IPv4",this,[display_filter,apply_filter](){display_filter->setText("ipv4");apply_filter->click();});
  is_ipv6 = filter_menu->addAction("IPv6",this,[display_filter,apply_filter](){display_filter->setText("ipv6");apply_filter->click();});
  is_tcp = filter_menu->addAction("TCP",this,[display_filter,apply_filter](){display_filter->setText("tcp");apply_filter->click();});
  is_udp = filter_menu->addAction("UDP",this,[display_filter,apply_filter](){display_filter->setText("udp");apply_filter->click();});
  filter_menu->addSeparator();
  source_ip_address = filter_menu->addAction(tr("Source IP Address"),this,[display_filter,apply_filter,this](){
      display_filter->setText(source_ip_address->data().toString());
      apply_filter->click();
  });
  destination_ip_address = filter_menu->addAction(tr("Destination IP Address"),this,[display_filter,apply_filter,this](){
      display_filter->setText(destination_ip_address->data().toString());
      apply_filter->click();
  });

  QMenu* trace_menu = menu->addMenu(tr("Trace"));
  trace_tcp_stream = trace_menu->addAction(tr("TCP stream"),this,[this](){
    if(edit)edit->deleteLater();
    auto streamid = trace_tcp_stream->data().toULongLong();
    std::vector<std::tuple<size_t,size_t,bool>> pkt_split;
    edit = new QHexEdit(nullptr);
    QBuffer* trace_bytes = new QBuffer(edit);
    uint64_t expected_seq[2];
    bool has_first_packet[2]={false,false};
    for(size_t i=0;i<packets.size();i++){
        if(stream_id[i].first != streamid)continue;
        auto pkt = reinterpret_cast<const PacketInterpreter::EthernetPacket*>(std::get<2>(packets[i]).data());
        auto tcp_pkt = pkt->get_as<PacketInterpreter::TCPPacket>();
        if(tcp_pkt==nullptr)continue;
        uint8_t my_side = stream_id[i].second?1:0;
        if(!has_first_packet[my_side])expected_seq[my_side] = tcp_pkt->get_seq();
        uint32_t expect_seq = expected_seq[my_side];
        auto diff = static_cast<int32_t>(tcp_pkt->get_seq()-expect_seq);

        size_t tcp_pkt_payload_len = (
                    pkt->get_as<PacketInterpreter::IPv4Packet>()?
                        (pkt->get_as<PacketInterpreter::IPv4Packet>()->total_size() - pkt->get_as<PacketInterpreter::IPv4Packet>()->header_size()):
                        native_to_big(pkt->get_as<PacketInterpreter::IPv6Packet>()->payload_len)
                        ) - tcp_pkt->header_size();

        if(tcp_pkt_payload_len==0){
            if(tcp_pkt->check_flag(PacketInterpreter::TCPPacket::TCPFLAG::SYN)) expected_seq[my_side]++;
            continue;
        }
        if(diff>0){
            //qDebug()<<"Missing "<<diff<<" bytes";
            pkt_split.emplace_back(trace_bytes->buffer().size(),
                                   tcp_pkt_payload_len+diff,
                                   stream_id[i].second);
            trace_bytes->buffer().append(static_cast<size_t>(diff),'\0');
            trace_bytes->buffer().append(reinterpret_cast<const char*>(tcp_pkt->getload()),static_cast<size_t>(tcp_pkt_payload_len));
        }
        if(diff==0){
            pkt_split.emplace_back(trace_bytes->buffer().size(),
                               tcp_pkt_payload_len,
                               stream_id[i].second);
            trace_bytes->buffer().append(reinterpret_cast<const char*>(tcp_pkt->getload()),static_cast<size_t>(tcp_pkt_payload_len));
            expected_seq[my_side]+=tcp_pkt_payload_len;
        }
        if(diff<0){
            //qDebug()<<"Resending "<<-diff<<" bytes";
            if(-diff >= tcp_pkt_payload_len)continue;
            int skip_bytes = tcp_pkt_payload_len + diff;
            pkt_split.emplace_back(trace_bytes->buffer().size(),
                               tcp_pkt_payload_len - skip_bytes,
                               stream_id[i].second);
            trace_bytes->buffer().append(reinterpret_cast<const char*>(tcp_pkt->getload()+skip_bytes),static_cast<size_t>(tcp_pkt_payload_len)-skip_bytes);
            expected_seq[my_side]+=tcp_pkt_payload_len - skip_bytes;
        }
    }
    trace_bytes->open(QBuffer::ReadOnly);
    QHexDocument* doc = QHexDocument::fromDevice(trace_bytes);
    doc->setParent(edit);
    edit->setDocument(doc);
    edit->setReadOnly(true);
    doc->beginMetadata();
    for(const auto& slice:pkt_split){
        doc->highlightBackRange(std::get<0>(slice),std::get<1>(slice),std::get<2>(slice)?QColor(255,225,225):QColor(225,225,255));
    }
    doc->endMetadata();
    edit->show();
  });
  trace_udp_stream = trace_menu->addAction(tr("UDP stream"),this,[this](){
      if(edit)
        edit->deleteLater();

      auto streamid = trace_udp_stream->data().toULongLong();
      std::vector<std::tuple<size_t,size_t,bool>> pkt_split;

      edit = new QHexEdit(nullptr);
      QBuffer* trace_bytes = new QBuffer(edit);
      for(size_t i=0;i<packets.size();i++){
          if(stream_id[i].first != streamid)continue;
          auto pkt = reinterpret_cast<const PacketInterpreter::EthernetPacket*>(std::get<2>(packets[i]).data());
          auto udp_pkt = pkt->get_as<PacketInterpreter::UDPPacket>();
          if(udp_pkt==nullptr)continue;
          size_t udp_pkt_payload_len = udp_pkt->total_len()- udp_pkt->header_size();
          if(udp_pkt_payload_len==0)continue;
          pkt_split.emplace_back(trace_bytes->buffer().size(),
                                 udp_pkt_payload_len,
                                 stream_id[i].second);
          trace_bytes->buffer().append(reinterpret_cast<const char*>(udp_pkt->getload()),static_cast<size_t>(udp_pkt_payload_len));
      }
      trace_bytes->open(QBuffer::ReadOnly);
      QHexDocument* doc = QHexDocument::fromDevice(trace_bytes);
      doc->setParent(edit);
      edit->setDocument(doc);
      edit->setReadOnly(true);
      doc->beginMetadata();
      for(const auto& slice:pkt_split){
          doc->highlightBackRange(std::get<0>(slice),std::get<1>(slice),std::get<2>(slice)?QColor(255,225,225):QColor(225,225,255));
      }
      doc->endMetadata();
      edit->show();
  });
  table->connect(table,&QTableWidget::customContextMenuRequested,table,[=](const QPoint& pt){
      auto id = table->itemAt(pt)->data(Qt::UserRole).toULongLong();
      auto pkt = reinterpret_cast<const PacketInterpreter::EthernetPacket*>(std::get<2>(packets[id]).data());
      not_later->setData(QString("no <= %1").arg(id));
      not_earlier->setData(QString("no >= %1").arg(id));

      is_eth->setEnabled(true);
      is_arp->setEnabled(pkt->get_as<PacketInterpreter::ARPPacket>()!=nullptr);
      is_ipv4->setEnabled(pkt->get_as<PacketInterpreter::IPv4Packet>()!=nullptr);
      is_ipv6->setEnabled(pkt->get_as<PacketInterpreter::IPv6Packet>()!=nullptr);
      is_tcp->setEnabled(pkt->get_as<PacketInterpreter::TCPPacket>()!=nullptr);
      is_udp->setEnabled(pkt->get_as<PacketInterpreter::UDPPacket>()!=nullptr);

      if(pkt->get_as<PacketInterpreter::IPv4Packet>()!=nullptr){
          source_ip_address->setEnabled(true);
          source_ip_address->setData(QString("ipv4.source == ")+PacketInterpreter::addr2Str(pkt->get_as<PacketInterpreter::IPv4Packet>()->get_source()));
          destination_ip_address->setEnabled(true);
          destination_ip_address->setData(QString("ipv4.destination == ")+PacketInterpreter::addr2Str(pkt->get_as<PacketInterpreter::IPv4Packet>()->get_destination()));
      }else if(pkt->get_as<PacketInterpreter::IPv6Packet>()!=nullptr){
          source_ip_address->setEnabled(true);
          source_ip_address->setData(QString("ipv6.source == ")+PacketInterpreter::addr2Str(pkt->get_as<PacketInterpreter::IPv6Packet>()->get_source()));
          destination_ip_address->setEnabled(true);
          destination_ip_address->setData(QString("ipv6.destination == ")+PacketInterpreter::addr2Str(pkt->get_as<PacketInterpreter::IPv6Packet>()->get_destination()));
      }
      else{
          source_ip_address->setEnabled(false);
          destination_ip_address->setEnabled(false);
      }

      if(pkt->get_as<PacketInterpreter::TCPPacket>()!=nullptr){
        trace_tcp_stream->setEnabled(true);
        trace_tcp_stream->setData(stream_id[id].first);
      }else trace_tcp_stream->setEnabled(false);
      if(pkt->get_as<PacketInterpreter::UDPPacket>()!=nullptr){
        trace_udp_stream->setEnabled(true);
        trace_tcp_stream->setData(stream_id[id].first);
      }else trace_udp_stream->setEnabled(false);
    menu->popup(table->mapToGlobal(pt));
  });
}
