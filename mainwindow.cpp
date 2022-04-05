#include "mainwindow.h"
#include "adapterselector.h"
#include "packetinterpreter.hpp"
#include "qt-collapsible-section/Section.h"
#include "sniffthread.h"
#include "tracer.hpp"
#include <QApplication>
#include <QHeaderView>
#include <QHexView.h>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPushButton>
#include <QSplitter>
#include <QVBoxLayout>
#include <optional>
MainWindow::MainWindow(QWidget *parent) : QWidget{parent} {
  this->resize(1200, 800);
  this->show();
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
  int id = table->rowCount();
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
  packets.emplace_back(timestamp, total_len, data);

  stream_id.push_back(Tracer::trace(packet));
}
void MainWindow::raiseError(QString text) {
  QMessageBox msgbox(QMessageBox::Critical, tr("Error"), text, QMessageBox::Ok,
                     this);
  msgbox.exec();
  QApplication::exit(0);
}
void MainWindow::startCapture(QString friendly_name, QString adapter) {
  base_time.reset();
  packets.clear();

  QLineEdit *display_filter = new QLineEdit(this);
  display_filter->setGeometry(20, 5, this->width() - 150, 20);
  display_filter->show();

  QPushButton *apply_filter = new QPushButton(this);
  apply_filter->setGeometry(this->width() - 110, 5, 90, 20);
  apply_filter->setText("Apply");
  apply_filter->show();

  this->setWindowTitle(tr("Capturing on: ") + friendly_name);
  SniffThread *sniff_thread = new SniffThread(adapter, this);
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
}
