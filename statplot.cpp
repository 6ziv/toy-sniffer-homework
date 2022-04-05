#include "statplot.h"
#include <QPainter>
#include <QPainterPath>
StatPlot::StatPlot(QWidget *parent) : QWidget{parent}, path(QPointF(0, 25)) {
  samples.push_back(std::make_pair(0, 0));
  path.moveTo(0, 25);
}
void StatPlot::paintEvent(QPaintEvent *e) {
  QPainter painter(this);
  painter.setRenderHint(QPainter::Antialiasing, true);
  painter.setPen(QPen(Qt::black, 1));
  painter.drawPath(path);
  return QWidget::paintEvent(e);
}
void StatPlot::path_advance(unsigned long long timestamp,
                            unsigned long long bps) {
  samples.push_back(std::make_pair(timestamp, bps));
  QPointF pt = calc(timestamp, bps, ubound);
  if (samples.size() == 1)
    path.moveTo(pt);
  else
    path.lineTo(pt);
  this->repaint();
}
void StatPlot::scale_to(unsigned long long n_ubound) {
  ubound = n_ubound;
  redraw_path();
}
void StatPlot::redraw_path() {
  path.clear();
  path.moveTo(calc(samples[0].first, samples[0].second, ubound));
  for (size_t i = 1; i < samples.size(); i++) {
    path.lineTo(calc(samples[i].first, samples[i].second, ubound));
  }
  this->repaint();
}
QPointF StatPlot::calc(unsigned long long ts, unsigned long long bps,
                       unsigned long long ubound) {
  return QPointF(ts * 10.0 / 1000000, 25 - 25 * (bps * 1.0 / ubound));
}
void StatPlot::clear_path(unsigned long long ub) {
  unsigned long long t = getCurrentVal();
  ubound = ub;
  samples.clear();
  path.clear();
  samples.push_back(std::make_pair(0, t));
  path.moveTo(calc(0, t, ubound));
}
unsigned long long StatPlot::getCurrentVal() {
  if (samples.empty())
    return 0;
  return samples.back().second;
}
