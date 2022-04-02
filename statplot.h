#ifndef STATPLOT_H
#define STATPLOT_H

#include <QWidget>
#include <vector>
#include <QVector>
#include <QPointF>
#include <QPainterPath>
class StatPlot : public QWidget
{
    Q_OBJECT
public:
    explicit StatPlot(QWidget *parent = nullptr);
    void paintEvent(QPaintEvent *e)override;
    void path_advance(unsigned long long timestamp,unsigned long long bps);

    void scale_to(unsigned long long n_ubound);
    void redraw_path();
    void clear_path(unsigned long long ub);
    unsigned long long getCurrentVal();
private:
    unsigned long long ubound = 256;
    std::vector<std::pair<unsigned long long,unsigned long long>> samples;
    QPainterPath path;



    QPointF calc(unsigned long long ts,unsigned long long bps,unsigned long long ubound);
};

#endif // STATPLOT_H
