#pragma once
#ifndef ADAPTERSELECTOR_H
#define ADAPTERSELECTOR_H

#include "statplot.h"
#include "statthread.h"
#include <QListWidget>
#include <QVector>
#include <QWidget>
class AdapterSelector : public QWidget {
  Q_OBJECT
private:
  QListWidget *list = nullptr;
  QVector<StatPlot *> plots;
  QVector<StatThread *> workers;
  unsigned long long ubound = 256;
  unsigned long long basetime = 0;

public:
  AdapterSelector(QWidget *parent);
public slots:
  void update(int id, unsigned long long bps, unsigned long long time);
};

#endif // ADAPTERSELECTOR_H
