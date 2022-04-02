#include "mainwindow.h"
#include "adapterselector.h"
MainWindow::MainWindow(QWidget *parent)
    : QWidget{parent}
{
    this->resize(1200,800);
    this->show();
    AdapterSelector* selector =new AdapterSelector(this);
    selector->show();
}
