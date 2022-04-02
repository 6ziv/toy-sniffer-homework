#include "adapterselector.h"
#include <QApplication>
#include <QLabel>
#include <QTranslator>
#include <QListWidget>
#include <QListWidgetItem>
#include "listhelper.h"
#include <pcap.h>

#include "qdebug.h"
AdapterSelector::AdapterSelector(QWidget* parent):
    QWidget(parent)
{
    this->resize(1200,800);
    this->show();
    QLabel* lab = new QLabel(this);
    lab->setGeometry(100,50,1000,30);
    lab->setText(tr("Select an adaptor"));
    QFont f=lab->font();
    f.setPixelSize(24);
    lab->setFont(f);
    lab->show();

    list = new QListWidget(this);
    list->setGeometry(100,100,1000,650);
    list->show();

    auto adapters = ListHelper::list_adapters();

    for(const auto& adapter:adapters.keys()){
        QListWidgetItem* item=new QListWidgetItem(list);
        item->setSizeHint(QSize(950,25));
        QWidget* w=new QWidget(list);
        w->resize(950,25);
        QLabel* name =new QLabel(w);
        name->setGeometry(0,0,350,25);
        name->setText(adapter);
        name->show();
        plots.push_back(new StatPlot(w));
        plots.back()->setGeometry(350,0,950,25);
        plots.back()->show();
        list->addItem(item);
        list->setItemWidget(item,w);

        item->setData(Qt::UserRole,QString::fromStdString(adapters[adapter]));
    }
    for(int i=0;i<adapters.size();i++){
        workers.push_back(new StatThread(adapters.values()[i],i,this));
        workers.back()->start();
    }
    connect(list,&QListWidget::itemDoubleClicked,this,[this](QListWidgetItem *item){
        qDebug()<<"Selected:"<<item->data(Qt::UserRole);
        for(auto worker:workers){
            worker->is_finished = -1;
            worker->wait();
        }
        this->deleteLater();
    });
}
void AdapterSelector::update(int id,unsigned long long  bps,unsigned long long  time){
    if(bps>ubound){
        while(ubound<bps)ubound*=2;
        for(auto plot:plots){
            plot->scale_to(ubound);
        }
    }
    plots[id]->path_advance(time-basetime,bps);
    if(time - basetime > 60 * 1000000){
        basetime = time;
        unsigned long long new_ubound = 256;
        for(auto plot:plots){
            unsigned long long t=plot->getCurrentVal();
            if(t>new_ubound)new_ubound = t;
        }
        this->ubound = new_ubound;
        for(auto plot:plots){
            plot->clear_path(new_ubound);
        }
    }
}
