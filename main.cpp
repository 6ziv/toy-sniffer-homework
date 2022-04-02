#include <QApplication>
#include <QLocale>
#include <QTranslator>
#include <aixlog.hpp>
#include <memory>
#include "mainwindow.h"
int main(int argc, char *argv[])
{
    AixLog::Log::init({std::make_shared<AixLog::SinkFile>(AixLog::Severity::error, "error.log")});
    QApplication a(argc, argv);

    QTranslator translator;
    const QStringList uiLanguages = QLocale::system().uiLanguages();
    for (const QString &locale : uiLanguages) {
        const QString baseName = "MySniffer_" + QLocale(locale).name();
        if (translator.load(":/i18n/" + baseName)) {
            a.installTranslator(&translator);
            break;
        }
    }
    MainWindow* m=new MainWindow();
    m->show();
    return a.exec();
}
