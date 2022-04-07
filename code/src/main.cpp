#include "mainwindow.h"
#include <QApplication>
#include <QLocale>
#include <QTranslator>
#include <aixlog.hpp>
#include <memory>
#include <Windows.h>
#include <sysinfoapi.h>
#include <pcap.h>
void update_dir(){
  UINT len_system = 0;
  wchar_t *ptr = reinterpret_cast<wchar_t*>(malloc(sizeof(wchar_t)));
  if(!ptr)return;
  len_system = GetSystemDirectoryW(ptr,0);
  free(ptr);
  if(len_system==0)return;
  
  ptr = reinterpret_cast<wchar_t*>(malloc((len_system + 16)*sizeof(wchar_t)));
  if(!ptr)return;
  len_system = GetSystemDirectoryW(ptr,len_system);
  if(len_system==0){
	free(ptr);
	return;
  }
  ptr[len_system] = L'\0';
  wcscat(ptr,L"\\Npcap");
  SetDllDirectoryW(ptr);
  const char *pcap_version = pcap_lib_version();
  //LOG(INFO)<<"PCAP Version="<<pcap_version;
  
}
int main(int argc, char *argv[]) {
  
  AixLog::Log::init({
	  std::make_shared<AixLog::SinkFile>(AixLog::Severity::error,"error.log")
	  ,std::make_shared<AixLog::SinkFile>(AixLog::Severity::warning,"warning.log")
//	  ,std::make_shared<AixLog::SinkFile>(AixLog::Severity::info,"info.log")
	  });
  update_dir();
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
  MainWindow *m = new MainWindow();
  m->show();
  return a.exec();
}
