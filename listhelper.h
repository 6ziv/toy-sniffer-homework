#pragma once
#ifndef LISTHELPER_H
#define LISTHELPER_H
#include <Windows.h>
#include <guiddef.h>
#include <QString>
#include <QMap>
#include <memory>

namespace ListHelper
{
    bool guid_parser(const std::string& p,GUID& o);
    QString friendly_name_from_guid(const GUID& guid);
    QMap<QString,std::string> list_adapters();
};

#endif // LISTHELPER_H
