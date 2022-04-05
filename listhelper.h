#pragma once
#ifndef LISTHELPER_H
#define LISTHELPER_H
#include <QMap>
#include <QString>
#include <Windows.h>
#include <guiddef.h>
#include <memory>

namespace ListHelper {
bool guid_parser(const std::string &p, GUID &o);
QString friendly_name_from_guid(const GUID &guid);
QMap<QString, std::string> list_adapters();
}; // namespace ListHelper

#endif // LISTHELPER_H
