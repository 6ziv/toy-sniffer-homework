#include <Windows.h>
#include <ntddndis.h>
#include <Iphlpapi.h>
#include <pcap.h>

#include <boost/phoenix/core.hpp>
#include <boost/phoenix/operator.hpp>
#include <boost/spirit/home/qi.hpp>
#include <boost/spirit/home/qi/numeric/uint.hpp>

#include <aixlog.hpp>

#include "listhelper.h"
namespace ListHelper {

bool guid_parser(const std::string &p, GUID &o) {
  char const *from = p.c_str();
  char const *to = from + p.length();

  bool ok = boost::spirit::qi::parse(
      from, to,
      ('{' >> boost::spirit::qi::uint_parser<unsigned int, 16U, 8, 8>()
                  [boost::phoenix::ref(o.Data1) = boost::spirit::qi::_1] >>
       '-' >> boost::spirit::qi::uint_parser<unsigned int, 16U, 4, 4>()
                  [boost::phoenix::ref(o.Data2) = boost::spirit::qi::_1] >>
       '-' >> boost::spirit::qi::uint_parser<unsigned int, 16U, 4, 4>()
                  [boost::phoenix::ref(o.Data3) = boost::spirit::qi::_1] >>
       '-' >> boost::spirit::qi::repeat(
                  2)[boost::spirit::qi::uint_parser<unsigned char, 16U, 2, 2>()]
                    [([&o](const std::vector<unsigned char> &x) -> void {
                      for (size_t i = 0; i < 2; i++)
                        o.Data4[i] = x[i];
                    })] >>
       '-' >> boost::spirit::qi::repeat(
                  6)[boost::spirit::qi::uint_parser<unsigned char, 16U, 2, 2>()]
                    [([&o](const std::vector<unsigned char> &x) -> void {
                      for (size_t i = 0; i < 6; i++)
                        o.Data4[i + 2] = x[i];
                    })] >>
       '}'));
  if (!ok)
    return false;
  if (from != to)
    return false;
  return true;
}

QString friendly_name_from_guid(const GUID &guid) {

  NET_LUID luid;
  if (NO_ERROR != ConvertInterfaceGuidToLuid(&guid, &luid)) {
    return QString();
  }
  WCHAR t[NDIS_IF_MAX_STRING_SIZE + 1];
  if (NO_ERROR !=
      ConvertInterfaceLuidToAlias(&luid, t, NDIS_IF_MAX_STRING_SIZE + 1)) {
    return QString();
  }
  return QString::fromWCharArray(t);
}

QMap<QString, std::string> list_adapters() {
  pcap_if_t *devs;
  char errbuf[PCAP_ERRBUF_SIZE];
  if (-1 == pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &devs, errbuf)) {
    LOG(ERROR) << "pcap_findalldevs_ex failed:" << errbuf << "\n";
    return QMap<QString, std::string>();
  }

  QMap<QString, std::string> result;
  for (pcap_if_t *dev = devs; dev != nullptr; dev = dev->next) {
    constexpr std::string_view prefix = "rpcap://\\Device\\NPF_";

    std::string name = dev->name;
    std::string guid_text;
    if (name.starts_with(prefix)) {
      guid_text = name.substr(prefix.size());
    } else {
      guid_text = name;
    }
    GUID guid;

    if (guid_parser(guid_text, guid)) {
      QString displayName = friendly_name_from_guid(guid);
      if (displayName.isNull() || displayName.isNull())
        displayName = dev->description;
      if (displayName.isNull() || displayName.isNull())
        displayName = dev->name;
      result[displayName] = name;
    }
  }
  pcap_freealldevs(devs);
  return result;
}

} // namespace ListHelper
