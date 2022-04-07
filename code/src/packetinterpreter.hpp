#pragma once
#ifndef PACKETINTERPRETER_HPP
#define PACKETINTERPRETER_HPP
#include "addresstranslator.hpp"
#include "endian.hpp"
#include "headerformats.hpp"
#include "protocols.h"
#include <QCoreApplication>
#include <QString>
#include <QStringList>
#include <array>
#include <bit>
#include <boost/property_tree/ptree.hpp>
#include <concepts>
#include <deque>
#include <map>
#include <set>
#include <stdint.h>
#define MEMBER_OFFSET(MEMBER)                                                  \
  (reinterpret_cast<const uint8_t *>(&this->MEMBER) -                          \
   reinterpret_cast<const uint8_t *>(this))
#define TREE_ADD(NAME, VALUE, MEMBER)                                          \
  tree.add(L#NAME, std::make_tuple((VALUE), offset + MEMBER_OFFSET(MEMBER),    \
                                   sizeof(this->MEMBER)))
#define TREE2_ADD(TREE2, NAME, VALUE, MEMBER)                                  \
  TREE2.add(L#NAME, std::make_tuple((VALUE), offset + MEMBER_OFFSET(MEMBER),   \
                                    sizeof(this->MEMBER)))
#define TREE_ADD2(NAME, VALUE, MEMBER, OFFSET, LENGTH)                         \
  tree.add(L#NAME,                                                             \
           std::make_tuple((VALUE), offset + MEMBER_OFFSET(MEMBER) + (OFFSET), \
                           static_cast<size_t>(LENGTH)))
#define TREE_ADD3(NAME, VALUE, OFFSET, LENGTH)                                 \
  tree.add(L#NAME, std::make_tuple((VALUE), offset + (OFFSET),                 \
                                   static_cast<size_t>(LENGTH)))
#define TREE2_ADD2(TREE2, NAME, VALUE, MEMBER, OFFSET, LENGTH)                 \
  TREE2.add(L#NAME, std::make_tuple((VALUE),                                   \
                                    offset + MEMBER_OFFSET(MEMBER) + (OFFSET), \
                                    static_cast<size_t>(LENGTH)))
#define TREE2_ADD3(TREE2, NAME, VALUE, OFFSET, LENGTH)                         \
  TREE2.add(L#NAME, std::make_tuple((VALUE), offset + (OFFSET),                \
                                    static_cast<size_t>(LENGTH)))
namespace PacketInterpreter {
typedef boost::property_tree::basic_ptree<std::wstring,
                                          std::tuple<QString, size_t, size_t>>
    my_ptree;
class UDPPacket : public UDPHeader {
public:
  inline QString get_comment() const {
    return QString::number(native_to_big(this->src_port)) +
           QChar::fromUcs2(u'\u2192') +
           QString::number(native_to_big(this->dest_port)) + QString(" Len=") +
           QString::number(total_len());
  }
  inline uint16_t get_source_port() const { return native_to_big(src_port); }
  inline uint16_t get_destination_port() const {
    return native_to_big(dest_port);
  }
  inline uint16_t total_len() const { return native_to_big(len); }
  inline std::deque<std::pair<std::wstring, my_ptree>>
  get_details(size_t offset = 0) const {
    std::deque<std::pair<std::wstring, my_ptree>> ret;
    PacketInterpreter::my_ptree tree;
    TREE_ADD(Source Port, QString::number(get_source_port()), src_port);
    TREE_ADD(Destiantion Port, QString::number(get_destination_port()),
             dest_port);
    TREE_ADD(Length,
             QString("%1 = (%2 + %3)")
                 .arg(total_len())
                 .arg(sizeof(UDPPacket))
                 .arg(total_len() - sizeof(UDPPacket)),
             len);
    TREE_ADD(CRC(Unverified), QString::number(crc, 16).rightJustified(4, '0'),
             crc);

    PacketInterpreter::my_ptree tree2;
    TREE2_ADD3(tree2, Payload,
               QString("( %1 bytes )").arg(total_len() - header_size()),
               header_size(), total_len() - header_size());
    ret.emplace_front(L"User Data", tree2);

    ret.emplace_front(L"User Datagram Protocol", tree);

    return ret;
  }

  inline const uint8_t *getload() const {
    return reinterpret_cast<const uint8_t *>(this + 1);
  }
  inline size_t header_size() const { return sizeof(*this); }
};
class ICMPPacket:public ICMPHeader{

public:
    inline QString get_comment()const{
        return get_icmp_typename(this->type);
    }
    inline std::deque<std::pair<std::wstring, my_ptree>>
    get_details(size_t offset = 0) const {
        std::deque<std::pair<std::wstring, my_ptree>> ret;
        PacketInterpreter::my_ptree tree;
        TREE_ADD(Type, QString::number(type), type);
        TREE_ADD(Code, QString::number(subtype), subtype);
        TREE_ADD(CRC, QString::number(native_to_big(checksum),16).rightJustified(4,'0'),checksum);
        TREE_ADD(Rest Of Header, QString::number(native_to_big(rest_of_header),16).rightJustified(8,'0'),rest_of_header);
        ret.emplace_front(L"Internet Control Message Protocol",tree);
        return ret;
    }
};
class TCPPacket : public TCPHeader {
public:
  inline QString get_comment2(uint16_t packet_size) const {
    return QString::number(native_to_big(this->src_port)) +
           QChar::fromUcs2(u'\u2192') +
           QString::number(native_to_big(this->dest_port)) + QString(" Len=") +
           QString::number(packet_size - (native_to_big(this->tags) >> 12) * 4);
  }

  inline const uint8_t *getload() const {
    return reinterpret_cast<const uint8_t *>(this) +
           (native_to_big(this->tags) >> 12) * 4;
  }
  inline size_t header_size() const {
    return (native_to_big(this->tags) >> 12) * 4;
  }
  inline uint16_t get_source_port() const {
    return native_to_big(this->src_port);
  }
  inline uint16_t get_destination_port() const {
    return native_to_big(this->dest_port);
  }
  inline uint32_t get_seq() const { return native_to_big(this->seq); }
  inline uint32_t get_ack() const { return native_to_big(this->ack); }
  enum TCPFLAG : uint8_t {
    FIN = 0,
    SYN = 1,
    RST = 2,
    PSH = 3,
    ACK = 4,
    URG = 5,
    ECE = 6,
    CWR = 7,
    NS = 8
  };
  inline bool check_flag(TCPFLAG flag) const {
    return (native_to_big(tags) >> flag) & 1;
  }
  inline uint16_t get_window_size() const { return native_to_big(window_size); }
  inline uint16_t get_checksum() const { return native_to_big(checksum); }
  inline std::deque<std::pair<std::wstring, my_ptree>>
  get_details2(size_t pktsize, size_t offset = 0) const {
    std::deque<std::pair<std::wstring, my_ptree>> ret;
    PacketInterpreter::my_ptree tree;
    TREE_ADD(Source Port, QString::number(get_source_port()), src_port);
    TREE_ADD(Destiantion Port, QString::number(get_destination_port()),
             dest_port);
    TREE_ADD(Sequence Number, QString::number(get_seq()), seq);
    if (check_flag(ACK)) {
      TREE_ADD(Acknowledgment number, QString::number(get_ack()), ack);
    }
    TREE_ADD2(Data Offset, QString::number(header_size()), tags, 0, 1);
    QString flags;
    if (check_flag(NS))
      flags.append("NS,");
    if (check_flag(CWR))
      flags.append("CWR,");
    if (check_flag(ECE))
      flags.append("ECE,");
    if (check_flag(URG))
      flags.append("URG,");
    if (check_flag(ACK))
      flags.append("ACK,");
    if (check_flag(PSH))
      flags.append("PSH,");
    if (check_flag(RST))
      flags.append("RST,");
    if (check_flag(SYN))
      flags.append("SYN,");
    if (check_flag(FIN))
      flags.append("FIN,");
    if (flags.isEmpty())
      flags = "[no flags]";
    else
      flags = flags.left(flags.length() - 1);
    TREE_ADD(Flags, flags, tags);
    TREE_ADD(Window Size, QString::number(get_window_size()), window_size);
    TREE_ADD(Checksum,
             QString::number(get_checksum(), 16).rightJustified(4, '0'),
             checksum);
    if (check_flag(URG)) {
      TREE_ADD(Urgent Pointer, QString::number(native_to_big(urgent_pointer)),
               urgent_pointer);
    }
    uint16_t pktend_ptr = static_cast<uint16_t>(this->header_size());
    uint16_t current_ptr = sizeof(TCPHeader);
    const uint8_t *asbyte = reinterpret_cast<const uint8_t *>(this);
    my_ptree options;

    while (current_ptr < pktend_ptr) {
      uint8_t option_id = asbyte[current_ptr];
      uint8_t option_size;
      if (option_id == 0 || option_id == 1)
        option_size = 1;
      else
        option_size = asbyte[current_ptr + 1];
      TREE2_ADD3(options, Option, get_tcp_option_name(option_id), current_ptr,
                 option_size);
      current_ptr += option_size;
    }
    if (!options.empty())
      tree.add_child(L"Options", options);
    if (current_ptr < pktend_ptr) {
      TREE_ADD3(Paddings, QString("( %1 bytes )").arg(pktend_ptr - current_ptr),
                current_ptr, pktend_ptr - current_ptr);
    }

    PacketInterpreter::my_ptree tree2;
    TREE2_ADD3(tree2, Payload,
               QString("( %1 bytes )").arg(pktsize - header_size()),
               header_size(), pktsize - header_size());
    ret.emplace_front(L"User Data", tree2);

    ret.emplace_front(L"Transmission Control Protocol", tree);
    return ret;
  }
};

class IPv4Packet : public Ipv4Header {
public:
  inline COMMONADDR get_source() const {
    return COMMONADDR(reinterpret_cast<const uint8_t *>(saddr),
                      static_cast<size_t>(4));
  }
  inline COMMONADDR get_destination() const {
    return COMMONADDR(reinterpret_cast<const uint8_t *>(daddr),
                      static_cast<size_t>(4));
  }
  inline uint8_t get_version() const { return (this->ver_ihl >> 4) & 0x0F; }
  inline QStringList get_protocols() const {
    return {"IPV4", get_protocol_name(this->proto)};
  };
  inline uint16_t total_size() const { return native_to_big(this->tlen); }
  inline uint16_t header_size() const { return (this->ver_ihl & 0x0F) * 4; }
  inline uint16_t fragment_offset() const {
    return native_to_big(this->flags_fo) & 0x1FFF;
  };
  inline uint16_t flags() const { return native_to_big(this->flags_fo) >> 13; };
  inline bool MF() const { return flags() & 4; }
  inline bool DF() const { return flags() & 2; }
  inline QString get_comment() const {
    if (this->get_as<UDPPacket>())
      return this->get_as<UDPPacket>()->get_comment();
    if (this->get_as<TCPPacket>())
      return this->get_as<TCPPacket>()->get_comment2(total_size() -
                                                     header_size());
    if(this->get_as<ICMPPacket>())
        return this->get_as<ICMPPacket>()->get_comment();
    return QString();
  }
  std::deque<std::pair<std::wstring, my_ptree>>
  get_details(size_t offset = 0) const {
    std::deque<std::pair<std::wstring, my_ptree>> ret;
    PacketInterpreter::my_ptree tree;
    TREE_ADD(Version, QString::number(get_version()), ver_ihl);
    TREE_ADD(Header Length, QString::number(header_size()), ver_ihl);

    uint8_t dscp = this->tos >> 2;
    uint8_t dscp_l = dscp >> 3;
    uint8_t dscp_r = dscp & 7;
    QString dscp_tag;
    if (dscp_r == 0)
      dscp_tag = QString("CS") + QString::number(dscp_l);
    else if (((dscp_r & 1) == 0) && (dscp_l >= 1) && (dscp_l <= 4))
      dscp_tag =
          QString("AF") + QString::number(dscp_l) + QString::number(dscp_r / 2);
    else if (dscp == 46)
      dscp_tag = QString("EF");
    else if (dscp == 44)
      dscp_tag = QString("VOICE-ADMIT");
    else if (dscp == 1)
      dscp_tag = QString("LE");
    else
      dscp_tag = QString("Unknown DSCP:") + QString::number(dscp);
    my_ptree tos_tree;
    TREE2_ADD(tos_tree, DSCP, dscp_tag, tos);

    uint8_t ecn = this->tos & 0x03;
    const char *ect_tags[] = {"Not-ECT", "ECT(1)", "ECT(0)", "CE"};
    TREE2_ADD(tos_tree, ECN, QString(ect_tags[ecn]), tos);
    tree.add_child(L"Type Of Service", tos_tree);

    TREE_ADD(Total Length,
             QString("%1 (=%2 + %3)")
                 .arg(total_size())
                 .arg(header_size())
                 .arg(total_size() - header_size()),
             tlen);
    TREE_ADD(Identification, QString::number(identification), identification);

    uint8_t flags = this->flags();
    QString flags_str;
    if (DF())
      flags_str += "Don't fragment";
    if (MF())
      flags_str += (flags_str.isEmpty() ? QString(" , ") : QString("")) +
                   "More fragments";
    if (flags & 1)
      flags_str += (flags_str.isEmpty() ? QString(" , ") : QString("")) +
                   "Illegal bit 1";
    if (flags_str.isEmpty())
      flags_str = "No Flags";
    TREE_ADD(Flags, flags_str, flags_fo);
    TREE_ADD(Fragment offset, QString::number(fragment_offset()), flags_fo);
    TREE_ADD(Time to Live, QString::number(this->ttl), ttl);
    TREE_ADD(Protocol,
             get_protocol_name(this->proto) + QString("(%1)").arg(proto),
             proto);
    TREE_ADD(
        CRC(Unverified),
        QString::number(native_to_big(this->crc), 16).rightJustified(4, '0'),
        crc);
    TREE_ADD(Source Address, addr2Str(this->get_source()), saddr);
    TREE_ADD(Source Address, addr2Str(this->get_destination()), daddr);

    if (get_as<UDPPacket>())
      ret = get_as<UDPPacket>()->get_details(offset + this->header_size());
    if (get_as<TCPPacket>())
      ret = get_as<TCPPacket>()->get_details2(total_size() - header_size(),
                                              offset + this->header_size());
    if(get_as<ICMPPacket>())
        return get_as<ICMPPacket>()->get_details(offset+this->header_size());
    ret.emplace_front(L"Internet Protocol Version 4", tree);
    return ret;
  }

  inline const uint8_t *getload() const {
    return reinterpret_cast<const uint8_t *>(this) + this->header_size();
  }
  template <class T> const T *get_as() const { return nullptr; }
  template <> const TCPPacket *get_as() const {
    return (proto == TCP) ? reinterpret_cast<const TCPPacket *>(getload())
                          : nullptr;
  }
  template <> const UDPPacket *get_as() const {
    return (proto == UDP) ? reinterpret_cast<const UDPPacket *>(getload())
                          : nullptr;
  }
  template <> const ICMPPacket *get_as() const {
    return (proto == ICMP) ? reinterpret_cast<const ICMPPacket *>(getload())
                           : nullptr;
  }
};

class IPv6Packet : public IPv6Header {
private:
  static QString ipv6_uint16_tostr(const uint16_t &x);

public:
  static constexpr uint8_t ICMP = 1;
  static constexpr uint8_t TCP = 6;
  static constexpr uint8_t UDP = 17;
  inline size_t header_size() const { return sizeof(*this); }
  inline COMMONADDR get_source() const {
    return COMMONADDR(reinterpret_cast<const uint8_t *>(saddr),
                      static_cast<size_t>(16));
  }
  inline COMMONADDR get_destination() const {
    return COMMONADDR(reinterpret_cast<const uint8_t *>(daddr),
                      static_cast<size_t>(16));
  }

  inline QStringList get_protocols() const {
    return {"IPV6", get_protocol_name(this->next_header)};
  };
  inline QString get_comment() const {
    if (this->get_as<UDPPacket>())
      return this->get_as<UDPPacket>()->get_comment();
    if (this->get_as<TCPPacket>())
      return this->get_as<TCPPacket>()->get_comment2(this->payload_len);
    return QString();
  }

  std::deque<std::pair<std::wstring, my_ptree>>
  get_details(size_t offset = 0) const {
    std::deque<std::pair<std::wstring, my_ptree>> ret;
    PacketInterpreter::my_ptree tree;

    TREE_ADD2(Version, QString::number((this->tag1 >> 28) & 0x0F), tag1, 0, 1);

    uint32_t native_tag = native_to_big(tag1);
    uint8_t traffic_class = (native_tag >> 20) & 0xFF;
    uint8_t dscp = traffic_class >> 2;
    uint8_t dscp_l = dscp >> 3;
    uint8_t dscp_r = dscp & 7;
    QString dscp_tag;
    if (dscp_r == 0)
      dscp_tag = QString("CS") + QString::number(dscp_l);
    else if (((dscp_r & 1) == 0) && (dscp_l >= 1) && (dscp_l <= 4))
      dscp_tag =
          QString("AF") + QString::number(dscp_l) + QString::number(dscp_r / 2);
    else if (dscp == 46)
      dscp_tag = QString("EF");
    else if (dscp == 44)
      dscp_tag = QString("VOICE-ADMIT");
    else if (dscp == 1)
      dscp_tag = QString("LE");
    else
      dscp_tag = QString("Unknown DSCP:") + QString::number(dscp);
    my_ptree tos_tree;
    TREE2_ADD2(tos_tree, DSCP, dscp_tag, tag1, 0, 2);
    uint8_t ecn = traffic_class & 0x03;
    const char *ect_tags[] = {"Not-ECT", "ECT(1)", "ECT(0)", "CE"};
    TREE2_ADD2(tos_tree, ECN, QString(ect_tags[ecn]), tag1, 0, 2);
    tree.add_child(L"Traffic Class", tos_tree);
    TREE_ADD2(Flow label,
              QString::number(native_tag & 0xFFFFF, 16).rightJustified(5, '0'),
              tag1, 1, sizeof(tag1) - 1);
    TREE_ADD(Payload length, QString::number(native_to_big(payload_len)),
             payload_len);
    TREE_ADD(Next Header,
             get_protocol_name(this->next_header) +
                 QString("(%1)").arg(next_header),
             next_header);
    TREE_ADD(Hop limit, QString::number(hop), hop);
    TREE_ADD(Source Address, addr2Str(get_source()), saddr);
    TREE_ADD(Destination Address, addr2Str(get_destination()), daddr);

    if (get_as<UDPPacket>())
      ret = get_as<UDPPacket>()->get_details(offset + this->header_size());
    if (get_as<TCPPacket>())
      ret = get_as<TCPPacket>()->get_details2(native_to_big(payload_len),
                                              offset + this->header_size());
    ret.emplace_back(L"Internet Protocol Version 6", tree);
    return ret;
  }

  inline const uint8_t *getload() const {
    return reinterpret_cast<const uint8_t *>(this + 1);
  }
  template <class T> const T *get_as() const { return nullptr; }
  template <> const TCPPacket *get_as() const {
    return (next_header == TCP) ? reinterpret_cast<const TCPPacket *>(getload())
                                : nullptr;
  }
  template <> const UDPPacket *get_as() const {
    return (next_header == UDP) ? reinterpret_cast<const UDPPacket *>(getload())
                                : nullptr;
  }
  template <> const ICMPPacket *get_as() const {
    return (next_header == ICMP)
               ? reinterpret_cast<const ICMPPacket *>(getload())
               : nullptr;
  }
};
class ARPPacket : public ARPHeader {
public:
  static constexpr uint8_t ARP_REQUEST = 1;
  static constexpr uint8_t ARP_REPLY = 2;
  static constexpr uint8_t RARP_REQUEST = 3;
  static constexpr uint8_t RARP_REPLY = 4;
  static constexpr uint8_t DRARP_REQUEST = 5;
  static constexpr uint8_t DRARP_REPLY = 6;
  static constexpr uint8_t InARP_REQUEST = 7;
  static constexpr uint8_t InARP_REPLY = 8;
  inline QStringList get_protocols() const { return {"ARP"}; }

  inline QString get_comment() const {
    const uint8_t *sender_physical_address =
        reinterpret_cast<const uint8_t *>(this + 1);
    const uint8_t *sender_protocol_address =
        sender_physical_address + hardware_address_len;
    const uint8_t *receiver_physical_address =
        sender_protocol_address + protocol_address_len;
    const uint8_t *receiver_protocol_address =
        receiver_physical_address + hardware_address_len;
    if (this->protocol == IPV4 || this->protocol == IPV6) {
      if (opcode & 1) {
        if (*reinterpret_cast<const uint32_t *>(sender_protocol_address) ==
            *reinterpret_cast<const uint32_t *>(receiver_protocol_address))
          return QString("ARP Announcement for %1")
              .arg(addr2Str(get_protocol_source()));
        else
          return QString("Who has %1? Tell %2.")
              .arg(addr2Str(get_protocol_destination()),
                   addr2Str(get_protocol_source()));
      } else {
        return QString("%1 is at %2.")
            .arg(addr2Str(get_protocol_source()),
                 addr2Str(get_physical_source()));
      }
    } else {
      return QString("Unknown protocol type");
    }
  }
  inline COMMONADDR get_physical_source() const {
    const uint8_t *sender_physical_address =
        reinterpret_cast<const uint8_t *>(this + 1);
    return COMMONADDR(sender_physical_address, hardware_address_len);
  }
  inline COMMONADDR get_physical_destination() const {
    const uint8_t *receiver_physical_address =
        reinterpret_cast<const uint8_t *>(this + 1) + hardware_address_len +
        protocol_address_len;
    return COMMONADDR(receiver_physical_address, hardware_address_len);
  }
  inline COMMONADDR get_protocol_source() const {
    const uint8_t *sender_protocol_address =
        reinterpret_cast<const uint8_t *>(this + 1) + hardware_address_len;
    return COMMONADDR(sender_protocol_address, protocol_address_len);
  }
  inline COMMONADDR get_protocol_destination() const {
    const uint8_t *receiver_protocol_address =
        reinterpret_cast<const uint8_t *>(this + 1) + 2 * hardware_address_len +
        protocol_address_len;
    return COMMONADDR(receiver_protocol_address, protocol_address_len);
  }
  std::deque<std::pair<std::wstring, my_ptree>>
  get_details(size_t offset = 0) const {
    std::deque<std::pair<std::wstring, my_ptree>> ret;
    PacketInterpreter::my_ptree tree;
    TREE_ADD(Hardware type,
             (this->hardware_type == 1)
                 ? QString("Ethernet (1)")
                 : QString("Unknown (%1)").arg(hardware_type),
             hardware_type);
    TREE_ADD(Protocol type, type_tag(this->protocol), protocol);
    TREE_ADD(Hardware Address Size, QString::number(hardware_address_len),
             hardware_address_len);
    TREE_ADD(Hardware Address Size, QString::number(protocol_address_len),
             protocol_address_len);

    QString op;
    switch (native_to_big(opcode)) {
    case ARP_REQUEST:
      op = "ARP Request";
      break;
    case ARP_REPLY:
      op = "ARP Reply";
      break;
    case RARP_REQUEST:
      op = "RARP Request";
      break;
    case RARP_REPLY:
      op = "RARP Reply";
      break;
    case DRARP_REQUEST:
      op = "DRARP Request";
      break;
    case DRARP_REPLY:
      op = "DRARP Reply";
      break;
    case InARP_REQUEST:
      op = "InARP Request";
      break;
    case InARP_REPLY:
      op = "InARP Reply";
      break;
    default:
      op = QString("Unknown opcode %1").arg(native_to_big(opcode));
    }
    TREE_ADD(OpCode, op, opcode);

    TREE_ADD3(Sender Hardware Address, addr2Str(get_physical_source()),
              sizeof(ARPHeader), hardware_address_len);
    TREE_ADD3(Sender IP Address, addr2Str(get_protocol_source()),
              sizeof(ARPHeader) + hardware_address_len, protocol_address_len);
    TREE_ADD3(Sender Hardware Address, addr2Str(get_physical_destination()),
              sizeof(ARPHeader) + hardware_address_len + protocol_address_len,
              hardware_address_len);
    TREE_ADD3(Sender IP Address, addr2Str(get_protocol_destination()),
              sizeof(ARPHeader) + 2 * hardware_address_len +
                  protocol_address_len,
              protocol_address_len);
    ret.emplace_front(L"Address Resolution Protocol", tree);
    return ret;
  }

  template <class T> const T *get_as() const { return nullptr; }
  inline size_t header_size() const {
    return (hardware_address_len + protocol_address_len) * 2 + sizeof(*this);
  }
};
class RARPPacket;
class SNMPPacket;
class IEEE802_1QPacket;
class IEEE802_1XPacket;
class EthernetPacket : public EthernetHeader {
public:
  inline const uint8_t *getload() const {
    return reinterpret_cast<const uint8_t *>(this + 1);
  }
  inline COMMONADDR get_source() const {
    return COMMONADDR(reinterpret_cast<const uint8_t *>(src),
                      static_cast<size_t>(6));
  }
  inline COMMONADDR get_destination() const {
    return COMMONADDR(reinterpret_cast<const uint8_t *>(dest),
                      static_cast<size_t>(6));
  }
  inline QString getDisplaySource() const {
    if (get_as<IPv4Packet>())
      return addr2Str(get_as<IPv4Packet>()->get_source());
    if (get_as<IPv6Packet>())
      return addr2Str(get_as<IPv6Packet>()->get_source());
    return addr2Str(get_source());
  }
  inline QString getDisplayDestination() const {
    if (get_as<IPv4Packet>())
      return addr2Str(get_as<IPv4Packet>()->get_destination());
    if (get_as<IPv6Packet>())
      return addr2Str(get_as<IPv6Packet>()->get_destination());
    return addr2Str(get_destination());
  }
  inline QStringList get_protocols() const {
    QStringList ret;
    if (get_as<IPv4Packet>())
      ret = get_as<IPv4Packet>()->get_protocols();
    if (get_as<IPv6Packet>())
      ret = get_as<IPv6Packet>()->get_protocols();
    if (get_as<ARPPacket>())
      ret = get_as<ARPPacket>()->get_protocols();

    ret.push_front("Ethernet");
    return ret;
  }
  inline QString get_comment() const {
    if (get_as<IPv4Packet>())
      return get_as<IPv4Packet>()->get_comment();
    if (get_as<IPv6Packet>())
      return get_as<IPv6Packet>()->get_comment();
    if (get_as<ARPPacket>())
      return get_as<ARPPacket>()->get_comment();
    return nullptr;
  }
  inline uint16_t get_type() const { return native_to_big(this->type); }

  std::deque<std::pair<std::wstring, my_ptree>>
  get_details(size_t offset = 0) const {
    std::deque<std::pair<std::wstring, my_ptree>> ret;
    PacketInterpreter::my_ptree tree;
    TREE_ADD(Destination, addr2Str(get_destination()), dest);
    TREE_ADD(Source, addr2Str(get_source()), src);
    TREE_ADD(Type, type_tag(this->type), type);
    if (get_as<IPv4Packet>())
      ret = get_as<IPv4Packet>()->get_details(offset + sizeof(EthernetHeader));
    if (get_as<IPv6Packet>())
      ret = get_as<IPv6Packet>()->get_details(offset + sizeof(EthernetHeader));
    if (get_as<ARPPacket>())
      ret = get_as<ARPPacket>()->get_details(offset + sizeof(EthernetHeader));
    ret.emplace_front(L"Ethernet", tree);
    return ret;
  }
  void fill_properties(
      std::deque<std::pair<std::wstring, my_ptree>> &properties) const;

  template <class T> const T *get_as() const {
    if (get_as<IPv4Packet>())
      return get_as<IPv4Packet>()->get_as<T>();
    if (get_as<IPv6Packet>())
      return get_as<IPv6Packet>()->get_as<T>();
    if (get_as<ARPPacket>())
      return get_as<ARPPacket>()->get_as<T>();
    return nullptr;
  }

  template <> const IPv4Packet *get_as() const {
    return (type == IPV4) ? reinterpret_cast<const IPv4Packet *>(getload())
                          : nullptr;
  }
  template <> const IPv6Packet *get_as() const {
    return (type == IPV6) ? reinterpret_cast<const IPv6Packet *>(getload())
                          : nullptr;
  }
  template <> const ARPPacket *get_as() const {
    return (type == ARP) ? reinterpret_cast<const ARPPacket *>(getload())
                         : nullptr;
  }
  template <> const RARPPacket *get_as() const {
    return (type == RARP) ? reinterpret_cast<const RARPPacket *>(getload())
                          : nullptr;
  }
  template <> const SNMPPacket *get_as() const {
    return (type == SNMP) ? reinterpret_cast<const SNMPPacket *>(getload())
                          : nullptr;
  }
  template <> const IEEE802_1QPacket *get_as() const {
    return (type == IEEE802_1Q)
               ? reinterpret_cast<const IEEE802_1QPacket *>(getload())
               : nullptr;
  }
  template <> const IEEE802_1XPacket *get_as() const {
    return (type == IEEE802_1X)
               ? reinterpret_cast<const IEEE802_1XPacket *>(getload())
               : nullptr;
  }
};
}; // namespace PacketInterpreter

#endif // PACKETINTERPRETER_H
