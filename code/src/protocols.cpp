#include "protocols.h"
#include <string_view>
// From https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
constexpr std::pair<std::string_view, std::string_view> protocols[] = {
    {"HOPOPT", "IPv6 Hop-by-Hop Option"},
    {"ICMP", "Internet Control Message"},
    {"IGMP", "Internet Group Management"},
    {"GGP", "Gateway-to-Gateway"},
    {"IPv4", "IPv4 encapsulation"},
    {"ST", "Stream"},
    {"TCP", "Transmission Control"},
    {"CBT", "CBT"},
    {"EGP", "Exterior Gateway Protocol"},
    {"IGP", "any private interior gateway (used by Cisco for their IGRP)"},
    {"BBN-RCC-MON", "BBN RCC Monitoring"},
    {"NVP-II", "Network Voice Protocol"},
    {"PUP", "PUP"},
    {"ARGUS (deprecated)", "ARGUS"},
    {"EMCON", "EMCON"},
    {"XNET", "Cross Net Debugger"},
    {"CHAOS", "Chaos"},
    {"UDP", "User Datagram"},
    {"MUX", "Multiplexing"},
    {"DCN-MEAS", "DCN Measurement Subsystems"},
    {"HMP", "Host Monitoring"},
    {"PRM", "Packet Radio Measurement"},
    {"XNS-IDP", "XEROX NS IDP"},
    {"TRUNK-1", "Trunk-1"},
    {"TRUNK-2", "Trunk-2"},
    {"LEAF-1", "Leaf-1"},
    {"LEAF-2", "Leaf-2"},
    {"RDP", "Reliable Data Protocol"},
    {"IRTP", "Internet Reliable Transaction"},
    {"ISO-TP4", "ISO Transport Protocol Class 4"},
    {"NETBLT", "Bulk Data Transfer Protocol"},
    {"MFE-NSP", "MFE Network Services Protocol"},
    {"MERIT-INP", "MERIT Internodal Protocol"},
    {"DCCP", "Datagram Congestion Control Protocol"},
    {"3PC", "Third Party Connect Protocol"},
    {"IDPR", "Inter-Domain Policy Routing Protocol"},
    {"XTP", "XTP"},
    {"DDP", "Datagram Delivery Protocol"},
    {"IDPR-CMTP", "IDPR Control Message Transport Proto"},
    {"TP++", "TP++ Transport Protocol"},
    {"IL", "IL Transport Protocol"},
    {"IPv6", "IPv6 encapsulation"},
    {"SDRP", "Source Demand Routing Protocol"},
    {"IPv6-Route", "Routing Header for IPv6"},
    {"IPv6-Frag", "Fragment Header for IPv6"},
    {"IDRP", "Inter-Domain Routing Protocol"},
    {"RSVP", "Reservation Protocol"},
    {"GRE", "Generic Routing Encapsulation"},
    {"DSR", "Dynamic Source Routing Protocol"},
    {"BNA", "BNA"},
    {"ESP", "Encap Security Payload"},
    {"AH", "Authentication Header"},
    {"I-NLSP", "Integrated Net Layer Security TUBA"},
    {"SWIPE (deprecated)", "IP with Encryption"},
    {"NARP", "NBMA Address Resolution Protocol"},
    {"MOBILE", "IP Mobility"},
    {"TLSP",
     "Transport Layer Security Protocol using Kryptonet key management"},
    {"SKIP", "SKIP"},
    {"IPv6-ICMP", "ICMP for IPv6"},
    {"IPv6-NoNxt", "No Next Header for IPv6"},
    {"IPv6-Opts", "Destination Options for IPv6"},
    {"", "any host internal protocol"},
    {"CFTP", "CFTP"},
    {"", "any local network"},
    {"SAT-EXPAK", "SATNET and Backroom EXPAK"},
    {"KRYPTOLAN", "Kryptolan"},
    {"RVD", "MIT Remote Virtual Disk Protocol"},
    {"IPPC", "Internet Pluribus Packet Core"},
    {"", "any distributed file system"},
    {"SAT-MON", "SATNET Monitoring"},
    {"VISA", "VISA Protocol"},
    {"IPCV", "Internet Packet Core Utility"},
    {"CPNX", "Computer Protocol Network Executive"},
    {"CPHB", "Computer Protocol Heart Beat"},
    {"WSN", "Wang Span Network"},
    {"PVP", "Packet Video Protocol"},
    {"BR-SAT-MON", "Backroom SATNET Monitoring"},
    {"SUN-ND", "SUN ND PROTOCOL-Temporary"},
    {"WB-MON", "WIDEBAND Monitoring"},
    {"WB-EXPAK", "WIDEBAND EXPAK"},
    {"ISO-IP", "ISO Internet Protocol"},
    {"VMTP", "VMTP"},
    {"SECURE-VMTP", "SECURE-VMTP"},
    {"VINES", "VINES"},
    {"TTP/IPTM",
     "Transaction Transport Protocol/Internet Protocol Traffic Manager"},
    {"NSFNET-IGP", "NSFNET-IGP"},
    {"DGP", "Dissimilar Gateway Protocol"},
    {"TCF", "TCF"},
    {"EIGRP", "EIGRP"},
    {"OSPFIGP", "OSPFIGP"},
    {"Sprite-RPC", "Sprite RPC Protocol"},
    {"LARP", "Locus Address Resolution Protocol"},
    {"MTP", "Multicast Transport Protocol"},
    {"AX.25", "AX.25 Frames"},
    {"IPIP", "IP-within-IP Encapsulation Protocol"},
    {"MICP (deprecated)", "Mobile Internetworking Control Pro."},
    {"SCC-SP", "Semaphore Communications Sec. Pro."},
    {"ETHERIP", "Ethernet-within-IP Encapsulation"},
    {"ENCAP", "Encapsulation Header"},
    {"", "any private encryption scheme"},
    {"GMTP", "GMTP"},
    {"IFMP", "Ipsilon Flow Management Protocol"},
    {"PNNI", "PNNI over IP"},
    {"PIM", "Protocol Independent Multicast"},
    {"ARIS", "ARIS"},
    {"SCPS", "SCPS"},
    {"QNX", "QNX"},
    {"A/N", "Active Networks"},
    {"IPComp", "IP Payload Compression Protocol"},
    {"SNP", "Sitara Networks Protocol"},
    {"Compaq-Peer", "Compaq Peer Protocol"},
    {"IPX-in-IP", "IPX in IP"},
    {"VRRP", "Virtual Router Redundancy Protocol"},
    {"PGM", "PGM Reliable Transport Protocol"},
    {"", "any 0-hop protocol"},
    {"L2TP", "Layer Two Tunneling Protocol"},
    {"DDX", "D-II Data Exchange (DDX)"},
    {"IATP", "Interactive Agent Transfer Protocol"},
    {"STP", "Schedule Transfer Protocol"},
    {"SRP", "SpectraLink Radio Protocol"},
    {"UTI", "UTI"},
    {"SMP", "Simple Message Protocol"},
    {"SM (deprecated)", "Simple Multicast Protocol"},
    {"PTP", "Performance Transparency Protocol"},
    {"ISIS over IPv4", ""},
    {"FIRE", ""},
    {"CRTP", "Combat Radio Transport Protocol"},
    {"CRUDP", "Combat Radio User Datagram"},
    {"SSCOPMCE", ""},
    {"IPLT", ""},
    {"SPS", "Secure Packet Shield"},
    {"PIPE", "Private IP Encapsulation within IP"},
    {"SCTP", "Stream Control Transmission Protocol"},
    {"FC", "Fibre Channel"},
    {"RSVP-E2E-IGNORE", ""},
    {"Mobility Header", ""},
    {"UDPLite", ""},
    {"MPLS-in-IP", ""},
    {"manet", "MANET Protocols"},
    {"HIP", "Host Identity Protocol"},
    {"Shim6", "Shim6 Protocol"},
    {"WESP", "Wrapped Encapsulating Security Payload"},
    {"ROHC", "Robust Header Compression"},
    {"Ethernet", "Ethernet"},
    {"", "Unassigned"},
    {"", "Use for experimentation and testing"},
    {"", "Use for experimentation and testing"},
    {"Reserved", ""}};
inline uint8_t translate_protocol_id(uint8_t id) {
  if (id < 144)
    return id;
  if (id < 253)
    return 144;
  return id - 108;
}
QString get_protocol_name(uint8_t id) {
  uint8_t realid = translate_protocol_id(id);
  if (protocols[realid].first.empty())
    return QString::number(id);
  return QString::fromLocal8Bit(protocols[realid].first.data(),
                                protocols[realid].first.size());
}
QString get_protocol_description(uint8_t id) {
  uint8_t realid = translate_protocol_id(id);
  if (protocols[realid].second.empty())
    return QString("[no description]");
  return QString::fromLocal8Bit(protocols[realid].second.data(),
                                protocols[realid].second.size());
}

constexpr std::string_view tcp_option_tags[] = {
    "End of Option List",
    "No-Operation",
    "Maximum Segment Size",
    "Window Scale",
    "SACK Permitted",
    "SACK",
    "Echo",
    "Echo Reply",
    "Timestamps",
    "Partial Order Connection Permitted",
    "Partial Order Service Profile",
    "CC",
    "CC.NEW",
    "CC.ECHO",
    "TCP Alternate Checksum Request",
    "TCP Alternate Checksum Data",
    "Skeeter",
    "Bubba",
    "Trailer Checksum Option",
    "MD5 Signature Option",
    "SCPS Capabilities",
    "Selective Negative Acknowledgements",
    "Record Boundaries",
    "Corruption experienced",
    "SNAP",
    "Unassigned",
    "TCP Compression Filter",
    "Quick-Start Response",
    "User Timeout Option",
    "TCP Authentication Option",
    "Multipath TCP",
    "TCP Fast Open Cookie",
    "Encryption Negotiation",
    "RFC3692-style Experiment 1",
    "RFC3692-style Experiment 2"};
QString get_tcp_option_name(uint8_t id) {
  if (id < 31)
    return QString::fromLocal8Bit(tcp_option_tags[id].data(),
                                  tcp_option_tags[id].size());
  if (id == 34)
    return QString::fromLocal8Bit(tcp_option_tags[31].data(),
                                  tcp_option_tags[31].size());
  if (id == 69)
    return QString::fromLocal8Bit(tcp_option_tags[32].data(),
                                  tcp_option_tags[32].size());
  if (id == 253)
    return QString::fromLocal8Bit(tcp_option_tags[33].data(),
                                  tcp_option_tags[33].size());
  if (id == 254)
    return QString::fromLocal8Bit(tcp_option_tags[34].data(),
                                  tcp_option_tags[34].size());
  return "Reserved";
}
constexpr std::string_view icmp_typenames[] =
{
    "Echo reply","","","Destination Unreachable","Source Quench","Redirect Message","Alternate Host Address","","Echo Request","Router Advertisement",
    "Router Solicitation","Time Exceeded","Parameter Problem:Bad IP Header","Timestamp","Timestamp Reply","Information Request","Information Reply",
    "Address Mask Request","Address Mask Reply",
    "Traceroute","Datagram Conversion Error","Mobile Host Redirect","Where Are You","Here I Am","Mobile Registration Request","Mobile Registration Reply",
    "Domain Name Request","Domain Name Reply","Simple Key-Management for Internet Protocol","Photuris, Security failures","experimental mobility protocol",
    "Extended Echo Request","Extended Echo Reply"
};
QString get_icmp_typename(uint8_t type){
    QString ret;
    if(type<19)ret= QString::fromLocal8Bit(icmp_typenames[type].data(),icmp_typenames[type].size());
    else if(type>29 && type<44)return ret=QString::fromLocal8Bit(icmp_typenames[type-11].data(),icmp_typenames[type-11].size());
    if(ret.isEmpty())ret=QString("ICMP Type %1").arg(static_cast<int>(type));
    return ret;
}
