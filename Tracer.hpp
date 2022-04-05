#ifndef TRACER_H
#define TRACER_H
#include "packetinterpreter.hpp"
#include <bit>
#include <cstdint>
#include <map>
#include <set>
#include <span_ext/span_ext.h>
#include <tuple>
#include <vector>
namespace Tracer {
using namespace PacketInterpreter;
typedef std::pair<std::span<const uint8_t>, uint16_t> address_and_port;
typedef std::array<address_and_port, 2> TraceKey;
typedef uint64_t HashedKey;
inline static struct {
  uint64_t cnt = 0;
  std::map<HashedKey, uint64_t> active_connections;
  std::map<uint64_t, uint8_t> connection_sides;
} tcp_tracer;

inline static std::map<HashedKey, uint64_t> udp_tracer;
inline HashedKey hash_key(const address_and_port &k1,
                          const address_and_port &k2) {
  uint8_t tmp_key[sizeof(HashedKey)] = {0};
  for (size_t i = 0; i < k1.first.size_bytes(); i++)
    tmp_key[i % sizeof(HashedKey)] ^=
        reinterpret_cast<const uint8_t *>(k1.first.data())[i];

  for (size_t i = 0; i < sizeof(k1.second); i++)
    tmp_key[(k1.first.size_bytes() + i) % sizeof(HashedKey)] ^=
        reinterpret_cast<const uint8_t *>(&k2.second)[i];
  return std::bit_cast<HashedKey>(tmp_key);
}
inline std::pair<HashedKey, bool> hash_key(const TraceKey &k) {
  if (k[0] < k[1])
    return std::make_pair(hash_key(k[0], k[1]), false);
  else
    return std::make_pair(hash_key(k[1], k[0]), true);
}
template <class IPPacket> uint64_t trace_udp_impl(const IPPacket *pkt) {
  auto key =
      hash_key(
          {std::make_pair(pkt->get_source(),
                          pkt->template get_as<UDPPacket>()->get_source_port()),
           std::make_pair(
               pkt->get_destination(),
               pkt->template get_as<UDPPacket>()->get_destination_port())})
          .first;
  if (udp_tracer.contains(key))
    return udp_tracer[key];
  else
    return udp_tracer[key] = udp_tracer.size();
}
uint64_t trace_udp(const PacketInterpreter::EthernetPacket *pkt) {
  if (pkt->get_as<IPv4Packet>())
    return trace_udp_impl(pkt->get_as<IPv4Packet>());
  if (pkt->get_as<IPv6Packet>())
    return trace_udp_impl(pkt->get_as<IPv6Packet>());
  return std::numeric_limits<uint64_t>::max();
}
template <class IPPacket> uint64_t trace_tcp_impl(const IPPacket *pkt) {
  auto key_and_side = hash_key(
      {std::make_pair(pkt->get_source(),
                      pkt->template get_as<TCPPacket>()->get_source_port()),
       std::make_pair(
           pkt->get_destination(),
           pkt->template get_as<TCPPacket>()->get_destination_port())});
  auto &key = key_and_side.first;
  uint8_t sidemask = key_and_side.second ? 1 : 2;
  if (tcp_tracer.active_connections.contains(key)) {
    uint64_t ret = tcp_tracer.active_connections[key];
    if ((tcp_tracer.connection_sides[ret] & sidemask) == 0) // should drop this.
    {
      return std::numeric_limits<uint64_t>::max();
    }
    if (pkt->template get_as<PacketInterpreter::TCPPacket>()->check_flag(
            PacketInterpreter::TCPPacket::TCPFLAG::FIN) ||
        pkt->template get_as<PacketInterpreter::TCPPacket>()->check_flag(
            PacketInterpreter::TCPPacket::TCPFLAG::RST)) {
      tcp_tracer.connection_sides[ret] &= (~sidemask); // close this side.
      if (tcp_tracer.connection_sides[ret] == 0) {
        tcp_tracer.active_connections.erase(key);
        tcp_tracer.connection_sides.erase(ret);
      }
    }
    return ret;
  } else {
    tcp_tracer.active_connections[key] = tcp_tracer.cnt;
    tcp_tracer.connection_sides[tcp_tracer.cnt] = 3;
    tcp_tracer.cnt++;
    return tcp_tracer.active_connections[key];
  }
}
uint64_t trace_tcp(const PacketInterpreter::EthernetPacket *pkt) {
  if (pkt->get_as<IPv4Packet>())
    return trace_tcp_impl(pkt->get_as<IPv4Packet>());
  if (pkt->get_as<IPv6Packet>())
    return trace_tcp_impl(pkt->get_as<IPv6Packet>());
  return std::numeric_limits<uint64_t>::max();
}
uint64_t trace(const PacketInterpreter::EthernetPacket *pkt) {
  if (pkt->get_as<PacketInterpreter::TCPPacket>())
    return trace_tcp(pkt);
  if (pkt->get_as<PacketInterpreter::UDPPacket>())
    return trace_udp(pkt);
  return std::numeric_limits<uint64_t>::max();
}
} // namespace Tracer
#endif // TRACER_H
