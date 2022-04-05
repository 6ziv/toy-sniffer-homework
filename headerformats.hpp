#pragma once
#ifndef HEADERFORMATS_HPP
#define HEADERFORMATS_HPP
#include <cstdint>
#include "endian.hpp"
#include <QString>
namespace PacketInterpreter
{
    typedef struct EthernetHeader
    {
        unsigned char dest[6];
        unsigned char src[6];
        uint16_t type;
    } EthernetHeader;

    // From Npcap turtorial.
    typedef struct IPv4Header
    {
        uint8_t  ver_ihl; // Version (4 bits) + IP header length (4 bits)
        uint8_t  tos;     // Type of service
        uint16_t tlen;    // Total length
        uint16_t identification; // Identification
        uint16_t flags_fo; // Flags (3 bits) + Fragment offset (13 bits)
        uint8_t  ttl;      // Time to live
        uint8_t  proto;    // Protocol
        uint16_t crc;      // Header checksum
        uint8_t  saddr[4]; // Source address
        uint8_t  daddr[4]; // Destination address
    }Ipv4Header;

    typedef struct IPv6Header
    {
        uint32_t tag1;              //4-bit version + 8-bit traffic class + 20-bit flow label
        uint16_t payload_len;       //Payload length
        uint8_t  next_header;       //Upper header (or extension)
        uint8_t  hop;               //Hop limit
        uint8_t  saddr[16];         //Source address
        uint8_t  daddr[16];         //Destination address
    }IPv6Header;

    typedef struct{
        uint16_t src_port;
        uint16_t dest_port;
        uint16_t len;           //data and this header.
        uint16_t crc;           //optional. checksum and padding
    }UDPHeader;

    typedef struct{
        uint16_t src_port;
        uint16_t dest_port;
        uint32_t seq;
        uint32_t ack;
        uint16_t tags;          //4-bit header length(in 4 bytes) + 3-bit reserved(unused) + 9-bit flags(NS,CWR,ECE,URG,ACK,PSH,RST,SYN,FIN)
        uint16_t window_size;
        uint16_t checksum;
        uint16_t urgent_pointer;//+1 = how many bytes are urgent.
    }TCPHeader;

    typedef struct
    {
        uint16_t hardware_type;
        uint16_t protocol;
        uint8_t  hardware_address_len;
        uint8_t  protocol_address_len;
        uint16_t opcode;
    }ARPHeader;

    constexpr uint16_t IPV4 = native_to_big<uint16_t>(0x0800);
    constexpr uint16_t IPV6 = native_to_big<uint16_t>(0x86DD);
    constexpr uint16_t IEEE802_1Q = native_to_big<uint16_t>(0x8100);
    constexpr uint16_t IEEE802_1X = native_to_big<uint16_t>(0x888E);
    constexpr uint16_t ARP = native_to_big<uint16_t>(0x0806);
    constexpr uint16_t RARP = native_to_big<uint16_t>(0x8035);
    constexpr uint16_t SNMP = native_to_big<uint16_t>(0x814C);

    constexpr uint8_t ICMP    =   1;
    constexpr uint8_t TCP     =   6;
    constexpr uint8_t UDP     =   17;

    inline QString type_tag(uint16_t protocol){
        switch(protocol){
            case IPV4:return "IPv4";
            case IPV6:return "IPv6";
            case ARP: return "ARP";
            case RARP:return "RARP";
            case SNMP:return "SNMP";
            case IEEE802_1Q:return "IEEE802.1Q";
            case IEEE802_1X:return "IEEE802.1X";
            default:return QString("Unknown type:")+QString::number(native_to_big<uint16_t>(protocol));
        }
    }
}
#endif // HEADERFORMATS_H
