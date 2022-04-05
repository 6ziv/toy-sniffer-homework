#pragma once
#ifndef ADDRESSTRANSLATOR_HPP
#define ADDRESSTRANSLATOR_HPP
#include <cstdint>
#include <span>
#include <QString>
#include "endian.hpp"
namespace PacketInterpreter{
inline static QString Ipv42Str(const uint8_t* addr){
    QString str = QString::number(addr[0]);
    for(int i=1;i<4;i++)
        str+=QString(".")+QString::number(addr[i]);
    return str;
}
inline QString Mac2Str(const uint8_t* mac){
    QString str=QString::number(mac[0],16).rightJustified(2,'0');
    for(int i=1;i<6;i++)
    str+=QString(":")+QString::number(mac[i],16).rightJustified(2,'0');
    return str;
}
inline QString ipv6_uint16_tostr(const uint16_t& x){
    if(x==0)return QString("0");
    if(x < std::numeric_limits<uint8_t>::max())return QString::number(x,16).leftJustified(2,'0');
    return QString::number(x,16).leftJustified(4,'0');
}
inline QString Ipv62Str(const uint8_t* addr){
    uint16_t addr2[8];
    uint8_t longest_z_start  = 8;
    uint8_t longest_zero_seq = 0;
    uint8_t conseq_zeros     = 0;
    for(int i=0;i<8;i++){
        addr2[i]=native_to_big(reinterpret_cast<const uint16_t*>(addr)[i]);
        if(addr2[i]==0)conseq_zeros++;else conseq_zeros=0;
        if(conseq_zeros>longest_zero_seq){
            longest_z_start = i + 1 - conseq_zeros;
            longest_zero_seq = conseq_zeros;
        }
    }
    QString str;
    if(longest_zero_seq<2){
        str=ipv6_uint16_tostr(addr2[0]);
        for(int i=1;i<8;i++)str+=QString(":")+ipv6_uint16_tostr(addr2[i]);
    }
    else
    {
        if(longest_z_start){
            str=ipv6_uint16_tostr(addr2[0]);
            for(int i=1;i<longest_z_start;i++)
                str+=QString(":")+ipv6_uint16_tostr(addr2[i]);
        }
        str+="::";
        for(int i = longest_z_start+longest_zero_seq;i<8;i++){
            str+=ipv6_uint16_tostr(addr2[i]);
            if(i != 7)str+=":";
        }
    }
    return str;
}
typedef std::span<const uint8_t> COMMONADDR;
inline QString addr2Str(const COMMONADDR& x){
    if(x.size()==4)return Ipv42Str(x.data());
    if(x.size()==6)return Mac2Str(x.data());
    if(x.size()==16)return Ipv62Str(x.data());
    return QString();
}
}
#endif // ADDRESSTRANSLATOR_HPP
