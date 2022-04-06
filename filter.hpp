#pragma once
#ifndef FILTER_HPP
#define FILTER_HPP
#include <cstdint>
#include <string>
#include <variant>
#include <optional>
#include <map>
#include <bitset>
#include <QtMath>
#include "filterhelper.hpp"
#include "packetinterpreter.hpp"
#include "fieldnames.hpp"
namespace Filter{
using namespace PacketInterpreter;
const std::string known_protocols[] = {"ethernet", "ipv4", "ipv6",
                                       "arp",      "tcp",  "udp"};
const std::string global_fields[] = {"no","time"};

typedef std::variant<std::monostate,std::vector<uint8_t>,uint64_t,bool> FilterValue;

inline std::vector<uint8_t> to_vec(const COMMONADDR& addr){
    return std::vector<uint8_t>(addr.data(),addr.data()+addr.size());
}

class FilterContext
{
    template<class T>
    inline FilterValue lookup(uint8_t type);

    template<>
    inline FilterValue lookup<EthernetPacket>(uint8_t type){
        if(ethernet_header==nullptr)return std::monostate();
        switch(type){
        case 2:return true;
        case 3:return to_vec(ethernet_header->get_destination());
        case 4:return to_vec(ethernet_header->get_source());
        case 5:return ethernet_header->get_type();
        }
        return std::monostate();
    }
    template<>
    inline FilterValue lookup<ARPPacket>(uint8_t type){
        if(arp_header==nullptr)return std::monostate();
        switch(type){
        case 6:return true;
        case 7:return native_to_big(arp_header->hardware_type);
        case 8:return native_to_big(arp_header->protocol);
        case 9:return arp_header->hardware_address_len;
        case 10:return arp_header->protocol_address_len;
        case 11:return native_to_big(arp_header->opcode);
        case 12:return to_vec(arp_header->get_physical_source());
        case 13:return to_vec(arp_header->get_protocol_source());
        case 14:return to_vec(arp_header->get_physical_destination());
        case 15:return to_vec(arp_header->get_protocol_destination());
        }
        return std::monostate();
    }
    template<>
    inline FilterValue lookup<IPv4Packet>(uint8_t type){
        if(ipv4_header==nullptr)return std::monostate();
        switch(type){
        case 16:return true;
        case 17:return ipv4_header->get_version();
        case 18:return ipv4_header->header_size();
        case 19:return static_cast<uint8_t>(ipv4_header->tos >> 2);
        case 20:return static_cast<uint8_t>(ipv4_header->tos & 3);
        case 21:return ipv4_header->total_size();
        case 22:return static_cast<uint32_t>(ipv4_header->total_size()-ipv4_header->header_size());
        case 23:return native_to_big(ipv4_header->identification);
        case 24:return ipv4_header->flags();
        case 25:return ipv4_header->DF();
        case 26:return ipv4_header->MF();
        case 27:return ipv4_header->ttl;
        case 28:return ipv4_header->proto;
        case 29:return native_to_big(ipv4_header->crc);
        case 30:return to_vec(ipv4_header->get_source());
        case 31:return to_vec(ipv4_header->get_destination());
        }
        return std::monostate();
    }
    template<>
    inline FilterValue lookup<IPv6Packet>(uint8_t type){
        if(ipv6_header==nullptr)return std::monostate();
        switch(type){
        case 32:return true;
        case 33:return (ipv6_header->tag1 >> 28) & 0x0F;
        case 34:return (native_to_big(ipv6_header->tag1) >> 20) & 0xFF;
        case 35:return (native_to_big(ipv6_header->tag1) >> 22) & 0x3F;
        case 36:return (native_to_big(ipv6_header->tag1) >> 20) & 3;
        case 37:return ipv6_header->tag1 & 0xFFFFF;
        case 38:return native_to_big(ipv6_header->payload_len);
        case 39:return ipv6_header->header_size() + native_to_big(ipv6_header->payload_len);
        case 40:return ipv6_header->next_header;
        case 41:return ipv6_header->hop;
        case 42:return to_vec(ipv6_header->get_source());
        case 43:return to_vec(ipv6_header->get_destination());
        }
        return std::monostate();
    }
    template<>
    inline FilterValue lookup<UDPPacket>(uint8_t type){
        if(udp_header==nullptr)return std::monostate();
        switch(type){
        case 44:return true;
        case 45:return udp_header->get_source_port();
        case 46:return udp_header->get_destination_port();
        case 47:return udp_header->total_len();
        case 48:return udp_header->total_len()-udp_header->header_size();
        case 49:return native_to_big(udp_header->crc);
        }
        return std::monostate();
    }
    template<>
    inline FilterValue lookup<TCPPacket>(uint8_t type){
        if(tcp_header==nullptr)return std::monostate();
        switch(type){
        case 50:return true;
        case 51:return tcp_header->get_source_port();
        case 52:return tcp_header->get_destination_port();
        case 53:return tcp_header->header_size();
        case 54:return native_to_big(tcp_header->tags);
        case 55:
        case 56:
        case 57:
        case 58:
        case 59:
        case 60:
        case 61:
        case 62:
        case 63:
        case 64:
        case 65:
            return tcp_header->check_flag(static_cast<TCPPacket::TCPFLAG>(type - 55));
        case 66:return native_to_big(tcp_header->window_size);
        case 67:return native_to_big(tcp_header->checksum);
        case 68:return native_to_big(tcp_header->urgent_pointer);
        }
        return std::monostate();
    }
    template<>
    inline FilterValue lookup<ICMPPacket>(uint8_t type){
        if(icmp_header==nullptr)return std::monostate();
        switch(type){
        case 73:return true;
        case 74:return icmp_header->type;
        case 75:return icmp_header->subtype;
        case 76:return native_to_big(icmp_header->checksum);
        case 77:return native_to_big(icmp_header->rest_of_header);
        }
        return std::monostate();
    }
    const ARPPacket* arp_header=nullptr;
    const IPv4Packet* ipv4_header=nullptr;
    const IPv6Packet* ipv6_header=nullptr;
    const TCPPacket* tcp_header=nullptr;
    const UDPPacket* udp_header=nullptr;
    const ICMPPacket* icmp_header=nullptr;
    const EthernetPacket* ethernet_header=nullptr;
    std::map<uint8_t,FilterValue> data;

    uint64_t no,timestamp;
public:
    FilterContext(const EthernetPacket* p,uint64_t id,uint64_t ts/*,const std::bitset<count_fieldnames>& mask*/):
        ethernet_header(p),no(id),timestamp(ts)
    {
        arp_header = ethernet_header->get_as<ARPPacket>();
        ipv4_header = ethernet_header->get_as<IPv4Packet>();
        ipv6_header = ethernet_header->get_as<IPv6Packet>();
        tcp_header = ethernet_header->get_as<TCPPacket>();
        udp_header = ethernet_header->get_as<UDPPacket>();
        icmp_header = ethernet_header->get_as<ICMPPacket>();
    /*
        if(mask[0])data[0]=id;
        if(mask[1])data[1]=ts;

        for(int i=2;i<6;i++)if(mask[i])data.emplace(i,lookup<EthernetPacket>(i));
        if(arp_header)for(int i=6;i<16;i++)if(mask[i])data.emplace(i,lookup<ARPPacket>(i));
        if(ipv4_header)for(int i=16;i<32;i++)if(mask[i])data.emplace(i,lookup<IPv4Packet>(i));
        if(ipv6_header)for(int i=32;i<44;i++)if(mask[i])data.emplace(i,lookup<IPv6Packet>(i));
        if(udp_header)for(int i=44;i<50;i++)if(mask[i])data.emplace(i,lookup<UDPPacket>(i));
        if(tcp_header)for(int i=50;i<69;i++)if(mask[i])data.emplace(i,lookup<TCPPacket>(i));
        */
    };
    inline FilterValue getVal(uint8_t type)
    {
        if(type==0)return no;
        if(type==1)return timestamp;
        if(type<6)return lookup<EthernetPacket>(type);
        if(type<16)return lookup<ARPPacket>(type);
        if(type<32)return lookup<IPv4Packet>(type);
        if(type<44)return lookup<IPv6Packet>(type);
        if(type<50)return lookup<UDPPacket>(type);
        if(type<69)return lookup<TCPPacket>(type);
        if(type==69)return (ethernet_header->get_as<RARPPacket>()!=nullptr);
        if(type==70)return (ethernet_header->get_as<SNMPPacket>()!=nullptr);
        if(type==71)return (ethernet_header->get_as<IEEE802_1QPacket>()!=nullptr);
        if(type==72)return (ethernet_header->get_as<IEEE802_1XPacket>()!=nullptr);
        if(type==73)return (ethernet_header->get_as<ICMPPacket>()!=nullptr);
        if(type==73)return (ethernet_header->get_as<ICMPPacket>()!=nullptr);
        if(type<78)return lookup<ICMPPacket>(type);
        return std::monostate();
/*
 * this should be faster in theory
 * but seems I've made a faulty implementation
 * so finally I decided not to cache anything.
        qDebug()<<"GETVAL:";
        if(!data.contains(type))return std::monostate();
        qDebug()<<std::get<std::vector<uint8_t>>(this->data[type]).size();
        for(auto ch:std::get<std::vector<uint8_t>>(this->data[type]))
            qDebug()<<ch;
        return this->data[type];*/
    }
};
struct FValue
{
    enum VALUE_TYPE:uint8_t
    {
        ADDRESS = 0,
        NUMBER = 1,
        BOOLEAN = 2,
        ERROR_TYPE = 3
    };
    inline VALUE_TYPE value_type()const{
        if(val.index()==0){
            switch(std::get<0>(val)){
            case 2:case 6:case 25:case 26:case 32:case 44:case 55:case 56:case 57:
            case 58:case 59:case 60:case 61:case 62:case 63:case 64:case 65:
                return BOOLEAN;
            case 3:case 4:case 12:case 13:case 14:case 15:case 30:case 31:case 42:case 43:
                return ADDRESS;
            default:
                return NUMBER;
            }
        }else{
            return static_cast<VALUE_TYPE>((std::get<1>(val).index()+3)%4);
        }
    }
    inline bool is_property()const{
        return val.index()==0;
    }
    std::variant<uint8_t,FilterValue> val;
    inline FilterValue get_value(FilterContext *ctx)const{
        if(is_property())return ctx->getVal(std::get<0>(val));
        else return std::get<1>(val);
    }
};
struct AbstractFilter{
    //virtual void prepare(std::bitset<69> &x)const =0;
    virtual bool filter(FilterContext *ctx)const = 0;
    virtual ~AbstractFilter(){}
};
struct AndFilter:AbstractFilter{
    std::vector<AbstractFilter *>sub_filters;
    /*virtual void prepare(std::bitset<69> &x)const override final{
        for(auto sub_filter:sub_filters)sub_filter->prepare(x);
    }*/
    virtual bool filter(FilterContext *ctx)const override final{
        for(auto sub_filter:sub_filters){
            if(!sub_filter->filter(ctx))return false;
        }
        return true;
    }
    ~AndFilter()override{for(auto sub_filter:sub_filters){delete sub_filter;}}
};
struct OrFilter:AbstractFilter{
    std::vector<AbstractFilter *>sub_filters;
    /*virtual void prepare(std::bitset<69> &x)const override final{
        for(auto sub_filter:sub_filters)sub_filter->prepare(x);
    }*/
    virtual bool filter(FilterContext *ctx)const override final{
        for(auto sub_filter:sub_filters){
            if(sub_filter->filter(ctx))return true;
        }
        return false;
    }
    ~OrFilter()override{for(auto sub_filter:sub_filters){delete sub_filter;}}
};
template<bool b>
struct ConstantFilter:AbstractFilter{
    //virtual void prepare(std::bitset<69> &)const override final{}
    virtual bool filter(FilterContext *)const override final{
        return b;
    }
};
struct BoolFilter:AbstractFilter{
    FValue op;
    /*virtual void prepare(std::bitset<69> &x)const override final{
        if(op.is_property())x.set(std::get<0>(op.val));
    }*/
    virtual bool filter(FilterContext *ctx)const override final{
        if(!op.is_property()){
            return((std::get<1>(op.val).index()==3 && std::get<3>(std::get<1>(op.val)))==true);
        }
        if(ctx->getVal(std::get<0>(op.val)).index()!=3)return false;
        else return std::get<3>(ctx->getVal(std::get<0>(op.val)));
    }
};
struct CompareFilter:AbstractFilter{
    enum COMPARE_OP{
        EQ=0,NE=1,LE=2,GE=3,LT=4,GT=5
    };
    COMPARE_OP operation;
    FValue op[2];
    /*virtual void prepare(std::bitset<69> &x)const override final{
        if(op[0].is_property())x.set(std::get<0>(op[0].val));
        if(op[1].is_property())x.set(std::get<0>(op[1].val));
    }*/
    virtual bool filter(FilterContext *ctx)const override final{
        if(op[0].value_type()!=op[1].value_type())
            return false;
        switch(operation){
        case EQ:return op[0].get_value(ctx)==op[1].get_value(ctx);
        case NE:return op[0].get_value(ctx)!=op[1].get_value(ctx);
        case LE:return op[0].get_value(ctx)<=op[1].get_value(ctx);
        case GE:return op[0].get_value(ctx)>=op[1].get_value(ctx);
        case LT:return op[0].get_value(ctx)< op[1].get_value(ctx);
        case GT:return op[0].get_value(ctx)> op[1].get_value(ctx);
        }
        return false;
    }
};

inline uint8_t compile_string(std::string str){
    if(name_to_id.contains(str))
        return name_to_id[QString::fromStdString(str).toLower().toStdString()];
    else return 255;
}
inline bool initValue(const filter::ast::ast_value& r, FValue& v){
    if(r.get().which()==0){
        qDebug()<<"init constant id = "<< boost::get<filter::ast::constant_value>(r.get()).get().which();
        FilterValue cv;
        switch(boost::get<filter::ast::constant_value>(r.get()).get().which()){
        case 0:cv=boost::get<filter::ast::address>(boost::get<filter::ast::constant_value>(r.get()).get());break;
        case 1:cv=boost::get<uint64_t>(boost::get<filter::ast::constant_value>(r.get()).get());break;
        case 2:cv=static_cast<uint64_t>(qFloor(boost::get<double>(boost::get<filter::ast::constant_value>(r.get()).get()) * 1000000));break;
        case 3:cv=boost::get<bool>(boost::get<filter::ast::constant_value>(r.get()).get());break;
        }
        v.val=cv;
    }else{
        std::string path = boost::get<filter::ast::property_path>(r.get());
        auto compiled = compile_string(path);
        if(compiled==255)return false;
        v.val = compiled;
    }
    return true;
}
inline AbstractFilter* createFilter(const filter::ast::binop& r){
    auto filter = new CompareFilter;
    if(r.tag=="==")filter->operation=filter->EQ;
    if(r.tag=="!=")filter->operation=filter->NE;
    if(r.tag==">=")filter->operation=filter->GE;
    if(r.tag=="<=")filter->operation=filter->LE;
    if(r.tag==">") filter->operation=filter->GT;
    if(r.tag=="<") filter->operation=filter->LT;
    bool ok=
    initValue(r.op1,filter->op[0]) &&
    initValue(r.op2,filter->op[1]);
    if(!ok){
        delete filter;
        return nullptr;
    }
    return filter;
}
inline AbstractFilter* createFilter(const filter::ast::filter_rule& r);
inline AbstractFilter* createFilter(const filter::ast::b_expr& r){
    if(r.get().which()==0)return createFilter(boost::get<filter::ast::binop>(r.get()));
    if(r.get().which()==1)return createFilter(boost::get<x3::forward_ast<filter::ast::filter_rule>>(r.get()).get());
    if(r.get().which()==2){
        auto p = new BoolFilter;
        auto compiled = compile_string(boost::get<filter::ast::property_path>(r.get()));
        p->op.val = compiled;
        if(compiled==255){
            delete p;
            return nullptr;
        }
        return p;
    }
    return nullptr;
}
inline AbstractFilter* createFilter(const filter::ast::clousure_value& r){
    if(r.size()==0)return new ConstantFilter<true>;
    if(r.size()==1)return createFilter(r[0]);
    auto ret = new AndFilter;
    for(const auto& x:r) ret->sub_filters.emplace_back(createFilter(x));
    return ret;
}
inline AbstractFilter* createFilter(const filter::ast::filter_rule& r){
    if(r.size()==0)return new ConstantFilter<false>;
    if(r.size()==1)return createFilter(r[0]);
    auto ret = new OrFilter;
    for(const auto& x:r){
        auto new_item =createFilter(x);
        if(new_item==nullptr){
            delete ret;
            return nullptr;
        }
        ret->sub_filters.emplace_back(new_item);
    }
    return ret;
}

inline AbstractFilter* compile(const std::string code){
    auto& grammar = filter::filter;
    auto iter = code.begin();

    boost::spirit::x3::ascii::space_type space;
    filter::ast::filter_rule rule;
    bool r = phrase_parse(iter, code.end(), grammar, space,rule);
    if (r && iter == code.end()){
        return createFilter(rule);
    }else{
        return nullptr;
    }
}
}
#endif // FILTER_HPP
