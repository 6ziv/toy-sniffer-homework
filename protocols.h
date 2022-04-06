#ifndef PROTOCOLS_H
#define PROTOCOLS_H
#include <QString>
#include <stdint.h>
QString get_protocol_name(uint8_t id);
QString get_protocol_description(uint8_t id);
QString get_tcp_option_name(uint8_t id);
QString get_icmp_typename(uint8_t type);
#endif // PROTOCOLS_H
