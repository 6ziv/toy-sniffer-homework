#ifndef PROTOCOLS_H
#define PROTOCOLS_H
#include <stdint.h>
#include <QString>
QString get_protocol_name(uint8_t id);
QString get_protocol_description(uint8_t id);
QString get_tcp_option_name(uint8_t id);
#endif // PROTOCOLS_H
