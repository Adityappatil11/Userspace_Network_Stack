#ifndef PROTOCOLHEADERS_H
#define PROTOCOLHEADERS_H

#include <cstdint>
#include <array>

#pragma pack(push, 1)
struct EthernetHeader {
    std::array<uint8_t, 6> dest_mac;
    std::array<uint8_t, 6> src_mac;
    uint16_t ether_type;
};

struct IPV4Header {
    uint8_t  version_ihl;
    uint8_t  tos;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_fo;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dest_ip;
};

struct IPV6Header {
    uint32_t ver_tc_fl;
    uint16_t payload_len;
    uint8_t  next_header;
    uint8_t  hop_limit;
    std::array<uint8_t, 16> src_ip;
    std::array<uint8_t, 16> dest_ip;
};

struct ARPHeader {
    uint16_t hw_type;
    uint16_t proto_type;
    uint8_t  hw_addr_len;
    uint8_t  proto_addr_len;
    uint16_t opcode;
    std::array<uint8_t, 6> sender_mac;
    uint32_t sender_ip;
    std::array<uint8_t, 6> target_mac;
    uint32_t target_ip;
};

struct ICMPHeader {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint16_t id;
    uint16_t sequence;
};
#pragma pack(pop)

uint16_t calculate_checksum(void* b, int len);

#endif