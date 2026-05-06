#include "networkstack.h"
#include <iostream>
#include <cstring>
#include <vector>

uint16_t calculate_checksum(void* b, int len) {
    uint32_t sum = 0;
    uint16_t* ptr = static_cast<uint16_t*>(b);
    while (len > 1) { sum += *ptr++; len -= 2; }
    if (len > 0) sum += *reinterpret_cast<uint8_t*>(ptr);
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return ~static_cast<uint16_t>(sum);
}

void NetworkStack::handle_packet(uint8_t* buffer, size_t len) {
    std::span<const uint8_t> packet(buffer, len);
    if (packet.size() < sizeof(EthernetHeader)) return;

    EthernetHeader eth;
    std::memcpy(&eth, packet.data(), sizeof(EthernetHeader));
    uint16_t type = __builtin_bswap16(eth.ether_type);

    if (type == 0x0800) handle_ipv4(packet, eth);
    else if (type == 0x0806) handle_arp(packet, eth);
}

void NetworkStack::handle_arp(std::span<const uint8_t> packet, const EthernetHeader& eth) {
    auto payload = packet.subspan(sizeof(EthernetHeader));
    if (payload.size() < sizeof(ARPHeader)) return;

    ARPHeader arp;
    std::memcpy(&arp, payload.data(), sizeof(ARPHeader));
    uint32_t my_ip = 0x050aa8c0; // 192.168.10.5

    if (__builtin_bswap16(arp.opcode) == 1 && arp.target_ip == my_ip) {
        std::cout << "[ARP] Replying...\n";
        uint8_t res[sizeof(EthernetHeader) + sizeof(ARPHeader)];
        
        auto* eth_r = reinterpret_cast<EthernetHeader*>(res);
        eth_r->dest_mac = eth.src_mac;
        eth_r->src_mac = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
        eth_r->ether_type = __builtin_bswap16(0x0806);

        auto* arp_r = reinterpret_cast<ARPHeader*>(res + sizeof(EthernetHeader));
        std::memcpy(arp_r, &arp, sizeof(ARPHeader));
        arp_r->opcode = __builtin_bswap16(2);
        arp_r->sender_mac = eth_r->src_mac;
        arp_r->sender_ip = my_ip;
        arp_r->target_mac = arp.sender_mac;
        arp_r->target_ip = arp.sender_ip;

        tap_device.write_packet(res, sizeof(res));
    }
}

void NetworkStack::handle_ipv4(std::span<const uint8_t> packet, const EthernetHeader& eth) {
    auto payload = packet.subspan(sizeof(EthernetHeader));
    if (payload.size() < sizeof(IPV4Header)) return;

    IPV4Header ip4;
    std::memcpy(&ip4, payload.data(), sizeof(IPV4Header));

    if (ip4.protocol == 1) { // ICMP
        auto icmp_p = payload.subspan(sizeof(IPV4Header));
        if (icmp_p.size() < sizeof(ICMPHeader)) return;

        ICMPHeader icmp;
        std::memcpy(&icmp, icmp_p.data(), sizeof(ICMPHeader));

        if (icmp.type == 8) {
            std::cout << "[ICMP] Replying...\n";
            std::vector<uint8_t> rep(packet.begin(), packet.end());
            
            auto* eth_r = reinterpret_cast<EthernetHeader*>(rep.data());
            std::swap(eth_r->src_mac, eth_r->dest_mac);

            auto* ip_r = reinterpret_cast<IPV4Header*>(rep.data() + sizeof(EthernetHeader));
            std::swap(ip_r->src_ip, ip_r->dest_ip);

            auto* ic_r = reinterpret_cast<ICMPHeader*>(rep.data() + sizeof(EthernetHeader) + sizeof(IPV4Header));
            ic_r->type = 0;
            ic_r->checksum = 0;
            ic_r->checksum = calculate_checksum(ic_r, icmp_p.size());

            tap_device.write_packet(rep.data(), rep.size());
        }
    }
}