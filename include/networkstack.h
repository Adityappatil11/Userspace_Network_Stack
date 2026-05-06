#ifndef NETWORKSTACK_H
#define NETWORKSTACK_H

#include "protocolheaders.h"
#include "tapinterface.h"
#include <span>

class NetworkStack {
public:
    NetworkStack(TapInterface& tap) : tap_device(tap) {}
    void handle_packet(uint8_t* buffer, size_t len);

private:
    TapInterface& tap_device;
    void handle_arp(std::span<const uint8_t> packet, const EthernetHeader& eth);
    void handle_ipv4(std::span<const uint8_t> packet, const EthernetHeader& eth);
};

#endif