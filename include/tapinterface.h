#ifndef TAPINTERFACE_H
#define TAPINTERFACE_H

#include <string>
#include <cstdint>

class TapInterface {
public:
    TapInterface(const std::string& dev_name);
    ~TapInterface();
    int read_packet(uint8_t* buffer, size_t size);
    void write_packet(const uint8_t* buffer, size_t size);

private:
    int tap_fd;
    std::string device_name;
};

#endif