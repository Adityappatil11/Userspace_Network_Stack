#include "tapinterface.h"
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <cstring>
#include <stdexcept>

TapInterface::TapInterface(const std::string& dev_name) : device_name(dev_name) {
    tap_fd = open("/dev/net/tun", O_RDWR);
    if (tap_fd < 0) throw std::runtime_error("Cannot open /dev/net/tun");

    struct ifreq ifr;
    std::memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    std::strncpy(ifr.ifr_name, dev_name.c_str(), IFNAMSIZ);

    if (ioctl(tap_fd, TUNSETIFF, reinterpret_cast<void*>(&ifr)) < 0) {
        close(tap_fd);
        throw std::runtime_error("ioctl failed to bind to " + dev_name);
    }
}

TapInterface::~TapInterface() { if (tap_fd >= 0) close(tap_fd); }

int TapInterface::read_packet(uint8_t* buffer, size_t size) { return read(tap_fd, buffer, size); }

void TapInterface::write_packet(const uint8_t* buffer, size_t size) { write(tap_fd, buffer, size); }