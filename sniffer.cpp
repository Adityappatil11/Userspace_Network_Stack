#include <iostream>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <cstring>
#include <iomanip>
#include <cstdint>
#include <array>
#include <span>


#pragma pack(push, 1)
struct EthernetHeader {
    std::array<uint8_t, 6> dest_mac;
    std::array<uint8_t, 6> src_mac;
    uint16_t ether_type;
};
#pragma pack(pop)

int open_tap_device(const char* dev_name){
    struct ifreq ifr;

    int fd = open("/dev/net/tun",O_RDWR);
    if(fd<0){
        std::cerr << "ERROR: Cannot open /dev/net/tun. Run with sudo.\n";
        return -1;
    }

    std::memset(&ifr,0,sizeof(ifr));
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    std::strncpy(ifr.ifr_name,dev_name,IFNAMSIZ);

    if(ioctl(fd,TUNSETIFF,reinterpret_cast<void*>(&ifr))<0){
        std::cerr<<"ERROR: ioctl failed to bind to "<<dev_name<<"\n";
        close(fd);
        return -1;
    }

    return fd;
}

void print_mac(const std::array<uint8_t,6>& mac){
    for(size_t i=0;i<mac.size();++i){
        std::cout<< std::hex << std::setw(2) <<std::setfill('0')<<static_cast<int>(mac[i]);
        if(i < mac.size()-1) std::cout<<":";
    }
}

int main(){
    const char* dev_name = "tap0";
    int tap_fd = open_tap_device(dev_name);
    if(tap_fd<0)return 1;

    std::cout<<"Successfully connected to "<<dev_name<< ".Listening for packets....\n";

    uint8_t buffer[2048];
    while(true){
        ssize_t bytes_read  =read(tap_fd,buffer,sizeof(buffer));
        if(bytes_read<0){
            std::cerr<<"Read error!\n";
            break;
        }

        std::span<const uint8_t> packet(buffer,bytes_read);
        if(packet.size()>=sizeof(EthernetHeader)){
            EthernetHeader eth;
            std::memcpy(&eth,packet.data(),sizeof(EthernetHeader));
            eth.ether_type = __builtin_bswap16(eth.ether_type);
            std::cout << "------------------------------------------\n";
            std::cout << "Parsed Ethernet Frame (" << bytes_read << " bytes):\n";
            std::cout << "  Src MAC:    "; print_mac(eth.src_mac); std::cout << "\n";
            std::cout << "  Dest MAC:   "; print_mac(eth.dest_mac); std::cout << "\n";
            std::cout << "  EtherType:  0x" << std::hex << eth.ether_type << std::dec << "\n";

            // Identify the payload
            if (eth.ether_type == 0x0806) {
                std::cout << "  Protocol:   ARP\n";
            } else if (eth.ether_type == 0x0800) {
                std::cout << "  Protocol:   IPv4\n";
            } else if (eth.ether_type == 0x86dd) {
                std::cout << "  Protocol:   IPv6\n";
            } else {
                std::cout << "  Protocol:   Unknown\n";
            }
            std::cout << "------------------------------------------\n\n";
        }
    }
    close(tap_fd);
    return 0;
}