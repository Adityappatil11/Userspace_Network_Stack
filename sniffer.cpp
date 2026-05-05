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

struct IPV4Header {
    uint8_t  version_ihl;      // Version (4 bits) + Header Length (4 bits)
    uint8_t  tos;              // Type of Service
    uint16_t total_length;     // Entire packet length
    uint16_t identification;
    uint16_t flags_fo;         // Flags + Fragment Offset
    uint8_t  ttl;              // Time to Live
    uint8_t  protocol;         // ICMP=1, TCP=6, UDP=17
    uint16_t checksum;
    uint32_t src_ip;           // Source IP (Big Endian)
    uint32_t dest_ip;          // Dest IP (Big Endian)
};

struct IPV6Header {
    uint32_t ver_tc_fl;       // Version, Traffic Class, Flow Label
    uint16_t payload_len;     // Length of the data following this header
    uint8_t  next_header;     // Next header type (TCP=6, UDP=17, ICMPv6=58)
    uint8_t  hop_limit;       // Similar to TTL
    std::array<uint8_t, 16> src_ip;
    std::array<uint8_t, 16> dest_ip;
};

#pragma pack(pop)

// --- Helper Functions ---

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

void print_ipv4(uint32_t ip){
    uint8_t bytes[4];
    std::memcpy(bytes,&ip,4);
    std::cout<<std::dec<<(int)bytes[0]<<"."<<(int)bytes[1]<<"."<<(int)bytes[2]<<"."<<(int)bytes[3];
}

void print_ipv6(const std::array<uint8_t,16> &ip){
    for(size_t i=0;i<16;i+=2){
        std::cout<<std::hex<<std::setw(2)<<std::setfill('0')<<(int)ip[i]<<std::setw(2)<<std::setfill('0')<<(int)ip[i+1];
        if(i<14)std::cout<<":";
    }
}

// --- Main Logic ---

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

        // 1. Layer 2: Ethernet
        if(packet.size()>=sizeof(EthernetHeader)){
            EthernetHeader eth;
            std::memcpy(&eth,packet.data(),sizeof(EthernetHeader));
            eth.ether_type = __builtin_bswap16(eth.ether_type);

            std::cout << "------------------------------------------\n";
            std::cout << "Parsed Ethernet Frame (" << bytes_read << " bytes):\n";
            std::cout << "  Src MAC:    "; print_mac(eth.src_mac); std::cout << "\n";
            std::cout << "  Dest MAC:   "; print_mac(eth.dest_mac); std::cout << "\n";
            std::cout << "  EtherType:  0x" << std::hex << eth.ether_type << std::dec << "\n";

            // 2. Layer 3: IPv4
            // Identify the payload
            if (eth.ether_type == 0x0800) {    //IPv4 Protocol
                std::span<const uint8_t> payload = packet.subspan(sizeof(EthernetHeader));

                if(payload.size() >= sizeof(IPV4Header)){
                    IPV4Header ip4;
                    std::memcpy(&ip4,payload.data(),sizeof(IPV4Header));

                    std::cout<<" [IPv4] ";print_ipv4(ip4.src_ip);std::cout<<" -> ";print_ipv4(ip4.dest_ip);
                    std::cout << " | proto: "<<std::dec<<(int)ip4.protocol<<"\n";
                }
            }
            else if(eth.ether_type == 0x86dd){  //IPv6 Protocol
                std::span<const uint8_t> payload = packet.subspan(sizeof(EthernetHeader));

                if(payload.size() >= sizeof(IPV6Header)){
                    IPV6Header ip6;
                    std::memcpy(&ip6,payload.data(),sizeof(IPV6Header));

                    std::cout<<" [IPv6] ";print_ipv6(ip6.src_ip);std::cout<<" -> ";print_ipv6(ip6.dest_ip);
                    std::cout<<" | Next Header: "<< std::dec << (int)ip6.next_header << "\n";
                }
            }
            else if(eth.ether_type == 0x0806){
                std::cout<<" [ARP] Request/Reply detection\n";
            }
            std::cout << "------------------------------------------\n\n";
        }
    }
    close(tap_fd);
    return 0;
}