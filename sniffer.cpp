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
#include <vector>


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

struct ARPHeader {
    uint16_t hw_type;        // Hardware type (1 for Ethernet)
    uint16_t proto_type;     // Protocol type (0x0800 for IPv4)
    uint8_t  hw_addr_len;    // 6 for MAC
    uint8_t  proto_addr_len; // 4 for IP
    uint16_t opcode;         // 1 for Request, 2 for Reply
    std::array<uint8_t, 6> sender_mac;
    uint32_t sender_ip;
    std::array<uint8_t, 6> target_mac;
    uint32_t target_ip;
};

struct ICMPHeader{
    uint8_t type;   // 8 for echo request, 0 for echo reply
    uint8_t code;   //0
    uint16_t checksum;
    uint16_t id;
    uint16_t sequence;
};

#pragma pack(pop)

// --- Checksum Function ---

uint16_t calculate_checksum(void* b,int len){
    uint32_t sum = 0;
    uint16_t* ptr = static_cast<uint16_t*>(b);
    while(len>1){
        sum += *ptr++;
        len -= 2;
    }
    if(len > 0) sum += *reinterpret_cast<uint8_t*>(ptr);
    while(sum>>16) sum = (sum & 0xFFFF) + (sum >> 16);
    return ~static_cast<uint16_t>(sum);
}

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

                    // ICMP echo reply
                    if(ip4.protocol == 1){  // ICMP
                        std::span<const uint8_t> icmp_payload = payload.subspan(sizeof(IPV4Header));

                        if(icmp_payload.size() >= sizeof(ICMPHeader)){
                            ICMPHeader icmp;
                            std::memcpy(&icmp,icmp_payload.data(),sizeof(ICMPHeader));

                            if(icmp.type == 8){ // echo request
                                std::cout<< " [ICMP] Echo request! replying... \n";
                                
                                //creating a copy of response
                                std::vector<uint8_t> reply(buffer,buffer+bytes_read);

                                //1.swap MAC
                                EthernetHeader* eth_res = reinterpret_cast<EthernetHeader*>(reply.data());
                                std::swap(eth_res->src_mac,eth_res->dest_mac);

                                //2.swap IPs
                                IPV4Header* ip_res = reinterpret_cast<IPV4Header*>(reply.data() + sizeof(EthernetHeader));
                                std::swap(ip_res->src_ip,ip_res->dest_ip);

                                //3.build ICMP reply
                                ICMPHeader* icmp_res = reinterpret_cast<ICMPHeader*>(reply.data() + sizeof(EthernetHeader) + sizeof(IPV4Header));
                                icmp_res->type = 0;     //echo reply
                                icmp_res->checksum = 0; //clear before calculation

                                //recalculating the checksum
                                int icmp_len = bytes_read - sizeof(EthernetHeader) - sizeof(IPV4Header);
                                icmp_res->checksum = calculate_checksum(icmp_res,icmp_len);

                                write(tap_fd,reply.data(),reply.size());
                            }
                        }
                    }
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
            else if(eth.ether_type == 0x0806){  //ARP Request/Reply

                std::span<const uint8_t>arp_payload = packet.subspan(sizeof(EthernetHeader));
                if(arp_payload.size() >= sizeof(ARPHeader)){
                    ARPHeader arp;
                    std::memcpy(&arp,arp_payload.data(),sizeof(ARPHeader));

                    uint16_t opcode = __builtin_bswap16(arp.opcode);
                    uint32_t my_ip = 0x050aa8c0;    //192.168.10.5 in little endian

                    if(opcode == 1 && arp.target_ip == my_ip){
                        std::cout<<" [ARP] Request from my IP! Sending reply... \n";

                        //1. build reply packet 
                        uint8_t replybuffer[sizeof(EthernetHeader)+sizeof(ARPHeader)];

                        //2. configure ethernet header
                        EthernetHeader* eth_res = reinterpret_cast<EthernetHeader*>(replybuffer);
                        eth_res->dest_mac = eth.src_mac;
                        eth_res->src_mac = {0x00,0x11,0x22,0x33,0x44,0x55};
                        eth_res->ether_type = __builtin_bswap16(0x0806);

                        //3. configure arp header
                        ARPHeader* arp_res = reinterpret_cast<ARPHeader*>(replybuffer + sizeof(EthernetHeader));
                        arp_res->hw_type = arp.hw_type;
                        arp_res->proto_type = arp.proto_type;
                        arp_res->hw_addr_len = 6;
                        arp_res->proto_addr_len = 4;
                        arp_res->opcode = __builtin_bswap16(2); //2 = reply

                        arp_res->sender_mac = {0x00,0x11,0x22,0x33,0x44,0x55};
                        arp_res->sender_ip = my_ip;
                        arp_res->target_mac = arp.sender_mac;
                        arp_res->target_ip = arp.sender_ip;

                        //4. write back to tap device
                        write(tap_fd,replybuffer,sizeof(replybuffer));
                    }
                }
            }
            std::cout << "------------------------------------------\n\n";
        }
    }
    close(tap_fd);
    return 0;
}