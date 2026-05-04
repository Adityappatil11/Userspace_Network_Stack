#include <iostream>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <cstring>
#include <iomanip>
#include <cstdint>

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

        std::cout<<"Received a packet of"<<bytes_read<<" bytes.\n";

        for(ssize_t i=0;i<bytes_read;++i){
            std::cout<<std::hex<<std::setw(2)<<std::setfill('0')<<static_cast<int>(buffer[i])<<" ";
            if((i+1)%16==0)std::cout<<"\n";
        }
        std::cout<<std::dec<<"\n\n";
    }
    close(tap_fd);
    return 0;
}