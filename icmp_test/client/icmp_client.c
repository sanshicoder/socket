#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <net/if.h>// struct ifreq    
#include <sys/ioctl.h> // ioctl、SIOCGIFADDR      
#include <netpacket/packet.h> // struct sockaddr_ll

#include<arpa/inet.h>  // inet_addr()
#include<netinet/if_ether.h>

#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#include <time.h>
#include <sys/time.h>

typedef struct {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint16_t id;
    uint16_t seq_number;
} icmp_header;

#define ICMP_ECHO_REQUEST 8

uint16_t icmp_checksum(uint16_t* data, int size) {
    uint32_t sum = 0;
    while (size > 1) {
        sum += *data;
        data++;
        size -= 2;
        sum = (sum >> 16) + (sum & 0xffff);
    }
    if (size == 1) {
        sum += *(uint8_t *)data;
        sum = (sum >> 16) + (sum & 0xffff);
    }

    return (uint16_t)(~sum);
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: sudo %s <ip> \n", argv[0]);
        return -1;
    }
    // Create a socket  
    int socket_raw_fd = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (socket_raw_fd < 0) {
        printf("Create socket_raw failed\n");
        return -1;
    }

    struct timeval tv;
    tv.tv_sec = 5;  // 设置超时为5秒
    tv.tv_usec = 0;
    if (setsockopt(socket_raw_fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv)) < 0) {
        perror("setsockopt");
        return -1;
    }

    // 使用当前时间设置随机数种子
    srand(time(NULL));

    // Create a icmp echo packet
    icmp_header icmp_h;
    icmp_h.type = ICMP_ECHO_REQUEST;
    icmp_h.code = 0;
    icmp_h.checksum = 0;
    icmp_h.id = htons(rand() % 100);
    icmp_h.seq_number = htons(rand() % 10000);
    
    // set the packet data
    char data[] = "This is a icmp echo test packet!";
    int data_len = strlen(data);
    char packet[sizeof(icmp_header) + data_len]; 

    // Copy the header and data to the packet
    memcpy(packet, &icmp_h, sizeof(icmp_header));
    memcpy(packet + sizeof(icmp_header), data, data_len);

    // Calculate the checksum
    icmp_h.checksum = icmp_checksum((uint16_t *)packet, sizeof(packet));

    // Copy the calculated checksum back to the header
    memcpy(packet, &icmp_h, sizeof(icmp_header));

    // Set the source and destination MAC addresses
    struct sockaddr_in socket_address, din;
    memset(&socket_address, 0, sizeof(struct sockaddr_in));
    memset(&din, 0, sizeof(struct sockaddr_in));
    // socket_address.sin_family = PF_INET;
    din.sin_family = PF_INET;
    // socket_address.sin_addr.s_addr = INADDR_ANY;
    din.sin_addr.s_addr = inet_addr(argv[1]);
    
    int len = sendto(socket_raw_fd, packet, sizeof(packet), 0, (struct sockaddr *)&din, sizeof(din));
    if (len == -1) {
        printf("Failed to send packet!\n");
        close(socket_raw_fd);
        return -1;
    }
    printf("send icmp echo packet!\n");

    // Receive the response packet
    char buf[1024];
    socklen_t leng = sizeof(din);
    len = recvfrom(socket_raw_fd, buf, sizeof(buf), 0, (struct sockaddr *)&din, &leng);  // why need the parameter length
    if (len == -1) {
        printf("Failed to receive packet!\n");
        close(socket_raw_fd);
        return -1;
    }
    else if (len > 0) 
        printf("Received reply from Server: %s\n", buf+20+8);       // buf: ip header + icmp header + data
    close(socket_raw_fd);

    return 0;
}