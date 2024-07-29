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

#include<arpa/inet.h>  // inet_addr()
#include<netinet/if_ether.h>

#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#include <time.h>
#include <sys/time.h>


typedef struct {
    uint16_t rd: 1;
    uint16_t tc: 1;
    uint16_t aa: 1;
    uint16_t opcode: 4;
    uint16_t qr: 1;

    uint16_t rcode: 4;
    uint16_t z: 3;
    uint16_t ra: 1;
} dns_flags;


typedef struct {
    uint16_t transaction_id;
    dns_flags  flags;
    uint16_t questions_count;
    uint16_t answer_count;
    uint16_t authotiry_count;
    uint16_t additional_count;
} dns_header;

#define DNS_REQUEST 0
#define DNS_RSPONSE 1


#define DNS_STANDARD_QUERY 0

int main(int argc, char* argv[]) {
    // Create a socket  
    int socket_fd = socket(PF_INET, SOCK_DGRAM, 0);
    if (socket_fd < 0) {
        printf("Create socket failed\n");
        return -1;
    }

    struct timeval tv;
    tv.tv_sec = 5;  // 设置超时为5秒
    tv.tv_usec = 0;
    if (setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv)) < 0) {
        perror("setsockopt");
        return -1;
    }

    // 使用当前时间设置随机数种子
    srand(time(NULL));

    // Create a DNS request packet
    dns_header dns_h;
    dns_h.transaction_id = htons(rand() % 1000);
    dns_h.flags.qr = DNS_REQUEST;
    dns_h.flags.opcode = DNS_STANDARD_QUERY;
    dns_h.flags.aa = 0;
    dns_h.flags.tc = 0;
    dns_h.flags.rd = 1;
    dns_h.flags.ra = 0;
    dns_h.flags.z = 0;
    dns_h.flags.rcode = 0;
    dns_h.questions_count = htons(1);
    dns_h.answer_count = 0;
    dns_h.authotiry_count = 0;
    dns_h.additional_count = 0;

   
    
    // set the packet data: queries
    uint8_t data[512];
    char domain[] = "www.google.com";
    int pos = sizeof(dns_header);
    memcpy(data, &dns_h, pos);
    char *label = domain;

    while (*label) {
        char *next = strchr(label, '.');
        if (!next) {
            next = label + strlen(label);
        }

        data[pos++] = next - label;  // Label length
        memcpy(&data[pos], label, next - label);
        pos += next - label;
        if (*next == '.') {
            label = next + 1;
        }
        else {
            label = next;
        }
    }

    data[pos++] = '\0';
    data[pos++] = 0;  // Type: A (IPv4)
    data[pos++] = 1;
    data[pos++] = 0;  // Class: INET
    data[pos++] = 1;
    // Set the source and destination MAC addresses
    struct sockaddr_in din;
    memset(&din, 0, sizeof(struct sockaddr_in));
    
    din.sin_family = PF_INET;
    din.sin_port = htons(53);  // DNS port is 53
    din.sin_addr.s_addr = inet_addr("192.168.1.1");
    
    int len = sendto(socket_fd, data, pos, 0, (struct sockaddr *)&din, sizeof(din));
    if (len == -1) {
        printf("Failed to send packet!\n");
        close(socket_fd);
        return -1;
    }
    printf("Send DNS request packet successfully!\n");

    // Receive the response packet
    char buf[1024];
    socklen_t leng = sizeof(din);
    len = recvfrom(socket_fd, buf, sizeof(buf), 0, (struct sockaddr *)&din, &leng);  // why need the parameter length
    if (len == -1) {
        printf("Failed to receive packet!\n");
        close(socket_fd);
        return -1;
    }
    else if (len > 0) {
        printf("Received reply from Server:\n");  
        uint8_t* rsp_ip = (uint8_t *)(buf + pos + 12);     
        printf("%s -> ip is %d.%d.%d.%d\n", domain, rsp_ip[0], rsp_ip[1], rsp_ip[2], rsp_ip[3]);
    } 
    
    close(socket_fd);

    return 0;
}
