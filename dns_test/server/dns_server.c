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

#pragma pack(push, 2)
typedef struct {
    uint16_t name;
    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    uint16_t length;
} answer_header;
#pragma pack(pop)

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

    uint8_t domain[] = {0x03, 0x77, 0x77, 0x77, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00};
    answer_header ans;
    ans.name = htons(0xc00c);
    ans.type = htons(0x0001);
    ans.class = htons(0x0001);
    ans.ttl = htonl(0x00000040);
    ans.length = htons(0x0004);
    // set the packet data: queries
    uint8_t data[512];


    
    struct sockaddr_in sin, din;
    memset(&sin, 0, sizeof(struct sockaddr_in));
    
    sin.sin_family = PF_INET;
    sin.sin_port = htons(53);  // DNS port is 53
    sin.sin_addr.s_addr = inet_addr("127.0.0.1");
    
    if (bind(socket_fd, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        // printf("bind(socket_fd) failed!\n");
        perror("bind");
        close(socket_fd);
        return -1;
    }
    // Receive the response packet
    char buf[1024];
    socklen_t addrlen = sizeof(din);
    while (1) {
        int len = recvfrom(socket_fd, buf, sizeof(buf), 0, (struct sockaddr *)&din, &addrlen);  // why need the parameter length
        if (len == -1) {
            printf("Failed to receive packet!\n");
            continue;
        }
        
        uint8_t* req_domain = (uint8_t *)(buf + 12); 
        uint8_t flag = 1;    
        for (int i = 0; i < 16; i++) {
            if (req_domain[i] != domain[i]) {
                flag = 0;
                break;
            }
        }
        
        if (!flag) {
            continue;
        }
        printf("Received DNS request!\n");
        memcpy(data, buf, len);
        dns_header *dns_h = (dns_header *)data;
        dns_h->flags.qr = 1;
        dns_h->flags.ra = 1;
        dns_h->answer_count = htons(1);
        memcpy((uint8_t *)dns_h + sizeof(dns_header) + 20, &ans, sizeof(ans));
        int ip_offset = sizeof(dns_header) + 20 + sizeof(ans);
        data[ip_offset++] = 172;
        data[ip_offset++] = 217;
        data[ip_offset++] = 160;
        data[ip_offset++] = 100;

        int len2 = sendto(socket_fd, data, ip_offset, 0, (struct sockaddr *)&din, sizeof(din));
        if (len2 == -1) {
            printf("Failed to send packet!\n");
            close(socket_fd);
            continue;
        }
        printf("Send DNS reply packet successfully!\n");
        printf("\n");
    }
    close(socket_fd);

    return 0;
}