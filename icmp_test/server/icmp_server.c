#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <stdint.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ether.h>

#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

uint16_t caclulate_checksum(uint16_t *data, int size) {
    uint32_t sum = 0;
    while (size > 1) {
        sum += *data;
        data++;
        sum = (sum >> 16) + (sum & 0xffff);
        size -= 2;
    }

    if (size == 1) {
        sum += *((uint8_t *)data);
        sum = (sum >> 16) + (sum & 0xffff);
    }

    return (uint16_t)(~sum);
}


int main() {
    int sock_raw_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP); 
    if (sock_raw_fd < 0) {
        printf("Crate socket raw failed!\n");
        return -1;
    }

    uint8_t buf[1024] = { 0 };
    struct sockaddr_in daddr;
    socklen_t addrlen = sizeof(daddr);
    printf("Socket created\n"); 
    while (1) {
        memset(buf, 0, sizeof(buf));
        int len = recvfrom(sock_raw_fd, buf, sizeof(buf), 0, (struct sockaddr *)&daddr, &addrlen);
        if (len < 0) {
            perror("len < 0");
            continue;
        }  
        struct iphdr *ip_h = (struct iphdr *)buf;
        struct icmphdr *icmp_h = (struct icmphdr *)(buf + (ip_h->ihl << 2));
        
        if (len < (ip_h->ihl << 2) + sizeof(struct icmphdr)) {
            printf("Packet is too short for ICMP header\n");
            continue;
        }

        if (ip_h->protocol == IPPROTO_ICMP && icmp_h->type == ICMP_ECHO) {
            uint16_t recv_checksum = icmp_h->checksum;
            uint16_t data_len = ntohs(ip_h->tot_len ) - (ip_h->ihl << 2);
            // printf("%d,data_len: %d\n", ip_h->ihl, data_len);
            
            icmp_h->checksum = 0;
            if (recv_checksum == caclulate_checksum((uint16_t *)icmp_h, data_len)) {
                icmp_h->type = ICMP_ECHOREPLY;
                icmp_h->checksum = caclulate_checksum((uint16_t *)icmp_h, data_len);
                
                if (sendto(sock_raw_fd, icmp_h, data_len, 0, (struct sockaddr *)&daddr, addrlen) < 0) {
                    printf("Send ICMP echo reply failed!\n");
                    continue;
                }
                printf("ICMP echo reply successful!\n");
                printf("\n");
            }
            else {
                printf("Received ICMP echo request, but checksum mismatch!\n");
                continue;
            }
        } 

    }

    return 0;
}

