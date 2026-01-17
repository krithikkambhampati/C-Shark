#include <stdio.h>
#include <arpa/inet.h>
#include "../include/sniffer.h"
#include "../include/ipv6.h"

void handle_ipv6(const u_char *packet) {
    packet += 14;
    unsigned short payload_length = (packet[4] << 8) | packet[5];
    unsigned char next_header = packet[6];
    unsigned char hop_limit = packet[7];

    unsigned int traffic_class = ((packet[0] & 0x0F) << 4) | ((packet[1] & 0xF0) >> 4);
    unsigned int flow_label = ((packet[1] & 0x0F) << 16) | (packet[2] << 8) | packet[3];

    char src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, packet + 8, src, sizeof(src));
    inet_ntop(AF_INET6, packet + 24, dst, sizeof(dst));

    printf("Src IP: %s | ", src);
    printf("Dst IP: %s \n", dst);

    printf("Next Header: ");
    if (next_header == 6) {
        printf("TCP (6) | ");
    } else if (next_header == 17) {
        printf("UDP (17)| ");
    } else {
        printf("Unknown (%d)\n", next_header);
    }

    printf("Hop Limit: %u | Traffic Class: %u | Flow Label: 0x%05X | Payload Length: %u\n", 
           hop_limit, traffic_class, flow_label, payload_length);
    
    if (next_header == 6 || next_header == 17) {
        handle_l4(packet + 40, next_header, payload_length);
    }
}
