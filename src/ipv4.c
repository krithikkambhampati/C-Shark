#include <stdio.h>
#include <arpa/inet.h>
#include "../include/sniffer.h"
#include "../include/ipv4.h"

void handle_ipv4(const u_char *packet) {
    packet += 14;
    unsigned char version_ihl = packet[0];
    unsigned char ttl = packet[8];
    unsigned char protocol = packet[9];
    unsigned short total_length = (packet[2] << 8) | packet[3];
    unsigned short identification = (packet[4] << 8) | packet[5];
    unsigned int ihl = (version_ihl & 0x0F) * 4;

    printf("Src IP: %u.%u.%u.%u | ", packet[12], packet[13], packet[14], packet[15]);
    printf("Dst IP: %u.%u.%u.%u | ", packet[16], packet[17], packet[18], packet[19]);

    printf("Protocol: ");
    if (protocol == 6) {
        printf("TCP (6) |\n");
    } else if (protocol == 17) {
        printf("UDP (17) |\n");
    } else {
        printf("Unknown (%d)\n", protocol);
    }

    printf("TTL: %u\n", ttl);
    printf("ID: 0x%04X | Total Length: %u | Header Length: %u bytes\n", identification, total_length, ihl);

    if (protocol == 6 || protocol == 17) {
        handle_l4(packet + ihl, protocol, total_length - ihl);
    }
}
