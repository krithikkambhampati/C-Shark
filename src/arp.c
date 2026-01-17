#include <stdio.h>
#include "../include/sniffer.h"
#include "../include/arp.h"

void handle_arp(const u_char *packet) {
    packet += 14;
    unsigned short hw_type = (packet[0] << 8) | packet[1];
    unsigned short proto_type = (packet[2] << 8) | packet[3];
    unsigned char hw_len = packet[4];
    unsigned char proto_len = packet[5];
    unsigned short operation = (packet[6] << 8) | packet[7];

    unsigned char *sender_mac = (unsigned char*)(packet + 8);
    unsigned char *sender_ip  = (unsigned char*)(packet + 14);
    unsigned char *target_mac = (unsigned char*)(packet + 18);
    unsigned char *target_ip  = (unsigned char*)(packet + 24);

    printf("Operation: ");
    if (operation == 1) {
        printf("Request (1) | ");
    } else if (operation == 2) {
        printf("Reply (2) | ");
    } else {
        printf("Unknown (%u) | ", operation);
    }

    printf("Sender IP: %u.%u.%u.%u | ",
           sender_ip[0], sender_ip[1], sender_ip[2], sender_ip[3]);
    printf("Target IP: %u.%u.%u.%u\n",
           target_ip[0], target_ip[1], target_ip[2], target_ip[3]);

    printf("Sender MAC: %02x:%02x:%02x:%02x:%02x:%02x | ",
           sender_mac[0], sender_mac[1], sender_mac[2],
           sender_mac[3], sender_mac[4], sender_mac[5]);
    printf("Target MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           target_mac[0], target_mac[1], target_mac[2],
           target_mac[3], target_mac[4], target_mac[5]);

    printf("HW Type: %u | Proto Type: 0x%04x | HW Len: %u | Proto Len: %u\n",
           hw_type, proto_type, hw_len, proto_len);
}
