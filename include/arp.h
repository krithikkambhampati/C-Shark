#ifndef ARP_H
#define ARP_H

#include <pcap.h>

void handle_arp(const u_char *packet);

#endif
