#ifndef SNIFFER_H
#define SNIFFER_H

#include <pcap.h>
#include <ctype.h>
#ifndef u_char
typedef unsigned char u_char;
#endif
extern int packet_count;
extern pcap_t *current_handle;

void handle_sigint(int sig);
void packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet);
void start_sniffing(const char *dev_name);
void handle_l3(uint16_t ethertype,const u_char *packet);
void handle_l4(const u_char *packet, unsigned char protocol, int l3_payload_len);
void handle_l7(const u_char *payload, int payload_len, unsigned short src_port, unsigned short dst_port);   
void start_sniffing_with_filter(const char *dev_name);
void inspect_last_session();
#endif
