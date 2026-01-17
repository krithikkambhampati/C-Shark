#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/types.h>
#include <stdint.h>
#include "../include/ipv4.h"
#include "../include/ipv6.h"
#include "../include/arp.h"
#include "../include/sniffer.h"
#include <ctype.h>
#include <string.h>

#define MAX_PACKETS 10000

typedef struct {
    struct pcap_pkthdr header; // packet header
    u_char *data;              // packet data
} StoredPacket;

StoredPacket *packetStorage[MAX_PACKETS]; // array of pointers to store packets
int storedCount = 0;                      // number of packets stored in the current session

void freePreviousSession() {
    for (int i = 0; i < storedCount; i++) {
        free(packetStorage[i]->data);
        free(packetStorage[i]);
        packetStorage[i] = NULL;
    }
    storedCount = 0;
}

int packet_count = 1;
pcap_t *current_handle = NULL;

void handle_sigint(int sig) {
    (void)sig; 
    if (current_handle) {
        pcap_breakloop(current_handle);
    }
}

void print_mac(const u_char *mac) {
    for (int i = 0; i < 6; i++) {
        printf("%02X", mac[i]);
        if (i != 5) {
            printf(":");
        }
    }
}


void handle_l3(uint16_t ethertype,const u_char *packet){
    if (ethertype == 0x0800) {
        printf("L3 (IPv4): ");
        handle_ipv4(packet);

    } else if (ethertype == 0x86DD) {
        //ipv6
        printf("L3 (IPv6): ");
        handle_ipv6(packet);

    } else if (ethertype == 0x0806) {
        //arp
        printf("L3 (ARP): ");
        handle_arp(packet);
    } 
    else {


    }
}

void handle_l4(const u_char *packet, unsigned char protocol, int l3_payload_len) {
    const u_char *segment = packet;

    if (protocol == 6) {  // TCP
        unsigned short src_port = (segment[0] << 8) | segment[1];
        unsigned short dst_port = (segment[2] << 8) | segment[3];
        unsigned int seq = (segment[4] << 24) | (segment[5] << 16) | (segment[6] << 8) | segment[7];
        unsigned int ack = (segment[8] << 24) | (segment[9] << 16) | (segment[10] << 8) | segment[11];
        unsigned char offset_reserved = segment[12];
        unsigned char flags = segment[13];
        unsigned short window = (segment[14] << 8) | segment[15];
        unsigned short checksum = (segment[16] << 8) | segment[17];

        unsigned int header_len = ((offset_reserved >> 4) & 0xF) * 4;

        printf("L4 (TCP): Src Port: %u ", src_port);
        if (src_port == 80) printf("(HTTP) ");
        else if (src_port == 443) printf("(HTTPS) ");
        else if (src_port == 53) printf("(DNS) ");
        printf("| Dst Port: %u ", dst_port);
        if (dst_port == 80) printf("(HTTP) ");
        else if (dst_port == 443) printf("(HTTPS) ");
        else if (dst_port == 53) printf("(DNS) ");
        printf("| Seq: %u | Ack: %u | Flags: [", seq, ack);
        
        int first_flag = 1;
        if (flags & 0x02) { printf("%sSYN", first_flag ? "" : ","); first_flag = 0; }
        if (flags & 0x10) { printf("%sACK", first_flag ? "" : ","); first_flag = 0; }
        if (flags & 0x01) { printf("%sFIN", first_flag ? "" : ","); first_flag = 0; }
        if (flags & 0x04) { printf("%sRST", first_flag ? "" : ","); first_flag = 0; }
        if (flags & 0x08) { printf("%sPSH", first_flag ? "" : ","); first_flag = 0; }
        if (flags & 0x20) { printf("%sURG", first_flag ? "" : ","); first_flag = 0; }
        printf("]\nWindow: %u | Checksum: 0x%04X | Header Length: %u bytes\n", window, checksum, header_len);

        int payload_len = l3_payload_len - header_len;
        if (payload_len > 0) {
            handle_l7(segment + header_len, payload_len, src_port, dst_port);
        }

    } else if (protocol == 17) {  // UDP
        unsigned short src_port = (segment[0] << 8) | segment[1];
        unsigned short dst_port = (segment[2] << 8) | segment[3];
        unsigned short length = (segment[4] << 8) | segment[5];
        unsigned short checksum = (segment[6] << 8) | segment[7];

        printf("L4 (UDP): Src Port: %u ", src_port);
        if (src_port == 53) printf("(DNS) ");
        printf("| Dst Port: %u ", dst_port);
        if (dst_port == 53) printf("(DNS) ");
        printf("| Length: %u | Checksum: 0x%04X\n", length, checksum);

        int payload_len = length - 8;  // UDP header is 8 bytes
        if (payload_len > 0) {
            handle_l7(segment + 8, payload_len, src_port, dst_port);
        }

    } else {
        printf("L4: Unsupported protocol (%u)\n", protocol);
    }
}

void handle_l7(const u_char *payload, int payload_len, unsigned short src_port, unsigned short dst_port) {
    const char *protocol_name = "Unknown";

    if (src_port == 80 || dst_port == 80) {
        protocol_name = "HTTP";
    } 
    else if (src_port == 443 || dst_port == 443) {
        protocol_name = "HTTPS/TLS";
    } 
    else if (src_port == 53 || dst_port == 53) {
        protocol_name = "DNS";
    }

    printf("L7 (Payload): Identified as %s on port %u - %d bytes\n", 
           protocol_name, dst_port, payload_len);

    if (payload_len <= 0) return;

    int display_len = payload_len < 64 ? payload_len : 64;

    printf("Data (first %d bytes):\n", display_len);

    for (int i = 0; i < display_len; i += 16) {
        // Print hex part
        for (int j = 0; j < 16; j++) {
            if (i + j < display_len) {
                printf("%02X ", payload[i + j]);
            } else {
                printf("   "); // 3 spaces for missing bytes
            }
        }

        // Print ASCII part
        for (int j = 0; j < 16 && i + j < display_len; j++) {
            unsigned char c = payload[i + j];
            printf("%c", isprint(c) ? c : '.');
        }
        printf("\n");
    }
}

void packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    (void)user;
    printf("-----------------------------------------\n");
    printf("Packet #%d | ", packet_count++);
    printf("Timestamp: %ld.%06ld | Length: %d bytes\n", 
           pkthdr->ts.tv_sec, (long)pkthdr->ts.tv_usec, pkthdr->caplen);
    
    const u_char *dst_mac = &packet[0];   // first 6 bytes
    const u_char *src_mac = &packet[6]; 

    uint16_t ethertype = (packet[12] << 8) | packet[13];  // bytes 12-13 combined as big-endian

    printf("L2 (Ethernet): ");
    printf("Dst MAC: "); print_mac(dst_mac); printf(" | ");
    printf("Src MAC: "); print_mac(src_mac); printf(" |");
   
    if (ethertype == 0x0800) {
        printf("\nEtherType: IPv4 (0x0800)\n");
    } else if (ethertype == 0x86DD) {
        printf("\nEtherType: IPv6 (0x86DD)\n");
    } else if (ethertype == 0x0806) {
        printf("\nEtherType: ARP (0x0806)\n");
    } else {
        printf("\nEtherType: Unknown (0x%04X)\n", ethertype);
    }
    handle_l3(ethertype, packet);


    if (storedCount < MAX_PACKETS) {
    packetStorage[storedCount] = malloc(sizeof(StoredPacket));
    if (!packetStorage[storedCount]) return; // malloc failed, skip

    // Copy header
    packetStorage[storedCount]->header = *pkthdr;

    // Copy packet data
    packetStorage[storedCount]->data = malloc(pkthdr->caplen);
    if (!packetStorage[storedCount]->data) {
        free(packetStorage[storedCount]);
        return;
    }
    memcpy(packetStorage[storedCount]->data, packet, pkthdr->caplen);

    storedCount++;
}

}

void start_sniffing(const char *dev_name){
    freePreviousSession();

    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    handle = pcap_open_live(dev_name, 65535, 1, 1000, errbuf); 

    if (handle == NULL) {
        fprintf(stderr, "[C-Shark] Could not open device %s: %s\n", dev_name, errbuf);
        return;
    }

    printf("[C-Shark] Starting sniffer on interface '%s'. Press Ctrl+C to return to menu...\n", dev_name);

    current_handle = handle;
    pcap_loop(handle, -1, packet_handler, NULL); 
    current_handle = NULL;

    pcap_close(handle);
    printf("\n[C-Shark] Sniffing session ended.\n");
}





void start_sniffing_with_filter(const char *dev_name) {
    freePreviousSession();
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;     // compiled filter
    char filter_exp[64];        // filter expression string
    bpf_u_int32 net = 0;

    printf("Select a filter:\n");
    printf("1. HTTP\n");
    printf("2. HTTPS\n");
    printf("3. DNS\n");
    printf("4. ARP\n");
    printf("5. TCP\n");
    printf("6. UDP\n");
    printf("Enter choice: ");

    int choice;
    int scan_result = scanf("%d", &choice);
    if (scan_result == EOF) {
        printf("\n[C-Shark] Exiting filter selection.\n");
        return;
    }
    if (scan_result != 1) {
        printf("[C-Shark] Invalid input. Exiting filter selection.\n");
        return;
    }

    switch (choice) {
        case 1: strcpy(filter_exp, "tcp port 80"); break;
        case 2: strcpy(filter_exp, "tcp port 443"); break;
        case 3: strcpy(filter_exp, "udp port 53"); break;
        case 4: strcpy(filter_exp, "arp"); break;
        case 5: strcpy(filter_exp, "tcp"); break;
        case 6: strcpy(filter_exp, "udp"); break;
        default:
            printf("Invalid choice.\n");
            return;
    }

    handle = pcap_open_live(dev_name, 65535, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "[C-Shark] Could not open device %s: %s\n", dev_name, errbuf);
        return;
    }

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Error compiling filter: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Error setting filter: %s\n", pcap_geterr(handle));
        pcap_freecode(&fp);
        pcap_close(handle);
        return;
    }

    printf("[C-Shark] Sniffing on interface '%s' with filter '%s'. Press Ctrl+C to stop...\n", dev_name, filter_exp);
    current_handle = handle;
    pcap_loop(handle, -1, packet_handler, NULL);
    current_handle = NULL;

    pcap_freecode(&fp);
    pcap_close(handle);
    printf("\n[C-Shark] Sniffing session ended.\n");
}



void inspect_packet(int id); // forward declaration

// --- Show summary of all stored packets ---
void inspect_last_session() {
    if (storedCount == 0) {
        printf("[C-Shark] No packets stored from previous session.\n");
        return;
    }

    printf("=== Last Session Packet Summary ===\n");
    for (int i = 0; i < storedCount; i++) {
        StoredPacket *pkt = packetStorage[i];
        const u_char *data = pkt->data;
        uint16_t ethertype = (data[12] << 8) | data[13];

        printf("Packet #%d | Timestamp: %ld.%06ld | Length: %d | ",
               i + 1, pkt->header.ts.tv_sec, (long)pkt->header.ts.tv_usec, pkt->header.caplen);

        if (ethertype == 0x0800) printf("IPv4 | ");
        else if (ethertype == 0x86DD) printf("IPv6 | ");
        else if (ethertype == 0x0806) printf("ARP | ");
        else printf("Unknown EtherType | ");

        if (ethertype == 0x0800) {
            unsigned char proto = data[23];
            if (proto == 6) printf("TCP");
            else if (proto == 17) printf("UDP");
            else printf("Other L4");
        }
        printf("\n");
    }

    int choice;
    printf("Enter Packet ID to inspect in detail (0 to cancel): ");
    int scan_result = scanf("%d", &choice);
    if (scan_result == EOF) {
        printf("\n[C-Shark] Exiting packet inspection.\n");
        return;
    }
    if (scan_result != 1 || choice == 0) return;

    inspect_packet(choice);
}

// --- Full detailed packet inspection ---
void inspect_packet(int id) {
    if (id < 1 || id > storedCount) {
        printf("[C-Shark] Invalid Packet ID.\n");
        return;
    }

    StoredPacket *pkt = packetStorage[id - 1];
    const u_char *data = pkt->data;
    int len = pkt->header.caplen;

    printf("\n");
    printf("===============================================\n");
    printf("        C-SHARK DETAILED PACKET ANALYSIS\n");
    printf("===============================================\n");
    printf("\n");
    
    // --- PACKET SUMMARY ---
    printf("📊 PACKET SUMMARY\n");
    printf("\n");
    printf("Packet ID:      #%d\n", id);
    printf("Timestamp:      %ld.%06ld\n", pkt->header.ts.tv_sec, (long)pkt->header.ts.tv_usec);
    printf("Frame Length:   %d bytes\n", len);
    printf("Captured:       %d bytes\n", len);
    printf("\n");

    // --- COMPLETE FRAME HEX DUMP ---
    printf("📋 COMPLETE FRAME HEX DUMP\n");
    printf("\n");
    printf("  0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F      ASCII\n");
    for (int i = 0; i < len; i += 16) {
        printf("%04X ", i);
        
        // Hex part
        for (int j = 0; j < 16; j++) {
            if (i + j < len) {
                printf("%02X ", data[i + j]);
            } else {
                printf("   ");
            }
        }
        
        printf(" ");
        
        // ASCII part
        for (int j = 0; j < 16 && i + j < len; j++) {
            unsigned char c = data[i + j];
            printf("%c", isprint(c) ? c : '.');
        }
        printf("\n");
    }
    printf("\n");

    // --- LAYER-BY-LAYER ANALYSIS ---
    printf("🔍 LAYER-BY-LAYER ANALYSIS\n");
    printf("\n");
    
    // --- ETHERNET II FRAME (Layer 2) ---
    const u_char *dst_mac = &data[0];
    const u_char *src_mac = &data[6];
    uint16_t ethertype = (data[12] << 8) | data[13];
    
    printf("🔗 ETHERNET II FRAME (Layer 2)\n");
    printf("\n");
    printf("Destination MAC: %02X:%02X:%02X:%02X:%02X:%02X (Bytes 0-5)\n",
           dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5]);
    printf("  └─ Hex: %02X %02X %02X %02X %02X %02X\n",
           data[0], data[1], data[2], data[3], data[4], data[5]);
    printf("Source MAC:      %02X:%02X:%02X:%02X:%02X:%02X (Bytes 6-11)\n",
           src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5]);
    printf("  └─ Hex: %02X %02X %02X %02X %02X %02X\n",
           data[6], data[7], data[8], data[9], data[10], data[11]);
    
    const char *ether_desc = "";
    if (ethertype == 0x0800) ether_desc = " (IPv4)";
    else if (ethertype == 0x86DD) ether_desc = " (IPv6)";
    else if (ethertype == 0x0806) ether_desc = " (ARP)";
    
    printf("EtherType:       0x%04X%s (Bytes 12-13)\n", ethertype, ether_desc);
    printf("  └─ Hex: %02X %02X\n", data[12], data[13]);
    printf("\n");

    // --- LAYER 3 ANALYSIS ---
    if (ethertype == 0x0800) {
        // IPv4 HEADER
        printf("🌐 IPv4 HEADER (Layer 3)\n");
        printf("\n");
        const u_char *ip = data + 14;
        
        unsigned char version = (ip[0] >> 4) & 0xF;
        unsigned char ihl = ip[0] & 0xF;
        unsigned char tos = ip[1];
        unsigned short total_len = (ip[2] << 8) | ip[3];
        unsigned short id = (ip[4] << 8) | ip[5];
        unsigned short flags_frag = (ip[6] << 8) | ip[7];
        unsigned char ttl = ip[8];
        unsigned char protocol = ip[9];
        unsigned short checksum = (ip[10] << 8) | ip[11];
        
        printf("Version:         %u (4-bit field in byte 14)\n", version);
        printf("  └─ Hex: %02X (upper 4 bits)\n", ip[0]);
        printf("Header Length:   %u (%u bytes) (4-bit field in byte 14)\n", ihl, ihl * 4);
        printf("  └─ Hex: %02X (lower 4 bits)\n", ip[0]);
        printf("Type of Service: 0x%02X (Byte 15)\n", tos);
        printf("Total Length:    %u bytes (Bytes 16-17)\n", total_len);
        printf("  └─ Hex: %02X %02X\n", ip[2], ip[3]);
        printf("Identification:  0x%04X (%u) (Bytes 18-19)\n", id, id);
        printf("  └─ Hex: %02X %02X\n", ip[4], ip[5]);
        printf("Flags:           0x%04X (Byte 20-21)\n", flags_frag);
        printf("  └─ Hex: %02X %02X\n", ip[6], ip[7]);
        printf("Time to Live:    %u (Byte 22)\n", ttl);
        printf("  └─ Hex: %02X\n", ip[8]);
        
        const char *proto_name = "Unknown";
        if (protocol == 6) proto_name = "TCP";
        else if (protocol == 17) proto_name = "UDP";
        else if (protocol == 1) proto_name = "ICMP";
        
        printf("Protocol:        %u (%s) (Byte 23)\n", protocol, proto_name);
        printf("  └─ Hex: %02X\n", ip[9]);
        printf("Header Checksum: 0x%04X (Bytes 24-25)\n", checksum);
        printf("  └─ Hex: %02X %02X\n", ip[10], ip[11]);
        printf("Source IP:       %u.%u.%u.%u (Bytes 26-29)\n", ip[12], ip[13], ip[14], ip[15]);
        printf("  └─ Hex: %02X %02X %02X %02X\n", ip[12], ip[13], ip[14], ip[15]);
        printf("Destination IP:  %u.%u.%u.%u (Bytes 30-33)\n", ip[16], ip[17], ip[18], ip[19]);
        printf("  └─ Hex: %02X %02X %02X %02X\n", ip[16], ip[17], ip[18], ip[19]);
        printf("\n");
        
        // --- LAYER 4 TCP/UDP ANALYSIS ---
        if (protocol == 6 || protocol == 17) {
            const u_char *l4_data = ip + (ihl * 4);
            
            if (protocol == 6) {
                printf("📦 TCP HEADER (Layer 4)\n");
                printf("\n");
                
                unsigned short src_port = (l4_data[0] << 8) | l4_data[1];
                unsigned short dst_port = (l4_data[2] << 8) | l4_data[3];
                unsigned int seq = (l4_data[4] << 24) | (l4_data[5] << 16) | (l4_data[6] << 8) | l4_data[7];
                unsigned int ack = (l4_data[8] << 24) | (l4_data[9] << 16) | (l4_data[10] << 8) | l4_data[11];
                unsigned char data_offset = (l4_data[12] >> 4) & 0xF;
                unsigned char flags = l4_data[13];
                unsigned short window = (l4_data[14] << 8) | l4_data[15];
                unsigned short tcp_checksum = (l4_data[16] << 8) | l4_data[17];
                unsigned short urgent = (l4_data[18] << 8) | l4_data[19];
                
                int tcp_offset = 14 + (ihl * 4);
                
                const char *src_service = "";
                const char *dst_service = "";
                if (src_port == 80) src_service = " (HTTP)";
                else if (src_port == 443) src_service = " (HTTPS)";
                else if (src_port == 53) src_service = " (DNS)";
                if (dst_port == 80) dst_service = " (HTTP)";
                else if (dst_port == 443) dst_service = " (HTTPS)";
                else if (dst_port == 53) dst_service = " (DNS)";
                
                printf("Source Port:     %u%s (Bytes %d-%d)\n", src_port, src_service, tcp_offset, tcp_offset+1);
                printf("  └─ Hex: %02X %02X\n", l4_data[0], l4_data[1]);
                printf("Destination Port:%u%s (Bytes %d-%d)\n", dst_port, dst_service, tcp_offset+2, tcp_offset+3);
                printf("  └─ Hex: %02X %02X\n", l4_data[2], l4_data[3]);
                printf("Sequence Number: %u (Bytes %d-%d)\n", seq, tcp_offset+4, tcp_offset+7);
                printf("  └─ Hex: %02X %02X %02X %02X\n", l4_data[4], l4_data[5], l4_data[6], l4_data[7]);
                printf("Acknowledgment:  %u (Bytes %d-%d)\n", ack, tcp_offset+8, tcp_offset+11);
                printf("  └─ Hex: %02X %02X %02X %02X\n", l4_data[8], l4_data[9], l4_data[10], l4_data[11]);
                printf("Header Length:   %u (%u bytes) (upper 4 bits of byte %d)\n", data_offset, data_offset*4, tcp_offset+12);
                printf("  └─ Hex: %02X\n", l4_data[12]);
                
                printf("Flags:           0x%02X (Byte %d)\n", flags, tcp_offset+13);
                printf("  └─ Hex: %02X\n", l4_data[13]);
                printf("  └─ URG:%d ACK:%d PSH:%d RST:%d SYN:%d FIN:%d\n",
                       (flags & 0x20) ? 1 : 0, (flags & 0x10) ? 1 : 0, (flags & 0x08) ? 1 : 0,
                       (flags & 0x04) ? 1 : 0, (flags & 0x02) ? 1 : 0, (flags & 0x01) ? 1 : 0);
                       
                printf("Window Size:     %u (Bytes %d-%d)\n", window, tcp_offset+14, tcp_offset+15);
                printf("  └─ Hex: %02X %02X\n", l4_data[14], l4_data[15]);
                printf("Checksum:        0x%04X (Bytes %d-%d)\n", tcp_checksum, tcp_offset+16, tcp_offset+17);
                printf("  └─ Hex: %02X %02X\n", l4_data[16], l4_data[17]);
                printf("Urgent Pointer:  %u (Bytes %d-%d)\n", urgent, tcp_offset+18, tcp_offset+19);
                printf("  └─ Hex: %02X %02X\n", l4_data[18], l4_data[19]);
                printf("\n");
                
                // APPLICATION DATA
                int payload_offset = tcp_offset + (data_offset * 4);
                int payload_len = len - payload_offset;
                
                if (payload_len > 0) {
                    const char *app_protocol = "Unknown/Custom";
                    if (src_port == 80 || dst_port == 80) app_protocol = "HTTP";
                    else if (src_port == 443 || dst_port == 443) app_protocol = "HTTPS/TLS";
                    else if (src_port == 53 || dst_port == 53) app_protocol = "DNS";
                    
                    printf("📱 APPLICATION DATA (Layer 5-7)\n");
                    printf("\n");
                    printf("Protocol:        Identified as %s on port %u\n", app_protocol, dst_port);
                    printf("Payload Length:  %d bytes\n", payload_len);
                    printf("\n");
                    
                    int display_len = payload_len < 64 ? payload_len : 64;
                    printf("First %d bytes of payload:\n", display_len);
                    for (int i = 0; i < display_len; i += 16) {
                        printf("%04X ", payload_offset + i);
                        for (int j = 0; j < 16; j++) {
                            if (i + j < display_len) {
                                printf("%02X ", data[payload_offset + i + j]);
                            } else {
                                printf("   ");
                            }
                        }
                        printf(" ");
                        for (int j = 0; j < 16 && i + j < display_len; j++) {
                            unsigned char c = data[payload_offset + i + j];
                            printf("%c", isprint(c) ? c : '.');
                        }
                        printf("\n");
                    }
                }
            }
            else if (protocol == 17) {
                printf("📦 UDP HEADER (Layer 4)\n");
                printf("\n");
                
                unsigned short src_port = (l4_data[0] << 8) | l4_data[1];
                unsigned short dst_port = (l4_data[2] << 8) | l4_data[3];
                unsigned short udp_len = (l4_data[4] << 8) | l4_data[5];
                unsigned short udp_checksum = (l4_data[6] << 8) | l4_data[7];
                
                int udp_offset = 14 + (ihl * 4);
                
                const char *src_service = "";
                const char *dst_service = "";
                if (src_port == 53) src_service = " (DNS)";
                if (dst_port == 53) dst_service = " (DNS)";
                
                printf("Source Port:     %u%s (Bytes %d-%d)\n", src_port, src_service, udp_offset, udp_offset+1);
                printf("  └─ Hex: %02X %02X\n", l4_data[0], l4_data[1]);
                printf("Destination Port:%u%s (Bytes %d-%d)\n", dst_port, dst_service, udp_offset+2, udp_offset+3);
                printf("  └─ Hex: %02X %02X\n", l4_data[2], l4_data[3]);
                printf("Length:          %u (Bytes %d-%d)\n", udp_len, udp_offset+4, udp_offset+5);
                printf("  └─ Hex: %02X %02X\n", l4_data[4], l4_data[5]);
                printf("Checksum:        0x%04X (Bytes %d-%d)\n", udp_checksum, udp_offset+6, udp_offset+7);
                printf("  └─ Hex: %02X %02X\n", l4_data[6], l4_data[7]);
                printf("\n");
                
                // APPLICATION DATA
                int payload_offset = udp_offset + 8;
                int payload_len = udp_len - 8;
                
                if (payload_len > 0) {
                    const char *app_protocol = "Unknown/Custom";
                    if (src_port == 53 || dst_port == 53) app_protocol = "DNS";
                    
                    printf("📱 APPLICATION DATA (Layer 5-7)\n");
                    printf("\n");
                    printf("Protocol:        Identified as %s on port %u\n", app_protocol, dst_port);
                    printf("Payload Length:  %d bytes\n", payload_len);
                    printf("\n");
                    
                    int display_len = payload_len < 64 ? payload_len : 64;
                    printf("First %d bytes of payload:\n", display_len);
                    for (int i = 0; i < display_len; i += 16) {
                        printf("%04X ", payload_offset + i);
                        for (int j = 0; j < 16; j++) {
                            if (i + j < display_len) {
                                printf("%02X ", data[payload_offset + i + j]);
                            } else {
                                printf("   ");
                            }
                        }
                        printf(" ");
                        for (int j = 0; j < 16 && i + j < display_len; j++) {
                            unsigned char c = data[payload_offset + i + j];
                            printf("%c", isprint(c) ? c : '.');
                        }
                        printf("\n");
                    }
                }
            }
        }
    }
    else if (ethertype == 0x0806) {
        // ARP PACKET
        printf("🔗 ARP PACKET (Layer 2/3)\n");
        printf("\n");
        const u_char *arp = data + 14;
        
        unsigned short hw_type = (arp[0] << 8) | arp[1];
        unsigned short proto_type = (arp[2] << 8) | arp[3];
        unsigned char hw_len = arp[4];
        unsigned char proto_len = arp[5];
        unsigned short operation = (arp[6] << 8) | arp[7];
        
        printf("Hardware Type:   %u (Ethernet) (Bytes 14-15)\n", hw_type);
        printf("  └─ Hex: %02X %02X\n", arp[0], arp[1]);
        printf("Protocol Type:   0x%04X (IPv4) (Bytes 16-17)\n", proto_type);
        printf("  └─ Hex: %02X %02X\n", arp[2], arp[3]);
        printf("Hardware Length: %u (Bytes 18)\n", hw_len);
        printf("  └─ Hex: %02X\n", arp[4]);
        printf("Protocol Length: %u (Bytes 19)\n", proto_len);
        printf("  └─ Hex: %02X\n", arp[5]);
        printf("Operation:       %u (%s) (Bytes 20-21)\n", operation, 
               operation == 1 ? "Request" : operation == 2 ? "Reply" : "Unknown");
        printf("  └─ Hex: %02X %02X\n", arp[6], arp[7]);
        printf("Sender MAC:      %02X:%02X:%02X:%02X:%02X:%02X (Bytes 22-27)\n",
               arp[8], arp[9], arp[10], arp[11], arp[12], arp[13]);
        printf("  └─ Hex: %02X %02X %02X %02X %02X %02X\n",
               arp[8], arp[9], arp[10], arp[11], arp[12], arp[13]);
        printf("Sender IP:       %u.%u.%u.%u (Bytes 28-31)\n",
               arp[14], arp[15], arp[16], arp[17]);
        printf("  └─ Hex: %02X %02X %02X %02X\n", arp[14], arp[15], arp[16], arp[17]);
        printf("Target MAC:      %02X:%02X:%02X:%02X:%02X:%02X (Bytes 32-37)\n",
               arp[18], arp[19], arp[20], arp[21], arp[22], arp[23]);
        printf("  └─ Hex: %02X %02X %02X %02X %02X %02X\n",
               arp[18], arp[19], arp[20], arp[21], arp[22], arp[23]);
        printf("Target IP:       %u.%u.%u.%u (Bytes 38-41)\n",
               arp[24], arp[25], arp[26], arp[27]);
        printf("  └─ Hex: %02X %02X %02X %02X\n", arp[24], arp[25], arp[26], arp[27]);
        printf("\n");
    }
    
    printf("===============================================\n");
    printf("           END OF PACKET ANALYSIS\n");
    printf("===============================================\n");
}

