#include <sys/types.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h> 
#include <time.h> 
#include <signal.h>
#include <string.h>
#include "../include/sniffer.h"
#include "../include/cshark.h"

interface_list_t list_interfaces() {
    pcap_if_t *alldevs = NULL;
    pcap_if_t *d;
    char errbuf[PCAP_ERRBUF_SIZE];
    interface_list_t result = { .devices = NULL, .count = 0 };

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "[C-Shark] Error finding devices: %s\n", errbuf);
        return result; 
    }

    if (alldevs == NULL) {
        puts("[C-Shark] No interfaces found.");
        return result;
    }

    puts("[C-Shark] Searching for available interfaces... Found!");

    int i = 1;
    for (d = alldevs; d != NULL; d = d->next) {
        printf("%2d. %s", i, d->name);
        if (d->description) {
            printf(" (%s)", d->description);
        }
        printf("\n");
        i++;
    }
    
    result.devices = alldevs;
    result.count = i - 1; 
    return result;
}

int main_menu(const char* interface_name) {
    int choice;
    printf("\n[C-Shark] Interface '%s' selected. What's next?\n\n", interface_name);
    printf("1. Start Sniffing (All Packets)\n");
    printf("2. Start Sniffing (With Filters)\n");
    printf("3. Inspect Last Session\n");
    printf("4. Exit C-Shark\n");
    
    printf("\nEnter choice (1-4): ");
    
    int scan_result = scanf("%d", &choice);
    
    if (scan_result == EOF) {
        return 4; 
    }

    if (scan_result != 1) {
        while (getchar() != '\n'); 
        return -1; 
    }
    return choice;
}

int main(void) {
    printf("[C-Shark] The Command-Line Packet Predator\n==============================================\n");
    
    if (signal(SIGINT, handle_sigint) == SIG_ERR) {
        perror("Could not set up signal handler");
        return 1;
    }
    
    interface_list_t list = list_interfaces();
    pcap_if_t *alldevs = list.devices;
    int dev_count = list.count;
    
    if (alldevs == NULL) {
        return 1;
    }

    int selection = 0;
    while (selection < 1 || selection > dev_count) {
        printf("\nSelect an interface to sniff (1-%d): ", dev_count);
        
        int scan_result = scanf("%d", &selection);
        
        if (scan_result == EOF) {
            printf("\n[C-Shark] Exiting C-Shark. Goodbye!\n");
            pcap_freealldevs(alldevs);
            return 0;
        }
        
        if (scan_result != 1) {
            printf("[C-Shark] Invalid input. Please enter a number.\n");
            while (getchar() != '\n');
            continue; 
        }

        if (selection < 1 || selection > dev_count) {
            printf("[C-Shark] Invalid selection. Please choose a number between 1 and %d.\n", dev_count);
        }
    }

    pcap_if_t *d = alldevs;
    for (int i = 1; i < selection; i++) {
        d = d->next;
    }
    char *selected_dev_name = d->name;

    int menu_choice = 0;
    while (menu_choice != 4) {
        menu_choice = main_menu(selected_dev_name);
        
        if (menu_choice == 1) {
            packet_count = 1; 
            start_sniffing(selected_dev_name);
        } 
        else if (menu_choice == 2) {
            packet_count = 1;
            start_sniffing_with_filter(selected_dev_name);
        }
        else if (menu_choice == 3) {
            inspect_last_session();
        }
        else if (menu_choice == 4) {
            printf("[C-Shark] Exiting C-Shark. Goodbye!\n");
        } 
        else if (menu_choice != 4) {
            printf("[C-Shark] Option %d is not yet implemented or invalid.\n", menu_choice);
        }
    }   
    
    pcap_freealldevs(alldevs);
    return 0;
}
