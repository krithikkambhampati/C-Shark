#ifndef CSHARK_H
#define CSHARK_H

#include <pcap.h>

typedef struct {
    pcap_if_t *devices;
    int count;
} interface_list_t;

interface_list_t list_interfaces();
int main_menu(const char* interface_name);

#endif
