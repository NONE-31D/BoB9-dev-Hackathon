#pragma once
#include <string>
#include <unistd.h>
#include <cstring>
#include <iostream>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

using namespace std;

void show_interface();
void traffic(const char *interface);
void pcap_f(const char *file);
void analysis(pcap_t * pcap);
void usage();
void print_mac(u_int8_t *smac, u_int8_t *dmac, u_int16_t type);
void print_binary(u_char *payload, int length);