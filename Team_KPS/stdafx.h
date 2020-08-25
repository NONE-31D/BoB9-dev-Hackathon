#pragma once
#include <string>
#include <unistd.h>
#include <cstring>
#include <iostream>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <jsoncpp/json/json.h>
#include <fstream>

using namespace std;
using namespace Json;

class Protocols{
public:
    char* cmd, *argv, *proto;
    u_int8_t *dmac, *smac;
    struct in_addr ip_src, ip_dst;
    u_int16_t sport, dport;
    void print_mac(u_int8_t* mac, char* mac_str){
        sprintf(mac_str, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    }
    void print_ip(in_addr ip, char* ip_str){
        char* tmp;
        tmp = inet_ntoa(ip);
        strcpy(ip_str, tmp);
    }
};

void show_interface();
void traffic(const char *interface);
void pcap_f(const char *file);
void analysis(pcap_t * pcap);
void usage();
void print_mac(u_int8_t *smac, u_int8_t *dmac, u_int16_t type);
void print_binary(u_char *payload, int length);