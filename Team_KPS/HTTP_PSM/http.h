#include <map>
#include <stdio.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <errno.h>
#include <fstream>
#include <iostream>

struct IPv4_INFO {
    u_int32_t sip;
    u_int32_t dip;
    u_int16_t sport;
    u_int16_t dport;
    char      file_name[256];
};


void http_analysis (struct tcphdr *tcp_header, struct ip *ip_header, u_char *payload, int payload_size);
void handle_http (u_char *payload, int payload_size, std::map<u_int16_t, IPv4_INFO> &receiver, u_int16_t my_port, u_int8_t request_flag);
